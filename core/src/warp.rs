//! Cloudflare WARP поверх своего сервера.
//!
//! WireGuard в РФ ТСПУ узнаёт по рукопожатию и режет, поэтому по умолчанию WARP
//! идёт **через сервер** (outbound wireguard в Xray с `sockopt.dialerProxy` на
//! исходящий сервера): провайдер видит только сервер, Cloudflare — IP сервера,
//! а сайты — IP Cloudflare (удобно для сервисов, которые не пускают с IP
//! хостеров). Напрямую — только как «попробовать».
//!
//! В списке серверов WARP — обычный сервер «WARP · <сервер>» с id `warp-…`:
//! так он сам работает в выборе сервера, «Авто», «Сайт → сервер» и проверках.
//! Сам сервер собирается из `Store::warp` (`Store::sync_warp`) и при каждом
//! изменении списка пересобирается: исходящие «подложки» всегда свежие.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::node::{fnv64, Node, Protocol, Security, Transport};

/// Сколько WARP-серверов можно (по одному на сервер-«подложку»).
pub const WARP_MAX: usize = 8;
/// Префикс id WARP-серверов. Обычные id — 16 hex-символов, не совпадут.
pub const ID_PREFIX: &str = "warp-";
/// Тег главного исходящего «подложки» внутри WARP-сервера.
const VIA_TAG: &str = "warp-via";
/// Запасной адрес WARP (engage.cloudflareclient.com), если API не дал свой.
const DEFAULT_ENDPOINT: &str = "162.159.192.1:2408";

const API: &str = "https://api.cloudflareclient.com/v0a5641/reg";
const UA: &str = "1.1.1.1/6.38.9-5641 (Android 16.0.0)";
const CLIENT_VERSION: &str = "a-6.38.9-5641";

/// Учётка WARP: всё, что нужно для WireGuard. Секрет — как пароль сервера:
/// в state.json (под DPAPI, если включено «Шифровать»), в лог не попадает.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct WarpKey {
    /// Приватный ключ x25519, base64.
    pub secret: String,
    /// Ключ сервера Cloudflare, base64.
    pub peer: String,
    /// Адреса интерфейса: v4 и v6 без маски.
    pub v4: String,
    pub v6: String,
    /// 3 байта из client_id — Cloudflare по ним узнаёт устройство.
    pub reserved: [u8; 3],
    /// IP:порт сервера WARP.
    pub endpoint: String,
}

impl std::fmt::Debug for WarpKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WarpKey(endpoint {}, секрет скрыт)", self.endpoint) // i18n-skip: только для отладки
    }
}

/// WARP через сервер `via` (id + подписка, как в «Сайт → сервер»).
/// `via` пустой — напрямую («попробовать»).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Warp {
    pub via: String,
    pub via_sub: String,
    pub key: WarpKey,
}

fn b64_key(s: &str) -> bool {
    use base64::Engine;
    s.len() == 44 && base64::engine::general_purpose::STANDARD.decode(s).is_ok_and(|b| b.len() == 32)
}

/// Публичный адрес: WARP не должен смотреть в локалку (запись из чужого бэкапа).
fn public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified() || v.is_broadcast() || v.is_multicast() || v.octets()[0] == 0 || (v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64) || v.octets()[0] >= 240),
        IpAddr::V6(v) => {
            let s = v.segments()[0];
            !(v.is_loopback() || v.is_unspecified() || v.is_multicast() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80 || v.to_ipv4_mapped().is_some())
        }
    }
}

impl WarpKey {
    pub fn validate(&self) -> Result<(), String> {
        if !b64_key(&self.secret) || !b64_key(&self.peer) {
            return Err(trs!("WARP: ключи испорчены").into());
        }
        if self.v4.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(trs!("WARP: кривой адрес IPv4").into());
        }
        if !self.v6.is_empty() && self.v6.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(trs!("WARP: кривой адрес IPv6").into());
        }
        let ep: SocketAddr = self.endpoint.parse().map_err(|_| trs!("WARP: кривой адрес сервера").to_string())?;
        if ep.port() == 0 || !public_ip(&ep.ip()) {
            return Err(trs!("WARP: адрес сервера не похож на Cloudflare").into());
        }
        Ok(())
    }
}

impl Warp {
    pub fn sane(&self) -> bool {
        let plain = |x: &str| x.len() <= 128 && x.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        plain(&self.via) && plain(&self.via_sub) && !self.via.starts_with(ID_PREFIX) && (self.via.is_empty() || self.via != crate::store::AUTO_ID) && self.key.validate().is_ok()
    }

    /// id WARP-сервера: один на «подложку».
    pub fn node_id(&self) -> String {
        format!("{ID_PREFIX}{}", &fnv64(&format!("{}|{}", self.via, self.via_sub))[..12])
    }
}

pub fn is_warp(id: &str) -> bool {
    id.starts_with(ID_PREFIX)
}

/// Исходящий wireguard (tag "proxy"). Только в своём процессе (`noKernelTun`),
/// MTU 1280 — с запасом на обёртку VLESS.
pub fn outbound(k: &WarpKey, via: bool) -> Value {
    let mut addr = vec![format!("{}/32", k.v4)];
    if !k.v6.is_empty() {
        addr.push(format!("{}/128", k.v6));
    }
    let mut o = json!({
        "tag": "proxy",
        "protocol": "wireguard",
        "settings": {
            "secretKey": k.secret,
            "address": addr,
            "peers": [{ "publicKey": k.peer, "endpoint": k.endpoint, "allowedIPs": ["0.0.0.0/0", "::/0"], "keepAlive": 25 }],
            "reserved": k.reserved,
            "mtu": 1280,
            "noKernelTun": true
        }
    });
    if via {
        o["streamSettings"] = json!({ "sockopt": { "dialerProxy": VIA_TAG } });
    }
    o
}

/// Сервер «WARP · …» для списка. `via` — сервер-«подложка» (None — напрямую;
/// у записи с `via` его нет — сервера тоже нет: эти сайты закрыты, а не идут напрямую).
pub fn node(w: &Warp, via: Option<&Node>) -> Option<Node> {
    if !w.via.is_empty() && via.is_none() {
        return None;
    }
    let mut outs = vec![outbound(&w.key, via.is_some())];
    let (name, address, port) = match via {
        Some(v) => {
            outs.extend(retag_via(crate::xray::node_outbounds(v)));
            (format!("WARP · {}", v.name), v.address.clone(), v.port)
        }
        None => {
            let ep: SocketAddr = w.key.endpoint.parse().ok()?;
            (trs!("WARP · напрямую").to_string(), ep.ip().to_string(), ep.port())
        }
    };
    Some(Node {
        id: w.node_id(),
        name: crate::store::tidy_name(&name, crate::store::MAX_SERVER_NAME),
        protocol: Protocol::Other,
        address,
        port,
        uuid: None,
        password: None,
        method: None,
        flow: None,
        encryption: None,
        alter_id: 0,
        transport: Transport { network: if via.is_some() { trs!("через сервер").into() } else { "udp".into() }, ..Default::default() },
        security: Security { kind: "none".into(), ..Default::default() },
        // Ссылки для телефона у WARP нет (секрет и цепочка — только в rxvpn).
        link: String::new(),
        sub_id: None,
        group: Some("WARP".into()),
        raw: Some(json!({ "outbounds": outs })),
    })
}

/// Исходящие «подложки»: главный → "warp-via", помощники → "warp-via-…".
fn retag_via(list: Vec<Value>) -> Vec<Value> {
    let tags: std::collections::BTreeSet<String> = list.iter().filter_map(|o| o["tag"].as_str().map(str::to_string)).collect();
    let rename = |t: &str| if t == "proxy" { VIA_TAG.to_string() } else { format!("{VIA_TAG}-{t}") };
    list.into_iter()
        .map(|mut o| {
            if let Some(t) = o["tag"].as_str().map(str::to_string) {
                o["tag"] = json!(rename(&t));
            }
            if let Some(t) = o.pointer("/streamSettings/sockopt/dialerProxy").and_then(Value::as_str).map(str::to_string) {
                if tags.contains(&t) {
                    o["streamSettings"]["sockopt"]["dialerProxy"] = json!(rename(&t));
                }
            }
            if let Some(t) = o["proxySettings"]["tag"].as_str().map(str::to_string) {
                if tags.contains(&t) {
                    o["proxySettings"]["tag"] = json!(rename(&t));
                }
            }
            o
        })
        .collect()
}

/// Новый ключ x25519: (секрет, публичный), base64 как у WireGuard.
pub fn new_keypair() -> (String, String) {
    use base64::Engine;
    let mut sk = [0u8; 32];
    getrandom::getrandom(&mut sk).expect("нет источника случайных чисел");
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    let pk = curve25519_dalek::MontgomeryPoint::mul_base_clamped(sk);
    let e = base64::engine::general_purpose::STANDARD;
    let r = (e.encode(sk), e.encode(pk.to_bytes()));
    sk.fill(0);
    r
}

/// Тело запроса регистрации (как у wgcf).
pub fn reg_body(public: &str, tos: &str) -> Value {
    json!({
        "key": public,
        "install_id": "",
        "fcm_token": "",
        "tos": tos,
        "model": "PC",
        "serial_number": "",
        "os_version": "16.0.0",
        "key_type": "curve25519",
        "tunnel_type": "wireguard",
        "type": "Android",
        "locale": "en_US"
    })
}

/// Ответ регистрации → учётка. `secret` — наш приватный ключ.
pub fn parse_reg(v: &Value, secret: &str) -> Result<WarpKey, String> {
    use base64::Engine;
    let c = &v["config"];
    let cid = c["client_id"].as_str().ok_or(trs!("WARP: в ответе нет client_id"))?;
    let r = base64::engine::general_purpose::STANDARD.decode(cid).map_err(|_| trs!("WARP: кривой client_id").to_string())?;
    let reserved: [u8; 3] = r.get(..3).and_then(|x| x.try_into().ok()).ok_or(trs!("WARP: короткий client_id"))?;
    let peer = &c["peers"][0];
    let ep = &peer["endpoint"];
    // v4 приходит как «162.159.192.1:0» — порт берём из host (…:2408).
    let port = ep["host"].as_str().and_then(|h| h.rsplit_once(':')).and_then(|(_, p)| p.parse::<u16>().ok()).filter(|p| *p > 0).unwrap_or(2408);
    let endpoint = ep["v4"]
        .as_str()
        .and_then(|a| a.rsplit_once(':').map_or(Some(a), |(h, _)| Some(h)))
        .and_then(|h| h.parse::<std::net::Ipv4Addr>().ok())
        .map(|ip| format!("{ip}:{port}"))
        .unwrap_or_else(|| DEFAULT_ENDPOINT.into());
    let addr = &c["interface"]["addresses"];
    let k = WarpKey {
        secret: secret.to_string(),
        peer: peer["public_key"].as_str().unwrap_or("").to_string(),
        v4: addr["v4"].as_str().unwrap_or("").split('/').next().unwrap_or("").to_string(),
        v6: addr["v6"].as_str().unwrap_or("").split('/').next().unwrap_or("").to_string(),
        reserved,
        endpoint,
    };
    k.validate()?;
    Ok(k)
}

/// Время для поля tos: RFC 3339 в UTC.
fn rfc3339(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Дни с 1970-01-01 → дата (алгоритм Хиннанта).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z", secs / 3600, secs % 3600 / 60, secs % 60)
}

/// TLS как у приложения 1.1.1.1 (TLS 1.2, AES-256-GCM, http/1.1): API WARP
/// отвечает не всем клиентам.
fn tls() -> rustls::ClientConfig {
    use rustls::crypto::ring::{cipher_suite as cs, default_provider};
    let mut p = default_provider();
    p.cipher_suites = vec![cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384];
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let mut c = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(p))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS 1.2 есть")
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    c
}

/// Зарегистрировать новую бесплатную учётку WARP. `proxy` — через VPN
/// (socks5h://…): API Cloudflare из РФ открывается не везде.
pub async fn register(proxy: Option<&str>, now: i64) -> Result<WarpKey, String> {
    let (secret, public) = new_keypair();
    let secret = zeroize::Zeroizing::new(secret);
    let mut b = reqwest::Client::builder()
        .use_preconfigured_tls(tls())
        .http1_only()
        .timeout(Duration::from_secs(25))
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none());
    b = match proxy {
        Some(p) => b.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?),
        None => b.no_proxy(),
    };
    let c = b.build().map_err(|e| e.to_string())?;
    let resp = c
        .post(API)
        .header("User-Agent", UA)
        .header("CF-Client-Version", CLIENT_VERSION)
        .header("Content-Type", "application/json; charset=UTF-8")
        .body(reg_body(&public, &rfc3339(now)).to_string())
        .send()
        .await
        .map_err(|e| tr!("WARP: не достучался до Cloudflare ({})", crate::net::explain(&e)))?;
    let status = resp.status();
    let body = crate::net::read_capped(resp, 64 << 10).await?;
    if !status.is_success() {
        return Err(match status.as_u16() {
            429 => trs!("WARP: Cloudflare просит подождать (слишком много регистраций) — попробуй через час").into(),
            403 => trs!("WARP: Cloudflare не пустил регистрацию с этого адреса — подключись к другому серверу и повтори").into(),
            s => tr!("WARP: Cloudflare ответил {s}"),
        });
    }
    let v: Value = serde_json::from_slice(&body).map_err(|_| trs!("WARP: непонятный ответ Cloudflare").to_string())?;
    parse_reg(&v, &secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> WarpKey {
        let (secret, peer) = new_keypair();
        WarpKey { secret, peer, v4: "172.16.0.2".into(), v6: "2606:4700:110:8a1a::1".into(), reserved: [1, 2, 3], endpoint: DEFAULT_ENDPOINT.into() }
    }

    #[test]
    fn registration_reply() {
        let v = json!({"id": "x", "token": "t", "config": {
            "client_id": "AQID", // [1,2,3]
            "peers": [{"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                       "endpoint": {"v4": "162.159.192.5:0", "v6": "[2606:4700:d0::a29f:c005]:0", "host": "engage.cloudflareclient.com:2408"}}],
            "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110:8a1a::1"}}}});
        let (secret, _) = new_keypair();
        let k = parse_reg(&v, &secret).unwrap();
        assert_eq!(k.reserved, [1, 2, 3]);
        assert_eq!(k.endpoint, "162.159.192.5:2408");
        assert_eq!(k.v6, "2606:4700:110:8a1a::1");
        assert!(!format!("{k:?}").contains(&secret), "секрет не в отладке");
        // Чужой бэкап: адрес в локалку, кривые ключи — нет.
        for bad in [
            WarpKey { endpoint: "127.0.0.1:2408".into(), ..k.clone() },
            WarpKey { endpoint: "192.168.1.1:2408".into(), ..k.clone() },
            WarpKey { endpoint: "[::ffff:127.0.0.1]:2408".into(), ..k.clone() },
            WarpKey { peer: "x".into(), ..k.clone() },
            WarpKey { v4: "a".into(), ..k.clone() },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        assert!(parse_reg(&json!({"config": {}}), &secret).is_err());
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_793_534_400), "2026-11-01T12:00:00.000Z");
    }

    #[test]
    fn chain_through_server() {
        let via = crate::parse_link("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&sni=a.com&pbk=AAAA&sid=ab&type=tcp&flow=xtls-rprx-vision#NL").unwrap();
        let w = Warp { via: via.id.clone(), via_sub: String::new(), key: key() };
        assert!(w.sane());
        let n = node(&w, Some(&via)).unwrap();
        assert!(is_warp(&n.id) && n.link.is_empty());
        let outs = crate::xray::node_outbounds(&n);
        assert_eq!(outs[0]["protocol"], "wireguard");
        assert_eq!(outs[0]["settings"]["noKernelTun"], true);
        assert_eq!(outs[0]["streamSettings"]["sockopt"]["dialerProxy"], VIA_TAG);
        assert_eq!(outs[1]["tag"], VIA_TAG);
        assert_eq!(outs[1]["protocol"], "vless");
        // Подложки нет — и WARP-сервера нет (сайты закрыты, а не напрямую).
        assert!(node(&w, None).is_none());
        // Напрямую — без dialerProxy.
        let d = node(&Warp { via: String::new(), ..w.clone() }, None).unwrap();
        assert!(crate::xray::node_outbounds(&d)[0].get("streamSettings").is_none());
        // WARP через WARP и «Авто» — нельзя.
        assert!(!Warp { via: n.id.clone(), ..w.clone() }.sane());
        assert!(!Warp { via: crate::store::AUTO_ID.into(), ..w }.sane());
    }
}
