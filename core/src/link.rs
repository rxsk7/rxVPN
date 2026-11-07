//! Парсинг ссылок: vless://, vmess://, trojan://, ss:// и текста подписки.

use std::collections::HashMap;

use base64::Engine;
use percent_encoding::percent_decode_str;
use serde_json::Value;
use url::Url;

use crate::node::{fnv64, Node, Protocol, Security, Transport};

#[derive(Debug, PartialEq)]
pub enum LinkError {
    UnknownScheme(String),
    Malformed(String),
    Unsupported(String),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&match self {
            LinkError::UnknownScheme(x) => tr!("неизвестная схема ссылки: {x}"),
            LinkError::Malformed(x) => tr!("битая ссылка: {x}"),
            LinkError::Unsupported(x) => tr!("не поддерживается: {x}"),
        })
    }
}

impl std::error::Error for LinkError {}

type Result<T> = std::result::Result<T, LinkError>;

/// Разобрать одну ссылку.
pub fn parse_link(link: &str) -> Result<Node> {
    let link = link.trim();
    let scheme = link
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .ok_or_else(|| LinkError::Malformed(trs!("нет '://'").into()))?;

    match scheme.as_str() {
        "vless" => parse_vless_like(link, Protocol::Vless),
        "trojan" => parse_vless_like(link, Protocol::Trojan),
        "vmess" => parse_vmess(link),
        "ss" => parse_ss(link),
        "hysteria2" | "hy2" => parse_hysteria2(link),
        "tuic" => Err(LinkError::Unsupported(
            trs!("tuic:// — в ядре Xray этого протокола нет (только в sing-box)").into(),
        )),
        "wireguard" | "wg" => Err(LinkError::Unsupported(tr!("{scheme}:// — пока не поддерживается ядром клиента"
        ))),
        other => Err(LinkError::UnknownScheme(shorten(other))),
    }
}

/// Разобрать произвольный текст: несколько ссылок построчно или base64-подписку.
/// Возвращает успешно разобранные сервера и ошибки по строкам.
pub fn parse_many(text: &str) -> (Vec<Node>, Vec<String>) {
    use crate::jsonsub::{looks_like_json, parse_json_subscription};

    let text = text.trim();
    // Remnawave/Marzban могут отдать массив готовых конфигов Xray вместо ссылок.
    if looks_like_json(text) {
        return parse_json_subscription(text).unwrap_or_else(|e| (Vec::new(), vec![e]));
    }
    if text.starts_with("proxies:") || text.contains("\nproxies:") {
        return (Vec::new(), vec![trs!("это формат Clash (YAML), нужен формат v2rayN").into()]);
    }

    // Подписки обычно отдают base64 от списка ссылок. Если в тексте нет "://",
    // пробуем раскодировать.
    let decoded;
    let body = if !text.contains("://") {
        match b64_decode(text) {
            Some(d) => {
                decoded = d;
                decoded.as_str()
            }
            None => text,
        }
    } else {
        text
    };
    if body.trim_start() != text && looks_like_json(body) {
        return parse_json_subscription(body).unwrap_or_else(|e| (Vec::new(), vec![e]));
    }

    let mut nodes = Vec::new();
    let mut errors = Vec::new();
    for line in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.starts_with("happ://") {
            errors.push(
                trs!("happ:// — зашифрованная ссылка, её понимает только Happ. \
                 Попроси у VPN-сервиса обычную ссылку или подписку для v2rayN")
                    .into(),
            );
            continue;
        }
        match parse_link(line) {
            Ok(n) => nodes.push(n),
            Err(e) => errors.push(format!("{}: {e}", shorten(line))),
        }
    }
    (nodes, errors)
}

fn shorten(s: &str) -> String {
    if s.chars().count() > 40 {
        format!("{}…", s.chars().take(40).collect::<String>())
    } else {
        s.to_string()
    }
}

/// Терпимый base64: обычный и url-safe, с паддингом и без, с переносами строк.
pub fn b64_decode(s: &str) -> Option<String> {
    let mut clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    while !clean.len().is_multiple_of(4) {
        clean.push('=');
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(clean.as_bytes())
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn pct(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

fn non_empty(v: Option<&String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Ссылка без #имени — по ней считаем id, чтобы переименование не плодило дубли.
fn id_for(link: &str) -> String {
    fnv64(link.split('#').next().unwrap_or(link))
}

// ---------- hysteria2:// (hy2://) ----------

/// hysteria2://пароль@хост:порт/?sni=…&obfs=salamander&obfs-password=…&pinSHA256=…#имя
/// Порт может быть списком для «прыжков»: хост:443,20000-30000 (или mport=…).
/// Собираем готовый outbound Xray (протокол hysteria, транспорт hysteria, TLS) —
/// дальше он идёт той же дорогой, что сервера из JSON-подписок (с той же очисткой).
fn parse_hysteria2(link: &str) -> Result<Node> {
    let rest = link.split_once("://").map(|x| x.1).unwrap_or("");
    let (main, frag) = rest.split_once('#').unwrap_or((rest, ""));
    let (before_q, query) = main.split_once('?').unwrap_or((main, ""));
    let authority = before_q.split('/').next().unwrap_or("");
    let (auth, hostport) = authority
        .rsplit_once('@')
        .ok_or_else(|| LinkError::Malformed(trs!("нет пароля перед '@'").into()))?;
    let auth = pct(auth);
    if auth.is_empty() || auth.chars().any(char::is_control) {
        return Err(LinkError::Malformed(trs!("пустой пароль").into()));
    }
    // [ipv6]:порт или хост:порт
    let (host, ports) = if let Some(r) = hostport.strip_prefix('[') {
        let (h, tail) = r.split_once(']').ok_or_else(|| LinkError::Malformed(trs!("кривой IPv6").into()))?;
        if h.parse::<std::net::Ipv6Addr>().is_err() || !(tail.is_empty() || tail.starts_with(':')) {
            return Err(LinkError::Malformed(trs!("кривой IPv6").into()));
        }
        (h.to_string(), tail.strip_prefix(':').unwrap_or("").to_string())
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.to_string()),
            None => (hostport.to_string(), String::new()),
        }
    };
    let host_ok = !host.is_empty()
        && (host.parse::<std::net::IpAddr>().is_ok()
            || Url::parse(&format!("http://{host}/")).ok().and_then(|u| u.host_str().map(str::to_string)).as_deref()
                == Some(host.to_ascii_lowercase().as_str()));
    if !host_ok {
        return Err(LinkError::Malformed(tr!("кривой адрес «{}»", shorten(&host))));
    }
    let q: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes()).into_owned().collect();
    let ports = if ports.is_empty() { q.get("mport").cloned().unwrap_or_else(|| "443".into()) } else { ports };
    let (port, hop) = port_spec(&ports)?;

    let sni = non_empty(q.get("sni").or_else(|| q.get("peer")))
        .or_else(|| host.parse::<std::net::IpAddr>().is_err().then(|| host.clone()));
    let pin = match non_empty(q.get("pinSHA256").or_else(|| q.get("pinsha256"))) {
        Some(p) => {
            let hex: String = p.chars().filter(|c| *c != ':').collect();
            if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(LinkError::Malformed(trs!("pinSHA256 — не SHA-256 сертификата").into()));
            }
            Some(hex.to_ascii_lowercase())
        }
        None => None,
    };
    if pin.is_none() && matches!(q.get("insecure").map(String::as_str), Some("1" | "true")) {
        return Err(LinkError::Unsupported(
            trs!("hysteria2 с insecure=1: Xray больше не подключается без проверки сертификата. \
             Нужна ссылка с pinSHA256 (отпечаток сертификата сервера) или сертификат от Let's Encrypt")
                .into(),
        ));
    }
    let mut udp_mask = Vec::new();
    match q.get("obfs").map(|o| o.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("none") => {}
        Some("salamander") => {
            let pw = non_empty(q.get("obfs-password")).ok_or_else(|| LinkError::Malformed(trs!("obfs=salamander без obfs-password").into()))?;
            udp_mask.push(serde_json::json!({ "type": "salamander", "settings": { "password": pw } }));
        }
        Some(other) => return Err(LinkError::Unsupported(tr!("обфускация {}", shorten(other)))),
    }
    if let Some(h) = &hop {
        udp_mask.push(serde_json::json!({ "type": "udphop", "settings": { "mode": "intervalRemote", "interval": "30", "remotePorts": h } }));
    }
    let mut tls = serde_json::json!({ "alpn": ["h3"] });
    if let Some(s) = &sni {
        tls["serverName"] = serde_json::json!(s);
    }
    if let Some(p) = &pin {
        tls["pinnedPeerCertSha256"] = serde_json::json!(p);
    }
    let mut stream = serde_json::json!({
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": tls,
        "hysteriaSettings": { "version": 2, "auth": auth },
    });
    if !udp_mask.is_empty() {
        stream["finalmask"] = serde_json::json!({ "udp": udp_mask });
    }
    let outbound = serde_json::json!({
        "tag": "proxy",
        "protocol": "hysteria",
        "settings": { "version": 2, "address": host, "port": port },
        "streamSettings": stream,
    });
    let name = Some(pct(frag)).filter(|s| !s.trim().is_empty()).unwrap_or_else(|| format!("{host}:{port}"));
    Ok(Node {
        id: id_for(link),
        name,
        protocol: Protocol::Other,
        address: host,
        port,
        uuid: None,
        password: Some(auth),
        method: None,
        flow: None,
        encryption: None,
        alter_id: 0,
        transport: Transport { network: "hysteria".into(), ..Default::default() },
        security: Security { kind: "tls".into(), sni, alpn: vec!["h3".into()], ..Default::default() },
        link: link.to_string(),
        sub_id: None,
        group: None,
        raw: Some(serde_json::json!({ "outbounds": [outbound] })),
    })
}

/// "443" → (443, None); "443,20000-30000" / "20000-30000" → (первый порт, Some(список для прыжков)).
fn port_spec(s: &str) -> Result<(u16, Option<String>)> {
    let s = s.trim().replace(':', "-");
    let bad = || LinkError::Malformed(tr!("кривой порт «{}»", shorten(&s)));
    if s.is_empty() || s.len() > 200 || !s.chars().all(|c| c.is_ascii_digit() || c == ',' || c == '-') {
        return Err(bad());
    }
    let mut first = None;
    for part in s.split(',') {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let (a, b): (u16, u16) = (a.parse().map_err(|_| bad())?, b.parse().map_err(|_| bad())?);
        if a == 0 || b < a {
            return Err(bad());
        }
        first.get_or_insert(a);
    }
    let port = first.ok_or_else(bad)?;
    let hop = (s.contains(',') || s.contains('-')).then_some(s);
    Ok((port, hop))
}

// ---------- vless:// и trojan:// (одинаковый формат) ----------

fn parse_vless_like(link: &str, protocol: Protocol) -> Result<Node> {
    let url = Url::parse(link).map_err(|e| LinkError::Malformed(e.to_string()))?;

    let cred = pct(url.username());
    if cred.is_empty() {
        return Err(LinkError::Malformed(trs!("нет UUID/пароля перед '@'").into()));
    }
    let address = url
        .host_str()
        .ok_or_else(|| LinkError::Malformed(trs!("нет адреса").into()))?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let port = url
        .port()
        .ok_or_else(|| LinkError::Malformed(trs!("нет порта").into()))?;

    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();

    let default_security = if protocol == Protocol::Trojan { "tls" } else { "none" };
    let transport = transport_from_query(&q)?;
    let security = security_from_query(&q, default_security);

    let name = url
        .fragment()
        .map(pct)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{address}:{port}"));

    let (uuid, password) = match protocol {
        Protocol::Vless => (Some(cred), None),
        _ => (None, Some(cred)),
    };

    Ok(Node {
        id: id_for(link),
        name,
        protocol,
        address,
        port,
        uuid,
        password,
        method: None,
        flow: non_empty(q.get("flow")),
        encryption: non_empty(q.get("encryption")),
        alter_id: 0,
        transport,
        security,
        link: link.to_string(),
        sub_id: None,
        group: None,
        raw: None,
    })
}

fn transport_from_query(q: &HashMap<String, String>) -> Result<Transport> {
    let network = normalize_network(q.get("type").map(String::as_str).unwrap_or("tcp"))?;

    let extra = match q.get("extra") {
        Some(raw) if !raw.trim().is_empty() => {
            let mut v = serde_json::from_str::<Value>(raw)
                .map_err(|e| LinkError::Malformed(tr!("xhttp extra не JSON: {e}")))?;
            // extra — произвольный JSON от автора ссылки: в downloadSettings бывает
            // целый свой транспорт (masterKeyLog, Lua-скрипт FinalMask, xdrive…).
            crate::defang::check(&mut v).map_err(|e| LinkError::Unsupported(format!("xhttp extra: {e}")))?;
            Some(v)
        }
        _ => None,
    };

    Ok(Transport {
        network,
        path: non_empty(q.get("path")),
        host: non_empty(q.get("host")),
        service_name: non_empty(q.get("serviceName")),
        mode: non_empty(q.get("mode")),
        header_type: non_empty(q.get("headerType")),
        extra,
    })
}

fn security_from_query(q: &HashMap<String, String>, default: &str) -> Security {
    let kind = q
        .get("security")
        .map(|s| s.to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.to_string());
    let truthy = |k: &str| matches!(q.get(k).map(String::as_str), Some("1" | "true"));

    Security {
        kind,
        sni: non_empty(q.get("sni")).or_else(|| non_empty(q.get("peer"))),
        fingerprint: non_empty(q.get("fp")),
        alpn: q
            .get("alpn")
            .map(|a| {
                a.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        allow_insecure: truthy("allowInsecure") || truthy("insecure"),
        public_key: non_empty(q.get("pbk")),
        short_id: non_empty(q.get("sid")),
        spider_x: non_empty(q.get("spx")),
        mldsa65_verify: non_empty(q.get("pqv")),
    }
}

/// Приводим названия транспорта к тем, что понимает свежий Xray.
fn normalize_network(n: &str) -> Result<String> {
    let n = n.trim().to_ascii_lowercase();
    Ok(match n.as_str() {
        "" | "tcp" | "raw" => "tcp".into(),
        "ws" | "websocket" => "ws".into(),
        "grpc" | "gun" => "grpc".into(),
        "xhttp" | "splithttp" => "xhttp".into(),
        "httpupgrade" => "httpupgrade".into(),
        "kcp" | "mkcp" => "kcp".into(),
        "h2" | "http" => {
            return Err(LinkError::Unsupported(
                trs!("транспорт h2/http удалён из Xray, попроси у сервера xhttp").into(),
            ))
        }
        other => return Err(LinkError::Unsupported(tr!("транспорт {other}"))),
    })
}

// ---------- vmess:// (base64 от JSON) ----------

fn parse_vmess(link: &str) -> Result<Node> {
    let body = &link["vmess://".len()..];
    let body = body.split('#').next().unwrap_or(body);
    let json = b64_decode(body).ok_or_else(|| LinkError::Malformed(trs!("vmess: не base64").into()))?;
    let v: Value =
        serde_json::from_str(&json).map_err(|e| LinkError::Malformed(format!("vmess JSON: {e}")))?;

    // В vmess-ссылках поля бывают и строками, и числами ("443" или 443).
    let s = |k: &str| -> Option<String> {
        match v.get(k)? {
            Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    };

    let address = s("add").ok_or_else(|| LinkError::Malformed(trs!("vmess: нет add").into()))?;
    let port: u16 = s("port")
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| LinkError::Malformed(trs!("vmess: нет port").into()))?;
    let uuid = s("id").ok_or_else(|| LinkError::Malformed(trs!("vmess: нет id").into()))?;

    let network = normalize_network(&s("net").unwrap_or_else(|| "tcp".into()))?;
    let header_or_mode = s("type");
    let (header_type, mode) = match network.as_str() {
        "grpc" => (None, header_or_mode),
        "xhttp" => (None, s("mode").or(header_or_mode)),
        _ => (header_or_mode, None),
    };
    let service_name = if network == "grpc" { s("path") } else { None };

    let tls = s("tls").unwrap_or_default().to_ascii_lowercase();
    let kind = if tls == "tls" || tls == "reality" { tls } else { "none".into() };

    Ok(Node {
        id: id_for(link),
        name: s("ps").unwrap_or_else(|| format!("{address}:{port}")),
        protocol: Protocol::Vmess,
        address,
        port,
        uuid: Some(uuid),
        password: None,
        method: s("scy").or(Some("auto".into())),
        flow: None,
        encryption: None,
        alter_id: s("aid").and_then(|a| a.parse().ok()).unwrap_or(0),
        transport: Transport {
            path: if network == "grpc" { None } else { s("path") },
            host: s("host"),
            service_name,
            mode,
            header_type,
            network,
            extra: None,
        },
        security: Security {
            kind,
            sni: s("sni"),
            fingerprint: s("fp"),
            alpn: s("alpn")
                .map(|a| a.split(',').map(|x| x.trim().to_string()).collect())
                .unwrap_or_default(),
            allow_insecure: matches!(s("allowInsecure").as_deref(), Some("1" | "true")),
            ..Default::default()
        },
        link: link.to_string(),
        sub_id: None,
        group: None,
        raw: None,
    })
}

// ---------- ss:// (SIP002 и старый формат) ----------

fn parse_ss(link: &str) -> Result<Node> {
    let rest = &link["ss://".len()..];
    let (rest, name) = match rest.split_once('#') {
        Some((r, n)) => (r, Some(pct(n))),
        None => (rest, None),
    };
    let (main, query) = match rest.split_once('?') {
        Some((m, q)) => (m.trim_end_matches('/'), Some(q)),
        None => (rest.trim_end_matches('/'), None),
    };
    if let Some(q) = query {
        if q.split('&').any(|kv| kv.starts_with("plugin=") && kv.len() > "plugin=".len()) {
            return Err(LinkError::Unsupported(
                trs!("ss с плагином (obfs/v2ray-plugin) Xray не умеет").into(),
            ));
        }
    }

    // SIP002: userinfo@host:port, где userinfo = base64(method:password)
    // или для 2022-blake3 просто "method:password" в percent-encoding.
    // Старый формат: base64(method:password@host:port).
    let (userinfo, hostport) = match main.rsplit_once('@') {
        Some((u, h)) => {
            let u = pct(u);
            let u = if u.contains(':') {
                u
            } else {
                b64_decode(&u).ok_or_else(|| LinkError::Malformed(trs!("ss: userinfo не base64").into()))?
            };
            (u, h.to_string())
        }
        None => {
            let full =
                b64_decode(main).ok_or_else(|| LinkError::Malformed(trs!("ss: не base64").into()))?;
            let (u, h) = full
                .rsplit_once('@')
                .ok_or_else(|| LinkError::Malformed(trs!("ss: нет '@'").into()))?;
            (u.to_string(), h.to_string())
        }
    };

    let (method, password) = userinfo
        .split_once(':')
        .ok_or_else(|| LinkError::Malformed(trs!("ss: нет method:password").into()))?;
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or_else(|| LinkError::Malformed(trs!("ss: нет порта").into()))?;
    let port: u16 = port
        .parse()
        .map_err(|_| LinkError::Malformed(trs!("ss: порт не число").into()))?;
    let address = host.trim_matches(|c| c == '[' || c == ']').to_string();

    Ok(Node {
        id: id_for(link),
        name: name
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("{address}:{port}")),
        protocol: Protocol::Shadowsocks,
        address,
        port,
        uuid: None,
        password: Some(password.to_string()),
        method: Some(method.to_string()),
        flow: None,
        encryption: None,
        alter_id: 0,
        transport: Transport {
            network: "tcp".into(),
            ..Default::default()
        },
        security: Security {
            kind: "none".into(),
            ..Default::default()
        },
        link: link.to_string(),
        sub_id: None,
        group: None,
        raw: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Тестовые ключи выдуманы.
    const VLESS_REALITY_XHTTP: &str = "vless://11111111-2222-3333-4444-555555555555@79.137.195.200:443?type=xhttp&encryption=none&path=%2Fapi%2Fv2%2Fsync&host=&mode=packet-up&security=reality&pbk=TESTPUBLICKEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&fp=chrome&sni=amsterdam.ubea.net&sid=22b928b1d1ce9632&spx=%2F#NL-rxmv";

    #[test]
    fn vless_reality_xhttp() {
        let n = parse_link(VLESS_REALITY_XHTTP).unwrap();
        assert_eq!(n.protocol, Protocol::Vless);
        assert_eq!(n.name, "NL-rxmv");
        assert_eq!(n.address, "79.137.195.200");
        assert_eq!(n.port, 443);
        assert_eq!(n.transport.network, "xhttp");
        assert_eq!(n.transport.path.as_deref(), Some("/api/v2/sync"));
        assert_eq!(n.transport.host, None);
        assert_eq!(n.transport.mode.as_deref(), Some("packet-up"));
        assert_eq!(n.security.kind, "reality");
        assert_eq!(n.security.sni.as_deref(), Some("amsterdam.ubea.net"));
        assert_eq!(n.security.short_id.as_deref(), Some("22b928b1d1ce9632"));
        assert_eq!(n.encryption.as_deref(), Some("none"));
    }

    #[test]
    fn vless_vision_tcp() {
        let l = "vless://uuid-1@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&pbk=K&sid=ab&sni=www.microsoft.com&fp=chrome#Test%20%D0%9D%D0%9B";
        let n = parse_link(l).unwrap();
        assert_eq!(n.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(n.name, "Test НЛ");
        assert_eq!(n.transport.network, "tcp");
    }

    #[test]
    fn rename_keeps_id() {
        let a = parse_link("vless://u@h.com:1?type=ws#A").unwrap();
        let b = parse_link("vless://u@h.com:1?type=ws#B").unwrap();
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn trojan_defaults_to_tls() {
        let n = parse_link("trojan://p%40ss@t.example.org:443?type=ws&path=%2Fws&sni=t.example.org#tr").unwrap();
        assert_eq!(n.protocol, Protocol::Trojan);
        assert_eq!(n.password.as_deref(), Some("p@ss"));
        assert_eq!(n.security.kind, "tls");
        assert_eq!(n.transport.network, "ws");
    }

    #[test]
    fn vmess_json_with_numbers() {
        let json = r#"{"v":"2","ps":"vm1","add":"v.example.com","port":443,"id":"abc","aid":"0","scy":"auto","net":"ws","type":"none","host":"v.example.com","path":"/ray","tls":"tls","sni":"v.example.com"}"#;
        let link = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json)
        );
        let n = parse_link(&link).unwrap();
        assert_eq!(n.protocol, Protocol::Vmess);
        assert_eq!(n.port, 443);
        assert_eq!(n.name, "vm1");
        assert_eq!(n.security.kind, "tls");
        assert_eq!(n.transport.path.as_deref(), Some("/ray"));
    }

    #[test]
    fn ss_sip002_and_legacy() {
        let ui = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:secret");
        let n = parse_link(&format!("ss://{ui}@1.2.3.4:8388#ss1")).unwrap();
        assert_eq!(n.method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(n.password.as_deref(), Some("secret"));
        assert_eq!(n.port, 8388);

        let legacy = base64::engine::general_purpose::STANDARD.encode("chacha20-ietf-poly1305:pw@5.6.7.8:443");
        let n = parse_link(&format!("ss://{legacy}#old")).unwrap();
        assert_eq!(n.address, "5.6.7.8");
        assert_eq!(n.name, "old");

        let n = parse_link("ss://2022-blake3-aes-128-gcm:a2V5%3D@9.9.9.9:443#new").unwrap();
        assert_eq!(n.method.as_deref(), Some("2022-blake3-aes-128-gcm"));
        assert_eq!(n.password.as_deref(), Some("a2V5="));
    }

    #[test]
    fn subscription_base64() {
        let text = format!("{VLESS_REALITY_XHTTP}\ntrojan://p@a.b:443#t\nhysteria2://x@y.com:1#h\ntuic://u:p@y.com:1#t\n");
        let sub = base64::engine::general_purpose::STANDARD.encode(text);
        let (nodes, errors) = parse_many(&sub);
        assert_eq!(nodes.len(), 3);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("sing-box"), "{errors:?}");
    }

    #[test]
    fn hysteria2_links() {
        let pin = "AB:CD:".repeat(15) + "AB:CD";
        let l = format!("hysteria2://p%40ss@hy.example.com:443,20000-30000/?sni=cdn.example.com&obfs=salamander&obfs-password=ob&pinSHA256={pin}#%F0%9F%87%B3%F0%9F%87%B1%20NL");
        let n = parse_link(&l).unwrap();
        assert_eq!((n.address.as_str(), n.port, n.name.as_str()), ("hy.example.com", 443, "🇳🇱 NL"));
        assert_eq!(n.summary(), "HYSTERIA · hysteria · tls");
        let o = &n.raw.as_ref().unwrap()["outbounds"][0];
        assert_eq!(o["protocol"], "hysteria");
        assert_eq!(o["settings"]["version"], 2);
        let ss = &o["streamSettings"];
        assert_eq!(ss["hysteriaSettings"]["auth"], "p@ss");
        assert_eq!(ss["tlsSettings"]["serverName"], "cdn.example.com");
        assert_eq!(ss["tlsSettings"]["pinnedPeerCertSha256"], "abcd".repeat(16));
        assert_eq!(ss["finalmask"]["udp"][0]["settings"]["password"], "ob");
        assert_eq!(ss["finalmask"]["udp"][1]["settings"]["remotePorts"], "443,20000-30000");
        // hy2://, без порта, IPv6, mport
        let n = parse_link("hy2://pw@[2001:db8::1]?mport=20000-20010#x").unwrap();
        assert_eq!((n.address.as_str(), n.port), ("2001:db8::1", 20000));
        assert!(n.raw.as_ref().unwrap()["outbounds"][0]["streamSettings"]["tlsSettings"].get("serverName").is_none());
        assert_eq!(parse_link("hy2://pw@h.com").unwrap().port, 443);
        // Без проверки сертификата Xray не подключится — говорим сразу и понятно.
        assert!(matches!(parse_link("hy2://pw@h.com:443?insecure=1"), Err(LinkError::Unsupported(e)) if e.contains("pinSHA256")));
        for bad in ["hy2://h.com:443", "hy2://pw@h.com:99999", "hy2://pw@h.com:5-1", "hy2://pw@h.com:443?pinSHA256=zz",
                    "hy2://pw@h.com:443?obfs=xor", "hy2://pw@h.com:443?obfs=salamander", "hy2://pw@ba d.com:443", "hy2://pw@:443",
                    "hy2://pw@[::1]junk", "hy2://pw@[::1]x:443", "hy2://pw@[h.com]:443"] {
            assert!(parse_link(bad).is_err(), "{bad}");
        }
        // Через очистку подписок проходит целиком (транспорт hysteria разрешён).
        let n = parse_link(&l).unwrap();
        let out = crate::xray::node_outbounds(&n);
        assert_eq!(out[0]["protocol"], "hysteria", "{out:?}");
        assert_eq!(out[0]["streamSettings"]["finalmask"]["udp"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn h2_is_rejected() {
        assert!(matches!(
            parse_link("vless://u@h:1?type=h2"),
            Err(LinkError::Unsupported(_))
        ));
    }
}
