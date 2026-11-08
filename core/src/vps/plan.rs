//! Что ставится на сервер: ключи Reality, конфиг Xray, служба, защита.
//! Только чистые функции — всё проверяется тестами без сервера.

use serde_json::{json, Value};

/// Порт stats API Xray на самом сервере (наружу не открыт, только 127.0.0.1).
pub const API_PORT: u16 = 10085;
pub const XRAY_BIN: &str = "/usr/local/bin/xray";
pub const XRAY_DIR: &str = "/usr/local/etc/xray";
pub const XRAY_CONF: &str = "/usr/local/etc/xray/config.json";
pub const UNIT: &str = "/etc/systemd/system/xray.service";
pub const SSHD_DROPIN: &str = "/etc/ssh/sshd_config.d/00-rxvpn.conf";
pub const OWNER_EMAIL: &str = "owner@rxvpn";

/// Сайты-маскировки: TLS 1.3 + h2, не за Cloudflare. Проверяются на сервере,
/// берётся самый близкий к нему. Только эти строки попадают в команды.
pub const SNI_CANDIDATES: &[&str] = &[
    "www.microsoft.com",
    "www.apple.com",
    "dl.google.com",
    "www.samsung.com",
    "www.nvidia.com",
    "www.intel.com",
    "www.amd.com",
    "addons.mozilla.org",
    "www.logitech.com",
    "www.asus.com",
];

/// Адреса, куда клиентам сервера нельзя: сам сервер (там stats API), его локалка.
pub const PRIVATE_NETS: &[&str] = &[
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
];

pub fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("нет источника случайных чисел");
    b
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn uuid_v4() -> String {
    let mut b = random(16);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

pub fn short_id() -> String {
    hex(&random(8))
}

/// Короткий id друга (он же «email» в статистике Xray): только [0-9a-f].
pub fn friend_id() -> String {
    hex(&random(5))
}

/// Ключи Reality: (private, public), base64url без `=`, как у `xray x25519`.
pub fn reality_keys() -> (String, String) {
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&random(32));
    reality_pair(sk)
}

pub fn reality_pair(mut sk: [u8; 32]) -> (String, String) {
    use base64::Engine;
    // Xray сам «зажимает» ключ (clamp) — храним уже зажатый, как и он.
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    let pk = curve25519_dalek::MontgomeryPoint::mul_base_clamped(sk);
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    (e.encode(sk), e.encode(pk.to_bytes()))
}

/// Публичный ключ из приватного (base64url).
pub fn reality_public(private: &str) -> Option<String> {
    use base64::Engine;
    let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(private.trim_end_matches('=')).ok()?;
    let sk: [u8; 32] = b.try_into().ok()?;
    Some(reality_pair(sk).1)
}

/// Клиент Xray на сервере.
#[derive(Debug, Clone)]
pub struct Client {
    pub uuid: String,
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct Reality {
    /// Сервер по IPv6-адресу: слушать "::" (иначе только IPv4).
    pub v6: bool,
    pub port: u16,
    pub sni: String,
    pub private_key: String,
    pub short_id: String,
}

/// Конфиг Xray сервера: VLESS + Reality + Vision, статистика по клиентам на
/// 127.0.0.1, в локалку сервера и торренты — нельзя, логов посещений нет.
///
/// `exit` — исходящие выходного сервера (главный с тегом "proxy"): тогда этот сервер —
/// мост для белых списков. Стоит в российском облаке (его адрес в белом списке),
/// а весь трафик клиентов везёт дальше, на выходной сервер. Пусто — выход прямо отсюда.
pub fn server_config(r: &Reality, clients: &[Client], own_ips: &[String], exit: &[Value]) -> Value {
    // Свои публичные адреса сервера — тоже закрыты: через lo ufw пускает ко всему,
    // что слушает 0.0.0.0 (базы, панели), а друзья не должны туда попадать.
    let mut block: Vec<String> = PRIVATE_NETS.iter().map(|x| x.to_string()).collect();
    for ip in own_ips.iter().filter_map(|x| x.parse::<std::net::IpAddr>().ok()) {
        block.push(if ip.is_ipv4() { format!("{ip}/32") } else { format!("{ip}/128") });
    }
    let list: Vec<Value> = clients
        .iter()
        .map(|c| json!({"id": c.uuid, "flow": "xtls-rprx-vision", "email": c.email, "level": 0}))
        .collect();
    let mut cfg = json!({
        "log": {"loglevel": "warning", "access": "none", "dnsLog": false},
        "api": {"tag": "api", "services": ["StatsService", "HandlerService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}},
            "system": {"statsInboundUplink": false, "statsInboundDownlink": false}
        },
        "inbounds": [
            {"tag": "api", "listen": "127.0.0.1", "port": API_PORT, "protocol": "dokodemo-door",
             "settings": {"address": "127.0.0.1"}},
            {"tag": "vless", "listen": if r.v6 { "::" } else { "0.0.0.0" }, "port": r.port, "protocol": "vless",
             "settings": {"clients": list, "decryption": "none"},
             "streamSettings": {"network": "raw", "security": "reality",
                "realitySettings": {"show": false, "target": format!("{}:443", r.sni), "serverNames": [r.sni],
                    "privateKey": r.private_key, "shortIds": [r.short_id]}},
             "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"], "routeOnly": true}}
        ],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP",
                "finalRules": [{"action": "block", "ip": block}]}},
            {"tag": "block", "protocol": "blackhole"}
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"inboundTag": ["api"], "outboundTag": "api"},
                {"ip": block, "outboundTag": "block"},
                {"protocol": ["bittorrent"], "outboundTag": "block"}
            ]
        }
    });
    if !exit.is_empty() {
        cfg["outbounds"].as_array_mut().unwrap().extend(exit.iter().cloned());
        // Всё, что не заблокировано выше, — на выходной сервер.
        cfg["routing"]["rules"].as_array_mut().unwrap().push(json!({"inboundTag": ["vless"], "outboundTag": "proxy"}));
    }
    cfg
}

/// Ссылка vless:// для клиента (Happ, v2rayNG, сам rxvpn).
pub fn link(host: &str, r: &Reality, public_key: &str, uuid: &str, name: &str) -> String {
    let h = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    let name = percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC);
    format!(
        "vless://{uuid}@{h}:{}?encryption=none&flow=xtls-rprx-vision&security=reality&sni={}&fp=chrome&pbk={public_key}&sid={}&type=tcp#{name}",
        r.port, r.sni, r.short_id
    )
}

pub fn unit() -> &'static str {
    "[Unit]
Description=Xray (rxvpn)
After=network-online.target
Wants=network-online.target

[Service]
User=xray
Group=xray
ExecStart=/usr/local/bin/xray run -c /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadOnlyPaths=/usr/local/etc/xray

[Install]
WantedBy=multi-user.target
"
}

pub fn sysctl_bbr() -> &'static str {
    "# rxvpn: BBR — быстрее на дальних и «шумных» каналах\nnet.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n" // i18n-skip: файл на сервере / отладка
}

pub fn fail2ban_jail(ssh_port: u16) -> String {
    format!("# rxvpn\n[sshd]\nenabled = true\nport = {ssh_port}\nbackend = systemd\nmaxretry = 5\nfindtime = 10m\nbantime = 1h\n")
}

pub fn auto_upgrades() -> &'static str {
    "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
}

// ---------- лимиты друзей: учёт и отключение на самом сервере ----------
// Таймер раз в 2 минуты (от root): забирает счётчики Xray со сбросом, копит их в файле
// состояния и отключает (`xray api rmu`) тех, у кого кончился трафик или срок. Работает,
// даже когда комп владельца выключен. Перезапуск Xray возвращает всех из конфига — таймер
// снова отключит превысивших (и apply() запускает его сразу после перезапуска).

pub const LIMITS_SCRIPT: &str = "/usr/local/lib/rxvpn/limits.py";
pub const LIMITS_JSON: &str = "/usr/local/etc/xray/rxvpn-limits.json";
pub const LIMITS_STATE: &str = "/var/lib/rxvpn/usage.json";
pub const LIMITS_SERVICE: &str = "/etc/systemd/system/rxvpn-limits.service";
pub const LIMITS_TIMER: &str = "/etc/systemd/system/rxvpn-limits.timer";

/// Скрипт учёта. Пути переопределяются переменными окружения только для тестов
/// (таймер systemd их не задаёт).
// i18n-skip-begin: текст скрипта для сервера, не для пользователя
pub fn limits_script() -> &'static str {
    r#"#!/usr/bin/env python3
# rxvpn: учёт трафика друзей и лимиты. Запускает таймер rxvpn-limits (root) раз в 2 минуты.
import json, os, subprocess, sys, tempfile, time

XRAY = os.environ.get("RXVPN_XRAY", "/usr/local/bin/xray")
API = "127.0.0.1:10085"
LIMITS = os.environ.get("RXVPN_LIMITS", "/usr/local/etc/xray/rxvpn-limits.json")
STATE = os.environ.get("RXVPN_STATE", "/var/lib/rxvpn/usage.json")

def load(p):
    try:
        with open(p, encoding="utf-8") as f:
            v = json.load(f)
        return v if isinstance(v, dict) else {}
    except Exception:
        return {}

def save(p, v):
    d = os.path.dirname(p)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(v, f)
    os.replace(tmp, p)

def api(*args):
    cmd = XRAY.split("|") + ["api", *args, "--server=" + API]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=20)

def main():
    limits = load(LIMITS)
    state = load(STATE)
    if "--reset" in sys.argv:
        email = sys.argv[sys.argv.index("--reset") + 1]
        state.pop(email, None)
    r = api("statsquery", "-pattern", "user>>>", "-reset")
    if r.returncode == 0:
        try:
            stats = json.loads(r.stdout or "{}").get("stat", [])
        except ValueError:
            stats = []
        for s in stats:
            parts = str(s.get("name", "")).split(">>>")
            if len(parts) != 4 or parts[0] != "user" or parts[2] != "traffic":
                continue
            u = state.setdefault(parts[1], {"up": 0, "down": 0, "blocked": False})
            key = "up" if parts[3] == "uplink" else "down" if parts[3] == "downlink" else None
            if key:
                u[key] = int(u.get(key, 0)) + int(s.get("value", 0) or 0)
    now = time.time()
    for email, l in limits.items():
        u = state.setdefault(email, {"up": 0, "down": 0, "blocked": False})
        limit, expires = int(l.get("limit", 0) or 0), int(l.get("expires", 0) or 0)
        over = (limit > 0 and u["up"] + u["down"] >= limit) or (expires > 0 and now >= expires)
        u["blocked"] = bool(over)
        if over:
            api("rmu", "-tag=vless", email)
    for email in list(state):
        if email not in limits and email != "owner@rxvpn":
            state[email]["blocked"] = False
    save(STATE, state)
    if "--json" in sys.argv:
        print(json.dumps(state))

main()
"#
}
// i18n-skip-end

pub fn limits_service() -> String {
    format!(
        "[Unit]\nDescription=rxvpn: friends traffic limits\nAfter=xray.service\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {LIMITS_SCRIPT}\n"
    )
}

pub fn limits_timer() -> &'static str {
    "[Unit]\nDescription=rxvpn: friends traffic limits every 2 minutes\n\n[Timer]\nOnBootSec=30s\nOnUnitActiveSec=2min\nAccuracySec=15s\n\n[Install]\nWantedBy=timers.target\n"
}

/// Лимиты для скрипта: email → {limit: байты, expires: unix}. 0 — без ограничения.
pub fn limits_json(friends: &[(String, u32, i64)]) -> Value {
    let mut m = serde_json::Map::new();
    for (email, limit_gb, expires) in friends {
        m.insert(email.clone(), json!({"limit": (*limit_gb as u64) << 30, "expires": (*expires).max(0)}));
    }
    Value::Object(m)
}

/// Трафик друга по данным сервера.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub up: u64,
    pub down: u64,
    /// Отключён сервером: кончился трафик или срок.
    pub blocked: bool,
}

/// Ответ `limits.py --json` (накопленный трафик) или, на старом сервере без скрипта,
/// `xray api statsquery` (трафик с запуска Xray).
pub fn parse_usage(out: &str) -> std::collections::HashMap<String, Usage> {
    let Ok(v) = serde_json::from_str::<Value>(out) else { return Default::default() };
    if v.get("stat").is_some() || v.as_object().is_some_and(|o| o.is_empty()) {
        return parse_stats(out).into_iter().map(|(k, (up, down))| (k, Usage { up, down, blocked: false })).collect();
    }
    let mut m = std::collections::HashMap::new();
    for (email, u) in v.as_object().into_iter().flatten() {
        m.insert(email.clone(), Usage {
            up: u["up"].as_u64().unwrap_or(0),
            down: u["down"].as_u64().unwrap_or(0),
            blocked: u["blocked"].as_bool().unwrap_or(false),
        });
    }
    m
}

pub fn sshd_dropin() -> &'static str {
    // 00- — раньше 50-cloud-init.conf: у sshd побеждает первое значение.
    "# rxvpn: вход только по ключу\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n" // i18n-skip: файл на сервере / отладка
}

/// Что за система: (id, версия) из /etc/os-release, если поддерживается.
pub fn os_supported(os_release: &str) -> Result<String, String> {
    let get = |k: &str| {
        os_release.lines().find_map(|l| l.strip_prefix(k).and_then(|v| v.strip_prefix('=')).map(|v| v.trim().trim_matches('"').to_string()))
    };
    let id = get("ID").unwrap_or_default();
    let ver = get("VERSION_ID").unwrap_or_default();
    let ok = matches!((id.as_str(), ver.as_str()), ("ubuntu", "22.04") | ("ubuntu", "24.04") | ("debian", "12"));
    let pretty = format!("{id} {ver}");
    if ok {
        Ok(pretty)
    } else {
        Err(tr!("система {} не поддерживается — нужна Ubuntu 22.04/24.04 или Debian 12", super::ssh::clean(&pretty, 60)))
    }
}

/// `uname -m` → (архитектура для показа, архив Xray).
pub fn arch_asset(uname: &str) -> Result<(&'static str, &'static str), String> {
    match uname.trim() {
        "x86_64" | "amd64" => Ok(("amd64", "Xray-linux-64.zip")),
        "aarch64" | "arm64" => Ok(("arm64", "Xray-linux-arm64-v8a.zip")),
        other => Err(tr!("процессор {} не поддерживается — нужен amd64 или arm64", super::ssh::clean(other, 30))),
    }
}

/// Скрипт выбора сайта-маскировки: для каждого кандидата — TLS 1.3 + h2 и время.
/// Строка вывода: `домен миллисекунды`.
pub fn sni_probe_script() -> String {
    let list: Vec<String> = SNI_CANDIDATES.iter().map(|d| super::ssh::sh_quote(d)).collect();
    format!(
        "for d in {}; do s=$(date +%s%N); o=$(timeout 6 openssl s_client -connect \"$d:443\" -servername \"$d\" -alpn h2 -tls1_3 </dev/null 2>/dev/null); \
         e=$(date +%s%N); if printf '%s' \"$o\" | grep -q 'ALPN protocol: h2' && printf '%s' \"$o\" | grep -q 'TLSv1.3'; then echo \"$d $(( (e-s)/1000000 ))\"; fi; done; true",
        list.join(" ")
    )
}

/// Самый быстрый подходящий сайт из вывода `sni_probe_script`.
pub fn pick_sni(out: &str) -> Option<String> {
    out.lines()
        .filter_map(|l| {
            let (d, ms) = l.split_once(' ')?;
            let ms: u64 = ms.trim().parse().ok()?;
            SNI_CANDIDATES.contains(&d).then(|| (ms, d.to_string()))
        })
        .min()
        .map(|(_, d)| d)
}

/// Порт sshd на самом сервере (4-е поле $SSH_CONNECTION): за NAT он не тот, к которому подключались.
pub fn ssh_server_port(ssh_connection: &str) -> Option<u16> {
    ssh_connection.split_whitespace().nth(3)?.parse().ok().filter(|p| *p > 0)
}

/// Публичные адреса сервера из `ip -o addr show scope global`.
pub fn parse_ips(out: &str) -> Vec<String> {
    let mut v: Vec<String> = out
        .lines()
        .filter_map(|l| {
            let a = l.split_whitespace().skip_while(|w| *w != "inet" && *w != "inet6").nth(1)?;
            a.split('/').next()?.parse::<std::net::IpAddr>().ok().map(|ip| ip.to_string())
        })
        .collect();
    v.dedup();
    v.truncate(16);
    v
}

/// Трафик из `xray api statsquery`: email → (вверх, вниз).
pub fn parse_stats(out: &str) -> std::collections::HashMap<String, (u64, u64)> {
    let mut m = std::collections::HashMap::new();
    let Ok(v) = serde_json::from_str::<Value>(out) else { return m };
    for s in v["stat"].as_array().into_iter().flatten() {
        let name = s["name"].as_str().unwrap_or("");
        let val = s["value"].as_u64().or_else(|| s["value"].as_str().and_then(|x| x.parse().ok())).unwrap_or(0);
        let parts: Vec<&str> = name.split(">>>").collect();
        if let ["user", email, "traffic", dir] = parts[..] {
            let e = m.entry(email.to_string()).or_insert((0, 0));
            match dir {
                "uplink" => e.0 = val,
                "downlink" => e.1 = val,
                _ => {}
            }
        }
    }
    m
}

pub fn is_uuid(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    p.len() == 5 && p.iter().zip([8, 4, 4, 4, 12]).all(|(x, n)| x.len() == n && x.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Хост от человека: IP или имя. Ничего, что могло бы стать опцией или путём.
pub fn valid_host(h: &str) -> Result<String, String> {
    let h = h.trim().trim_start_matches('[').trim_end_matches(']');
    if h.parse::<std::net::IpAddr>().is_ok() {
        return Ok(h.to_string());
    }
    let ok = !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|p| !p.is_empty() && p.len() <= 63 && !p.starts_with('-') && !p.ends_with('-') && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    if ok { Ok(h.to_ascii_lowercase()) } else { Err(trs!("адрес сервера: нужен IP или имя вроде vps.example.com").into()) }
}

/// Имя друга: как имя папки (без невидимых символов, до 40).
pub fn friend_name(n: &str) -> Result<String, String> {
    let n = crate::store::clean_name(n, 40)?;
    if n.is_empty() { Err(trs!("впиши имя друга").into()) } else { Ok(n) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn friend_limits_format_and_usage() {
        let l = limits_json(&[("f-aaaaaaaaaa@rxvpn".into(), 50, 1_900_000_000), ("f-bbbbbbbbbb@rxvpn".into(), 0, 0)]);
        assert_eq!(l["f-aaaaaaaaaa@rxvpn"]["limit"], 50u64 << 30, "ГБ → байты");
        assert_eq!(l["f-aaaaaaaaaa@rxvpn"]["expires"], 1_900_000_000);
        assert_eq!(l["f-bbbbbbbbbb@rxvpn"]["limit"], 0);
        // Ответ скрипта лимитов (накопительно, с отметкой «отключён»)
        let u = parse_usage(r#"{"f-aaaaaaaaaa@rxvpn":{"up":10,"down":20,"blocked":true},"owner@rxvpn":{"up":1,"down":2,"blocked":false}}"#);
        assert_eq!(u["f-aaaaaaaaaa@rxvpn"], Usage { up: 10, down: 20, blocked: true });
        // Старый сервер без скрипта — ответ statsquery; пустой — тоже не ошибка
        let u = parse_usage(r#"{"stat":[{"name":"user>>>owner@rxvpn>>>traffic>>>downlink","value":"7"}]}"#);
        assert_eq!(u["owner@rxvpn"], Usage { up: 0, down: 7, blocked: false });
        assert!(parse_usage("{}").is_empty() && parse_usage("мусор").is_empty());
        // Без HandlerService сервер не смог бы отключить друга на ходу
        let r = Reality { v6: false, port: 443, sni: "www.apple.com".into(), private_key: "k".into(), short_id: "ab".into() };
        assert!(server_config(&r, &[], &[], &[])["api"]["services"].as_array().unwrap().iter().any(|x| x == "HandlerService"));
        // Скрипт и таймер ссылаются на свои пути
        assert!(limits_service().contains(LIMITS_SCRIPT) && limits_script().contains("rmu") && limits_timer().contains("OnUnitActiveSec=2min"));
    }

    #[test]
    fn keys_ids_link() {
        // Тест-вектор RFC 7748 §6.1 (приватный ключ Алисы → её публичный).
        let sk: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f,
            0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        use base64::Engine;
        let (_, pk) = reality_pair(sk);
        let pk = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(pk).unwrap();
        assert_eq!(hex(&pk), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let (a, b) = reality_keys();
        assert_eq!((a.len(), b.len()), (43, 43));
        assert_eq!(reality_public(&a).as_deref(), Some(b.as_str()));
        let u = uuid_v4();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert_ne!(uuid_v4(), u);
        assert_eq!(short_id().len(), 16);
        let r = Reality { v6: false, port: 443, sni: "www.apple.com".into(), private_key: a, short_id: "0123456789abcdef".into() };
        let l = link("1.2.3.4", &r, &b, &u, "Мой VPS");
        let n = crate::link::parse_link(&l).unwrap();
        assert_eq!((n.address.as_str(), n.port, n.uuid.as_deref()), ("1.2.3.4", 443, Some(u.as_str())));
        assert_eq!((n.security.kind.as_str(), n.security.sni.as_deref(), n.flow.as_deref()), ("reality", Some("www.apple.com"), Some("xtls-rprx-vision")));
        assert_eq!(n.security.public_key.as_deref(), Some(b.as_str()));
        assert_eq!(n.name, "Мой VPS");
        assert!(link("2001:db8::1", &r, &b, &u, "x").contains("@[2001:db8::1]:443"));
    }

    #[test]
    fn checks_and_parsers() {
        assert!(os_supported("ID=ubuntu\nVERSION_ID=\"24.04\"\n").is_ok());
        assert!(os_supported("ID=debian\nVERSION_ID=\"12\"\n").is_ok());
        assert!(os_supported("ID=centos\nVERSION_ID=\"9\"\n").is_err());
        assert_eq!(arch_asset("aarch64\n").unwrap().1, "Xray-linux-arm64-v8a.zip");
        assert!(arch_asset("mips").is_err());
        assert_eq!(pick_sni("www.apple.com 80\ndl.google.com 12\nevil.com 1\ngarbage\n").as_deref(), Some("dl.google.com"));
        assert_eq!(pick_sni(""), None);
        let st = parse_stats(r#"{"stat":[{"name":"user>>>owner@rxvpn>>>traffic>>>uplink","value":"10"},
            {"name":"user>>>owner@rxvpn>>>traffic>>>downlink","value":2000},{"name":"inbound>>>api>>>traffic>>>uplink","value":5}]}"#);
        assert_eq!(st.get(OWNER_EMAIL), Some(&(10, 2000)));
        assert_eq!(st.len(), 1);
        assert!(parse_stats("<html>").is_empty());
        for bad in ["", "-oProxyCommand=x", "a b", "a;b", "a/b", "$(id)", &"a".repeat(300)] {
            assert!(valid_host(bad).is_err(), "{bad}");
        }
        assert_eq!(valid_host(" VPS.Example.com ").unwrap(), "vps.example.com");
        assert_eq!(valid_host("[2001:db8::1]").unwrap(), "2001:db8::1");
        assert!(sni_probe_script().contains("'www.apple.com'"));
        assert_eq!(ssh_server_port("10.0.0.1 51234 203.0.113.5 22"), Some(22));
        assert_eq!(ssh_server_port("bad"), None);
        assert_eq!(parse_ips("2: eth0    inet 203.0.113.5/24 brd 203.0.113.255 scope global eth0\n2: eth0    inet6 2001:db8::5/64 scope global\n"), ["203.0.113.5", "2001:db8::5"]);
        let c = server_config(&Reality { v6: false, port: 443, sni: "www.apple.com".into(), private_key: "k".into(), short_id: "ab".into() },
            &[Client { uuid: "u".into(), email: OWNER_EMAIL.into() }], &["203.0.113.5".into(), "2001:db8::5".into(), "junk".into()], &[]);
        let rule = c["routing"]["rules"][1]["ip"].as_array().unwrap();
        assert!(rule.iter().any(|x| x == "203.0.113.5/32") && rule.iter().any(|x| x == "2001:db8::5/128"), "свой IP закрыт");
        assert!(!rule.iter().any(|x| x == "junk/32"));
        assert_eq!(c["inbounds"][0]["listen"], "127.0.0.1", "API — только на самом сервере");
        assert_eq!(c["routing"]["rules"][1]["outboundTag"], "block");
        assert_eq!(c["log"]["access"], "none");
        assert_eq!(c["routing"]["rules"].as_array().unwrap().len(), 3, "без моста — выход прямо с сервера");

        // Мост: блокировки — как раньше и раньше выхода, остальное — на выходной сервер.
        let exit = [json!({"tag": "proxy", "protocol": "vless", "settings": {}})];
        let b = server_config(&Reality { v6: false, port: 443, sni: "www.apple.com".into(), private_key: "k".into(), short_id: "ab".into() }, &[], &[], &exit);
        let rules = b["routing"]["rules"].as_array().unwrap();
        assert_eq!(rules.last().unwrap()["outboundTag"], "proxy");
        assert_eq!(rules[1]["outboundTag"], "block", "локалка сервера закрыта и у моста");
        assert!(b["outbounds"].as_array().unwrap().iter().any(|o| o["tag"] == "proxy"));
    }
}
