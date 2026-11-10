//! «Сообщить о проблеме»: отчёт для чата поддержки или issue — версии, режим,
//! маршруты, хвост лога, последние проверки. Всё, по чему можно найти человека
//! или подключиться к его серверу, вырезается: пароли, UUID, ссылки серверов и
//! подписок, адреса и домены серверов, секрет Telegram-прокси, ключи WARP,
//! имя пользователя в путях, публичные IP (в том числе свой).
//!
//! Два слоя: (1) всё, что точно известно из `Store` (адреса, ключи, ссылки), —
//! заменяется по значению; (2) общие шаблоны — любые ссылки кроме известных
//! публичных сервисов, UUID, публичные IP, длинные ключи, пути `Users\имя`.
//! Второй слой ловит то, что попало в лог из ответов сервера или Xray.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::store::Store;

/// Сколько строк лога кладём в отчёт.
pub const LOG_LINES: usize = 200;

/// Хосты, которые можно оставить в ссылках: это сервисы проверок и обхода,
/// одинаковые у всех. Совпадение — по суффиксу домена.
const PUBLIC_HOSTS: &[&str] = &[
    "cloudflare.com", "cloudflare-dns.com", "one.one.one.one", "ipleak.net", "bash.ws", "ipwho.is",
    "github.com", "githubusercontent.com", "telegram.org", "google.com", "gstatic.com", "dns.google",
    "googlevideo.com", "youtube.com", "youtu.be", "ytimg.com", "discord.com", "discord.gg",
    "discordapp.com", "twitch.tv", "ttvnw.net", "jtvnw.net", "netflix.com", "openai.com", "chatgpt.com",
    "wikipedia.org", "ya.ru", "yandex.ru", "gosuslugi.ru", "vk.com", "sberbank.ru", "rutracker.org",
    "quad9.net", "microsoft.com", "ovh.net", "kick.com",
];

/// Схемы ссылок на сервер/прокси: вырезаются целиком всегда.
const SERVER_SCHEMES: &[&str] = &[
    "vless", "vmess", "trojan", "ss", "ssr", "socks", "socks5", "socks5h", "hy2", "hysteria", "hysteria2",
    "tuic", "wireguard", "wg", "tg", "happ", "v2rayn", "sing-box", "clash", "streisand", "shadowrocket",
];

/// Что известно наверняка: значение → чем заменить.
#[derive(Default, Debug, Clone)]
pub struct Secrets {
    /// Хосты и IP серверов: заменяются только целым словом (`1.2.3.4` не тронет `11.2.3.45`).
    hosts: Vec<(String, String)>,
    /// Пароли, ключи, ссылки: заменяются везде, где встретились.
    values: Vec<(String, String)>,
    /// Имена учётки Windows (из путей и переменных окружения).
    users: Vec<String>,
}

impl Secrets {
    /// Всё секретное из состояния rxvpn.
    pub fn from_store(s: &Store) -> Self {
        let mut x = Secrets::default();
        let mut host_no: HashMap<String, usize> = HashMap::new();
        let mut host = |x: &mut Secrets, h: &str| {
            let h = h.trim().trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
            // Адрес сервера вырезаем, даже если он локальный (сервер в своей сети) —
            // кроме 127.0.0.1/0.0.0.0: их полно в логе, и они ничего не выдают.
            if h.is_empty() || h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified()) {
                return;
            }
            let n = host_no.len() + 1;
            let n = *host_no.entry(h.clone()).or_insert(n);
            x.hosts.push((h, tr!("<сервер-{n}>")));
        };
        for n in &s.servers {
            x.value(&n.link, trs!("<ссылка-сервера>"));
            host(&mut x, &n.address);
            for v in [&n.uuid, &n.password, &n.security.public_key, &n.security.short_id, &n.security.mldsa65_verify, &n.transport.service_name].into_iter().flatten() {
                x.value(v, trs!("<секрет>"));
            }
            if let Some(p) = &n.transport.path {
                // Путь WebSocket/xhttp часто сам служит паролем («/a8f3…»).
                let p = p.trim_matches('/');
                if p.len() >= 6 {
                    x.value(p, trs!("<путь>"));
                }
            }
            for h in [&n.security.sni, &n.transport.host].into_iter().flatten() {
                if !public_host(h) {
                    host(&mut x, h);
                }
            }
            if let Some(raw) = &n.raw {
                raw_secrets(&mut x, &mut host, raw);
            }
        }
        for sub in &s.subscriptions {
            x.value(&sub.url, trs!("<подписка>"));
            if let Ok(u) = url::Url::parse(&sub.url) {
                if let Some(h) = u.host_str() {
                    if !public_host(h) {
                        host(&mut x, h);
                    }
                }
            }
        }
        for v in &s.vps {
            host(&mut x, &v.host);
            for h in v.server_ips.iter().map(String::as_str).chain([v.sni.as_str()]) {
                if !public_host(h) {
                    host(&mut x, h);
                }
            }
            for k in [&v.public_key, &v.short_id, &v.owner_uuid, &v.host_key, &v.key_fp] {
                x.value(k, trs!("<секрет>"));
            }
            for f in &v.friends {
                x.value(&f.uuid, trs!("<секрет>"));
            }
            if v.user != "root" {
                x.value_word(&v.user);
            }
        }
        for w in &s.warp {
            for k in [&w.key.secret, &w.key.peer] {
                x.value(k, trs!("<ключ-WARP>"));
            }
            for ip in [&w.key.v4, &w.key.v6] {
                x.value(ip, trs!("<адрес-WARP>"));
            }
        }
        x.value(&s.settings.tg_secret, trs!("<секрет-Telegram>"));
        // Свой DoH (NextDNS и т. п.): в пути — личный id.
        x.value(&s.settings.doh_url, trs!("<свой-DoH>"));
        for n in &s.settings.trusted_nets {
            x.value_word(&n.ssid);
            x.value(&n.bssid, trs!("<точка-Wi-Fi>"));
        }
        x
    }

    fn value(&mut self, v: &str, label: &str) {
        let v = v.trim();
        // Короткое не трогаем: «aes» или «/» вырезали бы полотчёта.
        if v.chars().count() >= 4 {
            self.values.push((v.to_string(), label.to_string()));
        }
    }

    /// Имя (сети Wi-Fi, пользователя на VPS): только целым словом.
    fn value_word(&mut self, v: &str) {
        let v = v.trim();
        if v.chars().count() >= 3 {
            self.hosts.push((v.to_ascii_lowercase(), trs!("<имя>").into()));
        }
    }

    /// Имя учётки Windows: в путях оно вырезается и так, это — для остальных мест.
    pub fn add_user(&mut self, name: &str) {
        let n = name.trim();
        if n.chars().count() >= 3 {
            self.users.push(n.to_string());
        }
    }

    /// Учётка из переменных окружения (USERNAME, USERPROFILE, HOME).
    pub fn add_env_user(&mut self) {
        if let Ok(u) = std::env::var("USERNAME").or_else(|_| std::env::var("USER")) {
            self.add_user(&u);
        }
        for var in ["USERPROFILE", "HOME"] {
            if let Some(name) = std::env::var(var).ok().and_then(|p| p.replace('\\', "/").rsplit('/').find(|s| !s.is_empty()).map(str::to_string)) {
                self.add_user(&name);
            }
        }
    }
}

/// Строковые поля JSON-конфигов подписки, где лежат адреса и ключи.
fn raw_secrets(x: &mut Secrets, host: &mut impl FnMut(&mut Secrets, &str), v: &serde_json::Value) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                if let Some(s) = val.as_str() {
                    match k.as_str() {
                        "address" | "server" | "endpoint" => host(x, s.rsplit_once(':').filter(|(h, _)| !h.contains(':') || h.starts_with('[')).map_or(s, |(h, _)| h)),
                        "serverName" | "host" | "Host" | "sni" => {
                            if !public_host(s) {
                                host(x, s)
                            }
                        }
                        "id" | "password" | "pass" | "user" | "publicKey" | "privateKey" | "secretKey" | "shortId" | "auth"
                        | "obfsPassword" | "preSharedKey" | "mldsa65Verify" | "path" | "serviceName" => {
                            x.value(s.trim_matches('/'), trs!("<секрет>"))
                        }
                        _ => {}
                    }
                }
                raw_secrets(x, host, val);
            }
        }
        serde_json::Value::Array(a) => a.iter().for_each(|i| raw_secrets(x, host, i)),
        _ => {}
    }
}

fn public_host(h: &str) -> bool {
    let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
    PUBLIC_HOSTS.iter().any(|p| h == *p || h.ends_with(&format!(".{p}")))
}

/// IP, который можно оставить: локальные, служебные и общеизвестные (DNS, Telegram).
fn keep_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_unspecified()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_multicast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // CGNAT
                || (o[0] == 198 && (o[1] & 0xfe) == 18) // fake-ip / тесты
                || (o[0] == 198 && o[1] == 51 && o[2] == 100) // заглушки (документация)
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                // Telegram (AS62041 и др.): 149.154.160.0/20, 91.108.4–23.0/22, 91.108.56.0/22, 91.105.192.0/23
                || (o[0] == 149 && o[1] == 154 && (160..=175).contains(&o[2]))
                || (o[0] == 91 && o[1] == 108 && ((4..=23).contains(&o[2]) || (56..=59).contains(&o[2])))
                || (o[0] == 91 && o[1] == 105 && (192..=193).contains(&o[2]))
                || [[1, 1, 1, 1], [1, 0, 0, 1], [8, 8, 8, 8], [8, 8, 4, 4], [9, 9, 9, 9], [149, 112, 112, 112], [77, 88, 8, 8], [77, 88, 8, 1]].contains(&o)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0xdb8)
                || [Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111), Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)].contains(&v)
                || v.to_ipv4_mapped().is_some_and(|m| keep_ip(IpAddr::V4(m)))
        }
    }
}

fn keep_ip_str(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok_and(keep_ip)
}

/// Символ — часть «слова» хоста/IP (граница для замены целым словом).
fn word_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '-' | '_')
}

/// Заменить `needle` (без учёта регистра ASCII) целым словом.
fn replace_word(text: &str, needle: &str, with: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut from = 0;
    while let Some(p) = lower[from..].find(needle) {
        let start = from + p;
        let end = start + needle.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        // Точка в конце предложения — не часть хоста.
        let after_ok = after.is_none_or(|c| !word_char(c) || (c == '.' && text[end + 1..].chars().next().is_none_or(|d| !word_char(d))));
        if before.is_none_or(|c| !word_char(c)) && after_ok {
            out.push_str(&text[last..start]);
            out.push_str(with);
            last = end;
        }
        from = end.max(start + 1);
        while !text.is_char_boundary(from) {
            from += 1;
        }
    }
    out.push_str(&text[last..]);
    out
}

/// Вырезать из текста всё, по чему можно найти человека или его сервер.
pub fn redact(text: &str, s: &Secrets) -> String {
    // 1. Точно известное: сначала длинное (ссылка целиком раньше её адреса).
    let mut values: Vec<&(String, String)> = s.values.iter().collect();
    values.sort_by_key(|(v, _)| std::cmp::Reverse(v.len()));
    let mut t = text.to_string();
    for (v, label) in values {
        if t.contains(v.as_str()) {
            t = t.replace(v.as_str(), label);
        }
    }
    let mut hosts: Vec<&(String, String)> = s.hosts.iter().collect();
    hosts.sort_by_key(|(v, _)| std::cmp::Reverse(v.len()));
    for (h, label) in hosts {
        t = replace_word(&t, h, label);
    }
    // 2. Шаблоны.
    t = redact_urls(&t);
    t = redact_tokens(&t);
    t = redact_paths(&t);
    for u in &s.users {
        t = replace_word(&t, &u.to_ascii_lowercase(), "<user>");
    }
    t
}

/// Ссылки: серверные схемы — всегда, http(s) — кроме известных публичных сервисов.
fn redact_urls(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    let mut rest = t;
    while let Some(p) = rest.find("://") {
        let head = &rest[..p];
        let scheme_start = head
            .char_indices()
            .rev()
            .take_while(|(_, c)| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
            .last()
            .map_or(p, |(i, _)| i);
        let scheme = head[scheme_start..].to_ascii_lowercase();
        let after = &rest[p + 3..];
        let end = after.find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '`' | '«' | '»' | ')' | ']' | ',' | ';')).unwrap_or(after.len());
        let body = &after[..end];
        out.push_str(&rest[..scheme_start]);
        if scheme.is_empty() {
            out.push_str("://");
            rest = after;
            continue;
        }
        let keep = (scheme == "http" || scheme == "https") && {
            let auth = body.split(['/', '?', '#']).next().unwrap_or("");
            let has_user = auth.contains('@');
            let host = auth.rsplit('@').next().unwrap_or("");
            let host = if host.starts_with('[') { host.split(']').next().unwrap_or("").trim_start_matches('[') } else { host.split(':').next().unwrap_or("") };
            !has_user && (public_host(host) || keep_ip_str(host))
        };
        if keep {
            out.push_str(&rest[scheme_start..p + 3 + end]);
        } else if SERVER_SCHEMES.contains(&scheme.as_str()) {
            out.push_str(trs!("<ссылка-сервера>"));
        } else {
            out.push_str(trs!("<ссылка>"));
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

fn is_uuid(w: &str) -> bool {
    let b = w.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

/// Похоже на ключ/секрет: длинная «каша» из букв и цифр.
fn is_key(w: &str) -> bool {
    let w = w.trim_end_matches('=');
    w.len() >= 32
        && w.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '_' | '-'))
        && w.chars().any(|c| c.is_ascii_digit())
        && w.chars().any(|c| c.is_ascii_alphabetic())
}

/// Слова: UUID, IPv4/IPv6 (кроме локальных и общеизвестных), длинные ключи.
fn redact_tokens(t: &str) -> String {
    let tok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '-' | '_' | '+' | '/' | '=' | '%' | '@');
    let mut out = String::with_capacity(t.len());
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        if !word.is_empty() {
            out.push_str(&redact_word(word));
            word.clear();
        }
    };
    for c in t.chars() {
        if tok(c) {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

fn redact_word(w: &str) -> String {
    // Внутри «слова» могут склеиться адрес, порт и путь: «1.2.3.4:443/path».
    // Сначала смотрим слово целиком, потом — куски между «/», «=» и «%».
    if let Some(r) = redact_atom(w) {
        return r;
    }
    let mut out = String::with_capacity(w.len());
    let mut part = String::new();
    for c in w.chars() {
        if matches!(c, '/' | '=' | '%' | '+') {
            out.push_str(&redact_atom(&part).unwrap_or_else(|| part.clone()));
            part.clear();
            out.push(c);
        } else {
            part.push(c);
        }
    }
    out.push_str(&redact_atom(&part).unwrap_or(part));
    out
}

/// Одно «слово»: что вырезать (None — оставить как есть).
fn redact_atom(w: &str) -> Option<String> {
    let core = w.trim_matches(|c: char| matches!(c, '.' | ':' | '-' | '_' | '='));
    if core.is_empty() {
        return None;
    }
    let (lead, trail) = {
        let s = w.find(core).unwrap_or(0);
        (&w[..s], &w[s + core.len()..])
    };
    if is_uuid(core) {
        return Some(format!("{lead}<uuid>{trail}"));
    }
    // «логин@хост», почта: всё целиком.
    if let Some((_, host)) = core.split_once('@') {
        if host.contains('.') {
            return Some(tr!("{lead}<скрыто>{trail}"));
        }
    }
    // IPv6 целиком (с «::» или 7 двоеточиями); с портом — в квадратных скобках, их режут как границу.
    if core.contains(':') && core.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.') {
        if let Ok(ip) = core.parse::<Ipv6Addr>() {
            return (!keep_ip(IpAddr::V6(ip))).then(|| format!("{lead}<ip>{trail}"));
        }
    }
    // IPv4, возможно с портом: «1.2.3.4:443».
    let (ip_part, port) = match core.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') => (h, Some(p)),
        _ => (core, None),
    };
    if let Ok(ip) = ip_part.parse::<Ipv4Addr>() {
        if ip_part.split('.').count() == 4 && !keep_ip(IpAddr::V4(ip)) {
            return Some(match port {
                Some(p) => format!("{lead}<ip>:{p}{trail}"),
                None => format!("{lead}<ip>{trail}"),
            });
        }
        return None;
    }
    if is_key(core) {
        return Some(tr!("{lead}<ключ>{trail}"));
    }
    None
}

/// `C:\Users\Имя\…` и `/home/имя/…` → `<user>`.
fn redact_paths(t: &str) -> String {
    let mut out = t.to_string();
    for marker in ["\\users\\", "/users/", "/home/", "\\documents and settings\\"] {
        let mut res = String::with_capacity(out.len());
        let mut last = 0;
        let lower = out.to_lowercase();
        // to_lowercase мог поменять длину (кириллица — нет, но мало ли): тогда просто по ASCII.
        let lower = if lower.len() == out.len() { lower } else { out.to_ascii_lowercase() };
        let mut from = 0;
        while let Some(p) = lower[from..].find(marker) {
            let start = from + p + marker.len();
            let end = out[start..].find(['\\', '/', '"', '\'', ' ', '\n', ')', ',', ';']).map_or(out.len(), |e| start + e);
            let name = &out[start..end];
            res.push_str(&out[last..start]);
            if name.is_empty() || matches!(name.to_ascii_lowercase().as_str(), "public" | "default" | "all users" | "<user>") {
                res.push_str(name);
            } else {
                res.push_str("<user>");
            }
            last = end;
            from = end.max(start);
            if from >= out.len() {
                break;
            }
        }
        res.push_str(&out[last..]);
        out = res;
    }
    out
}

/// Последняя проверка: что, когда (unix), итог одной строкой.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CheckNote {
    pub kind: String,
    pub at: i64,
    pub text: String,
}

/// Всё для отчёта. Текст собирается как есть и целиком проходит через `redact`.
#[derive(Debug, Default)]
pub struct Input {
    pub app_version: String,
    pub xray_version: String,
    pub windows: String,
    pub admin: bool,
    pub portable: bool,
    /// Режим, подключено ли, сервер (без имени — только тип), «Авто».
    pub state: Vec<(String, String)>,
    /// Маршруты по строке.
    pub routes: Vec<String>,
    pub checks: Vec<CheckNote>,
    pub log: Vec<String>,
    /// Ошибка, из окна которой нажали «Сообщить» (если оттуда).
    pub error: Option<String>,
    pub now: i64,
}

fn when(now: i64, at: i64) -> String {
    let d = (now - at).max(0);
    match d {
        0..=59 => trs!("только что").into(),
        60..=3599 => tr!("{} мин назад", d / 60),
        3600..=86_399 => tr!("{} ч назад", d / 3600),
        _ => tr!("{} дн назад", d / 86_400),
    }
}

/// Строки ядра называют сайты, на которые ходил человек («accepted tcp:site.com:443»,
/// «sniffed domain: site.com»): в отчёте, который вставляют в публичный issue, им не место.
/// Имя сайта → «<site>»; порт, протокол и выход остаются — для разбора хватает. Адреса
/// своих серверов не трогаем: их дальше заменит `redact` на «<сервер-N>».
fn hide_sites(line: &str, s: &Secrets) -> String {
    if !(line.starts_with("[xray]") || line.starts_with("[sing-box]")) {
        return line.to_string();
    }
    let known = |h: &str| {
        let h = h.trim_start_matches('[').trim_end_matches(']').to_ascii_lowercase();
        h.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified()) || s.hosts.iter().any(|(x, _)| *x == h)
    };
    let mut out = String::with_capacity(line.len());
    let mut after_domain = false;
    for w in line.split_inclusive(' ') {
        let (word, gap) = match w.strip_suffix(' ') {
            Some(x) => (x, " "),
            None => (w, ""),
        };
        let was_domain = std::mem::replace(&mut after_domain, word == "domain:");
        let dest = ["tcp:", "udp:"].iter().find_map(|p| word.strip_prefix(p).map(|r| (*p, r)));
        if let Some((proto, rest)) = dest {
            // «host:port» (+ возможный хвост из знаков после порта).
            if let Some((host, port)) = rest.rsplit_once(':') {
                if !host.is_empty() && !known(host) {
                    out.push_str(proto);
                    out.push_str("<site>:");
                    out.push_str(port);
                    out.push_str(gap);
                    continue;
                }
            }
        } else if was_domain && !word.is_empty() && !known(word) {
            out.push_str("<site>");
            out.push_str(gap);
            continue;
        }
        out.push_str(word);
        out.push_str(gap);
    }
    out
}

/// Собрать отчёт и вырезать секреты.
pub fn build(i: &Input, s: &Secrets) -> String {
    let mut t = String::new();
    let line = |t: &mut String, k: &str, v: &str| {
        t.push_str(k);
        t.push_str(": ");
        t.push_str(v);
        t.push('\n');
    };
    t.push_str(trs!("=== rxvpn: отчёт о проблеме ===\n"));
    line(&mut t, trs!("Создан (UTC)"), &format!("{} {:02}:{:02}", crate::backup::date(i.now), i.now.rem_euclid(86_400) / 3600, i.now.rem_euclid(3600) / 60));
    line(&mut t, "rxvpn", &format!("{}{}", i.app_version, if i.portable { trs!(" (портативная)") } else { "" }));
    line(&mut t, "Xray", if i.xray_version.is_empty() { trs!("не установлен") } else { &i.xray_version });
    line(&mut t, "Windows", &i.windows);
    line(&mut t, "lang", crate::i18n::lang().code());
    line(&mut t, trs!("Права администратора"), if i.admin { trs!("да") } else { trs!("нет") });
    if let Some(e) = &i.error {
        t.push_str(trs!("\n--- Ошибка ---\n"));
        t.push_str(e.trim());
        t.push('\n');
    }
    t.push_str(trs!("\n--- Состояние ---\n"));
    for (k, v) in &i.state {
        line(&mut t, k, v);
    }
    t.push_str(trs!("\n--- Маршруты ---\n"));
    if i.routes.is_empty() {
        t.push_str(trs!("(ничего своего)\n"));
    }
    for r in &i.routes {
        t.push_str(r);
        t.push('\n');
    }
    t.push_str(trs!("\n--- Последние проверки ---\n"));
    if i.checks.is_empty() {
        t.push_str(trs!("(не было)\n"));
    }
    for c in &i.checks {
        t.push_str(&format!("[{}] {}: {}\n", when(i.now, c.at), c.kind, c.text));
    }
    let start = i.log.len().saturating_sub(LOG_LINES);
    t.push_str(&tr!("\n--- Лог (последние {} строк) ---\n", i.log.len() - start));
    for l in &i.log[start..] {
        t.push_str(&hide_sites(l, s));
        t.push('\n');
    }
    // Windows-переводы строк: отчёт часто открывают в Блокноте.
    redact(&t, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_link;

    fn store() -> Store {
        let mut s = Store::default();
        let links = [
            "vless://11111111-2222-3333-4444-555555555555@nl1.myvpn-panel.xyz:443?type=ws&path=%2Fsecretpath42&security=tls&sni=cdn.myvpn-panel.xyz&host=cdn.myvpn-panel.xyz#NL",
            "trojan://Sup3rPassw0rd@203.0.113.77:8443?security=reality&pbk=Zx9vQk3mN7pL2wR8tY5uB1cD4eF6gH0jK9lM3nO7pQs&sid=abcd1234&sni=www.microsoft.com#DE",
            "ss://YWVzLTI1Ni1nY206c3NwYXNzd29yZDEyMw@45.83.12.200:8388#FI",
        ];
        for l in links {
            s.servers.push(parse_link(l).unwrap());
        }
        s.subscriptions.push(crate::Subscription {
            id: "s1".into(),
            name: "Мой сервис".into(),
            url: "https://panel.private-vpn.io/sub/AbCdEf0123456789xyz".into(),
            updated_at: None,
            usage: None,
            filter: Default::default(),
        });
        s.settings.tg_secret = "0123456789abcdef0123456789abcdef".into();
        s.warp.push(crate::warp::Warp {
            via: "x".into(),
            via_sub: String::new(),
            key: crate::warp::WarpKey {
                secret: "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qga2V5IQ==".into(),
                peer: "bWZtbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW0=".into(),
                v4: "172.16.0.2".into(),
                v6: "2606:4700:110:8a36:df92:102a:9602:fa18".into(),
                ..Default::default()
            },
        });
        s
    }

    fn report(log: &[&str]) -> String {
        let s = store();
        let mut sec = Secrets::from_store(&s);
        sec.add_user("ivanov");
        let input = Input {
            app_version: "0.10.0".into(),
            xray_version: "Xray 26.10.21".into(),
            windows: "Windows 11 (26100)".into(),
            log: log.iter().map(|x| x.to_string()).collect(),
            routes: vec!["Свои сайты → через VPN: chatgpt.com, nl1.myvpn-panel.xyz".into()],
            now: 1_793_000_000,
            ..Default::default()
        };
        build(&input, &sec)
    }

    #[test]
    fn cuts_all_secrets() {
        let s = store();
        let mut log: Vec<String> = s.servers.iter().map(|n| format!("[rxvpn] импорт: {}", n.link)).collect();
        log.extend([
            "[xray] 2026/11/02 tcp:nl1.myvpn-panel.xyz:443 accepted via proxy".into(),
            "[xray] dial tcp 203.0.113.77:8443: i/o timeout".into(),
            "[xray] listening TCP on 127.0.0.1:10809".into(),
            "[xray] proxy/vless: 11111111-2222-3333-4444-555555555555 rejected".into(),
            "[rxvpn] подписка https://panel.private-vpn.io/sub/AbCdEf0123456789xyz обновлена".into(),
            "[rxvpn] подписка panel.private-vpn.io: 12 серверов".into(),
            "[rxvpn] Telegram: tg://proxy?server=127.0.0.1&port=1443&secret=dd0123456789abcdef0123456789abcdef".into(),
            "[rxvpn] секрет dd0123456789abcdef0123456789abcdef".into(),
            "[rxvpn] WARP: ключ aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qga2V5IQ== пир bWZtbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW1tbW0=".into(),
            "[rxvpn] WARP адрес 2606:4700:110:8a36:df92:102a:9602:fa18".into(),
            "[rxvpn] мой IP через VPN: 45.83.12.200, напрямую: 95.24.11.8 (Магадан)".into(),
            "[rxvpn] IPv6 сайты видят 2a00:1370:8194:1c2a::5".into(),
            r"[rxvpn] бэкап сохранён: C:\Users\Ivanov\Desktop\rxvpn-backup.json".into(),
            "[rxvpn] запуск из /home/ivanov/rxvpn и C:/Users/Ivanov/AppData".into(),
            "[rxvpn] пользователь ivanov вошёл".into(),
            "[rxvpn] путь /secretpath42 и пароль Sup3rPassw0rd и ключ Zx9vQk3mN7pL2wR8tY5uB1cD4eF6gH0jK9lM3nO7pQs".into(),
            "[rxvpn] что-то пришло: user:pw@unknown-host.example ключ 9f8e7d6c5b4a39281706f5e4d3c2b1a0ffeeddcc".into(),
            "[rxvpn] ссылка vmess://eyJhZGQiOiJ4LmNvbSJ9 и hy2://pw@x.y:443".into(),
            "[rxvpn] https://unknown-site.example/x?token=abc".into(),
        ]);
        let refs: Vec<&str> = log.iter().map(String::as_str).collect();
        let r = report(&refs);
        for bad in [
            "11111111-2222-3333-4444-555555555555", "myvpn-panel", "secretpath42", "203.0.113.77", "Sup3rPassw0rd",
            "Zx9vQk3mN7pL2wR8tY5uB1cD4eF6gH0jK9lM3nO7pQs", "abcd1234", "45.83.12.200", "YWVzLTI1Ni1nY20",
            "private-vpn", "AbCdEf0123456789xyz", "0123456789abcdef0123456789abcdef", "aGVsbG8gd29ybGQ",
            "bWZtbW1tbW1t", "2606:4700:110:8a36", "95.24.11.8", "2a00:1370", "Ivanov", "ivanov",
            "9f8e7d6c5b4a39281706", "unknown-host", "user:pw", "eyJhZGQiOiJ4LmNvbSJ9", "unknown-site", "token=abc", "vless://", "trojan://",
            "ss://", "tg://", "hy2://",
        ] {
            assert!(!r.contains(bad), "осталось «{bad}» в отчёте:\n{r}");
        }
        // Нужное для разбора — на месте.
        for good in ["0.10.0", "Xray 26.10.21", "127.0.0.1:10809", "i/o timeout", "accepted via proxy", "chatgpt.com", "<сервер-1>", "<user>", r"\Desktop\rxvpn-backup.json", "Магадан", "2026/11/02"] {
            assert!(r.contains(good), "пропало «{good}»:\n{r}");
        }
        // Один и тот же сервер — один и тот же номер (лог остаётся читаемым).
        assert!(r.contains("tcp:<сервер-1>:443"), "{r}");
        assert!(r.contains("Свои сайты → через VPN: chatgpt.com, <сервер-1>"), "{r}");
    }

    #[test]
    fn keeps_public_services_and_local() {
        let sec = Secrets::default();
        let t = "https://speed.cloudflare.com/__down?bytes=1000 ipleak.net 1.1.1.1 8.8.8.8:53 192.168.1.10 \
                 10.0.0.1 ::1 fe80::1 149.154.167.51:443 время 12:30:45 sha 2026-11-02 https://www.youtube.com/";
        assert_eq!(redact(t, &sec), t);
        // Публичный хост с логином — уже не «просто сервис».
        assert_eq!(redact("https://user:pw@github.com/x", &sec), "<ссылка>");
        // Соседи Telegram по /16 — уже чужие адреса.
        assert_eq!(redact("91.108.200.5 149.154.10.1 91.108.56.130", &sec), "<ip> <ip> 91.108.56.130");
    }

    #[test]
    fn words_not_substrings() {
        let mut sec = Secrets::default();
        sec.hosts.push(("1.2.3.4".into(), "<сервер-1>".into()));
        sec.hosts.push(("vpn.io".into(), "<сервер-2>".into()));
        assert_eq!(redact("11.2.3.45 и 1.2.3.4. и myvpn.io и vpn.io:443", &sec), "<ip> и <сервер-1>. и myvpn.io и <сервер-2>:443");
    }

    #[test]
    fn visited_sites_are_hidden() {
        let r = report(&[
            "[xray] 2026/11/02 12:00:01 from 127.0.0.1:50123 accepted tcp:secret-forum.example:443 [socks -> proxy]",
            "[xray] 2026/11/02 12:00:02 from 127.0.0.1:50124 accepted udp:[2a00:1450:4010::5]:443 [tun -> direct]",
            "[xray] app/dispatcher: sniffed domain: my-bank.example",
            "[xray] proxy/vless/outbound: tunneling request to tcp:secret-forum.example:443 via nl1.myvpn-panel.xyz:443",
            "[xray] 2026/11/02 12:00:03 from 127.0.0.1:50125 accepted tcp:nl1.myvpn-panel.xyz:443 [socks -> proxy]",
            "[rxvpn] проверка tcp:not-xray.example:443",
        ]);
        for bad in ["secret-forum", "my-bank", "2a00:1450", "myvpn-panel"] {
            assert!(!r.contains(bad), "осталось «{bad}»:\n{r}");
        }
        assert!(r.contains("accepted tcp:<site>:443 [socks -> proxy]"), "{r}");
        assert!(r.contains("accepted udp:<site>:443 [tun -> direct]"), "{r}");
        assert!(r.contains("sniffed domain: <site>"), "{r}");
        assert!(r.contains("accepted tcp:<сервер-1>:443"), "свой сервер — номером, не «сайтом»:\n{r}");
        assert!(r.contains("from 127.0.0.1:50123"), "{r}");
        assert!(r.contains("not-xray.example"), "строки самого rxvpn не трогаем:\n{r}");
    }

    #[test]
    fn tail_only_and_header() {
        let log: Vec<String> = (0..450).map(|i| format!("строка {i}")).collect();
        let refs: Vec<&str> = log.iter().map(String::as_str).collect();
        let r = report(&refs);
        assert!(r.contains("последние 200 строк") && r.contains("строка 449") && r.contains("строка 250\n"));
        assert!(!r.contains("строка 249\n"));
        assert!(r.starts_with("=== rxvpn: отчёт о проблеме ==="));
    }
}
