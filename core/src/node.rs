//! Модель сервера (ноды). Все ссылки (vless://, vmess://, trojan://, ss://)
//! приводятся к одной структуре `Node`, из которой потом строится конфиг Xray.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    /// Сервер из JSON-подписки с протоколом, которого нет в списке выше
    /// (hysteria, wireguard...). Конфиг берётся из `Node::raw` как есть.
    Other,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Vless => "vless",
            Protocol::Vmess => "vmess",
            Protocol::Trojan => "trojan",
            Protocol::Shadowsocks => "shadowsocks",
            Protocol::Other => "other",
        }
    }

    pub fn from_xray(s: &str) -> Self {
        match s {
            "vless" => Protocol::Vless,
            "vmess" => Protocol::Vmess,
            "trojan" => Protocol::Trojan,
            "shadowsocks" => Protocol::Shadowsocks,
            _ => Protocol::Other,
        }
    }
}

/// Транспорт: как байты едут по сети (tcp, ws, grpc, xhttp, httpupgrade).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Transport {
    pub network: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    /// grpc serviceName
    #[serde(default)]
    pub service_name: Option<String>,
    /// xhttp: auto / packet-up / stream-up / stream-one; grpc: gun / multi
    #[serde(default)]
    pub mode: Option<String>,
    /// tcp header obfuscation: none / http
    #[serde(default)]
    pub header_type: Option<String>,
    /// xhttp "extra" (JSON из параметра ссылки)
    #[serde(default)]
    pub extra: Option<serde_json::Value>,
}

/// Шифрование поверх транспорта: none / tls / reality.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Security {
    pub kind: String,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    // reality
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub short_id: Option<String>,
    #[serde(default)]
    pub spider_x: Option<String>,
    #[serde(default)]
    pub mldsa65_verify: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Node {
    /// Стабильный id = хеш ссылки без имени. Одинаковые сервера не дублируются.
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,

    /// vless / vmess
    #[serde(default)]
    pub uuid: Option<String>,
    /// trojan / shadowsocks
    #[serde(default)]
    pub password: Option<String>,
    /// shadowsocks method или vmess security (auto, aes-128-gcm...)
    #[serde(default)]
    pub method: Option<String>,
    /// vless flow (xtls-rprx-vision)
    #[serde(default)]
    pub flow: Option<String>,
    /// vless encryption (none или новый VLESS Encryption)
    #[serde(default)]
    pub encryption: Option<String>,
    #[serde(default)]
    pub alter_id: u32,

    pub transport: Transport,
    pub security: Security,

    /// Исходная ссылка — чтобы можно было экспортировать обратно.
    /// Для серверов из JSON-подписки здесь исходный JSON сервера.
    pub link: String,
    /// Из какой подписки пришёл сервер (None = добавлен руками).
    #[serde(default)]
    pub sub_id: Option<String>,
    /// Папка, куда человек сложил сервер (свой сервис, друг, VPS…). Только у
    /// добавленных руками: у серверов подписки «папка» — сама подписка.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Готовые outbounds Xray из JSON-подписки: `{"outbounds": [главный, помощники...]}`.
    /// Главный уже с tag "proxy". Если есть — конфиг строится из них как есть,
    /// без пересборки из полей выше (так не теряются fragment, xhttp extra и т.п.).
    #[serde(default)]
    pub raw: Option<serde_json::Value>,
}

impl Node {
    /// Сервер без шифрования: между компом и сервером трафик идёт открытым текстом —
    /// провайдер видит адреса сайтов и всё, что не зашифровано самим сайтом. Так бывает:
    /// VLESS без TLS/Reality и без своего шифрования, VMess с `scy=none|zero`, Trojan
    /// без TLS, Shadowsocks с методом none, SOCKS/HTTP из JSON-подписки. Такой сервер
    /// может подсунуть и тот, кто подменил подписку по дороге. В «Авто» их не берём.
    pub fn plain(&self) -> bool {
        if self.transport.network == "tuic" {
            return false; // QUIC + TLS всегда
        }
        let tls = |sec: &str| matches!(sec, "tls" | "reality");
        let none = |v: Option<&str>| matches!(v.map(str::trim), None | Some("" | "none"));
        if let Some(o) = self.raw.as_ref().map(|r| &r["outbounds"][0]).filter(|o| o.is_object()) {
            if tls(o["streamSettings"]["security"].as_str().unwrap_or("none")) {
                return false;
            }
            let s = &o["settings"];
            // Пользователь: vnext[0].users[0] (старый вид) или прямо в settings (новый).
            let user = |k: &str| s["vnext"][0]["users"][0][k].as_str().or_else(|| s[k].as_str());
            let server = |k: &str| s["servers"][0][k].as_str().or_else(|| s[k].as_str());
            return match crate::defang::fold(o["protocol"].as_str().unwrap_or("")).as_str() {
                "vless" => none(user("encryption")),
                "vmess" => matches!(user("security").map(str::trim), Some("none" | "zero")),
                "trojan" | "socks" | "http" => true,
                "shadowsocks" => matches!(server("method").map(str::trim), None | Some("" | "none" | "plain")),
                // hysteria, wireguard — шифруют сами.
                _ => false,
            };
        }
        if tls(&self.security.kind) {
            return false;
        }
        match self.protocol {
            Protocol::Vless => none(self.encryption.as_deref()),
            Protocol::Vmess => matches!(self.method.as_deref().map(str::trim), Some("none" | "zero")),
            Protocol::Trojan => true,
            Protocol::Shadowsocks => matches!(self.method.as_deref().map(str::trim), None | Some("" | "none" | "plain")),
            Protocol::Other => false,
        }
    }

    /// Короткое описание для списка: "VLESS · xhttp · reality".
    pub fn summary(&self) -> String {
        if self.transport.network == "tuic" {
            return "TUIC · QUIC · sing-box".into();
        }
        let proto = match &self.raw {
            Some(raw) => raw["outbounds"][0]["protocol"]
                .as_str()
                .unwrap_or("?")
                .to_uppercase(),
            None => self.protocol.as_str().to_uppercase(),
        };
        let mut s = format!("{proto} · {}", self.transport.network);
        if self.security.kind != "none" && !self.security.kind.is_empty() {
            s.push_str(" · ");
            s.push_str(&self.security.kind);
        }
        s
    }
}

/// FNV-1a 64: простой стабильный хеш, не меняется между версиями Rust
/// (в отличие от DefaultHasher), поэтому id серверов не "плывут".
pub fn fnv64(data: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in data.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

#[cfg(test)]
mod tests {
    use crate::parse_link;

    #[test]
    fn plain_servers_are_recognized() {
        let plain = |l: &str| parse_link(l).unwrap().plain();
        let u = "11111111-2222-3333-4444-555555555555";
        // Без TLS и без своего шифрования — открытый текст.
        assert!(plain(&format!("vless://{u}@h.example:80?type=ws&path=%2F#x")));
        assert!(plain(&format!("vless://{u}@h.example:80?type=tcp&security=none&encryption=none#x")));
        // TLS или Reality — шифруется.
        assert!(!plain(&format!("vless://{u}@h.example:443?type=ws&security=tls&sni=h.example#x")));
        assert!(!plain(&format!("vless://{u}@h.example:443?type=tcp&security=reality&pbk=Zx9vQk3mN7pL2wR8tY5uB1cD4eF6gH0jK9lM3nO7pQs&sid=ab&sni=a.com#x")));
        // Shadowsocks шифрует сам.
        assert!(!plain("ss://YWVzLTI1Ni1nY206c3NwYXNzd29yZDEyMw@45.83.12.200:8388#FI"));

        // JSON-подписка.
        let raw = |o: serde_json::Value| {
            let mut n = parse_link(&format!("vless://{u}@h.example:443?type=tcp&security=tls#x")).unwrap();
            n.raw = Some(serde_json::json!({ "outbounds": [o] }));
            n.plain()
        };
        assert!(raw(serde_json::json!({"protocol": "socks", "settings": {"servers": [{"address": "h.example", "port": 1080}]}})));
        assert!(raw(serde_json::json!({"protocol": "vless", "settings": {"vnext": [{"address": "h", "port": 80, "users": [{"id": u, "encryption": "none"}]}]}, "streamSettings": {"network": "ws"}})));
        assert!(raw(serde_json::json!({"protocol": "vmess", "settings": {"vnext": [{"address": "h", "port": 80, "users": [{"id": u, "security": "zero"}]}]}})));
        assert!(!raw(serde_json::json!({"protocol": "vmess", "settings": {"vnext": [{"address": "h", "port": 80, "users": [{"id": u, "security": "auto"}]}]}})));
        assert!(!raw(serde_json::json!({"protocol": "vless", "settings": {"vnext": [{"address": "h", "port": 443, "users": [{"id": u, "encryption": "none"}]}]}, "streamSettings": {"network": "tcp", "security": "reality"}})));
        assert!(!raw(serde_json::json!({"protocol": "wireguard", "settings": {"peers": [{"endpoint": "h:51820"}]}})));
        assert!(!raw(serde_json::json!({"protocol": "hysteria", "settings": {"address": "h", "port": 443}})));
    }
}
