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
    /// Короткое описание для списка: "VLESS · xhttp · reality".
    pub fn summary(&self) -> String {
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
