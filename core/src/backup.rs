//! Бэкап: сервера, подписки, правила и настройки одним файлом — для переноса
//! на другой комп или отката. Внутри пароли от серверов, поэтому файл —
//! личный: rxvpn пишет об этом рядом с кнопкой.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::store::Store;
use crate::xray::validate_settings;

pub const KIND: &str = "rxvpn-backup";
const FORMAT: u64 = 1;
/// Больше — точно не наш бэкап (у живого — сотни КБ).
pub const MAX_BYTES: u64 = 50 << 20;

#[derive(Serialize, Deserialize)]
struct BackupFile {
    kind: String,
    format: u64,
    app_version: String,
    created_at: i64,
    store: Store,
}

pub fn export(store: &Store, app_version: &str, now: i64) -> String {
    serde_json::to_string_pretty(&BackupFile {
        kind: KIND.into(),
        format: FORMAT,
        app_version: app_version.into(),
        created_at: now,
        store: store.clone(),
    })
    .expect("Store всегда сериализуется")
}

#[derive(Debug)]
pub struct Restored {
    pub store: Store,
    /// Что поправили при восстановлении — показать человеку.
    pub notes: Vec<String>,
}

/// Разобрать бэкап (или голый state.json) и проверить, прежде чем подменять
/// текущие данные. Чужой файл — тот же уровень доверия, что подписка.
pub fn parse(text: &str) -> Result<Restored, String> {
    if text.len() as u64 > MAX_BYTES {
        return Err(trs!("файл слишком большой для бэкапа rxvpn").into());
    }
    let v: Value = serde_json::from_str(text).map_err(|_| trs!("это не бэкап rxvpn (не JSON)").to_string())?;
    let store_v = if v["kind"] == KIND {
        if v["format"].as_u64().unwrap_or(0) > FORMAT {
            return Err(trs!("бэкап из более новой версии rxvpn — сначала обнови программу").into());
        }
        v["store"].clone()
    } else if v.get("servers").is_some() && v.get("settings").is_some() {
        v // data\state.json тоже подойдёт
    } else {
        return Err(trs!("это не бэкап rxvpn").into());
    };
    let mut store: Store = serde_json::from_value(store_v).map_err(|e| tr!("бэкап повреждён: {e}"))?;
    let mut notes = Vec::new();

    // Открытый прокси для всей сети не включаем молча из чужого файла.
    if store.settings.allow_lan {
        store.settings.allow_lan = false;
        notes.push(trs!("«Пускать устройства из домашней сети» выключено — включи сам в настройках, если нужно").into());
    }
    validate_settings(&store.settings).map_err(|e| tr!("в бэкапе неправильные настройки: {e}"))?;

    let mut seen = std::collections::HashSet::new();
    let before = store.servers.len();
    store.servers.retain(|n| seen.insert(n.id.clone()));
    if store.servers.len() < before {
        notes.push(tr!("убрал {} повторов серверов", before - store.servers.len()));
    }
    let mut seen = std::collections::HashSet::new();
    store.subscriptions.retain(|s| seen.insert(s.id.clone()));
    store.normalize();
    Ok(Restored { store, notes })
}

/// "2026-10-30" из unix-времени (для имени файла; без зависимостей).
pub fn date(unix: i64) -> String {
    // Алгоритм Говарда Хиннанта: дни с 1970-01-01 → гражданская дата.
    let z = unix.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_checks() {
        let mut s = Store::default();
        s.import_links("vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?type=tcp&security=reality&pbk=K&sni=a.com#NL");
        s.add_subscription("Моя", "https://sub.example.com/x");
        s.settings.block_ads = true;
        s.settings.allow_lan = true;
        let text = export(&s, "0.4.0", 1_793_350_000);
        let r = parse(&text).unwrap();
        assert_eq!(r.store.servers.len(), 1);
        assert_eq!(r.store.subscriptions.len(), 1);
        assert!(r.store.settings.block_ads);
        assert!(!r.store.settings.allow_lan, "LAN не включаем молча");
        assert_eq!(r.notes.len(), 1);
        assert_eq!(r.store.selected, r.store.servers.first().map(|n| n.id.clone()));

        // голый state.json
        let raw = serde_json::to_string(&s).unwrap();
        assert_eq!(parse(&raw).unwrap().store.servers.len(), 1);

        // мусор, чужой JSON, будущий формат, кривые настройки
        assert!(parse("hello").is_err());
        assert!(parse(r#"{"a":1}"#).is_err());
        assert!(parse(&text.replace("\"format\": 1", "\"format\": 9")).unwrap_err().contains("новой версии"));
        let mut bad = s.clone();
        bad.settings.http_port = bad.settings.socks_port;
        assert!(parse(&export(&bad, "0.4.0", 0)).unwrap_err().contains("настройки"));
        let mut bad = s.clone();
        bad.settings.log_level = "debug\" } ] }".into();
        assert!(parse(&export(&bad, "0.4.0", 0)).is_err());

        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_793_350_000), "2026-10-30");
        assert_eq!(date(951_782_400), "2000-02-29");
    }
}
