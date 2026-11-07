//! Настройки, которые с правами администратора действуют на весь комп, — под охраной.
//!
//! Защищённая копия (Program Files) читает state.json из папки data портативной, а туда
//! пишет любая программа без прав. Без охраны вирус без прав поменял бы в state.json,
//! например, свой DoH-сервер — и rxvpn с правами администратора сам прописал бы его
//! системным DNS всей Windows; или открыл бы прокси без пароля в локальную сеть.
//!
//! Как устроено: копия с правами после каждого своего сохранения кладёт снимок этих
//! настроек в `%ProgramFiles%\rxvpn\settings-guard.json` (туда пишет только
//! администратор). При запуске с правами снимок сверяется с state.json: что-то
//! поменялось не ею — окно «Применить?» (по умолчанию «Нет» → вернуть как было).
//! Окно с правами администратора программа без прав не «нажмёт» (UIPI).
//!
//! DPAPI тут не помог бы: ключ учётки доступен любой программе под той же учёткой.

use std::path::Path;

use serde_json::{Map, Value};

use crate::xray::Settings;

pub const FILE: &str = "settings-guard.json";

/// Поля Settings (имена как в state.json) и как назвать их человеку.
fn fields() -> [(&'static str, &'static str); 9] {
    [
        ("allow_lan", trs!("Пускать устройства из сети (прокси без пароля)")),
        ("doh_sys", trs!("DNS без подмены для всей Windows")),
        ("doh_provider", trs!("DNS без подмены: сервер")),
        ("doh_url", trs!("DNS без подмены: свой адрес")),
        ("dns_remote", trs!("DNS через VPN")),
        ("dns_direct", trs!("DNS напрямую")),
        ("hosts", trs!("Свои записи DNS")),
        ("zapret_dir", trs!("Своя папка стратегий zapret")),
        ("kill_switch", trs!("Kill switch: интернет только через VPN")),
    ]
}

/// Снимок охраняемых полей.
pub fn snapshot(s: &Settings) -> Value {
    let all = serde_json::to_value(s).unwrap_or(Value::Null);
    let mut m = Map::new();
    for (k, _) in fields() {
        m.insert(k.to_string(), all.get(k).cloned().unwrap_or(Value::Null));
    }
    Value::Object(m)
}

/// Доверенный снимок из папки копии. Нет или битый — None (сверяемся с настройками
/// по умолчанию: первый запуск копии после обновления rxvpn).
pub fn load(dir: &Path) -> Option<Value> {
    let d = std::fs::read(dir.join(FILE)).ok()?;
    if d.len() > 1 << 20 {
        return None;
    }
    serde_json::from_slice::<Value>(&d).ok().filter(Value::is_object)
}

pub fn save(dir: &Path, s: &Settings) -> std::io::Result<()> {
    let p = dir.join(FILE);
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&snapshot(s)).unwrap_or_default())?;
    std::fs::rename(tmp, p)
}

/// Значение для окна: одной строкой, без управляющих и «невидимых» символов
/// (иначе в state.json можно было бы нарисовать в окне чужой текст), не длиннее 80.
fn shown(v: &Value) -> String {
    let raw = match v {
        Value::String(s) if s.is_empty() => trs!("(пусто)").to_string(),
        Value::String(s) => s.clone(),
        Value::Bool(true) => trs!("вкл").to_string(),
        Value::Bool(false) => trs!("выкл").to_string(),
        Value::Array(a) if a.is_empty() => trs!("(пусто)").to_string(),
        Value::Array(a) => a.iter().map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).collect::<Vec<_>>().join(", "),
        Value::Null => trs!("(пусто)").to_string(),
        other => other.to_string(),
    };
    let clean: String = raw
        .chars()
        .map(|c| if c.is_control() || crate::store::invisible(c) { ' ' } else { c })
        .collect();
    let mut out: String = clean.chars().take(80).collect();
    if clean.chars().count() > 80 {
        out.push('…');
    }
    out
}

/// Что изменилось относительно доверенного снимка: (название, было, стало).
pub fn diff(s: &Settings, trusted: Option<&Value>) -> Vec<(String, String, String)> {
    let def = snapshot(&Settings::default());
    let base = trusted.cloned().unwrap_or_else(|| def.clone());
    let now = snapshot(s);
    let mut out = Vec::new();
    for (k, name) in fields() {
        // Поля нет в снимке (снимок старой версии) — сверяем с настройкой по умолчанию.
        let was = base.get(k).cloned().unwrap_or_else(|| def[k].clone());
        let is = now.get(k).cloned().unwrap_or(Value::Null);
        if was != is {
            out.push((name.to_string(), shown(&was), shown(&is)));
        }
    }
    out
}

/// Вернуть охраняемые поля как в доверенном снимке (нет снимка — как по умолчанию).
/// Поле, которое из снимка не читается (снимок старой версии), — по умолчанию.
pub fn revert(s: &mut Settings, trusted: Option<&Value>) {
    let def = snapshot(&Settings::default());
    let base = trusted.cloned().unwrap_or_else(|| def.clone());
    let Ok(mut all) = serde_json::to_value(&*s) else { return };
    for (k, _) in fields() {
        all[k] = base.get(k).cloned().unwrap_or_else(|| def[k].clone());
    }
    match serde_json::from_value::<Settings>(all.clone()) {
        Ok(n) => *s = n,
        Err(_) => {
            // Снимок не читается — всё охраняемое по умолчанию.
            for (k, _) in fields() {
                all[k] = def[k].clone();
            }
            if let Ok(n) = serde_json::from_value::<Settings>(all) {
                *s = n;
            }
        }
    }
}

/// Текст окна «Применить?».
pub fn prompt(changes: &[(String, String, String)]) -> String {
    let list: Vec<String> = changes.iter().map(|(n, was, is)| format!("• {n}: «{was}» → «{is}»")).collect();
    tr!(
        "Эти настройки rxvpn поменялись не в rxvpn с правами администратора:\n\n{}\n\n\
         Если это ты (например, менял их в rxvpn без прав) — нажми «Да».\n\
         Если нет — нажми «Нет»: их могла поменять чужая программа, rxvpn вернёт прежние.",
        list.join("\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(n: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rxvpn-guard-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn default_settings_need_no_prompt() {
        assert!(diff(&Settings::default(), None).is_empty());
    }

    #[test]
    fn tampered_fields_are_seen_and_reverted() {
        let d = tmp("t");
        let mut s = Settings::default();
        s.doh_url = "https://good.example/dns-query".into();
        save(&d, &s).unwrap();
        let trusted = load(&d);
        assert!(diff(&s, trusted.as_ref()).is_empty(), "своё сохранение — без вопросов");

        // Чужая программа поменяла state.json.
        s.doh_url = "https://evil.example/dns-query\nНажми «Да»".into();
        s.allow_lan = true;
        s.socks_port = 12345; // не охраняется
        let ch = diff(&s, trusted.as_ref());
        assert_eq!(ch.len(), 2);
        assert!(ch.iter().all(|(_, _, is)| !is.contains('\n')), "переводы строк из state.json в окно не попадают");

        revert(&mut s, trusted.as_ref());
        assert_eq!(s.doh_url, "https://good.example/dns-query");
        assert!(!s.allow_lan);
        assert_eq!(s.socks_port, 12345, "остальное не трогаем");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn no_guard_yet_compares_with_defaults() {
        let mut s = Settings::default();
        s.allow_lan = true;
        assert_eq!(diff(&s, None).len(), 1);
        revert(&mut s, None);
        assert!(!s.allow_lan);
    }

    #[test]
    fn broken_guard_is_ignored() {
        let d = tmp("b");
        std::fs::write(d.join(FILE), b"[1,2,3]").unwrap();
        assert!(load(&d).is_none());
        let mut s = Settings::default();
        s.allow_lan = true;
        revert(&mut s, Some(&serde_json::json!({ "allow_lan": "не bool" })));
        assert!(!s.allow_lan, "нечитаемый снимок — по умолчанию");
        let _ = std::fs::remove_dir_all(&d);
    }
}
