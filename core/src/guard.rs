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

use crate::store::Store;
use crate::xray::Settings;

pub const FILE: &str = "settings-guard.json";

/// Ключ снимка для серверов и подписок (не поле Settings): отпечаток, см. `servers_print`.
const SERVERS: &str = "servers";

/// Поля второй очереди: куда и как идёт трафик всего компа. Чем отличаются от первых девяти:
/// нет поля в снимке (снимок старой версии rxvpn или первый запуск копии) — верим тому, что
/// есть сейчас, и запоминаем. Иначе обновление rxvpn спросило бы у каждого про его же
/// маршруты, а «Нет» сбросило бы их. Убрать поле из снимка без прав нельзя — он в Program Files.
fn fields_tofu() -> [(&'static str, &'static str); 17] {
    [
        ("tun", trs!("Весь комп через VPN (TUN)")),
        ("auto_connect", trs!("Подключаться при запуске")),
        ("connect_apps", trs!("Автоподключение по программам")),
        ("route", trs!("Режим маршрутов")),
        ("direct", trs!("Сайты напрямую, мимо VPN")),
        ("proxy", trs!("Сайты всегда через VPN")),
        ("apps_mode", trs!("Программы: режим")),
        ("apps_direct", trs!("Программы мимо VPN")),
        ("apps_proxy", trs!("Программы через VPN")),
        ("rules", trs!("Правила из редактора")),
        ("site_servers", trs!("Сайт → свой сервер")),
        ("zapret", trs!("Режим «Без VPN» (zapret)")),
        ("zapret_strategy", trs!("Стратегия zapret")),
        ("zapret_hybrid", trs!("Через zapret, мимо VPN")),
        ("hybrid_services", trs!("Через zapret: сервисы")),
        ("hybrid_sites", trs!("Через zapret: свои сайты")),
        ("tor_mode", "Tor"),
    ]
}

/// Все охраняемые поля Settings: (имя, название, «верить, если нет в снимке»).
fn all_fields() -> Vec<(&'static str, &'static str, bool)> {
    fields().into_iter().map(|(k, n)| (k, n, false)).chain(fields_tofu().into_iter().map(|(k, n)| (k, n, true))).collect()
}

/// Отпечаток серверов: SHA-256 от серверов, выбранного и адресов подписок. Сами сервера в
/// снимок не кладём: его читают все учётки компа, а в серверах — пароли.
pub fn servers_print(store: &Store) -> String {
    let subs: Vec<&str> = store.subscriptions.iter().map(|s| s.url.as_str()).collect();
    let v = serde_json::json!({ "servers": store.servers, "selected": store.selected, "subs": subs });
    crate::net::sha256_hex(v.to_string().as_bytes())
}

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
    for (k, ..) in all_fields() {
        m.insert(k.to_string(), all.get(k).cloned().unwrap_or(Value::Null));
    }
    Value::Object(m)
}

/// Снимок настроек и отпечаток серверов — то, что кладётся в файл.
pub fn snapshot_store(store: &Store) -> Value {
    let mut v = snapshot(&store.settings);
    v[SERVERS] = Value::String(servers_print(store));
    v
}

/// Сервера или подписки не те, что в доверенном снимке. Нет снимка или в нём нет
/// отпечатка (старая версия) — верим тому, что есть.
pub fn servers_changed(store: &Store, trusted: Option<&Value>) -> bool {
    trusted.and_then(|t| t.get(SERVERS)).and_then(Value::as_str).is_some_and(|was| was != servers_print(store))
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

pub fn save(dir: &Path, store: &Store) -> std::io::Result<()> {
    save_value(dir, &snapshot_store(store))
}

/// Как `save`, но отпечаток серверов — прежний (`trusted`): человек ответил «Нет» на
/// изменившиеся сервера, и при следующем запуске вопрос должен прозвучать снова.
pub fn save_keeping_servers(dir: &Path, store: &Store, trusted: Option<&Value>) -> std::io::Result<()> {
    let mut v = snapshot_store(store);
    if let Some(old) = trusted.and_then(|t| t.get(SERVERS)) {
        v[SERVERS] = old.clone();
    }
    save_value(dir, &v)
}

fn save_value(dir: &Path, v: &Value) -> std::io::Result<()> {
    let p = dir.join(FILE);
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(v).unwrap_or_default())?;
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
        // Список правил (объекты) — числом: JSON в окне никто не прочтёт.
        Value::Array(a) if a.iter().any(Value::is_object) => tr!("{} шт.", a.len()),
        Value::Array(a) => a.iter().map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string())).collect::<Vec<_>>().join(", "),
        Value::Null => trs!("(пусто)").to_string(),
        Value::Object(_) => trs!("(изменено)").to_string(),
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
    let now = snapshot(s);
    let mut out = Vec::new();
    for (k, name, tofu) in all_fields() {
        let is = now.get(k).cloned().unwrap_or(Value::Null);
        // Поля нет в снимке (снимок старой версии): первые девять сверяем с настройкой
        // по умолчанию, вторую очередь — принимаем как есть (см. `fields_tofu`).
        let was = match trusted.and_then(|t| t.get(k)) {
            Some(v) => v.clone(),
            None if tofu => is.clone(),
            None => def[k].clone(),
        };
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
    let Ok(mut all) = serde_json::to_value(&*s) else { return };
    for (k, _, tofu) in all_fields() {
        match trusted.and_then(|t| t.get(k)) {
            Some(v) => all[k] = v.clone(),
            None if tofu => {} // в снимке нет — оставляем как есть
            None => all[k] = def[k].clone(),
        }
    }
    match serde_json::from_value::<Settings>(all.clone()) {
        Ok(n) => *s = n,
        Err(_) => {
            // Снимок не читается — всё охраняемое по умолчанию.
            for (k, ..) in all_fields() {
                all[k] = def[k].clone();
            }
            if let Ok(n) = serde_json::from_value::<Settings>(all) {
                *s = n;
            }
        }
    }
}

/// Текст окна про сервера: вернуть прежние нельзя (в снимке только отпечаток), поэтому
/// «Нет» — не подключаться самому.
pub fn prompt_servers() -> String {
    trs!(
        "Сервера или подписки rxvpn поменялись не в rxvpn с правами администратора.\n\n\
         Если это ты (добавлял сервер или обновлял подписку в rxvpn без прав) — нажми «Да».\n\
         Если нет — нажми «Нет»: rxvpn не будет подключаться сам. Проверь список серверов \
         и подключись вручную — тогда вопрос больше не появится."
    )
    .to_string()
}

/// Текст окна «Применить?».
pub fn prompt(changes: &[(String, String, String)]) -> String {
    // В окно — не больше десяти строк: длинный список не влезет на экран.
    let mut list: Vec<String> = changes.iter().take(10).map(|(n, was, is)| format!("• {n}: «{was}» → «{is}»")).collect();
    if changes.len() > 10 {
        list.push(tr!("…и ещё {}", changes.len() - 10));
    }
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
        let mut s = Settings { doh_url: "https://good.example/dns-query".into(), ..Default::default() };
        save(&d, &Store { settings: s.clone(), ..Default::default() }).unwrap();
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
    fn traffic_fields_and_servers() {
        let d = tmp("tf");
        let mut st = Store::default();
        st.settings.tun = true;
        st.settings.direct = vec!["bank.example".into()];
        // Снимка нет или он старый (без новых полей) — про маршруты не спрашиваем.
        assert!(diff(&st.settings, None).is_empty(), "первый запуск копии с TUN — без вопросов");
        let old = serde_json::json!({ "allow_lan": false });
        assert!(diff(&st.settings, Some(&old)).is_empty());
        assert!(!servers_changed(&st, Some(&old)) && !servers_changed(&st, None));
        let mut kept = st.settings.clone();
        revert(&mut kept, Some(&old));
        assert!(kept.tun && kept.direct.len() == 1, "чего нет в снимке — не сбрасываем");

        save(&d, &st).unwrap();
        let trusted = load(&d);
        assert!(diff(&st.settings, trusted.as_ref()).is_empty() && !servers_changed(&st, trusted.as_ref()));

        // Чужая программа: свой сайт мимо VPN, автоподключение и свой сервер.
        st.settings.direct.push("evil.example".into());
        st.settings.auto_connect = true;
        st.import_links("vless://11111111-2222-3333-4444-555555555555@evil.example:443?type=tcp#x");
        assert_eq!(diff(&st.settings, trusted.as_ref()).len(), 2);
        assert!(servers_changed(&st, trusted.as_ref()));
        revert(&mut st.settings, trusted.as_ref());
        assert_eq!(st.settings.direct, ["bank.example"]);
        assert!(!st.settings.auto_connect && st.settings.tun);

        // «Нет» на сервера: отпечаток в снимке прежний — спросим и в следующий раз.
        save_keeping_servers(&d, &st, trusted.as_ref()).unwrap();
        assert!(servers_changed(&st, load(&d).as_ref()));
        save(&d, &st).unwrap();
        assert!(!servers_changed(&st, load(&d).as_ref()));
        // В снимке нет ни адресов, ни паролей серверов.
        let text = std::fs::read_to_string(d.join(FILE)).unwrap();
        assert!(!text.contains("evil.example:443") && !text.contains("11111111-2222"), "{text}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn no_guard_yet_compares_with_defaults() {
        let mut s = Settings { allow_lan: true, ..Default::default() };
        assert_eq!(diff(&s, None).len(), 1);
        revert(&mut s, None);
        assert!(!s.allow_lan);
    }

    #[test]
    fn broken_guard_is_ignored() {
        let d = tmp("b");
        std::fs::write(d.join(FILE), b"[1,2,3]").unwrap();
        assert!(load(&d).is_none());
        let mut s = Settings { allow_lan: true, ..Default::default() };
        revert(&mut s, Some(&serde_json::json!({ "allow_lan": "не bool" })));
        assert!(!s.allow_lan, "нечитаемый снимок — по умолчанию");
        let _ = std::fs::remove_dir_all(&d);
    }
}
