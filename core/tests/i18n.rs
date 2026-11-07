//! Этап 6: переводы. Отдельный тестовый процесс — здесь можно переключить глобальный язык,
//! не мешая остальным тестам (они сверяют русский текст).

use rxvpn_core::i18n::{self, Lang};
use rxvpn_core::link::parse_link;
use rxvpn_core::report::{redact, Secrets};
use rxvpn_core::store::{clean_name, Store};

/// Ни одной строки без перевода: scripts/i18n_check.py (кириллица вне tr!/trs!/trc!, пропуски,
/// лишние ключи, подстановки {…}). На Windows (Wine) Python нет — проверка идёт в Linux-прогоне.
#[cfg(not(windows))]
#[test]
fn every_string_is_translated() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let out = std::process::Command::new("python3")
        .arg("-I")
        .arg(root.join("scripts").join("i18n_check.py"))
        .output()
        .expect("нужен python3 для scripts/i18n_check.py");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "i18n_check.py:\n{text}{}", String::from_utf8_lossy(&out.stderr));
}

/// lib.rs (`engine_warn`) узнаёт подмену движка zapret по `trs!("не совпадает")` внутри текста ошибки —
/// английские тексты этих ошибок обязаны содержать тот же кусок.
#[test]
fn engine_mismatch_marker_survives_translation() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../locales/en.json");
    let en: std::collections::HashMap<String, String> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let marker = &en["не совпадает"];
    let msgs: Vec<_> = en.iter().filter(|(k, _)| k.starts_with("{f}") && k.contains("не совпадает")).collect();
    assert!(msgs.len() >= 4, "{msgs:?}");
    for (k, v) in msgs {
        assert!(v.contains(marker.as_str()), "{k} → {v}: нет «{marker}»");
    }
}

#[test]
fn english_mode() {
    i18n::set_lang(Lang::En);

    // Ошибки ядра — по-английски, без кириллицы.
    let e = parse_link("foo://x").unwrap_err().to_string();
    assert!(e.starts_with("unknown link scheme"), "{e}");
    assert_eq!(clean_name("abcdef", 3).unwrap_err(), "Name is longer than 3 characters");
    let e = rxvpn_core::store::Store::default().settings.clone();
    let mut bad = e;
    bad.lang = "de".into();
    assert_eq!(rxvpn_core::xray::validate_settings(&bad).unwrap_err(), "Language: unknown value");

    // Вырезание секретов от языка не зависит — меняется только подпись.
    let mut s = Store::default();
    s.servers.push(parse_link("vless://11111111-2222-3333-4444-555555555555@nl1.myvpn-panel.xyz:443?security=tls&sni=cdn.myvpn-panel.xyz#NL").unwrap());
    let sec = Secrets::from_store(&s);
    let r = redact("dial tcp:nl1.myvpn-panel.xyz:443 user 11111111-2222-3333-4444-555555555555", &sec);
    assert!(r.contains("<server-1>") && !r.contains("myvpn-panel") && !r.contains("11111111-2222"), "{r}");

    i18n::set_lang(Lang::Ru);
    let e = parse_link("foo://x").unwrap_err().to_string();
    assert!(e.starts_with("неизвестная схема ссылки"), "{e}");
}
