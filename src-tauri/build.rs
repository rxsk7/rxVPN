fn main() {
    // Английские строки подставляются при компиляции (rxvpn-i18n-macros) — пересобрать при правке перевода.
    println!("cargo:rerun-if-changed=../locales/en.json");
    check_update_env();
    tauri_build::build()
}

// i18n-skip-begin: сообщения сборки — для автора, не для пользователя.
/// Релизная сборка без репозитория и ключа обновлений не собирается: такой rxvpn.exe
/// никогда не обновится сам (так вышла 0.11.0). Осознанно без обновлений —
/// RXVPN_ALLOW_NO_UPDATES=1. Отладочные сборки и `cargo test` не трогаем.
fn check_update_env() {
    for v in ["RXVPN_UPDATE_REPO", "RXVPN_UPDATE_PUBKEY", "RXVPN_ALLOW_NO_UPDATES"] {
        println!("cargo:rerun-if-env-changed={v}");
    }
    if std::env::var("PROFILE").as_deref() != Ok("release") {
        return;
    }
    let repo = std::env::var("RXVPN_UPDATE_REPO").ok();
    let key = std::env::var("RXVPN_UPDATE_PUBKEY").ok();
    let mut bad = Vec::new();
    match repo.as_deref() {
        None => bad.push("RXVPN_UPDATE_REPO не задан (нужно OWNER/REPO)".to_string()),
        Some(r) => {
            let ok_part = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) && p != "." && p != "..";
            let parts: Vec<&str> = r.split('/').collect();
            if parts.len() != 2 || !parts.iter().all(|p| ok_part(p)) {
                bad.push(format!("RXVPN_UPDATE_REPO=«{r}» — нужно OWNER/REPO"));
            }
        }
    }
    match key.as_deref() {
        None => bad.push("RXVPN_UPDATE_PUBKEY не задан (64 hex из `cargo run -p rxvpn-core --example sign -- keygen …`)".to_string()),
        Some(k) if k.len() != 64 || !k.bytes().all(|b| b.is_ascii_hexdigit()) => {
            bad.push("RXVPN_UPDATE_PUBKEY — нужно ровно 64 hex-символа (ed25519)".to_string())
        }
        _ => {}
    }
    if bad.is_empty() {
        return;
    }
    if std::env::var("RXVPN_ALLOW_NO_UPDATES").as_deref() == Ok("1") {
        println!("cargo:warning=rxvpn собирается БЕЗ автообновлений: {}", bad.join("; "));
        return;
    }
    panic!(
        "\n\nРелизная сборка rxvpn без автообновлений: {}.\n\
         Такой exe никогда не обновится сам. Задай переменные (см. README → «Обновления: как выпустить версию»)\n\
         или, если это осознанно, RXVPN_ALLOW_NO_UPDATES=1.\n\n",
        bad.join("; ")
    );
}
// i18n-skip-end
