//! Автообновление: раз в день смотрим последний релиз на GitHub, качаем
//! manifest.json (версия, адрес, sha256, размер, подпись ed25519) и, по кнопке,
//! сам rxvpn.exe. Публичный ключ вшивается при сборке (RXVPN_UPDATE_PUBKEY),
//! приватный — только у автора (`cargo run -p rxvpn-core --example sign`).
//!
//! Проверки: подпись, sha256, размер, версия строго выше текущей (откатить
//! на старую дырявую нельзя), только HTTPS и только релизы своего репозитория.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Репозиторий и ключ — из окружения сборки. Нет — обновления выключены.
pub const REPO: Option<&str> = option_env!("RXVPN_UPDATE_REPO");
pub const PUBKEY_HEX: Option<&str> = option_env!("RXVPN_UPDATE_PUBKEY");
pub const MAX_EXE: u64 = 100 << 20;
const MAX_MANIFEST: usize = 64 << 10;
pub const MANIFEST_NAME: &str = "manifest.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    /// ed25519 от `message()`, hex.
    pub sig: String,
    #[serde(default)]
    pub notes: String,
}

impl Manifest {
    /// Что подписывается: всё, от чего зависит безопасность (заметки — тоже).
    pub fn message(&self) -> Vec<u8> {
        format!("rxvpn-update-v1\n{}\n{}\n{}\n{}\n{}\n", self.version, self.sha256, self.size, self.url, self.notes).into_bytes()
    }
}

/// "0.7.0" → [0,7,0]. Только цифры и точки.
pub fn parse_version(v: &str) -> Option<Vec<u64>> {
    let parts: Option<Vec<u64>> = v.trim().split('.').map(|p| (!p.is_empty() && p.len() <= 6).then(|| p.parse().ok()).flatten()).collect();
    parts.filter(|p| (1..=4).contains(&p.len()))
}

pub fn newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(mut a), Some(mut b)) => {
            let n = a.len().max(b.len());
            a.resize(n, 0);
            b.resize(n, 0);
            a > b
        }
        _ => false,
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// Проверить manifest целиком. Ok — можно предлагать обновление.
pub fn verify(m: &Manifest, pubkey_hex: &str, repo: &str, current: &str) -> Result<(), String> {
    let pk = unhex(pubkey_hex).filter(|k| k.len() == 32).ok_or(trs!("в сборке кривой ключ обновлений"))?;
    let sig = unhex(&m.sig).filter(|s| s.len() == 64).ok_or(trs!("подпись обновления испорчена"))?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pk)
        .verify(&m.message(), &sig)
        .map_err(|_| trs!("подпись обновления не сходится — не ставлю").to_string())?;
    if parse_version(&m.version).is_none() {
        return Err(trs!("странная версия в обновлении").into());
    }
    if !newer(&m.version, current) {
        return Err(tr!("версия {} не новее текущей {current}", m.version));
    }
    let prefix = format!("https://github.com/{repo}/releases/download/");
    if !m.url.starts_with(&prefix) || m.url.contains("..") || m.url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(trs!("обновление ведёт не на релизы rxvpn на GitHub — не ставлю").into());
    }
    if m.size == 0 || m.size > MAX_EXE {
        return Err(trs!("странный размер обновления").into());
    }
    if m.sha256.len() != 64 || !m.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(trs!("странный хеш обновления").into());
    }
    Ok(())
}

fn client(proxy: Option<&str>, t: Duration) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder().timeout(t).https_only(true).user_agent(concat!("rxvpn/", env!("CARGO_PKG_VERSION")));
    if let Some(p) = proxy {
        b = b.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?);
    }
    b.build().map_err(|e| e.to_string())
}

/// Последний релиз: проверенный manifest, если есть что-то новее. None — новее нет.
pub async fn check(proxy: Option<&str>, current: &str) -> Result<Option<Manifest>, String> {
    let (Some(repo), Some(pk)) = (REPO, PUBKEY_HEX) else {
        return Err(trs!("в этой сборке обновления не настроены").into());
    };
    let c = client(proxy, Duration::from_secs(30))?;
    let r = c
        .get(format!("https://api.github.com/repos/{repo}/releases/latest"))
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| tr!("GitHub недоступен: {}", crate::net::explain(&e)))?;
    // 404 — в репозитории ещё нет ни одного релиза (или он пока не создан): обновлений просто нет.
    if r.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let r = r.error_for_status().map_err(|e| tr!("GitHub недоступен: {}", crate::net::explain(&e)))?;
    let rel: serde_json::Value = serde_json::from_slice(&crate::net::read_capped(r, 1 << 20).await?).map_err(|_| trs!("GitHub ответил не JSON").to_string())?;
    let url = rel["assets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| a["name"] == MANIFEST_NAME)
        .and_then(|a| a["browser_download_url"].as_str())
        .ok_or(trs!("в последнем релизе нет manifest.json"))?
        .to_string();
    if !url.starts_with(&format!("https://github.com/{repo}/releases/download/")) {
        return Err(trs!("manifest.json лежит не в релизах rxvpn").into());
    }
    let r = c.get(&url).send().await.and_then(|r| r.error_for_status()).map_err(|e| crate::net::explain(&e))?;
    let m: Manifest = serde_json::from_slice(&crate::net::read_capped(r, MAX_MANIFEST).await?).map_err(|_| trs!("manifest.json испорчен").to_string())?;
    if !newer(&m.version, current) {
        return Ok(None);
    }
    verify(&m, pk, repo, current)?;
    Ok(Some(m))
}

/// Скачать exe из проверенного manifest и сверить размер и sha256.
pub async fn download(m: &Manifest, proxy: Option<&str>) -> Result<Vec<u8>, String> {
    let c = client(proxy, Duration::from_secs(600))?;
    let r = c.get(&m.url).send().await.and_then(|r| r.error_for_status()).map_err(|e| tr!("не скачалось: {}", crate::net::explain(&e)))?;
    let body = crate::net::read_capped(r, m.size.min(MAX_EXE) as usize).await?;
    if body.len() as u64 != m.size {
        return Err(trs!("скачалось не столько, сколько обещано — не ставлю").into());
    }
    use sha2::Digest;
    let got: String = sha2::Sha256::digest(&body).iter().map(|b| format!("{b:02x}")).collect();
    if got != m.sha256.to_ascii_lowercase() {
        return Err(trs!("хеш скачанного не сходится с подписанным — не ставлю").into());
    }
    if !body.starts_with(b"MZ") {
        return Err(trs!("скачанное — не программа Windows").into());
    }
    Ok(body)
}

/// Подменить exe: rxvpn.exe → rxvpn.old.exe, новое — на место. Запущенный exe
/// Windows переименовать даёт, а удалить — нет: старый удаляется при следующем старте.
pub fn swap(exe: &std::path::Path, new: &[u8]) -> Result<(), String> {
    let dir = exe.parent().ok_or(trs!("нет папки программы"))?;
    let tmp = dir.join("rxvpn.new.exe");
    let old = dir.join("rxvpn.old.exe");
    std::fs::write(&tmp, new).map_err(|e| tr!("не записать обновление рядом с программой: {e}"))?;
    let _ = std::fs::remove_file(&old);
    std::fs::rename(exe, &old).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        tr!("не переименовать текущий rxvpn.exe: {e}")
    })?;
    if let Err(e) = std::fs::rename(&tmp, exe) {
        let _ = std::fs::rename(&old, exe); // вернуть как было
        return Err(tr!("не поставить новый rxvpn.exe: {e}"));
    }
    Ok(())
}

/// При старте: убрать rxvpn.old.exe от прошлого обновления.
pub fn cleanup(exe: &std::path::Path) {
    if let Some(d) = exe.parent() {
        let _ = std::fs::remove_file(d.join("rxvpn.old.exe"));
        let _ = std::fs::remove_file(d.join("rxvpn.new.exe"));
    }
}

/// Подписать (для утилиты автора): pkcs8 приватного ключа ed25519.
pub fn sign(m: &mut Manifest, pkcs8: &[u8]) -> Result<(), String> {
    let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| trs!("это не ключ ed25519 (pkcs8)").to_string())?;
    m.sig = kp.sign(&m.message()).as_ref().iter().map(|b| format!("{b:02x}")).collect();
    Ok(())
}

pub fn public_hex(pkcs8: &[u8]) -> Result<String, String> {
    use ring::signature::KeyPair;
    let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| trs!("это не ключ ed25519 (pkcs8)").to_string())?;
    Ok(kp.public_key().as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_manifest() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pk = public_hex(pkcs8.as_ref()).unwrap();
        let mut m = Manifest {
            version: "0.7.1".into(),
            url: "https://github.com/rxmv/rxvpn/releases/download/v0.7.1/rxvpn.exe".into(),
            sha256: "a".repeat(64),
            size: 10 << 20,
            sig: String::new(),
            notes: "фиксы".into(),
        };
        sign(&mut m, pkcs8.as_ref()).unwrap();
        assert!(verify(&m, &pk, "rxmv/rxvpn", "0.7.0").is_ok());
        assert!(verify(&m, &pk, "rxmv/rxvpn", "0.7.1").unwrap_err().contains("не новее"), "та же версия — нет");
        assert!(verify(&m, &pk, "rxmv/rxvpn", "0.8.0").is_err(), "откат — нет");
        assert!(verify(&m, &pk, "evil/rxvpn", "0.7.0").is_err(), "чужой репозиторий — нет");
        let mut t = m.clone();
        t.sha256 = "b".repeat(64);
        assert!(verify(&t, &pk, "rxmv/rxvpn", "0.7.0").unwrap_err().contains("подпись"), "подменили хеш — подпись не сходится");
        let mut t = m.clone();
        t.notes = "другое".into();
        assert!(verify(&t, &pk, "rxmv/rxvpn", "0.7.0").is_err());
        let other = public_hex(ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap().as_ref()).unwrap();
        assert!(verify(&m, &other, "rxmv/rxvpn", "0.7.0").is_err(), "чужой ключ");
        assert!(newer("0.10.0", "0.9.9") && newer("1.0", "0.99.99") && !newer("0.7", "0.7.0") && !newer("x", "0.1"));
    }

    #[test]
    fn swap_and_cleanup() {
        let d = std::env::temp_dir().join(format!("rxvpn-upd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let exe = d.join("rxvpn.exe");
        std::fs::write(&exe, b"old").unwrap();
        swap(&exe, b"new").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        assert_eq!(std::fs::read(d.join("rxvpn.old.exe")).unwrap(), b"old");
        cleanup(&exe);
        assert!(!d.join("rxvpn.old.exe").exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
