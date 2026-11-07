//! Утилита автора для обновлений rxvpn (ключ ed25519 и подписанный manifest.json).
//!
//!   cargo run -p rxvpn-core --example sign -- keygen rxvpn-update.key
//!   cargo run -p rxvpn-core --example sign -- sign rxvpn-update.key rxvpn.exe 0.7.1 \
//!       https://github.com/OWNER/REPO/releases/download/v0.7.1/rxvpn.exe "что нового" > manifest.json
//!
//! Ключ храни у себя (не в репозитории!). Публичный ключ из keygen — в переменную
//! RXVPN_UPDATE_PUBKEY при сборке, репозиторий — в RXVPN_UPDATE_REPO=OWNER/REPO.

use rxvpn_core::update::{public_hex, sign, Manifest};
use sha2::Digest;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("keygen") if a.len() == 2 => {
            let p = std::path::Path::new(&a[1]);
            if p.exists() {
                die("файл ключа уже есть — не затираю");
            }
            let rng = ring::rand::SystemRandom::new();
            let k = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap_or_else(|_| die("нет случайных чисел"));
            std::fs::write(p, k.as_ref()).unwrap_or_else(|e| die(&e.to_string()));
            println!("RXVPN_UPDATE_PUBKEY={}", public_hex(k.as_ref()).unwrap());
        }
        Some("sign") if a.len() >= 5 => {
            let key = std::fs::read(&a[1]).unwrap_or_else(|e| die(&e.to_string()));
            let exe = std::fs::read(&a[2]).unwrap_or_else(|e| die(&e.to_string()));
            let mut m = Manifest {
                version: a[3].clone(),
                url: a[4].clone(),
                sha256: sha2::Sha256::digest(&exe).iter().map(|b| format!("{b:02x}")).collect(),
                size: exe.len() as u64,
                sig: String::new(),
                notes: a.get(5).cloned().unwrap_or_default(),
            };
            sign(&mut m, &key).unwrap_or_else(|e| die(&e));
            println!("{}", serde_json::to_string_pretty(&m).unwrap());
        }
        _ => die("использование: keygen <файл-ключа> | sign <файл-ключа> <rxvpn.exe> <версия> <url> [заметки]"),
    }
}

fn die(m: &str) -> ! {
    eprintln!("{m}");
    std::process::exit(1)
}
