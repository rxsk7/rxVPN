//! Проверить manifest.json релиза тем же кодом, что и rxvpn при обновлении.
//!   cargo run -p rxvpn-core --example verify_manifest -- <manifest.json> <rxvpn.exe> <OWNER/REPO> <pubkey-hex> <текущая-версия>
use sha2::Digest;
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let m: rxvpn_core::update::Manifest = serde_json::from_slice(&std::fs::read(&a[0]).unwrap()).unwrap();
    match rxvpn_core::update::verify(&m, &a[3], &a[2], &a[4]) {
        Ok(()) => println!("подпись, адрес, версия и размер: OK"),
        Err(e) => println!("ОШИБКА: {e}"),
    }
    let exe = std::fs::read(&a[1]).unwrap();
    let h: String = sha2::Sha256::digest(&exe).iter().map(|b| format!("{b:02x}")).collect();
    println!("sha256 exe совпадает: {}; размер совпадает: {}", h == m.sha256, exe.len() as u64 == m.size);
}
