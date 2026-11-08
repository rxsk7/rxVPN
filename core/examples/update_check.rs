//! Живая проверка обновления против GitHub — тот же код, что в rxvpn (update::check + download).
//!   RXVPN_UPDATE_REPO=... RXVPN_UPDATE_PUBKEY=... cargo run -p rxvpn-core --example update_check -- <текущая-версия>
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cur = std::env::args().nth(1).unwrap_or_else(|| "0.0.1".into());
    match rxvpn_core::update::check(None, &cur).await {
        Ok(None) => println!("{cur}: новее нет"),
        Ok(Some(m)) => {
            println!("{cur}: найдено {} — подпись и адрес проверены", m.version);
            match rxvpn_core::update::download(&m, None).await {
                Ok(b) => println!("  скачано {} байт, хеш и размер сошлись", b.len()),
                Err(e) => println!("  скачивание: ОШИБКА {e}"),
            }
        }
        Err(e) => println!("{cur}: ОШИБКА {e}"),
    }
}
