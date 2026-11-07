//! Посмотреть, во что превращается ссылка:
//!   cargo run -p rxvpn-core --example gen -- "vless://..."
//! Печатает разобранный сервер и готовый config.json для Xray.

fn main() {
    let link = std::env::args().nth(1).expect("передай ссылку первым аргументом");
    match rxvpn_core::parse_link(&link) {
        Ok(node) => {
            eprintln!("{} — {}", node.name, node.summary());
            let cfg = rxvpn_core::build_config(&node, &Default::default());
            println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
        }
        Err(e) => eprintln!("ошибка: {e}"),
    }
}
