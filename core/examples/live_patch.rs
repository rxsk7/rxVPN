//! Помощник живой проверки перед выпуском (см. docs/DEVELOPMENT.md → «Живая проверка»).
//!   live_patch leftover                         — осталась ли блокировка kill switch (true/false)
//!   live_patch clear                            — снять блокировку kill switch
//!   live_patch set <state.json> <папка снимка охраны> ключ=true|false …
//!       поменять настройку в (возможно зашифрованном) state.json и переписать снимок охраны,
//!       чтобы копия с правами не спросила «Применить?». Ключи: auto_connect, close_to_tray.
//! Права администратора, та же учётка Windows (DPAPI).
// i18n-skip-begin: инструмент автора, не для пользователя.
use std::path::Path;

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("leftover") => println!("{}", rxvpn_core::killswitch::leftover()),
        Some("clear") => match rxvpn_core::killswitch::clear() {
            Ok(()) => println!("ok"),
            Err(e) => {
                println!("ОШИБКА: {e}");
                std::process::exit(1);
            }
        },
        Some("set") if a.len() >= 4 => {
            let (state, guard_dir) = (Path::new(&a[1]), Path::new(&a[2]));
            let (mut store, locked) = rxvpn_core::Store::load_ex(state);
            if locked || !state.exists() {
                println!("ОШИБКА: state.json не открылся");
                std::process::exit(1);
            }
            for kv in &a[3..] {
                let (k, v) = kv.split_once('=').expect("ключ=значение");
                let v: bool = v.parse().expect("true|false");
                match k {
                    "auto_connect" => store.settings.auto_connect = v,
                    "close_to_tray" => store.settings.close_to_tray = v,
                    _ => panic!("неизвестный ключ {k}"),
                }
            }
            store.save(state).expect("state.json");
            rxvpn_core::guard::save(guard_dir, &store).expect("снимок охраны");
            println!("ok");
        }
        _ => {
            println!("см. шапку файла");
            std::process::exit(2);
        }
    }
}
// i18n-skip-end
