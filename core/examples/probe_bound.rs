//! Диагностика: «Проверить все» с привязкой пробного Xray к сетевой карте и без неё —
//! при включённом TUN. Печатает только числа (ни имён, ни адресов серверов).
//!   cargo run -p rxvpn-core --example probe_bound -- <state.json> <папка ядра> [сколько]
// i18n-skip-begin: инструмент автора, не для пользователя.
#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut a = std::env::args().skip(1);
    let (state, core) = (a.next().expect("state.json"), a.next().expect("папка ядра"));
    let n: usize = a.next().and_then(|x| x.parse().ok()).unwrap_or(30);
    let (store, locked) = rxvpn_core::Store::load_ex(std::path::Path::new(&state));
    if locked {
        return println!("state.json не открылся");
    }
    let nodes: Vec<rxvpn_core::Node> = store.servers.iter().take(n).cloned().collect();
    let mask = rxvpn_core::xray::finalmask(&store.settings);
    let tun = rxvpn_core::xray::TUN_NAME;
    let alias = rxvpn_core::winsys::gateway_interface(tun).and_then(rxvpn_core::winsys::iface_alias);
    println!("серверов: {}, карта: {alias:?}", nodes.len());
    for bind in [None, alias] {
        let label = if bind.is_some() { "с привязкой к карте" } else { "без привязки (через туннель)" };
        rxvpn_core::batch::set_bind(bind);
        let t = std::time::Instant::now();
        match rxvpn_core::batch::test_all(std::path::Path::new(&core), &nodes, mask.clone(), store.settings.node_tweaks.clone(), |_| {}).await {
            Err(e) => println!("{label}: не запустилась: {e}"),
            Ok(res) => {
                let mut ms: Vec<u64> = res.iter().filter_map(|r| r.ms).collect();
                ms.sort_unstable();
                println!("{label}: отвечают {} из {}, медиана {:?} мс, быстрейший {:?} мс, заняло {:.1} с", ms.len(), res.len(), ms.get(ms.len() / 2), ms.first(), t.elapsed().as_secs_f32());
            }
        }
    }
}
// i18n-skip-end
