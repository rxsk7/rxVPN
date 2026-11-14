//! Диагностика маршрутов: какие настройки сейчас в state.json (без серверов, ссылок и секретов).
//!   cargo run -p rxvpn-core --example settings_dump -- <state.json>
// i18n-skip-begin: инструмент автора, не для пользователя.
fn main() {
    let path = std::env::args().nth(1).expect("state.json");
    let (store, locked) = rxvpn_core::Store::load_ex(std::path::Path::new(&path));
    if locked {
        return println!("state.json не открылся");
    }
    let s = &store.settings;
    println!("tun={} route={:?} kill_switch={} dns_ipv6={} block_ads={}", s.tun, s.route, s.kill_switch, s.dns_ipv6, s.block_ads);
    println!("dns_remote={} dns_direct={}", s.dns_remote, s.dns_direct);
    println!("zapret={} hybrid={} services={:?}", s.zapret, s.zapret_hybrid, s.hybrid_services);
    println!("hybrid_sites={:?}", s.hybrid_sites);
    println!("apps_mode={:?}\n  direct={:?}\n  proxy={:?}", s.apps_mode, s.apps_direct, s.apps_proxy);
    println!("свои сайты: через VPN={:?}\n  напрямую={:?}", s.proxy, s.direct);
    for r in &s.rules {
        println!("правило [{}] «{}» → {:?}\n  sites={:?} apps={:?} ports={:?} net={:?} proto={:?}", if r.enabled { "вкл" } else { "выкл" }, r.name, r.action, r.sites, r.apps, r.ports, r.network, r.protocols);
    }
}
// i18n-skip-end
