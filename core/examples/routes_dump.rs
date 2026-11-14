//! Диагностика: какие маршруты и DNS rxvpn соберёт из настроек state.json для каждого режима
//! маршрута (сервер подставной — настоящие серверы и секреты не печатаются).
//!   cargo run -p rxvpn-core --example routes_dump -- <state.json>
// i18n-skip-begin: инструмент автора, не для пользователя.
use rxvpn_core::xray::{build_run_config, RouteMode, RunOpts, Upstream};

fn main() {
    let path = std::env::args().nth(1).expect("state.json");
    let (store, locked) = rxvpn_core::Store::load_ex(std::path::Path::new(&path));
    if locked {
        return println!("state.json не открылся");
    }
    let node = rxvpn_core::parse_link("vless://u@203.0.113.7:443?type=tcp#t").unwrap();
    // «write <файл> <Global|BypassRu|Blocked>»: полный конфиг для пробного Xray (режим «Прокси», порты 21080/21081,
    // подставной сервер, журнал соединений) — посмотреть, в какой выход Xray отправит каждый адрес.
    if std::env::args().nth(2).as_deref() == Some("write") {
        let mut s = store.settings.clone();
        s.route = match std::env::args().nth(4).as_deref() { Some("Global") => RouteMode::Global, Some("BypassRu") => RouteMode::BypassRu, _ => RouteMode::Blocked };
        s.tun = false;
        s.kill_switch = false;
        s.allow_lan = false;
        s.socks_port = 21080;
        s.http_port = 21081;
        let mut c = build_run_config(&Upstream::Single(&node), &s, &RunOpts::default());
        c["log"] = serde_json::json!({ "loglevel": "info" });
        std::fs::write(std::env::args().nth(3).unwrap(), c.to_string()).unwrap();
        return;
    }
    for (route, tun) in [(RouteMode::Global, true), (RouteMode::BypassRu, true), (RouteMode::Blocked, true), (RouteMode::Blocked, false)] {
        let mut s = store.settings.clone();
        s.route = route;
        s.tun = tun;
        let c = build_run_config(&Upstream::Single(&node), &s, &RunOpts::default());
        println!("\n===== route={route:?} tun={tun} domainStrategy={}", c["routing"]["domainStrategy"]);
        for (i, r) in c["routing"]["rules"].as_array().into_iter().flatten().enumerate() {
            let mut r = r.clone();
            let to = r["outboundTag"].as_str().or(r["balancerTag"].as_str()).unwrap_or("?").to_string();
            let m = r.as_object_mut().unwrap();
            m.remove("type");
            m.remove("outboundTag");
            let mut t = serde_json::to_string(m).unwrap();
            if t.chars().count() > 230 {
                t = t.chars().take(230).collect::<String>() + "…";
            }
            println!("{i:>2}. → {to:<8} {t}");
        }
        println!("dns: {}", c["dns"]);
        println!("sniffing(tun/http): {}", c["inbounds"].as_array().unwrap().iter().map(|i| format!("{}={}", i["tag"], i["sniffing"])).collect::<Vec<_>>().join(" | "));
    }
}
// i18n-skip-end
