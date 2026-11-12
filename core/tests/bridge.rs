//! Мост для белых списков вживую, без VPS: два Xray с серверными конфигами rxvpn
//! на этом компе (мост → выходной) и клиент. Запрос идёт клиент → мост → выход → интернет;
//! выходной остановлен — через мост ничего не открывается.
//!   XRAY_DIR=путь\к\папке\с\xray cargo test -p rxvpn-core --test bridge -- --ignored --nocapture

use std::time::Duration;

use rxvpn_core::runner::XrayProcess;
use rxvpn_core::vps::plan::{self, Client, Reality};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn server(port: u16) -> (Reality, String) {
    let (private_key, public) = plan::reality_keys();
    (Reality { v6: false, port, sni: "www.apple.com".into(), private_key, short_id: plan::short_id() }, public)
}

#[test]
#[ignore]
fn bridge_chain_live() {
    let Some(dir) = std::env::var_os("XRAY_DIR").map(std::path::PathBuf::from) else {
        eprintln!("нет XRAY_DIR — пропускаю");
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    // Логи серверов — проверить, что Xray не ругается на устаревшие настройки.
    let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let start = |cfg: &serde_json::Value| {
        let l = logs.clone();
        XrayProcess::start(&dir, &serde_json::to_vec(cfg).unwrap(), move |x| l.lock().unwrap().push(x), || {}).unwrap()
    };

    // Выходной сервер.
    let (ex_uuid, ex_port) = (plan::uuid_v4(), free_port());
    let (ex_r, ex_pub) = server(ex_port);
    let mut ex_cfg = plan::server_config(&ex_r, &[Client { uuid: ex_uuid.clone(), email: "bridge@rxvpn".into() }], &[], &[]);
    ex_cfg["inbounds"][0]["port"] = free_port().into(); // на одном компе с мостом API-порт не поделить
    let exit_link = plan::link("127.0.0.1", &ex_r, &ex_pub, &ex_uuid, "exit");
    let exit_out = rxvpn_core::xray::node_outbounds(&rxvpn_core::parse_link(&exit_link).unwrap());

    // Мост: весь трафик клиентов — на выходной.
    let (br_uuid, br_port) = (plan::uuid_v4(), free_port());
    let (br_r, br_pub) = server(br_port);
    let br_cfg = plan::server_config(&br_r, &[Client { uuid: br_uuid.clone(), email: plan::OWNER_EMAIL.into() }], &[], &exit_out);
    assert_eq!(br_cfg["routing"]["rules"].as_array().unwrap().last().unwrap()["outboundTag"], "proxy");

    // Клиент rxvpn — к мосту.
    let node = rxvpn_core::parse_link(&plan::link("127.0.0.1", &br_r, &br_pub, &br_uuid, "bridge")).unwrap();
    let socks = free_port();
    let s = rxvpn_core::Settings { socks_port: socks, http_port: free_port(), route: rxvpn_core::RouteMode::Global, domain_strategy: "AsIs".into(), ..Default::default() };
    let cli_cfg = rxvpn_core::build_run_config(&rxvpn_core::Upstream::Single(&node), &s, &rxvpn_core::RunOpts::default());

    let exit_proc = start(&ex_cfg);
    let _bridge = start(&br_cfg);
    let _cli = start(&cli_cfg);
    // Холодный старт: три Xray поднимаются не за фиксированное время (антивирус, диск).
    // Ждём, пока каждый начнёт слушать свой порт, а не «1,2 секунды и надеемся».
    for (what, port) in [("выходной", ex_port), ("мост", br_port), ("клиент", socks)] {
        let up = (0..150).any(|_| {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() || {
                std::thread::sleep(Duration::from_millis(100));
                false
            }
        });
        assert!(up, "{what}: порт {port} не начал слушать за 15+ секунд; лог: {:?}", logs.lock().unwrap());
    }

    let c = reqwest::Client::builder().proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks}")).unwrap()).timeout(Duration::from_secs(20)).build().unwrap();
    let get = || rt.block_on(async { c.get("http://cp.cloudflare.com/generate_204").send().await.map(|r| r.status().as_u16()) });
    // Первый запрос на холодную может не успеть (Reality-рукопожатия двух звеньев, DNS выходного):
    // до пяти попыток. Проверку «без выходного наружу не идёт» ниже это не ослабляет.
    let mut ok = get();
    for _ in 0..4 {
        if matches!(ok, Ok(204)) {
            break;
        }
        eprintln!("клиент → мост → выход: {ok:?} — ещё попытка");
        std::thread::sleep(Duration::from_secs(1));
        ok = get();
    }
    eprintln!("клиент → мост → выход: {ok:?}");
    assert_eq!(ok.unwrap(), 204, "цепочка возит трафик");
    let local = rt.block_on(async { c.get(format!("http://127.0.0.1:{ex_port}/")).send().await.map(|r| r.status().as_u16()) });
    assert!(local.is_err(), "локалка сервера через мост закрыта: {local:?}");
    let warn: Vec<String> = logs.lock().unwrap().iter().filter(|l| l.contains("deprecated")).cloned().collect();
    assert!(warn.is_empty(), "Xray ругается на устаревшее: {warn:?}");

    drop(exit_proc);
    std::thread::sleep(Duration::from_millis(800));
    let dead = get();
    eprintln!("выходной остановлен: {dead:?}");
    assert!(dead.is_err() || dead.as_ref().is_ok_and(|s| *s != 204), "без выходного мост не выпускает напрямую");
}
