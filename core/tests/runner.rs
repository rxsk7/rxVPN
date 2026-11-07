//! Живой тест запуска ядра. Нужен настоящий xray:
//!   XRAY_DIR=путь\к\папке\с\xray cargo test -p rxvpn-core --test runner -- --ignored
//! Поднимает локальный "сервер" Xray и клиента rxvpn, проверяет, что трафик
//! идёт через туннель.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use rxvpn_core::runner::{port_free, XrayProcess};
use rxvpn_core::{build_config, parse_link, RouteMode, Settings};

fn xray_dir() -> Option<PathBuf> {
    std::env::var_os("XRAY_DIR").map(PathBuf::from)
}

fn tmp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("rxvpn-test-{}-{name}", std::process::id()))
}

#[test]
#[ignore]
fn bad_config_reports_error() {
    let Some(dir) = xray_dir() else { return };
    let cfg = tmp("bad.json");
    std::fs::write(&cfg, r#"{"inbounds":[{"protocol":"nope"}]}"#).unwrap();
    let err = XrayProcess::start(&dir, &std::fs::read(&cfg).unwrap(), |_| {}, || {}).err().expect("должно упасть");
    assert!(err.contains("xray завершился"), "{err}");
}

#[test]
#[ignore]
fn tunnel_end_to_end() {
    let Some(dir) = xray_dir() else { return };

    // 1. "Сайт", до которого будем ходить через туннель.
    let site = TcpListener::bind("127.0.0.1:0").unwrap();
    let site_port = site.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in site.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nrxvpn!");
        }
    });

    // 2. Сервер Xray: VLESS на локалхосте (без TLS разрешено только на private IP).
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let srv_port = 24311;
    let srv_cfg = tmp("srv.json");
    std::fs::write(
        &srv_cfg,
        serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": srv_port, "protocol": "vless",
                "settings": {"clients": [{"id": uuid}], "decryption": "none"}}],
            // Свежий Xray на сервере по умолчанию не пускает в локальные IP —
            // для теста разрешаем, "сайт" у нас на 127.0.0.1.
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
        })
        .to_string(),
    )
    .unwrap();
    let _server = XrayProcess::start(&dir, &std::fs::read(&srv_cfg).unwrap(), |l| eprintln!("srv: {l}"), || {}).unwrap();

    // 3. Клиент из ссылки — ровно так, как это делает приложение.
    let node = parse_link(&format!("vless://{uuid}@127.0.0.1:{srv_port}?type=tcp#local")).unwrap();
    let settings = Settings {
        socks_port: 24312,
        http_port: 24313,
        route: RouteMode::Global,
        ..Default::default()
    };
    assert!(port_free(settings.socks_port));
    let mut cfg = build_config(&node, &settings);
    // Убираем правило "локалка напрямую", иначе 127.0.0.1 пойдёт мимо туннеля.
    cfg["routing"]["rules"] = serde_json::json!([]);
    let cli_cfg = tmp("cli.json");
    std::fs::write(&cli_cfg, cfg.to_string()).unwrap();
    let mut client = XrayProcess::start(&dir, &std::fs::read(&cli_cfg).unwrap(), |l| eprintln!("cli: {l}"), || {}).unwrap();
    assert!(client.is_running());
    assert!(!port_free(settings.socks_port), "клиент должен занять порт");

    // 4. HTTP-запрос через HTTP-inbound клиента (как браузер с системным прокси).
    assert!(get_via(settings.http_port, site_port).ends_with("rxvpn!"));

    // 4b. Кнопка «Проверить задержку» — и через HTTP-вход, и через SOCKS.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let site = format!("http://127.0.0.1:{site_port}/");
    let dead = "http://127.0.0.1:1/"; // первый адрес не отвечает — должен сработать запасной
    let http = format!("http://127.0.0.1:{}", settings.http_port);
    let socks = format!("socks5h://127.0.0.1:{}", settings.socks_port);
    for proxy in [&http, &socks] {
        let r = rt.block_on(rxvpn_core::net::real_delay_via(proxy, &[dead, &site]));
        assert!(r.is_ok(), "{proxy}: {r:?}");
    }

    client.stop();
    assert!(!client.is_running());

    // 4c. Ядро выключено — ошибка должна это объяснять, а не «error sending request».
    let err = rt
        .block_on(rxvpn_core::net::real_delay_via(&http, &[&site]))
        .unwrap_err();
    assert!(err.contains("ядро не принимает"), "{err}");

    // 5. Тот же сервер, но пришедший JSON-подпиской (как от Remnawave),
    //    с помощником "fragment" через dialerProxy.
    let sub = serde_json::json!([{
        "remarks": "local json",
        "dns": {"servers": ["1.1.1.1"]},
        "inbounds": [{"tag": "socks", "port": 10808, "protocol": "socks"}],
        "outbounds": [
            {"tag": "proxy", "protocol": "vless",
             "settings": {"vnext": [{"address": "127.0.0.1", "port": srv_port,
                                      "users": [{"id": uuid, "encryption": "none"}]}]},
             "streamSettings": {"network": "tcp", "sockopt": {"dialerProxy": "fragment"}}},
            {"tag": "fragment", "protocol": "freedom",
             "settings": {"fragment": {"packets": "1-3", "length": "10-20", "interval": "1-2"},
                          "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}},
            {"tag": "direct", "protocol": "freedom"}
        ]
    }]);
    let (nodes, errors) = rxvpn_core::parse_many(&sub.to_string());
    assert!(errors.is_empty(), "{errors:?}");
    let mut cfg = build_config(&nodes[0], &settings);
    cfg["routing"]["rules"] = serde_json::json!([]);
    std::fs::write(&cli_cfg, cfg.to_string()).unwrap();
    let mut client = XrayProcess::start(&dir, &std::fs::read(&cli_cfg).unwrap(), |l| eprintln!("cli2: {l}"), || {}).unwrap();
    assert!(get_via(settings.http_port, site_port).ends_with("rxvpn!"));
    client.stop();
}

fn get_via(http_port: u16, site_port: u16) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", http_port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(s, "GET http://127.0.0.1:{site_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{site_port}\r\nConnection: close\r\n\r\n").unwrap();
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    resp
}

/// Поднять локальный "сайт" и сервер Xray (VLESS без TLS на 127.0.0.1).
fn local_site_and_server(dir: &std::path::Path, srv_port: u16, uuid: &str) -> (u16, XrayProcess) {
    let site = TcpListener::bind("127.0.0.1:0").unwrap();
    let site_port = site.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in site.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf);
                let body = vec![b'x'; 200_000];
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = s.write_all(&body);
            });
        }
    });
    let cfg = tmp(&format!("srv{srv_port}.json"));
    std::fs::write(
        &cfg,
        serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": srv_port, "protocol": "vless",
                "settings": {"clients": [{"id": uuid}], "decryption": "none"}}],
            "outbounds": [{"protocol": "freedom",
                "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
        })
        .to_string(),
    )
    .unwrap();
    let p = XrayProcess::start(dir, &std::fs::read(&cfg).unwrap(), |_| {}, || {}).unwrap();
    (site_port, p)
}

#[test]
#[ignore]
fn test_all_servers() {
    let Some(dir) = xray_dir() else { return };
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let (site_port, _srv) = local_site_and_server(&dir, 24511, uuid);

    let good = parse_link(&format!("vless://{uuid}@127.0.0.1:24511?type=tcp#good")).unwrap();
    let dead = parse_link(&format!("vless://{uuid}@127.0.0.1:24599?type=tcp#dead")).unwrap();
    let wrong_uuid =
        parse_link("vless://00000000-0000-0000-0000-000000000000@127.0.0.1:24511?type=tcp#wrong").unwrap();
    let sub = serde_json::json!([{"remarks": "json", "outbounds": [
        {"tag": "proxy", "protocol": "vless",
         "settings": {"vnext": [{"address": "127.0.0.1", "port": 24511, "users": [{"id": uuid, "encryption": "none"}]}]},
         "streamSettings": {"network": "tcp", "sockopt": {"dialerProxy": "fragment"}}},
        {"tag": "fragment", "protocol": "freedom",
         "settings": {"fragment": {"packets": "1-3", "length": "10-20", "interval": "1-2"},
                      "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]}]);
    let json_node = rxvpn_core::parse_many(&sub.to_string()).0.remove(0);
    let nodes = vec![good.clone(), dead.clone(), wrong_uuid.clone(), json_node.clone()];

    let rt = tokio::runtime::Runtime::new().unwrap();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen2 = seen.clone();
    let t = std::time::Instant::now();
    let res = rt
        .block_on(rxvpn_core::batch::test_all_with(
            &dir,
            &nodes,
            None,
            &Default::default(),
            vec![format!("http://127.0.0.1:{site_port}/")],
            Duration::from_secs(3),
            move |_| {
                seen2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            },
        ))
        .unwrap();
    eprintln!("за {:?}: {res:#?}", t.elapsed());
    assert_eq!(res.len(), 4);
    assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 4, "колбэк на каждый сервер");
    let get = |id: &str| res.iter().find(|r| r.id == id).unwrap();
    assert!(get(&good.id).ms.is_some());
    assert!(get(&json_node.id).ms.is_some(), "JSON-сервер с fragment тоже проходит");
    assert!(get(&dead.id).ms.is_none() && get(&dead.id).error.is_some());
    assert!(get(&wrong_uuid.id).ms.is_none(), "чужой UUID сервер не пустит");
    assert!(t.elapsed() < Duration::from_secs(12), "проверяются параллельно");
}

#[test]
#[ignore]
fn traffic_counters() {
    let Some(dir) = xray_dir() else { return };
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let (site_port, _srv) = local_site_and_server(&dir, 24521, uuid);
    let node = parse_link(&format!("vless://{uuid}@127.0.0.1:24521?type=tcp#s")).unwrap();
    let settings = Settings { socks_port: 24522, http_port: 24523, route: RouteMode::Global, ..Default::default() };
    let mut cfg = rxvpn_core::build_run_config(&rxvpn_core::Upstream::Single(&node), &settings, &rxvpn_core::RunOpts { metrics_port: Some(24524), ..Default::default() });
    cfg["routing"]["rules"] = serde_json::json!([]);
    let p = tmp("stats.json");
    std::fs::write(&p, cfg.to_string()).unwrap();
    let _cli = XrayProcess::start(&dir, &std::fs::read(&p).unwrap(), |_| {}, || {}).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let client = rxvpn_core::net::local_client();
    let before = rt.block_on(rxvpn_core::net::fetch_traffic(&client, 24524)).expect("metrics");
    for _ in 0..3 {
        assert!(get_via(24523, site_port).ends_with("xxxx"));
    }
    std::thread::sleep(Duration::from_millis(300));
    let after = rt.block_on(rxvpn_core::net::fetch_traffic(&client, 24524)).unwrap();
    eprintln!("до {before:?} после {after:?}");
    assert!(after.1 - before.1 >= 600_000, "скачали 3×200 КБ");
    // Отдачу маленькими запросами Xray не видит: первая порция данных уходит
    // вместе с заголовком VLESS мимо счётчика. Большие отправки считаются.
}

/// «Авто»: observatory видит живых и мёртвых, переключение через API
/// работает без перезапуска, после падения сервера трафик идёт через другой.
#[test]
#[ignore]
fn auto_failover_live() {
    use rxvpn_core::{net, RunOpts, Upstream};
    let Some(dir) = xray_dir() else { return };
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let (site, _s1) = local_site_and_server(&dir, 25011, uuid);
    let (_, s2) = local_site_and_server(&dir, 25012, uuid);
    let link = |p: u16, name: &str| parse_link(&format!("vless://{uuid}@127.0.0.1:{p}?type=tcp#{name}")).unwrap();
    let nodes = vec![link(25099, "dead"), link(25011, "one"), link(25012, "two")];
    let s = Settings { socks_port: 25021, http_port: 25022, route: RouteMode::Global, ..Default::default() };
    let o = RunOpts { metrics_port: Some(25023), probe_port: Some(25025), ..Default::default() };
    // Как в приложении: «Авто» = все сервера в одном Xray, трафик через выбранный.
    let start = |prefer: usize| {
        let mut cfg = rxvpn_core::build_run_config(&Upstream::Auto { nodes: &nodes, prefer }, &s, &o);
        // В песочнице нет интернета: проверяем серверы через локальный «сайт».
        cfg["observatory"]["probeURL"] = serde_json::json!(format!("http://127.0.0.1:{site}/"));
        cfg["observatory"]["probeInterval"] = serde_json::json!("1s");
        let p = tmp("auto.json");
        std::fs::write(&p, cfg.to_string()).unwrap();
        XrayProcess::start(&dir, &std::fs::read(&p).unwrap(), |l| eprintln!("cli: {l}"), || {}).unwrap()
    };
    let mut cli = start(2);

    let rt = tokio::runtime::Runtime::new().unwrap();
    let client = net::local_client();
    let vars = || rt.block_on(net::fetch_vars(&client, 25023)).unwrap();
    let mut v = vars();
    for _ in 0..50 {
        if ["node-1", "node-2"].iter().all(|t| v.observatory.get(*t).is_some_and(|o| o.alive))
            && v.observatory.get("node-0").is_some_and(|o| !o.alive && o.last_try > 0)
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
        v = vars();
    }
    assert!(v.observatory["node-1"].alive && v.observatory["node-2"].alive, "{:?}", v.observatory);
    assert!(!v.observatory["node-0"].alive, "мёртвый сервер замечен");

    let via_probe = || {
        rt.block_on(net::real_delay_with_timeout(
            "socks5h://127.0.0.1:25025",
            &[&format!("http://127.0.0.1:{site}/")],
            Duration::from_secs(3),
        ))
    };
    let before = vars().traffic["node-2"].1;
    assert!(via_probe().is_ok());
    assert!(vars().traffic["node-2"].1 > before, "трафик идёт именно через выбранный node-2");

    drop(s2); // сервер «two» упал
    std::thread::sleep(Duration::from_millis(300));
    assert!(via_probe().is_err(), "пока не переключились — не работает");
    // Переключение = перезапуск с другим выбранным сервером (так делает приложение).
    cli.stop();
    let _cli = start(1);
    let mut ok = false;
    for _ in 0..30 {
        if via_probe().is_ok() {
            ok = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(ok, "после переключения — работает");
    assert!(vars().traffic["node-1"].1 > 0, "трафик пошёл через node-1");
}

/// «Только заблокированное»: заблокированное — через VPN, остальное — напрямую.
/// Смотрим, куда Xray направил запрос (строка лога «[http >> proxy]»).
#[test]
#[ignore]
fn blocked_mode_routing_live() {
    use std::sync::{Arc, Mutex};
    let Some(dir) = xray_dir() else { return };
    if !dir.join(rxvpn_core::GEOSITE_RU).exists() {
        eprintln!("нет {} в XRAY_DIR — пропуск", rxvpn_core::GEOSITE_RU);
        return;
    }
    let node = parse_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:25099?type=tcp#x").unwrap();
    let s = Settings {
        socks_port: 25031,
        http_port: 25032,
        route: RouteMode::Blocked,
        dns_direct: "localhost".into(),
        domain_strategy: "AsIs".into(), // без DNS: в песочнице его нет
        ..Default::default()
    };
    let p = tmp("blocked.json");
    std::fs::write(&p, rxvpn_core::build_config(&node, &s).to_string()).unwrap();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let l2 = log.clone();
    let _cli = XrayProcess::start(&dir, &std::fs::read(&p).unwrap(), move |l| l2.lock().unwrap().push(l), || {}).unwrap();
    let sites = ["youtube.com", "rutracker.org", "chatgpt.com", "example.com", "ya.ru"];
    for h in sites {
        if let Ok(mut c) = TcpStream::connect(("127.0.0.1", 25032)) {
            let _ = c.set_read_timeout(Some(Duration::from_millis(300)));
            let _ = write!(c, "GET http://{h}/ HTTP/1.1\r\nHost: {h}\r\nConnection: close\r\n\r\n");
            let _ = c.read(&mut [0u8; 64]);
        }
    }
    std::thread::sleep(Duration::from_millis(500));
    let log = log.lock().unwrap();
    let route = |h: &str| {
        log.iter()
            .find(|l| l.contains(&format!("http://{h}/")))
            .map(|l| if l.contains("> proxy]") { "proxy" } else if l.contains("> direct]") { "direct" } else { "?" })
            .unwrap_or("нет в логе")
    };
    for h in sites {
        eprintln!("{h:15} -> {}", route(h));
    }

    assert_eq!(route("youtube.com"), "proxy");
    assert_eq!(route("rutracker.org"), "proxy");
    assert_eq!(route("chatgpt.com"), "proxy");
    assert_eq!(route("example.com"), "direct");
    assert_eq!(route("ya.ru"), "direct");
}

/// Заглушка за всех: ip-api, bash.ws (DNS-тест) и speed.cloudflare.com.
/// Возвращает порт и список Host, которые пришли «резолвить» поддомены.
fn fake_services() -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::sync::{Arc, Mutex};
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let seen = seen2.clone();
            std::thread::spawn(move || fake_serve(s, seen));
        }
    });
    (port, seen)
}

fn fake_serve(mut s: TcpStream, seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let head_end = loop {
        let Ok(n) = s.read(&mut tmp) else { return };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let req: Vec<&str> = lines.next().unwrap_or("").split(' ').collect();
    let (method, path) = (req.first().copied().unwrap_or(""), req.get(1).copied().unwrap_or("/"));
    // через прокси путь приходит целиком: "http://host/path"
    let path = path.split_once("://").map(|(_, r)| &r[r.find('/').unwrap_or(r.len())..]).unwrap_or(path);
    let path = if path.is_empty() { "/" } else { path };
    let hdr = |name: &str| {
        head.lines()
            .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string()))
    };
    if method == "POST" {
        let len: usize = hdr("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut got = buf.len() - head_end;
        while got < len {
            match s.read(&mut tmp) {
                Ok(0) | Err(_) => return,
                Ok(n) => got += n,
            }
        }
    }
    let reply = |s: &mut TcpStream, body: &str| {
        let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    };
    if let Some(n) = path.strip_prefix("/__down?bytes=") {
        let n: usize = n.parse().unwrap_or(0);
        let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n");
        let chunk = vec![0u8; 64 * 1024];
        let mut left = n;
        while left > 0 {
            let k = left.min(chunk.len());
            if s.write_all(&chunk[..k]).is_err() {
                return;
            }
            left -= k;
        }
    } else if path == "/__up" || path.starts_with("/myip/test/") {
        reply(&mut s, "ok");
    } else if path == "/id" {
        reply(&mut s, "abc123");
    } else if path.starts_with("/dnsleak/test/abc123") {
        let mut hosts = seen.lock().unwrap().clone();
        hosts.sort();
        hosts.dedup();
        let mut list: Vec<serde_json::Value> = hosts
            .iter()
            .enumerate()
            .map(|(i, _)| serde_json::json!({"ip": format!("10.0.0.{i}"), "country": "NL", "country_name": "Netherlands", "asn": "AS1 Test", "type": "dns"}))
            .collect();
        list.push(serde_json::json!({"ip": "DNS is not leaking.", "type": "conclusion"}));
        reply(&mut s, &serde_json::Value::Array(list).to_string());
    } else if hdr("host").is_some_and(|h| h.ends_with(".ipleak.test")) && path.starts_with("/dnsdetection/") {
        // ipleak: «резолвер» = номер поддомена, ответ — все за сессию.
        let host = hdr("host").unwrap();
        let session = host.split('-').next().unwrap_or("").to_string();
        let mut ips = serde_json::Map::new();
        {
            let mut seen = seen.lock().unwrap();
            seen.push(host);
            let mut hosts: Vec<String> = seen.iter().filter(|h| h.starts_with(&session)).cloned().collect();
            hosts.sort();
            hosts.dedup();
            for i in 0..hosts.len() {
                ips.insert(format!("10.0.1.{i}"), serde_json::json!(1));
            }
        }
        reply(&mut s, &serde_json::json!({"session": session, "ip": ips}).to_string());
    } else if hdr("host").as_deref() == Some("ipleak.test") && path.starts_with("/json/") {
        let ip = path.trim_start_matches("/json/");
        let ip = if ip.is_empty() { "79.137.195.200" } else { ip };
        reply(&mut s, &serde_json::json!({"as_number": 210644, "isp_name": "Test", "country_code": "NL", "country_name": "Netherlands", "ip": ip}).to_string());
    } else if path.starts_with("/json") {
        reply(&mut s, r#"{"status":"success","country":"Нидерланды","countryCode":"NL","city":"Амстердам","isp":"Test VPN","query":"79.137.195.200"}"#);
    } else {
        if let Some(h) = hdr("host").filter(|h| h.ends_with(".leak.test")) {
            seen.lock().unwrap().push(h);
        }
        reply(&mut s, "hi");
    }
}

/// «Мой IP», DNS-тест и скорость — через настоящий туннель Xray, служебный
/// вход probe и HTTP-вход (как браузер). Без интернета: всё уходит в заглушку.
#[test]
#[ignore]
fn checks_live() {
    use rxvpn_core::checks::{self, IpleakApi, LeakApi, LeakService, SpeedLimits, SpeedUrls, Trigger};
    use rxvpn_core::{build_run_config, RunOpts, Upstream};
    let Some(dir) = xray_dir() else { return };
    let (fake, seen) = fake_services();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let lim = SpeedLimits { down_secs: 1.5, up_secs: 1.0, down_max_bytes: 300 << 20, up_max_bytes: 100 << 20, streams: 2 };

    // 1. Скорость напрямую.
    let direct = SpeedUrls {
        down: format!("http://127.0.0.1:{fake}/__down?bytes={{bytes}}"),
        down_fallback: None,
        up: Some(format!("http://127.0.0.1:{fake}/__up")),
    };
    let r = rt.block_on(checks::speedtest(None, &direct, lim, |_| {})).unwrap();
    eprintln!("напрямую: {r:?}");
    assert!(r.down_mbps > 10.0 && r.up_mbps.unwrap() > 10.0);
    assert!(r.down_bytes <= (300 << 20) + (64 << 20), "лимит по объёму держится");

    // 2. Сервер VPN: всё, что к нему пришло, — в заглушку.
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let srv_cfg = tmp("srv24521.json");
    std::fs::write(
        &srv_cfg,
        serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": 24521, "protocol": "vless",
                "settings": {"clients": [{"id": uuid}], "decryption": "none"}}],
            "outbounds": [{"protocol": "freedom", "settings": {"redirect": format!("127.0.0.1:{fake}"),
                "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
        })
        .to_string(),
    )
    .unwrap();
    let _srv = XrayProcess::start(&dir, &std::fs::read(&srv_cfg).unwrap(), |_| {}, || {}).unwrap();

    // 3. Клиент как в приложении, «Только блок.»: обычные сайты напрямую —
    //    а проверки всё равно должны пойти через VPN (вход probe).
    let node = parse_link(&format!("vless://{uuid}@127.0.0.1:24521?type=tcp#t")).unwrap();
    let s = Settings { socks_port: 24522, http_port: 24523, route: RouteMode::Global, domain_strategy: "AsIs".into(), ..Default::default() };
    let opts = RunOpts { probe_port: Some(24524), ..Default::default() };
    let cfg = tmp("cli24522.json");
    std::fs::write(&cfg, build_run_config(&Upstream::Single(&node), &s, &opts).to_string()).unwrap();
    let _cli = XrayProcess::start(&dir, &std::fs::read(&cfg).unwrap(), |_| {}, || {}).unwrap();
    let probe = "socks5h://127.0.0.1:24524";

    let ip = rt.block_on(checks::my_ip(Some(probe), &["http://ip.test/json/?lang=ru"])).unwrap();
    assert_eq!((ip.ip.as_str(), ip.flag.as_str()), ("79.137.195.200", "🇳🇱"));

    // ipleak (основной): 10 поддоменов через HTTP-вход, страны — служебным путём.
    let ipl = LeakService::Ipleak(IpleakApi { scheme: "http".into(), zone: "ipleak.test".into(), geo: "http://ipleak.test".into() });
    let bash = LeakService::BashWs(LeakApi { base: "http://leak.test".into(), domain: "leak.test".into() });
    let (leak, who) = rt
        .block_on(checks::dns_leak_any(&[ipl, bash.clone()], Some(probe), Trigger::Proxy("http://127.0.0.1:24523".into())))
        .unwrap();
    eprintln!("DNS ipleak: {leak:?}");
    assert_eq!(who, "ipleak.test");
    assert_eq!(seen.lock().unwrap().iter().filter(|h| h.ends_with(".ipleak.test")).count(), 10, "все 10 поддоменов прошли через HTTP-вход");
    assert_eq!(leak.servers.len(), 10);
    assert!(leak.servers.iter().all(|d| d.country_code == "NL" && d.asn == "AS210644 Test"));
    assert_eq!(leak.seen_ip.as_ref().map(|d| d.ip.as_str()), Some("79.137.195.200"));
    assert_eq!(checks::leak_verdict(&leak, true, false).level, "ok");
    seen.lock().unwrap().clear();

    // ipleak сломан (вместо API — «страница») → запасной bash.ws.
    let broken = LeakService::Ipleak(IpleakApi { scheme: "http".into(), zone: "broken.test".into(), geo: "http://broken.test".into() });
    let (leak, who) = rt
        .block_on(checks::dns_leak_any(&[broken.clone(), bash], Some(probe), Trigger::Proxy("http://127.0.0.1:24523".into())))
        .unwrap();
    eprintln!("DNS bash.ws: {leak:?}");
    assert_eq!(who, "leak.test");
    assert_eq!(seen.lock().unwrap().len(), 10, "все 10 поддоменов прошли через HTTP-вход");
    assert_eq!(leak.servers.len(), 10);
    // Не ответил никто — понятная ошибка с причинами.
    let e = rt.block_on(checks::dns_leak_any(&[broken], Some(probe), Trigger::Proxy("http://127.0.0.1:24523".into()))).unwrap_err();
    assert!(e.contains("не ответил ни один сервис") && e.contains("broken.test"), "{e}");

    let via = SpeedUrls {
        down: "http://speed.test/__down?bytes={bytes}".into(),
        down_fallback: None,
        up: Some("http://speed.test/__up".into()),
    };
    let r = rt.block_on(checks::speedtest(Some(probe), &via, lim, |_| {})).unwrap();
    eprintln!("через VPN: {r:?}");
    assert!(r.down_mbps > 10.0 && r.up_mbps.unwrap() > 10.0);

    // Основной адрес мёртв → запасной.
    let fb = SpeedUrls {
        down: "http://127.0.0.1:1/__down?bytes={bytes}".into(),
        down_fallback: Some(format!("http://127.0.0.1:{fake}/__down?bytes=50000000")),
        up: None,
    };
    let r = rt.block_on(checks::speedtest(None, &fb, lim, |_| {})).unwrap();
    assert!(r.down_mbps > 10.0 && r.up_mbps.is_none());
}

/// Hysteria2: настоящий сервер Xray (hysteria + TLS с самоподписанным сертификатом
/// + обфускация salamander), клиент — из ссылки hy2:// с pinSHA256, как в приложении.
#[test]
#[ignore]
fn hysteria2_live() {
    let Some(dir) = xray_dir() else { return };
    // Самоподписанный сертификат на localhost и его SHA-256 (как pinSHA256 в ссылке).
    let (cert, key) = (tmp("hy.crt"), tmp("hy.key"));
    let ok = std::process::Command::new("openssl")
        .args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "2", "-subj", "/CN=localhost"])
        .arg("-keyout").arg(&key).arg("-out").arg(&cert)
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("нет openssl — пропускаю");
        return;
    }
    let der = std::process::Command::new("openssl").args(["x509", "-outform", "der", "-in"]).arg(&cert).output().unwrap().stdout;
    let pin = rxvpn_core::net::sha256_hex(&der);

    // «Сайт» за сервером.
    let site = TcpListener::bind("127.0.0.1:0").unwrap();
    let site_port = site.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in site.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf);
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhy2ok!");
        }
    });
    let srv_port = 24341;
    let srv_cfg = tmp("hysrv.json");
    std::fs::write(
        &srv_cfg,
        serde_json::json!({
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": srv_port, "protocol": "hysteria",
                "settings": {"version": 2, "clients": [{"auth": "s3cret pass"}]},
                "streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2},
                    "security": "tls", "tlsSettings": {"alpn": ["h3"], "certificates": [{"certificateFile": cert, "keyFile": key}]},
                    "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "obfs-pw"}}]}}}],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
        })
        .to_string(),
    )
    .unwrap();
    let _server = XrayProcess::start(&dir, &std::fs::read(&srv_cfg).unwrap(), |l| eprintln!("srv: {l}"), || {}).unwrap();

    let settings = Settings { socks_port: 24342, http_port: 24343, route: RouteMode::Global, ..Default::default() };
    let run = |link: &str| -> String {
        let node = parse_link(link).unwrap();
        let mut cfg = build_config(&node, &settings);
        cfg["routing"]["rules"] = serde_json::json!([]);
        let cli_cfg = tmp("hycli.json");
        std::fs::write(&cli_cfg, cfg.to_string()).unwrap();
        let mut c = XrayProcess::start(&dir, &std::fs::read(&cli_cfg).unwrap(), |l| eprintln!("cli: {l}"), || {}).unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let r = get_via(settings.http_port, site_port);
        c.stop();
        r
    };
    let good = format!("hysteria2://s3cret%20pass@127.0.0.1:{srv_port}/?sni=localhost&obfs=salamander&obfs-password=obfs-pw&pinSHA256={pin}#hy2");
    assert!(run(&good).ends_with("hy2ok!"), "через hysteria2 сайт не открылся");
    // Чужой сертификат (не тот отпечаток) — соединения нет.
    let wrong = good.replace(&pin, &"0".repeat(64));
    assert!(!run(&wrong).ends_with("hy2ok!"), "с неверным pinSHA256 подключаться нельзя");
    // Неверный пароль — тоже нет.
    let badpw = good.replace("s3cret%20pass", "nope");
    assert!(!run(&badpw).ends_with("hy2ok!"));
}

/// Конфиг гибрида (YouTube/Discord напрямую + DNS для них) Xray принимает.
#[test]
#[ignore]
fn hybrid_config_accepted_by_xray() {
    let Some(dir) = xray_dir() else { return };
    let n = parse_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@nl1.example.com:443?type=tcp&security=reality&pbk=MYbXk4O6mTSi3jXZq5wQ_OlzYfFtSY-BLeQ5aG6lVQI&sid=ab&sni=x.com#t").unwrap();
    for tun in [false, true] {
        let s = Settings { zapret_hybrid: true, tun, hybrid_services: Some(vec!["youtube".into(), "discord".into(), "twitch".into()]), hybrid_sites: vec!["kick.com".into()], ..Default::default() };
        let cfg = rxvpn_core::build_run_config(&rxvpn_core::Upstream::Single(&n), &s, &rxvpn_core::RunOpts::default());
        let p = tmp(&format!("hybrid{tun}.json"));
        std::fs::write(&p, cfg.to_string()).unwrap();
        rxvpn_core::runner::test_config(&dir, cfg.to_string().as_bytes()).unwrap_or_else(|e| panic!("tun={tun}: {e}"));
    }
}

/// «Сайт → свой сервер»: сайт из правила идёт через свой сервер (site-0),
/// остальное — через основной; Xray принимает такой конфиг.
#[test]
#[ignore]
fn site_server_live() {
    use rxvpn_core::{net, site_routes, RunOpts, SiteServer, Upstream};
    let Some(dir) = xray_dir() else { return };
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let (site, _a) = local_site_and_server(&dir, 25111, uuid);
    let (_, _b) = local_site_and_server(&dir, 25112, uuid);
    let link = |p: u16, name: &str| parse_link(&format!("vless://{uuid}@127.0.0.1:{p}?type=tcp#{name}")).unwrap();
    let (main, other) = (link(25111, "main"), link(25112, "other"));
    let all = vec![main.clone(), other.clone()];
    let mut s = Settings { socks_port: 25121, http_port: 25122, route: RouteMode::Global, ..Default::default() };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let client = net::local_client();
    let run = |s: &Settings, metrics: u16, all: &[rxvpn_core::Node]| {
        let routes = site_routes(s, all);
        let o = RunOpts { metrics_port: Some(metrics), sites: &routes, ..Default::default() };
        let mut cfg = rxvpn_core::build_run_config(&Upstream::Single(&main), s, &o);
        // «Сайт» на 127.0.0.1: убираем «локальные адреса — напрямую».
        cfg["routing"]["rules"].as_array_mut().unwrap().retain(|r| r["ip"][0] != "geoip:private");
        let p = tmp(&format!("site{metrics}.json"));
        std::fs::write(&p, cfg.to_string()).unwrap();
        XrayProcess::start(&dir, &std::fs::read(&p).unwrap(), |l| eprintln!("cli: {l}"), || {}).unwrap()
    };

    // Без правила — через основной.
    let mut cli = run(&s, 25123, &all);
    assert!(get_via(25122, site).ends_with("xxxx"));
    std::thread::sleep(Duration::from_millis(300));
    let v = rt.block_on(net::fetch_vars(&client, 25123)).unwrap();
    assert!(v.traffic["proxy"].1 >= 200_000, "{:?}", v.traffic);
    cli.stop();

    // Правило: 127.0.0.1 — через «other».
    s.site_servers = vec![SiteServer { name: "Тест".into(), sites: vec!["127.0.0.1".into()], server: other.id.clone(), ..Default::default() }];
    rxvpn_core::validate_settings(&s).unwrap();
    let mut cli = run(&s, 25124, &all);
    assert!(get_via(25122, site).ends_with("xxxx"));
    std::thread::sleep(Duration::from_millis(300));
    let v = rt.block_on(net::fetch_vars(&client, 25124)).unwrap();
    assert!(v.traffic["site-0"].1 >= 200_000, "{:?}", v.traffic);
    assert!(v.traffic.get("proxy").map_or(0, |x| x.1) < 10_000, "основной не трогали: {:?}", v.traffic);
    cli.stop();

    // Сервера для сайта больше нет — сайт закрыт, а не идёт через основной.
    let _cli = run(&s, 25125, std::slice::from_ref(&main));
    assert!(!get_via(25122, site).ends_with("xxxx"), "закрыто");
    std::thread::sleep(Duration::from_millis(300));
    let v = rt.block_on(net::fetch_vars(&client, 25125)).unwrap();
    assert!(v.traffic.get("proxy").map_or(0, |x| x.1) < 10_000, "не через основной: {:?}", v.traffic);
}

/// Проверка сервисов поднимает свой Xray (конфиг через stdin). Без интернета
/// в песочнице сервисы не ответят — ждём понятную ошибку, не панику.
#[test]
#[ignore]
fn check_services_plumbing() {
    let Some(dir) = xray_dir() else { return };
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let (_, _srv) = local_site_and_server(&dir, 25211, uuid);
    let node = parse_link(&format!("vless://{uuid}@127.0.0.1:25211?type=tcp#s")).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let r = rt.block_on(rxvpn_core::batch::check_services(&dir, &node, None, &Default::default()));
    match r {
        Ok(rep) => eprintln!("есть интернет: {rep:?}"),
        Err(e) => assert!(e.contains("не ответил"), "{e}"),
    }
}

/// «Подобрать обход»: все варианты в одном временном Xray, Xray принимает
/// конфиг (в т.ч. с отпечатками и нарезкой у REALITY), до сервера доходят.
#[test]
#[ignore]
fn pick_tweak_live() {
    let Some(dir) = xray_dir() else { return };
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let (site, _srv) = local_site_and_server(&dir, 25311, uuid);
    let node = parse_link(&format!("vless://{uuid}@127.0.0.1:25311?type=tcp#s")).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let url = format!("http://127.0.0.1:{site}/");
    let res = rt
        .block_on(rxvpn_core::batch::pick_tweak_with(&dir, &node, &[&url], Duration::from_secs(4)))
        .unwrap();
    assert_eq!(res.len(), rxvpn_core::xray::tweak_variants(&node).len());
    assert!(res.iter().all(|r| r.ms.is_some()), "{res:?}");
    assert_eq!(res[0].label, "без обхода");
    // REALITY: варианты с отпечатками и нарезкой — конфиг принимается.
    let r = parse_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@nl1.example.com:443?type=tcp&security=reality&pbk=MYbXk4O6mTSi3jXZq5wQ_OlzYfFtSY-BLeQ5aG6lVQI&sid=ab&sni=x.com#t").unwrap();
    let v: Vec<_> = rxvpn_core::xray::tweak_variants(&r).into_iter().enumerate().map(|(i, t)| (t, 26000 + i as u16)).collect();
    assert!(v.len() >= 8);
    let cfg = rxvpn_core::xray::build_variant_config(&r, &v);
    rxvpn_core::runner::test_config(&dir, cfg.to_string().as_bytes()).unwrap();
    let txt = cfg.to_string();
    assert!(txt.contains("\"fingerprint\":\"firefox\"") && txt.contains("\"lengths\":[\"1-5\"]"));
}

/// «Сайт → сервер» с запасным: основной мёртв — сайт идёт через запасной (sb-00),
/// оба мертвы — сайт не открывается и не идёт мимо (ни через основной сервер
/// подключения, ни напрямую).
#[test]
#[ignore]
fn site_backup_live() {
    use rxvpn_core::{net, site_routes, RunOpts, SiteServer, Upstream};
    let Some(dir) = xray_dir() else { return };
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let (site, _a) = local_site_and_server(&dir, 25411, uuid);
    let (_, _b) = local_site_and_server(&dir, 25412, uuid);
    let link = |p: u16, name: &str| parse_link(&format!("vless://{uuid}@127.0.0.1:{p}?type=tcp#{name}")).unwrap();
    let (main, spare, dead, dead2) = (link(25411, "main"), link(25412, "spare"), link(25499, "dead"), link(25498, "dead2"));
    let all = vec![main.clone(), spare.clone(), dead.clone(), dead2.clone()];
    let rt = tokio::runtime::Runtime::new().unwrap();
    let client = net::local_client();
    let run = |s: &Settings, metrics: u16| {
        let routes = site_routes(s, &all);
        let o = RunOpts { metrics_port: Some(metrics), sites: &routes, ..Default::default() };
        let mut cfg = rxvpn_core::build_run_config(&Upstream::Single(&main), s, &o);
        cfg["routing"]["rules"].as_array_mut().unwrap().retain(|r| r["ip"][0] != "geoip:private");
        assert!(cfg["routing"]["balancers"].is_array());
        XrayProcess::start(&dir, cfg.to_string().as_bytes(), |l| eprintln!("cli: {l}"), || {}).unwrap()
    };
    let rule = |server: &str, backup: &str| SiteServer {
        name: "Тест".into(),
        sites: vec!["127.0.0.1".into()],
        server: server.into(),
        backup: backup.into(),
        ..Default::default()
    };
    let mut s = Settings { socks_port: 25421, http_port: 25422, route: RouteMode::Global, ..Default::default() };

    s.site_servers = vec![rule(&dead.id, &spare.id)];
    rxvpn_core::validate_settings(&s).unwrap();
    let mut cli = run(&s, 25423);
    std::thread::sleep(Duration::from_millis(500));
    assert!(get_via(25422, site).ends_with("xxxx"), "основной мёртв — через запасной");
    std::thread::sleep(Duration::from_millis(300));
    let v = rt.block_on(net::fetch_vars(&client, 25423)).unwrap();
    assert!(v.traffic["sb-00"].1 >= 200_000, "{:?}", v.traffic);
    assert!(v.traffic.get("proxy").map_or(0, |x| x.1) < 10_000, "не через основной сервер подключения: {:?}", v.traffic);
    cli.stop();

    s.site_servers = vec![rule(&dead.id, &dead2.id)];
    let mut cli = run(&s, 25424);
    std::thread::sleep(Duration::from_millis(500));
    assert!(!get_via(25422, site).ends_with("xxxx"), "оба мертвы — закрыто");
    std::thread::sleep(Duration::from_millis(300));
    let v = rt.block_on(net::fetch_vars(&client, 25424)).unwrap();
    for t in ["proxy", "direct"] {
        assert!(v.traffic.get(t).map_or(0, |x| x.1) < 10_000, "не мимо через {t}: {:?}", v.traffic);
    }
    cli.stop();
}

/// WARP поверх сервера по-настоящему: WireGuard идёт внутри VLESS (dialerProxy).
/// «Cloudflare» — локальный Xray с wireguard-входом; до него можно только через
/// сервер (его UDP-порт клиенту напрямую закрыт правилом).
#[test]
#[ignore]
fn warp_over_server_live() {
    use rxvpn_core::warp::{self, Warp, WarpKey};
    use rxvpn_core::{net, RunOpts, Upstream};
    let Some(dir) = xray_dir() else { return };
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let (_, _srv) = local_site_and_server(&dir, 25511, uuid);
    // «Сайт» — на адресе сетевой карты: стек WireGuard в Xray не ходит на 127.0.0.1.
    let ip = std::net::UdpSocket::bind("0.0.0.0:0").and_then(|u| u.connect("8.8.8.8:53").and_then(|_| u.local_addr())).unwrap().ip();
    let l = TcpListener::bind((ip, 0)).unwrap();
    let site = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut c in l.incoming().flatten() {
            let mut buf = [0u8; 2048];
            let _ = c.read(&mut buf);
            let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nwarp-okxx");
        }
    });
    // «Cloudflare»: wireguard-вход, выход — freedom в локалку (к «сайту»).
    let (srv_secret, srv_public) = warp::new_keypair();
    let (cli_secret, cli_public) = warp::new_keypair();
    let wg_port = 25512;
    let wg = serde_json::json!({
        "log": {"loglevel": std::env::var("XLOG").unwrap_or("warning".into())},
        "inbounds": [{"listen": "127.0.0.1", "port": wg_port, "protocol": "wireguard",
            "settings": {"secretKey": srv_secret, "peers": [{"publicKey": cli_public, "allowedIPs": ["172.16.0.2/32"]}], "mtu": 1280}}],
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": [format!("{ip}/32")]}]}}]
    });
    // Под Wine Xray для Windows не работает с UDP (WSAIoctl 10045) — тест только на Linux-xray.
    let _wg = XrayProcess::start(&dir, wg.to_string().as_bytes(), |l| eprintln!("wg: {l}"), || {}).unwrap();
    let via = parse_link(&format!("vless://{uuid}@127.0.0.1:25511?type=tcp#nl")).unwrap();
    let key = WarpKey { secret: cli_secret, peer: srv_public, v4: "172.16.0.2".into(), v6: String::new(), reserved: [0, 0, 0], endpoint: format!("127.0.0.1:{wg_port}") };
    let w = Warp { via: via.id.clone(), via_sub: String::new(), key };
    let node = warp::node(&w, Some(&via)).unwrap();
    let s = Settings { socks_port: 25521, http_port: 25522, route: RouteMode::Global, log_level: std::env::var("XLOG").unwrap_or("warning".into()), ..Default::default() };
    let o = RunOpts { metrics_port: Some(25523), ..Default::default() };
    let mut cfg = rxvpn_core::build_run_config(&Upstream::Single(&node), &s, &o);
    cfg["routing"]["rules"].as_array_mut().unwrap().retain(|r| r["ip"][0] != "geoip:private");
    rxvpn_core::runner::test_config(&dir, cfg.to_string().as_bytes()).unwrap();
    let mut cli = XrayProcess::start(&dir, cfg.to_string().as_bytes(), |l| eprintln!("cli: {l}"), || {}).unwrap();
    std::thread::sleep(Duration::from_millis(700));
    let mut c = TcpStream::connect(("127.0.0.1", 25522)).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    write!(c, "GET http://{ip}:{site}/ HTTP/1.1\r\nHost: {ip}:{site}\r\nConnection: close\r\n\r\n").unwrap();
    let mut resp = String::new();
    let _ = c.read_to_string(&mut resp);
    assert!(resp.ends_with("warp-okxx"), "через WARP поверх сервера сайт не открылся: {resp:?}");
    std::thread::sleep(Duration::from_millis(300));
    let client = net::local_client();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let v = rt.block_on(net::fetch_vars(&client, 25523)).unwrap();
    assert!(v.traffic["proxy"].1 > 0, "трафик по wireguard: {:?}", v.traffic);
    assert!(v.traffic["warp-via"].1 > v.traffic["proxy"].1, "и он же — внутри сервера (с заголовками WireGuard): {:?}", v.traffic);
    cli.stop();

    // «Авто» и «Сайт → сервер» с WARP — Xray принимает (теги цепочки не путаются).
    let all = vec![via.clone(), node.clone()];
    let a = rxvpn_core::build_run_config(&Upstream::Auto { nodes: &all, prefer: 1 }, &s, &RunOpts::default());
    rxvpn_core::runner::test_config(&dir, a.to_string().as_bytes()).unwrap();
    let ss = Settings {
        site_servers: vec![rxvpn_core::SiteServer { name: "ChatGPT".into(), sites: vec!["chatgpt.com".into()], server: node.id.clone(), backup: via.id.clone(), ..Default::default() }],
        ..s.clone()
    };
    let routes = rxvpn_core::site_routes(&ss, &all);
    let c = rxvpn_core::build_run_config(&Upstream::Single(&via), &ss, &RunOpts { sites: &routes, ..Default::default() });
    rxvpn_core::runner::test_config(&dir, c.to_string().as_bytes()).unwrap();
}

/// Конфиги Tor (все режимы) и входа «напрямую» Xray принимает.
#[test]
#[ignore]
fn tor_config_accepted_by_xray() {
    use rxvpn_core::xray::TorMode;
    let Some(dir) = xray_dir() else { return };
    let n = parse_link("vless://b831381d-6324-4d53-ad4f-8cda48b30811@nl1.example.com:443?type=tcp&security=reality&pbk=MYbXk4O6mTSi3jXZq5wQ_OlzYfFtSY-BLeQ5aG6lVQI&sid=ab&sni=x.com#t").unwrap();
    for mode in [TorMode::Onion, TorMode::Sites, TorMode::All] {
        for tor in [Some((9150, 9151)), None] {
            let s = Settings { tor_mode: mode, tor_sites: vec!["check.torproject.org".into(), "1.2.3.0/24".into()], ..Default::default() };
            let o = rxvpn_core::RunOpts { probe_port: Some(9152), direct: Some((9153, "pw")), tor, ..Default::default() };
            let cfg = rxvpn_core::build_run_config(&rxvpn_core::Upstream::Single(&n), &s, &o);
            rxvpn_core::runner::test_config(&dir, cfg.to_string().as_bytes()).unwrap_or_else(|e| panic!("{mode:?} {tor:?}: {e}"));
        }
    }
}

/// Вход «напрямую» (проверка белых списков): с паролем пускает, без — нет.
#[test]
#[ignore]
fn direct_probe_needs_password() {
    let Some(dir) = xray_dir() else { return };
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    let (site, _srv) = local_site_and_server(&dir, 25611, uuid);
    let n = parse_link(&format!("vless://{uuid}@127.0.0.1:25699?type=tcp#dead")).unwrap();
    let s = Settings { socks_port: 25621, http_port: 25622, ..Default::default() };
    let o = rxvpn_core::RunOpts { direct: Some((25623, "s3cret")), ..Default::default() };
    let cfg = rxvpn_core::build_run_config(&rxvpn_core::Upstream::Single(&n), &s, &o);
    let _c = XrayProcess::start(&dir, cfg.to_string().as_bytes(), |l| eprintln!("cli: {l}"), || {}).unwrap();
    std::thread::sleep(Duration::from_millis(400));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let get = |proxy: &str| {
        let c = reqwest::Client::builder().proxy(reqwest::Proxy::all(proxy).unwrap()).timeout(Duration::from_secs(5)).build().unwrap();
        rt.block_on(async { c.get(format!("http://127.0.0.1:{site}/")).send().await.map(|r| r.status().as_u16()) })
    };
    assert_eq!(get("socks5://rxvpn:s3cret@127.0.0.1:25623").ok(), Some(200), "напрямую, хотя сервер мёртв");
    assert!(get("socks5://127.0.0.1:25623").is_err(), "без пароля — нет");
    assert!(get("socks5://rxvpn:wrong@127.0.0.1:25623").is_err());
}

/// Локальный «Cloudflare»: `/__down?bytes=N` отдаёт N байт; `slow` — по 64 КБ
/// раз в 50 мс (~10 Мбит/с), чтобы проверить замер «не успел, но скачал».
fn bytes_site(slow: bool) -> u16 {
    let site = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = site.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in site.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut buf = [0u8; 2048];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                // Проверка задержки — «/», скачивание — с bytes=.
                let len: usize = req.split("bytes=").nth(1).and_then(|x| x.split([' ', '&']).next()).and_then(|x| x.parse().ok()).unwrap_or(100);
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n");
                let chunk = vec![b'x'; 64 * 1024];
                let mut left = len;
                while left > 0 {
                    let k = left.min(chunk.len());
                    if s.write_all(&chunk[..k]).is_err() {
                        return;
                    }
                    left -= k;
                    if slow {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                }
            });
        }
    });
    port
}

#[test]
#[ignore]
fn speed_all_live() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    let Some(dir) = xray_dir() else { return };
    let uuid = "c931381d-6324-4d53-ad4f-8cda48b30812";
    let (_site, _srv) = local_site_and_server(&dir, 24611, uuid);
    let good = parse_link(&format!("vless://{uuid}@127.0.0.1:24611?type=tcp#good")).unwrap();
    let dead = parse_link(&format!("vless://{uuid}@127.0.0.1:24699?type=tcp#dead")).unwrap();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let run = |site: u16, timeout: u64, cancel: bool| {
        let seen = Arc::new(AtomicUsize::new(0));
        let s2 = seen.clone();
        let r = rt
            .block_on(rxvpn_core::batch::speed_all_with(
                &dir,
                &[good.clone(), dead.clone()],
                None,
                &Default::default(),
                vec![format!("http://127.0.0.1:{site}/")],
                &format!("http://127.0.0.1:{site}/__down?bytes={{bytes}}"),
                3_000_000,
                Duration::from_secs(timeout),
                Arc::new(AtomicBool::new(cancel)),
                move |_| {
                    s2.fetch_add(1, Ordering::SeqCst);
                },
            ))
            .unwrap();
        assert_eq!(seen.load(Ordering::SeqCst), 2, "колбэк на каждый сервер");
        eprintln!("{r:#?}");
        r
    };
    // Быстрый сайт: скачалось всё, скорость есть; мёртвый — ошибка, без скорости.
    let fast = bytes_site(false);
    let r = run(fast, 10, false);
    let g = r.iter().find(|x| x.id == good.id).unwrap();
    assert!(g.ms.is_some() && g.mbps.is_some_and(|m| m > 20.0) && g.bytes >= 3_000_000, "{g:?}");
    let d = r.iter().find(|x| x.id == dead.id).unwrap();
    assert!(d.ms.is_none() && d.mbps.is_none() && d.error.is_some() && !d.skipped);
    // Медленный: за 2 с не докачал, но скорость по скачанному — около 10 Мбит/с.
    let slow = bytes_site(true);
    let r = run(slow, 2, false);
    let g = r.iter().find(|x| x.id == good.id).unwrap();
    let m = g.mbps.expect("скорость по частично скачанному");
    assert!((3.0..30.0).contains(&m) && g.bytes < 3_000_000, "{g:?}");
    // «Стоп» до начала: никто не качает.
    let r = run(fast, 10, true);
    assert!(r.iter().all(|x| x.skipped && x.bytes == 0), "{r:?}");
}
