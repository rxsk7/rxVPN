//! Живой тест «Свой сервер» на настоящем sshd + systemd (контейнер Ubuntu).
//! RXVPN_VPS=172.17.0.2 RXVPN_VPS_PASS=… XRAY_ZIP=…/Xray-linux-64.zip XRAY_DIR=…linux xray
//! cargo test -p rxvpn-core --test vps -- --ignored --nocapture

use std::sync::Arc;
use std::time::Duration;

use rxvpn_core::vps::{self, Login, Target};
use zeroize::Zeroizing;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

#[test]
#[ignore]
fn vps_install_live() {
    let (Some(host), Some(pass), Some(zip), Some(xdir)) = (env("RXVPN_VPS"), env("RXVPN_VPS_PASS"), env("XRAY_ZIP"), env("XRAY_DIR")) else {
        eprintln!("нет RXVPN_VPS / RXVPN_VPS_PASS / XRAY_ZIP / XRAY_DIR — пропускаю");
        return;
    };
    let rt = tokio::runtime::Runtime::new().unwrap();
    let zip_bytes = Arc::new(std::fs::read(&zip).unwrap());
    let fetch = move |asset: &'static str| -> futures_util::future::BoxFuture<'static, Result<Vec<u8>, String>> {
        let z = zip_bytes.clone();
        Box::pin(async move {
            assert_eq!(asset, "Xray-linux-64.zip");
            Ok((*z).clone())
        })
    };
    let log = |s: String| eprintln!("  [vps] {s}");

    // 1. TOFU: отпечаток без входа; чужой отпечаток — отказ.
    let fp = rt.block_on(vps::host_fingerprint(&host, 22)).unwrap();
    eprintln!("отпечаток: {fp}");
    assert!(fp.starts_with("SHA256:"));
    let bad = Target { host: host.clone(), port: 22, user: "root".into(), host_key: Some("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into()) };
    let e = rt.block_on(vps::install(&bad, Login::Password(Zeroizing::new(pass.clone())), vps::InstallOpts { name: "x".into(), port: 8443 }, &fetch, &log)).unwrap_err();
    assert!(e.contains("не совпал"), "{e}");

    // 2. Установка по паролю.
    let t = Target { host: host.clone(), port: 22, user: "root".into(), host_key: Some(fp.clone()) };
    let (mut v, sec) = rt
        .block_on(vps::install(&t, Login::Password(Zeroizing::new(pass.clone())), vps::InstallOpts { name: "Тест VPS".into(), port: 8443 }, &fetch, &log))
        .unwrap();
    eprintln!("сервер: {v:?}");
    assert!(v.password_off, "пароль выключен");
    assert_eq!(rt.block_on(vps::ssh::password_refused(&t)), Ok(true), "запущенный sshd пароль не предлагает");
    assert_eq!(v.xray_version, "26.10.21");
    v.node_id = "n".into();
    assert!(v.sane(), "поля сервера проходят свою же проверку");

    // 3. Пароль больше не пускает, свой ключ — пускает.
    let e = rt.block_on(vps::restart(&vps::Vps { ..v.clone() }, &sec));
    assert!(e.is_ok(), "{e:?}");
    let pw = rt.block_on(vps::install(&t, Login::Password(Zeroizing::new(pass.clone())), vps::InstallOpts { name: "x".into(), port: 8443 }, &fetch, &log));
    assert!(pw.unwrap_err().contains("не пустил"), "пароль не пускает");

    // 4. VLESS + Reality реально возит трафик; локалка сервера закрыта.
    let xdir = std::path::PathBuf::from(xdir);
    let node = rxvpn_core::parse_link(&v.owner_link("Тест")).unwrap();
    let s = rxvpn_core::Settings { socks_port: 25522, http_port: 25523, route: rxvpn_core::RouteMode::Global, domain_strategy: "AsIs".into(), ..Default::default() };
    let cfg = rxvpn_core::build_run_config(&rxvpn_core::Upstream::Single(&node), &s, &rxvpn_core::RunOpts::default()).to_string();
    let _cli = rxvpn_core::runner::XrayProcess::start(&xdir, cfg.as_bytes(), |_| {}, || {}).unwrap();
    std::thread::sleep(Duration::from_millis(800));
    let c = reqwest::Client::builder().proxy(reqwest::Proxy::all("socks5h://127.0.0.1:25522").unwrap()).timeout(Duration::from_secs(20)).build().unwrap();
    let got = rt.block_on(async { c.get("http://archive.ubuntu.com/ubuntu/dists/noble/Release").send().await.map(|r| r.status().as_u16()) });
    eprintln!("через свой сервер: {got:?}");
    assert_eq!(got.unwrap(), 200, "трафик идёт через сервер");
    assert!(v.server_ips.contains(&host), "свой адрес сервера найден: {:?}", v.server_ips);
    let own = format!("http://{host}:22/");
    for local in ["http://127.0.0.1:10085/", "http://127.0.0.1:22/", "http://localhost:22/", own.as_str()] {
        let r = rt.block_on(async { c.get(local).send().await.map(|r| r.status().as_u16()) });
        assert!(r.is_err(), "{local} с сервера должно быть закрыто: {r:?}");
    }

    // 5. Статистика (накопительно — скрипт лимитов), друг: свой UUID, лимиты, выключение.
    let st = rt.block_on(vps::traffic(&v, &sec)).unwrap();
    eprintln!("трафик: {st:?}");
    assert!(st.get(vps::plan::OWNER_EMAIL).is_some_and(|u| u.up > 0 && u.down > 0), "трафик хозяина посчитан");
    v.friends.push(vps::Friend { id: vps::plan::friend_id(), name: "Петя".into(), uuid: vps::plan::uuid_v4(), enabled: true, limit_gb: 0, expires: 0 });
    rt.block_on(vps::apply(&v, &sec)).unwrap();
    assert!(v.sane());
    // Срок вышел — сервер (скрипт лимитов, его запускает apply) помечает друга отключённым.
    v.friends[0].expires = 1;
    rt.block_on(vps::apply(&v, &sec)).unwrap();
    let st = rt.block_on(vps::traffic(&v, &sec)).unwrap();
    assert!(st.get(&v.friends[0].email()).is_some_and(|u| u.blocked), "просроченный друг отключён сервером: {st:?}");
    rt.block_on(vps::reset_usage(&v, &sec, &v.friends[0])).unwrap();
    v.friends[0].expires = 0;
    v.friends[0].enabled = false;
    rt.block_on(vps::apply(&v, &sec)).unwrap();

    // 6. Обновить Xray, удалить с сервера.
    assert_eq!(rt.block_on(vps::update_xray(&v, &sec, &fetch)).unwrap(), "26.10.21");
    rt.block_on(vps::uninstall(&v, &sec)).unwrap();
    let e = rt.block_on(vps::restart(&v, &sec)).unwrap_err();
    assert!(e.contains("перезапуск"), "Xray убран: {e}");
    assert_eq!(rt.block_on(vps::ssh::password_refused(&t)), Ok(false), "после удаления вход по паролю снова есть");
}
