//! sing-box рядом с Xray вживую: TUIC-сервер на sing-box (самоподписанный сертификат)
//! на этом компе, клиент — обычный запуск rxvpn (Xray + sing-box по метке в конфиге).
//!   XRAY_DIR=папка\ядра SINGBOX_ZIP=путь\к\sing-box-1.14.4-windows-amd64.zip
//!   cargo test -p rxvpn-core --test singbox -- --ignored --nocapture

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use rxvpn_core::runner::XrayProcess;
use rxvpn_core::singbox;
use serde_json::json;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
#[ignore]
fn tuic_through_sidecar_live() {
    let (Some(dir), Some(zip)) = (std::env::var_os("XRAY_DIR"), std::env::var_os("SINGBOX_ZIP")) else {
        eprintln!("нет XRAY_DIR / SINGBOX_ZIP — пропускаю");
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    // 1. Установка из архива — со сверкой обоих хешей.
    singbox::install_zip(&std::fs::read(zip).unwrap(), &dir).unwrap();
    assert!(singbox::installed(&dir));
    assert!(singbox::install_zip(b"not a zip", &dir).is_err(), "чужой архив — отказ");
    let exe = singbox::exe_path(&dir);

    // 2. TUIC-сервер на sing-box с самоподписанным сертификатом на localhost.
    let kp = String::from_utf8(Command::new(&exe).args(["generate", "tls-keypair", "localhost"]).output().unwrap().stdout).unwrap();
    let cert_at = kp.find("-----BEGIN CERTIFICATE-----").unwrap();
    let (key, cert) = (kp[..cert_at].trim().to_string(), kp[cert_at..].trim().to_string());
    let (uuid, pass, port) = ("2dd61d93-75d8-4da4-ac0e-6aece7eac365", "secret", free_port());
    let srv_cfg = json!({
        "log": {"level": "warn"},
        "inbounds": [{"type": "tuic", "listen": "127.0.0.1", "listen_port": port,
            "users": [{"uuid": uuid, "password": pass}], "congestion_control": "bbr",
            "tls": {"enabled": true, "alpn": ["h3"], "certificate": cert, "key": key}}],
        "outbounds": [{"type": "direct"}],
    });
    #[allow(clippy::zombie_processes)] // гасим ниже: kill + wait
    let mut srv = Command::new(&exe).args(["run", "-c", "stdin"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    srv.stdin.take().unwrap().write_all(srv_cfg.to_string().as_bytes()).unwrap();
    std::thread::sleep(Duration::from_millis(1500));

    // 3. Клиент rxvpn: обычный конфиг Xray для tuic://, только доверяем сертификату теста.
    let node = rxvpn_core::parse_link(&format!("tuic://{uuid}:{pass}@127.0.0.1:{port}?sni=localhost&alpn=h3#test")).unwrap();
    let socks = free_port();
    let s = rxvpn_core::Settings { socks_port: socks, http_port: free_port(), route: rxvpn_core::RouteMode::Global, domain_strategy: "AsIs".into(), ..Default::default() };
    let mut cfg = rxvpn_core::build_run_config(&rxvpn_core::Upstream::Single(&node), &s, &rxvpn_core::RunOpts::default());
    let ob = cfg["outbounds"].as_array_mut().unwrap().iter_mut().find(|o| o.get(singbox::MARK).is_some()).expect("выход TUIC помечен");
    ob[singbox::MARK]["tls"]["certificate"] = json!(cert);
    let x = XrayProcess::start(&dir, &serde_json::to_vec(&cfg).unwrap(), |l| eprintln!("  {l}"), || {}).unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let c = reqwest::Client::builder().proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{socks}")).unwrap()).timeout(Duration::from_secs(20)).build().unwrap();
    let r = rt.block_on(async { c.get("http://cp.cloudflare.com/generate_204").send().await.map(|r| r.status().as_u16()) });
    eprintln!("Xray → sing-box → TUIC: {r:?}");
    assert_eq!(r.unwrap(), 204);

    // 4. Подменённый sing-box.exe не запускается; sing-box гаснет вместе с Xray.
    drop(x);
    let _ = srv.kill();
    let _ = srv.wait();
    let mut bad = std::fs::read(&exe).unwrap();
    let n = bad.len();
    bad[n - 1] ^= 1;
    std::fs::write(&exe, &bad).unwrap();
    let e = XrayProcess::start(&dir, &serde_json::to_vec(&rxvpn_core::build_run_config(&rxvpn_core::Upstream::Single(&node), &s, &rxvpn_core::RunOpts::default())).unwrap(), |_| {}, || {});
    assert!(e.is_err_and(|e| e.contains("подменён")), "подменённый sing-box — отказ");
    std::fs::remove_file(&exe).unwrap();
}
