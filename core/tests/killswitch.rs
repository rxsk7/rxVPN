//! Живая проверка kill switch (Windows, права администратора, интернет):
//!   cargo test -p rxvpn-core --test killswitch -- --ignored --nocapture --test-threads=1
//!
//! Цель — Cloudflare на порту 8080 (обычный HTTP): его не перехватывает zapret/WinDivert.
//! Пакеты, которые WinDivert перехватил и отправил заново, Windows проверяет повторно уже
//! без имени программы — kill switch их режет. Поэтому rxvpn не включает kill switch вместе
//! с гибридом «Через zapret, мимо VPN» (см. src-tauri: kill_arm).
//!
//! Если на компе уже работает VPN в режиме TUN, задай RXVPN_TEST_LOCAL_IP (адрес настоящей
//! сетевой карты) и RXVPN_TEST_IFACE (её имя): тест пойдёт мимо чужого туннеля.
//! Сессия WFP динамическая: упади тест посередине — фильтры уберёт Windows.

#![cfg(windows)]

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use rxvpn_core::killswitch::{interface_luid, KillSwitch};

const TARGET: ([u8; 4], u16) = ([104, 16, 132, 229], 8080);

fn local_ip() -> Option<IpAddr> {
    std::env::var("RXVPN_TEST_LOCAL_IP").ok().and_then(|s| s.parse().ok())
}

/// curl.exe (сам он в разрешённые не входит).
fn curl_ok() -> bool {
    let sys = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let url = format!("http://{}.{}.{}.{}:{}/", TARGET.0[0], TARGET.0[1], TARGET.0[2], TARGET.0[3], TARGET.1);
    let mut args = vec!["-s".to_string(), "-o".into(), "NUL".into(), "--max-time".into(), "6".into()];
    if let Some(ip) = local_ip() {
        args.push("--interface".into());
        args.push(ip.to_string());
    }
    args.push(url);
    Command::new(sys.join("System32").join("curl.exe")).args(&args).status().map(|s| s.success()).unwrap_or(false)
}

/// Соединение от самого теста (он в разрешённых).
fn self_ok() -> bool {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let s = tokio::net::TcpSocket::new_v4().unwrap();
        if let Some(ip) = local_ip() {
            s.bind(SocketAddr::new(ip, 0)).unwrap();
        }
        let to = SocketAddr::from(TARGET);
        tokio::time::timeout(Duration::from_secs(6), s.connect(to)).await.map(|r| r.is_ok()).unwrap_or(false)
    })
}

#[test]
#[ignore]
fn blocks_everyone_but_allowed_apps() {
    assert!(curl_ok(), "до kill switch интернет должен быть");
    let me = std::env::current_exe().unwrap();
    let ks = KillSwitch::enable(&[me.as_path()]).expect("kill switch включился (нужны права администратора)");
    assert!(!curl_ok(), "неразрешённая программа заблокирована");
    assert!(self_ok(), "разрешённая программа выходит в сеть");
    drop(ks);
    assert!(curl_ok(), "после выключения сеть вернулась");
}

/// Разрешение по адаптеру (так в TUN пропускается туннель): разрешаем настоящую сетевую
/// карту — curl снова выходит, хотя сам он не в списке.
#[test]
#[ignore]
fn interface_permit_lets_traffic_through() {
    let alias = match std::env::var("RXVPN_TEST_IFACE") {
        Ok(a) => a,
        Err(_) => {
            let idx = rxvpn_core::winsys::best_interface().expect("есть маршрут в интернет");
            rxvpn_core::winsys::iface_alias(idx).expect("имя адаптера")
        }
    };
    let luid = interface_luid(&alias).expect("LUID адаптера");
    let me = std::env::current_exe().unwrap();
    let mut ks = KillSwitch::enable(&[me.as_path()]).expect("kill switch");
    assert!(!curl_ok(), "сначала curl закрыт");
    ks.allow_interface(luid).expect("разрешение адаптера");
    assert!(curl_ok(), "через разрешённый адаптер curl выходит ({alias})");
    ks.allow_interface(luid).expect("повторно — прошлое снимается");
    assert!(curl_ok());
    drop(ks);
    assert!(interface_luid("rxvpn-нет-такого").is_none());
}
