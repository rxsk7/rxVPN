//! DoH «Без VPN» вживую: свой HTTPS-сервер DoH (тестовый CA из fixtures) и
//! настоящие UDP/TCP-запросы к локальному DNS rxvpn. Интернет не нужен.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rxvpn_core::doh::{self, answer_ips, build_query, first_ttl, Config, Upstream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const CA: &[u8] = include_bytes!("fixtures/doh-ca.pem");

/// Ответ DNS: на `name` — `n` записей A (93.184.216.N), TTL 300.
fn dns_reply(q: &[u8], name_override: Option<&str>, n: usize) -> Vec<u8> {
    let p = doh::parse_query(q).unwrap();
    let mut r = match name_override {
        Some(other) => {
            let o = build_query(0, other, 1, None);
            o[..doh::parse_query(&o).unwrap().end].to_vec()
        }
        None => q[..p.end].to_vec(),
    };
    r[2] = 0x81;
    r[3] = 0x80;
    r[6..8].copy_from_slice(&(n as u16).to_be_bytes());
    r[10..12].fill(0);
    for i in 0..n {
        r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 93, 184, 216, (34 + i) as u8]);
    }
    r
}

/// Тестовый DoH: `cert` — какой сертификат показывать. Считает запросы.
async fn fake_doh(cert: &str, hits: Arc<AtomicUsize>) -> u16 {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let chain = vec![CertificateDer::from_pem_file(format!("tests/fixtures/{cert}-cert.pem")).unwrap()];
    let key = PrivateKeyDer::from_pem_file(format!("tests/fixtures/{cert}-key.pem")).unwrap();
    let cfg = rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(chain, key).unwrap();
    let acc = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { continue };
            let (acc, hits) = (acc.clone(), hits.clone());
            tokio::spawn(async move {
                let Ok(mut t) = acc.accept(s).await else { return };
                loop {
                    // Заголовки + тело по Content-Length (keep-alive: запросов может быть несколько).
                    let mut buf = Vec::new();
                    let mut b = [0u8; 1];
                    while !buf.ends_with(b"\r\n\r\n") {
                        if t.read_exact(&mut b).await.is_err() {
                            return;
                        }
                        buf.push(b[0]);
                    }
                    let head = String::from_utf8_lossy(&buf).to_lowercase();
                    let len: usize = head.lines().find_map(|l| l.strip_prefix("content-length:")).map(|v| v.trim().parse().unwrap()).unwrap_or(0);
                    let mut q = vec![0u8; len];
                    t.read_exact(&mut q).await.unwrap();
                    hits.fetch_add(1, Ordering::SeqCst);
                    assert!(head.starts_with("post ") && head.contains("application/dns-message"), "{head}");
                    assert_eq!(&q[0..2], &[0, 0], "наружу — с ID 0");
                    let name = String::from_utf8_lossy(&q[12..]).to_string();
                    let (ct, body) = if name.contains("html") {
                        ("text/html", b"<html>captive</html>".to_vec())
                    } else if name.contains("other") {
                        ("application/dns-message", dns_reply(&q, Some("evil.test"), 1))
                    } else if name.contains("big") {
                        ("application/dns-message", dns_reply(&q, None, 60))
                    } else {
                        ("application/dns-message", dns_reply(&q, None, 1))
                    };
                    let resp = format!("HTTP/1.1 200 OK\r\ncontent-type: {ct}\r\ncontent-length: {}\r\n\r\n", body.len());
                    if t.write_all(resp.as_bytes()).await.is_err() || t.write_all(&body).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

async fn start(port: u16, trust: bool) -> doh::Running {
    doh::start(Config {
        upstream: Upstream {
            url: format!("https://doh.test:{port}/dns-query"),
            host: "doh.test".into(),
            pins: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)],
        },
        listen: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)],
        extra_root_pem: trust.then(|| CA.to_vec()),
    })
    .await
    .unwrap()
}

async fn udp_ask(at: SocketAddr, q: &[u8]) -> Vec<u8> {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.send_to(q, at).await.unwrap();
    let mut b = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(8), s.recv(&mut b)).await.expect("UDP ответ").unwrap();
    b.truncate(n);
    b
}

async fn tcp_ask(at: SocketAddr, q: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(at).await.unwrap();
    let mut m = (q.len() as u16).to_be_bytes().to_vec();
    m.extend_from_slice(q);
    s.write_all(&m).await.unwrap();
    let mut l = [0u8; 2];
    s.read_exact(&mut l).await.unwrap();
    let mut r = vec![0u8; u16::from_be_bytes(l) as usize];
    s.read_exact(&mut r).await.unwrap();
    r
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_resolver_live() {
    let hits = Arc::new(AtomicUsize::new(0));
    let port = fake_doh("doh", hits.clone()).await;
    let r = start(port, true).await;
    let at = r.addrs[0];

    // UDP: ответ с нашим ID, адрес и TTL от DoH; второй раз — из кэша.
    let a = udp_ask(at, &build_query(0x4242, "site.test", 1, None)).await;
    assert_eq!((&a[0..2], a[3] & 0xf), (&[0x42u8, 0x42][..], 0));
    assert_eq!(answer_ips(&a), vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    assert_eq!(first_ttl(&a), Some(300));
    let b = udp_ask(at, &build_query(0x0101, "SITE.test", 1, None)).await;
    assert_eq!((&b[0..2], answer_ips(&b).len()), (&[1u8, 1][..], 1));
    assert_eq!(hits.load(Ordering::SeqCst), 1, "второй раз — из кэша (имя без учёта регистра)");
    assert_eq!(r.stats.cached.load(Ordering::SeqCst), 1);

    // TCP — так же.
    let t = tcp_ask(at, &build_query(9, "site.test", 1, None)).await;
    assert_eq!(answer_ips(&t).len(), 1);

    // Большой ответ: по UDP без EDNS — усечён (TC), по TCP — целиком.
    let u = udp_ask(at, &build_query(5, "big.test", 1, None)).await;
    assert!(u[2] & 0x02 != 0 && answer_ips(&u).is_empty() && u.len() <= 512, "TC");
    assert_eq!(answer_ips(&tcp_ask(at, &build_query(6, "big.test", 1, None)).await).len(), 60);
    // С EDNS 4096 — влезает и по UDP.
    assert_eq!(answer_ips(&udp_ask(at, &build_query(7, "big.test", 1, Some(4096))).await).len(), 60);

    // Страница вместо DNS и ответ на чужой вопрос — SERVFAIL, не подмена.
    let h = udp_ask(at, &build_query(8, "html.test", 1, None)).await;
    assert_eq!((h[3] & 0xf, answer_ips(&h).len()), (2, 0));
    let o = udp_ask(at, &build_query(10, "other.test", 1, None)).await;
    assert_eq!((o[3] & 0xf, answer_ips(&o).len()), (2, 0));
    assert!(r.stats.failed.load(Ordering::SeqCst) >= 2);

    // Мусор — FORMERR, сервер жив.
    let g = udp_ask(at, b"\x12\x34\x01\x00\x00\x05garbage-garbage").await;
    assert_eq!(g[3] & 0xf, 1);
    assert_eq!(answer_ips(&udp_ask(at, &build_query(11, "site.test", 1, None)).await).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn doh_checks_certificate() {
    // Сертификат не для doh.test — SERVFAIL (никаких «ну ладно»).
    let wrong = fake_doh("wrong", Arc::new(AtomicUsize::new(0))).await;
    let r = start(wrong, true).await;
    let a = udp_ask(r.addrs[0], &build_query(1, "site.test", 1, None)).await;
    assert_eq!((a[3] & 0xf, answer_ips(&a).len()), (2, 0));
    // Правильное имя, но CA не доверенный (обычные корни) — тоже SERVFAIL.
    let good = fake_doh("doh", Arc::new(AtomicUsize::new(0))).await;
    let r2 = start(good, false).await;
    let b = udp_ask(r2.addrs[0], &build_query(2, "site.test", 1, None)).await;
    assert_eq!(b[3] & 0xf, 2);
    assert!(!r2.stats.last_error.lock().unwrap().is_empty());
}

#[tokio::test]
async fn doh_listens_only_on_loopback() {
    let e = doh::start(Config {
        upstream: Upstream { url: "https://doh.test/".into(), host: "doh.test".into(), pins: vec![] },
        listen: vec!["0.0.0.0:0".parse().unwrap()],
        extra_root_pem: None,
    })
    .await;
    assert!(e.is_err());
    // Занятый порт — понятная ошибка, а не паника.
    let busy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let e = doh::start(Config {
        upstream: Upstream { url: "https://doh.test/".into(), host: "doh.test".into(), pins: vec![] },
        listen: vec![busy.local_addr().unwrap()],
        extra_root_pem: None,
    })
    .await;
    assert!(e.err().unwrap().contains("занят"));
}

/// Системный резолвер (как в «Почему не открывается сайт»: getaddrinfo) — до и
/// после «DNS без подмены». Меняет /etc/resolv.conf, поэтому только по запросу:
/// RXVPN_RESOLV_TEST=1, Linux, root, свободный 127.0.0.1:53.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn system_resolver_sees_doh_not_spoof() {
    if std::env::var_os("RXVPN_RESOLV_TEST").is_none() || !cfg!(target_os = "linux") {
        return;
    }
    // «DNS провайдера» на 127.0.0.2:53: на всё — заглушка 10.10.10.10.
    let isp = UdpSocket::bind("127.0.0.2:53").await.unwrap();
    tokio::spawn(async move {
        let mut b = vec![0u8; 1500];
        loop {
            let Ok((n, from)) = isp.recv_from(&mut b).await else { continue };
            let q = &b[..n];
            let Some(p) = doh::parse_query(q) else { continue };
            let mut r = q[..p.end].to_vec();
            r[2] = 0x81;
            r[3] = 0x80;
            r[6..8].copy_from_slice(&[0, (p.key[p.key.len() - 3] == 1) as u8]); // A — с заглушкой, AAAA — пусто
            r[10..12].fill(0);
            if r[7] == 1 {
                r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 10, 10, 10]);
            }
            let _ = isp.send_to(&r, from).await;
        }
    });
    let saved = std::fs::read("/etc/resolv.conf").unwrap();
    let restore = scopeguard(saved.clone());
    let lookup = || async { tokio::net::lookup_host(("site.test", 443)).await.map(|a| a.map(|x| x.ip()).collect::<Vec<_>>()).unwrap_or_default() };

    std::fs::write("/etc/resolv.conf", "nameserver 127.0.0.2\noptions timeout:1 attempts:1\n").unwrap();
    let spoofed = lookup().await;
    assert_eq!(spoofed, vec![IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10))], "без DoH провайдер подсовывает заглушку");

    // Включили «DNS без подмены»: системный DNS — наш DoH на 127.0.0.1:53.
    let port = fake_doh("doh", Arc::new(AtomicUsize::new(0))).await;
    let _r = doh::start(Config {
        upstream: Upstream { url: format!("https://doh.test:{port}/dns-query"), host: "doh.test".into(), pins: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)] },
        listen: vec!["127.0.0.1:53".parse().unwrap()],
        extra_root_pem: Some(CA.to_vec()),
    })
    .await
    .unwrap();
    // Как на Windows: наш первым, прежний («провайдер») — запасным.
    std::fs::write("/etc/resolv.conf", "nameserver 127.0.0.1\nnameserver 127.0.0.2\noptions timeout:1 attempts:1\n").unwrap();
    let real = lookup().await;
    assert_eq!(real, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))], "система получает адрес из DoH, не заглушку");
    // Вывод проверки на этих фактах: адрес «от системы» = адресу DoH и публичный → не подмена.
    let f = rxvpn_core::diag::Facts {
        control_ok: true,
        sys_ips: real.clone(),
        doh: Some(rxvpn_core::diag::Doh::Ips(real)),
        ..Default::default()
    };
    let spoof_before = rxvpn_core::diag::Facts { control_ok: true, sys_ips: spoofed, doh: f.doh.clone(), ..Default::default() };
    assert_eq!(rxvpn_core::diag::decide(&spoof_before).0, rxvpn_core::diag::Verdict::DnsSpoof);
    assert_ne!(rxvpn_core::diag::decide(&f).0, rxvpn_core::diag::Verdict::DnsSpoof);
    drop(restore);
}

/// Вернуть /etc/resolv.conf, даже если тест упал.
struct Restore(Vec<u8>);
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = std::fs::write("/etc/resolv.conf", &self.0);
    }
}
fn scopeguard(v: Vec<u8>) -> Restore {
    Restore(v)
}
