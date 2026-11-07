//! Tor на Arti внутри rxvpn: локальный SOCKS5 на 127.0.0.1 (случайный порт) —
//! в него смотрит исходящий Xray с тегом "tor".
//!
//! Схема «VPN → Tor»: сама Arti подключается к сети Tor через служебный вход
//! Xray (`tor-up`), а он всегда идёт через VPN-сервер. Провайдер видит только
//! VPN (Tor из РФ напрямую закрыт), сервер VPN — только то, что ты в Tor, сайт —
//! выходной узел Tor. Через Tor идёт только TCP; UDP по правилам — в блок.
//!
//! Изоляция по сайтам: у каждого сайта (последние два уровня домена или IP) свой
//! `IsolationToken` — разные сайты не делят цепочку Tor и не видят общий выход.

use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// Куда просят подключиться через Tor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dest {
    pub host: String,
    pub port: u16,
}

/// Ключ изоляции: «сайт» — последние два уровня домена (`mail.google.com` →
/// `google.com`), .onion — сам адрес, IP — сам IP.
pub fn isolation_key(host: &str) -> String {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h.parse::<std::net::IpAddr>().is_ok() {
        return h;
    }
    let parts: Vec<&str> = h.rsplit('.').take(2).collect();
    parts.into_iter().rev().collect::<Vec<_>>().join(".")
}

/// Разобрать запрос SOCKS5 (без пароля, только CONNECT) и ответить клиенту.
/// Возвращает цель; клиенту уже отправлен ответ «ок» — после подключения
/// (`reply_ok`) или ошибка.
async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> std::io::Result<Dest> {
    let bad = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m.to_string());
    let mut h = [0u8; 2];
    s.read_exact(&mut h).await?;
    if h[0] != 5 || h[1] == 0 {
        return Err(bad(trs!("не SOCKS5")));
    }
    let mut methods = vec![0u8; h[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 0xff]).await?;
        return Err(bad(trs!("нужен вход без пароля")));
    }
    s.write_all(&[5, 0]).await?;
    let mut r = [0u8; 4];
    s.read_exact(&mut r).await?;
    if r[0] != 5 {
        return Err(bad(trs!("не SOCKS5")));
    }
    let host = match r[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            Ipv6Addr::from(a).to_string()
        }
        3 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n).await?;
            let mut d = vec![0u8; n[0] as usize];
            s.read_exact(&mut d).await?;
            String::from_utf8(d).map_err(|_| bad(trs!("кривое имя")))?
        }
        _ => {
            reply(s, 8).await?;
            return Err(bad(trs!("непонятный адрес")));
        }
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    if r[1] != 1 {
        // Только CONNECT: UDP через Tor не ходит.
        reply(s, 7).await?;
        return Err(bad(trs!("только TCP")));
    }
    let ok = !host.is_empty() && host.len() <= 255 && host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_:".contains(&b));
    if !ok {
        reply(s, 4).await?;
        return Err(bad(trs!("кривое имя")));
    }
    Ok(Dest { host, port: u16::from_be_bytes(p) })
}

async fn reply<S: AsyncWrite + Unpin>(s: &mut S, code: u8) -> std::io::Result<()> {
    s.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

/// SOCKS5-сервер: каждое подключение — `connect(цель)`, потом байты туда-сюда.
pub async fn serve<C, F, T>(listener: TcpListener, connect: C)
where
    C: Fn(Dest) -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<T, String>> + Send + 'static,
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Не больше 512 соединений разом: чужая программа на компе не съест память.
    let limit = Arc::new(tokio::sync::Semaphore::new(512));
    loop {
        let (mut c, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => {
                // Кончились дескрипторы и т.п. — не крутимся впустую.
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        if !peer.ip().is_loopback() {
            continue;
        }
        let Ok(permit) = limit.clone().try_acquire_owned() else { continue };
        let connect = connect.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(dest)) = tokio::time::timeout(Duration::from_secs(10), handshake(&mut c)).await else { return };
            match connect(dest).await {
                Ok(mut up) => {
                    if reply(&mut c, 0).await.is_ok() {
                        let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
                    }
                }
                Err(_) => {
                    let _ = reply(&mut c, 5).await;
                }
            }
        });
    }
}

#[cfg(feature = "tor")]
pub use real::*;

#[cfg(feature = "tor")]
mod real {
    use super::*;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::sync::Mutex;
    use arti_client::{BootstrapBehavior, IsolationToken, StreamPrefs, TorClient, TorClientConfig};
    use tor_rtcompat::PreferredRuntime;

    /// Работающая Arti.
    pub struct Running {
        /// Порт SOCKS5 на 127.0.0.1 (для исходящего Xray "tor").
        pub port: u16,
        /// Куда Arti ходит в сеть Tor: вход `tor-up` Xray.
        pub upstream: u16,
        pub isolate: bool,
        client: Arc<TorClient<PreferredRuntime>>,
        task: tokio::task::JoinHandle<()>,
        boot: tokio::task::JoinHandle<()>,
    }

    impl Drop for Running {
        fn drop(&mut self) {
            self.task.abort();
            self.boot.abort();
        }
    }

    impl Running {
        /// «Tor: 45% — загружаю список узлов» / «Tor готов».
        pub fn status(&self) -> (bool, String) {
            let s = self.client.bootstrap_status();
            if s.ready_for_traffic() {
                return (true, trs!("Tor подключён").into());
            }
            let pct = (s.as_frac() * 100.0).round() as u32;
            match s.blocked() {
                Some(b) => (false, tr!("Tor: {pct}% — не выходит: {b}")),
                None => (false, tr!("Tor: {pct}% — подключаюсь к сети Tor")),
            }
        }
    }

    /// Запустить Arti. `dir` — data\tor, `upstream` — порт входа `tor-up` Xray
    /// (Arti ходит в сеть Tor только через него — то есть через VPN).
    pub fn start(handle: &tokio::runtime::Handle, dir: &Path, upstream: u16, isolate: bool, log: Arc<dyn Fn(String) + Send + Sync>) -> Result<Running, String> {
        let _g = handle.enter();
        let rt = PreferredRuntime::current().map_err(|e| format!("Tor: {e}"))?;
        let mut b = arti_client::config::TorClientConfigBuilder::from_directories(dir.join("state"), dir.join("cache"));
        // Свои права на папку data rxvpn уже проверил (портативная — на флешке
        // права бывают любыми); чужим этот кэш ничего не даёт.
        b.storage().permissions().dangerously_trust_everyone();
        let proxy: tor_chanmgr::ProxyProtocol = format!("socks5://127.0.0.1:{upstream}").parse().map_err(|e| format!("Tor: {e}"))?;
        b.channel().outbound_proxy(Some(proxy));
        b.address_filter().allow_onion_addrs(true);
        let cfg: TorClientConfig = b.build().map_err(|e| tr!("Tor: настройки: {e}"))?;
        let client = TorClient::with_runtime(rt)
            .config(cfg)
            .bootstrap_behavior(BootstrapBehavior::OnDemand)
            .create_unbootstrapped()
            .map_err(|e| tr!("Tor не запустился: {e}"))?;

        let std_l = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).map_err(|e| tr!("Tor: порт: {e}"))?;
        std_l.set_nonblocking(true).map_err(|e| e.to_string())?;
        let port = std_l.local_addr().map_err(|e| e.to_string())?.port();
        let listener = TcpListener::from_std(std_l).map_err(|e| e.to_string())?;

        let tokens: Arc<Mutex<HashMap<String, IsolationToken>>> = Arc::default();
        let c = client.clone();
        let connect = move |d: Dest| {
            let c = c.clone();
            let tokens = tokens.clone();
            async move {
                let mut prefs = StreamPrefs::new();
                if isolate {
                    let key = isolation_key(&d.host);
                    let mut t = tokens.lock().unwrap();
                    if t.len() > 4096 {
                        t.clear();
                    }
                    prefs.set_isolation(*t.entry(key).or_insert_with(IsolationToken::new));
                }
                c.connect_with_prefs((d.host.as_str(), d.port), &prefs).await.map_err(|e| e.to_string())
            }
        };
        let task = handle.spawn(serve(listener, connect));
        // Подключаемся к сети заранее, не дожидаясь первого сайта.
        let c = client.clone();
        let boot = handle.spawn(async move {
            match c.bootstrap().await {
                Ok(()) => log(trs!("Tor: подключён к сети Tor (через VPN)").into()),
                Err(e) => log(tr!("Tor: не подключился к сети: {e}")),
            }
        });
        Ok(Running { port, upstream, isolate, client, task, boot })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::net::TcpStream;

    #[test]
    fn isolation_keys() {
        assert_eq!(isolation_key("mail.google.com"), "google.com");
        assert_eq!(isolation_key("google.com."), "google.com");
        assert_eq!(isolation_key("abc.def.xyz.onion"), "xyz.onion");
        assert_eq!(isolation_key("1.2.3.4"), "1.2.3.4");
        assert_eq!(isolation_key("::1"), "::1");
        assert_eq!(isolation_key("localhost"), "localhost");
    }

    /// Arti создаётся (настройки, папки, рантайм) и слушает SOCKS; сети нет —
    /// статус «подключаюсь», а не паника.
    #[cfg(feature = "tor")]
    #[test]
    fn arti_starts_offline() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let dir = std::env::temp_dir().join(format!("rxvpn-tor-{}", std::process::id()));
        let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let r = start(rt.handle(), &dir, dead, true, Arc::new(|m| eprintln!("{m}"))).unwrap();
        assert!(std::net::TcpStream::connect(("127.0.0.1", r.port)).is_ok());
        let (ready, text) = r.status();
        assert!(!ready && text.starts_with("Tor:"), "{text}");
        drop(r);
        drop(rt);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SOCKS5: домен и IP доходят до «Tor», UDP и мусор — отказ, ответ — после подключения.
    #[tokio::test]
    async fn socks_server() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let seen: Arc<Mutex<Vec<Dest>>> = Arc::default();
        let s2 = seen.clone();
        tokio::spawn(serve(l, move |d: Dest| {
            let s2 = s2.clone();
            async move {
                s2.lock().unwrap().push(d.clone());
                if d.host == "fail.onion" {
                    return Err("нет".to_string());
                }
                let (a, mut b) = tokio::io::duplex(1024);
                tokio::spawn(async move {
                    let mut buf = [0u8; 4];
                    let _ = b.read_exact(&mut buf).await;
                    let _ = b.write_all(b"pong").await;
                });
                Ok(a)
            }
        }));
        let go = |req: Vec<u8>| async move {
            let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            c.write_all(&[5, 1, 0]).await.unwrap();
            let mut m = [0u8; 2];
            c.read_exact(&mut m).await.unwrap();
            assert_eq!(m, [5, 0]);
            c.write_all(&req).await.unwrap();
            let mut r = [0u8; 10];
            let n = c.read_exact(&mut r).await.map(|_| r[1]).unwrap_or(255);
            (n, c)
        };
        let mut dom = vec![5, 1, 0, 3, 10];
        dom.extend(b"abcd.onion");
        dom.extend(80u16.to_be_bytes());
        let (code, mut c) = go(dom).await;
        assert_eq!(code, 0);
        c.write_all(b"ping").await.unwrap();
        let mut p = [0u8; 4];
        c.read_exact(&mut p).await.unwrap();
        assert_eq!(&p, b"pong");
        let (code, _) = go(vec![5, 1, 0, 1, 93, 184, 216, 34, 1, 187]).await;
        assert_eq!(code, 0);
        let mut f = vec![5, 1, 0, 3, 10];
        f.extend(b"fail.onion");
        f.extend(443u16.to_be_bytes());
        assert_eq!(go(f).await.0, 5, "не подключилось — ошибка, а не «ок»");
        assert_eq!(go(vec![5, 3, 0, 1, 1, 2, 3, 4, 0, 53]).await.0, 7, "UDP ASSOCIATE — нет");
        let mut evil = vec![5, 1, 0, 3, 5];
        evil.extend(b"a b\0c");
        evil.extend(80u16.to_be_bytes());
        assert_eq!(go(evil).await.0, 4);
        let s = seen.lock().unwrap();
        assert_eq!(s[0], Dest { host: "abcd.onion".into(), port: 80 });
        assert_eq!(s[1], Dest { host: "93.184.216.34".into(), port: 443 });
        assert_eq!(s.len(), 3, "UDP и кривое имя до «Tor» не дошли");
    }
}
