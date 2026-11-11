//! Сеть: пинги, загрузка подписок, скачивание ядра Xray.

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::{Duration, Instant};

/// TCP-пинг: сколько мс занимает открыть соединение до host:port.
/// Внимание: успех НЕ значит, что VPN работает — ТСПУ может пускать TCP и рвать
/// трафик после рукопожатия. Для честной проверки есть `real_delay`.
pub fn tcping(host: &str, port: u16, timeout: Duration) -> Option<u64> {
    let addr = (host, port).to_socket_addrs().ok()?.next()?;
    let t = Instant::now();
    TcpStream::connect_timeout(&addr, timeout).ok()?;
    Some(t.elapsed().as_millis() as u64)
}

/// Адреса для проверки: отвечают пустым 204, лёгкие и почти никогда не лежат.
/// Второй — запасной, если первый недоступен с конкретного сервера.
pub const CHECK_URLS: &[&str] = &[
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
];

/// Реальная задержка: HTTPS-запрос через HTTP-вход ядра — тем же путём, что
/// и браузер с системным прокси. Если это прошло, сайты тоже откроются.
pub async fn real_delay(http_port: u16) -> Result<u64, String> {
    real_delay_via(&format!("http://127.0.0.1:{http_port}"), CHECK_URLS).await
}

/// То же, но с любым прокси (http:// или socks5h://) и своими адресами — для тестов.
pub async fn real_delay_via(proxy_url: &str, urls: &[&str]) -> Result<u64, String> {
    real_delay_with_timeout(proxy_url, urls, Duration::from_secs(10)).await
}

/// Реальная задержка через прокси с заданным таймаутом на каждый адрес.
pub async fn real_delay_with_timeout(
    proxy_url: &str,
    urls: &[&str],
    timeout: Duration,
) -> Result<u64, String> {
    probe(proxy_url, urls, timeout, false).await
}

/// Жив ли туннель: годится ЛЮБОЙ HTTP-ответ — раз сайт ответил хоть что-то,
/// трафик через сервер ходит. (Для кнопки «пинг» строже — нужен 2xx,
/// чтобы показать, если сервер что-то подменяет.)
pub async fn tunnel_alive(proxy_url: &str, urls: &[&str], timeout: Duration) -> Result<u64, String> {
    probe(proxy_url, urls, timeout, true).await
}

async fn probe(proxy_url: &str, urls: &[&str], timeout: Duration, any_status: bool) -> Result<u64, String> {
    let proxy = reqwest::Proxy::all(proxy_url).map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(timeout)
        .build()
        .map_err(|e| e.to_string())?;

    let mut last = String::from(trs!("нет адресов для проверки"));
    for url in urls {
        let t = Instant::now();
        match client.get(*url).send().await {
            Ok(r) if any_status || r.status().is_success() => return Ok(t.elapsed().as_millis() as u64),
            Ok(r) => last = tr!("сервер пропустил, но {url} ответил {}", r.status()),
            Err(e) => last = explain(&e),
        }
    }
    Err(last)
}

/// «Авто»: самый быстрый живой сервер по замерам Xray.
///
/// `bad` — с каких серверов мы ушли из-за сбоя (тег → unix-время ухода).
/// Такой сервер снова годится, только если Xray проверил его уже ПОСЛЕ
/// ухода и он ответил: иначе «жив» — это старый замер, и мы бы скакали
/// между двумя мёртвыми серверами.
pub fn pick_alive<'a>(
    obs: &HashMap<String, Observation>,
    tags: impl IntoIterator<Item = &'a str>,
    bad: &HashMap<String, i64>,
    exclude: Option<&str>,
) -> Option<String> {
    pick_alive_by(obs, tags, bad, exclude, |_, delay| (0, delay))
}

/// То же, но «лучший» — по ключу `key(тег, задержка)` (меньше — лучше):
/// «Авто» добавляет к задержке надёжность и скорость (`stats::auto_key`).
pub fn pick_alive_by<'a, K: Ord>(
    obs: &HashMap<String, Observation>,
    tags: impl IntoIterator<Item = &'a str>,
    bad: &HashMap<String, i64>,
    exclude: Option<&str>,
    key: impl Fn(&str, u64) -> K,
) -> Option<String> {
    tags.into_iter()
        .filter(|t| Some(*t) != exclude)
        .filter_map(|t| obs.get(t).map(|o| (t, o)))
        .filter(|(_, o)| o.alive)
        .filter(|(t, o)| bad.get(*t).is_none_or(|since| o.last_try > *since))
        .min_by_key(|(t, o)| key(t, o.delay))
        .map(|(t, _)| t.to_string())
}

/// Перевести ошибку reqwest в понятную причину + подробности для лога.
pub fn explain(e: &reqwest::Error) -> String {
    use std::error::Error;
    let mut chain = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        chain.push_str(" → ");
        chain.push_str(&c.to_string());
        cur = c.source();
    }
    let low = chain.to_lowercase();

    let reason = if low.contains("refused") || low.contains("10061") {
        trs!("ядро не принимает подключения на локальном порту — переподключись")
    } else if e.is_timeout() || low.contains("timed out") || low.contains("10060") {
        trs!("сервер не ответил вовремя — он лежит или его блокируют")
    } else if low.contains("reset")
        || low.contains("10054")
        || low.contains("forcibly closed")
        || low.contains("eof")
        || low.contains("closed")
        || low.contains("tunnel")
    {
        trs!("соединение оборвалось — сервер не принял подключение или его режет провайдер. \
         Открой лог: ошибка Xray будет там")
    } else {
        trs!("не удалось пройти через сервер")
    };
    tr!("{reason}\n(подробно: {chain})")
}

/// Что Xray отдаёт на /debug/vars: счётчики трафика и результаты проверок.
#[derive(Debug, Default, Clone)]
pub struct Vars {
    /// тег исходящего -> (отдано байт, получено байт)
    pub traffic: std::collections::HashMap<String, (u64, u64)>,
    /// тег исходящего -> результат последней проверки observatory
    pub observatory: std::collections::HashMap<String, Observation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub alive: bool,
    /// мс; у мёртвых Xray пишет 99999999
    pub delay: u64,
    /// unix-время последней попытки (0 — ещё не пробовал)
    pub last_try: i64,
}

pub async fn fetch_vars(client: &reqwest::Client, metrics_port: u16) -> Option<Vars> {
    let text = client
        .get(format!("http://127.0.0.1:{metrics_port}/debug/vars"))
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    Some(parse_vars(&serde_json::from_str(&text).ok()?))
}

pub fn parse_vars(v: &serde_json::Value) -> Vars {
    let mut out = Vars::default();
    if let Some(m) = v["stats"]["outbound"].as_object() {
        for (tag, c) in m {
            out.traffic.insert(
                tag.clone(),
                (c["uplink"].as_u64().unwrap_or(0), c["downlink"].as_u64().unwrap_or(0)),
            );
        }
    }
    if let Some(m) = v["observatory"].as_object() {
        for (tag, o) in m {
            out.observatory.insert(
                tag.clone(),
                Observation {
                    alive: o["alive"].as_bool().unwrap_or(false),
                    delay: o["delay"].as_u64().unwrap_or(99_999_999),
                    last_try: o["last_try_time"].as_i64().unwrap_or(0),
                },
            );
        }
    }
    out
}

/// Счётчики трафика через VPN (байт отдано, байт получено) из metrics Xray.
/// Считаем только исходящий "proxy": помощники вроде fragment гонят те же байты.
pub async fn fetch_traffic(client: &reqwest::Client, metrics_port: u16) -> Option<(u64, u64)> {
    let v = fetch_vars(client, metrics_port).await?;
    Some(v.traffic.get("proxy").copied().unwrap_or((0, 0)))
}

/// Клиент для локальных запросов к самому Xray: строго без прокси, иначе
/// reqwest на Windows возьмёт системный прокси (а он — наш же Xray).
pub fn local_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("reqwest client")
}

/// Скачать подписку. Если передан socks_port — качаем через запущенный VPN
/// (полезно, когда адрес подписки заблокирован).
/// Прочитать тело ответа, но не больше `max` байт: ответ приходит со стороны
/// (подписка, сервер VPN), и гигантский ответ не должен съесть всю память.
pub async fn read_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>, String> {
    if resp.content_length().is_some_and(|n| n > max as u64) {
        return Err(tr!("ответ больше {} МБ — не похоже на правду", max >> 20));
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| e.to_string())? {
        if out.len() + chunk.len() > max {
            return Err(tr!("ответ больше {} МБ — не похоже на правду", max >> 20));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Можно ли идти по перенаправлению подписки: не больше 10 шагов и,
/// если хоть раз были на https, — дальше только https.
pub fn redirect_verdict(previous: &[url::Url], next: &url::Url) -> Result<(), &'static str> {
    if previous.iter().any(|u| u.scheme() == "https") && next.scheme() != "https" {
        Err(trs!("подписка перенаправила с https на http — отказываюсь"))
    } else if previous.len() >= 10 {
        Err(trs!("слишком много перенаправлений"))
    } else {
        Ok(())
    }
}

/// Подписка больше этого — не подписка.
const MAX_SUB: usize = 32 << 20;
/// Архив Xray ~ 15 МБ; с запасом.
const MAX_CORE_ZIP: usize = 200 << 20;
/// Файлы, которые берём из архива Xray. Остальное (вдруг там окажется DLL)
/// рядом с xray.exe не кладём.
const CORE_FILES: &[&str] = &["xray", "xray.exe", "geoip.dat", "geosite.dat", "LICENSE", "README.md"];

pub async fn fetch_subscription(url: &str, socks_port: Option<u16>) -> Result<String, String> {
    fetch_subscription_full(url, socks_port, None).await.map(|f| f.0)
}

/// Подписка + остаток трафика и срок из заголовка `subscription-userinfo`
/// (Marzban, Remnawave, 3x-ui, Hiddify): `upload=…; download=…; total=…; expire=…`.
///
/// `hwid` — номер устройства для сервисов с привязкой подписки к устройствам (Remnawave:
/// `x-hwid`; без него такой сервис отдаёт «сервер»-записку «включите HWID» или 404).
pub async fn fetch_subscription_full(url: &str, socks_port: Option<u16>, hwid: Option<&str>) -> Result<(String, Option<crate::store::SubUsage>), String> {
    // Редирект с https на http не принимаем: на открытом участке подписку
    // мог бы подменить провайдер.
    let policy = reqwest::redirect::Policy::custom(|a| match redirect_verdict(a.previous(), a.url()) {
        Ok(()) => a.follow(),
        Err(e) => a.error(e),
    });
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(policy)
        // Панели (3x-ui, Marzban, Remnawave) по User-Agent решают, какой формат
        // отдать. "v2rayN" гарантирует обычный список ссылок.
        .user_agent("v2rayN/7.17.1");
    if let Some(p) = socks_port {
        b = b.proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{p}")).map_err(|e| e.to_string())?,
        );
    }
    let client = b.build().map_err(|e| e.to_string())?;
    let mut req = client.get(url);
    if let Some(h) = hwid {
        req = req.header("x-hwid", h).header("x-device-os", "Windows").header("x-device-model", "rxvpn");
    }
    let resp = req.send().await.map_err(|e| tr!("не скачалась: {e}"))?;
    if !resp.status().is_success() {
        return Err(tr!("сервер ответил {}", resp.status()));
    }
    let usage = resp
        .headers()
        .get("subscription-userinfo")
        .and_then(|v| v.to_str().ok())
        .and_then(crate::store::SubUsage::parse);
    let body = read_capped(resp, MAX_SUB).await?;
    Ok((String::from_utf8_lossy(&body).into_owned(), usage))
}

/// Имя архива Xray в релизах GitHub под текущую ОС.
pub fn xray_asset_name() -> &'static str {
    if cfg!(all(windows, target_arch = "x86_64")) {
        "Xray-windows-64.zip"
    } else if cfg!(all(windows, target_arch = "aarch64")) {
        "Xray-windows-arm64-v8a.zip"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "Xray-macos-arm64-v8a.zip"
    } else if cfg!(target_os = "macos") {
        "Xray-macos-64.zip"
    } else if cfg!(target_arch = "aarch64") {
        "Xray-linux-arm64-v8a.zip"
    } else {
        "Xray-linux-64.zip"
    }
}

/// Скачать архив свежего Xray с GitHub (через VPN, если передан socks_port).
pub async fn fetch_core_zip(socks_port: Option<u16>) -> Result<Vec<u8>, String> {
    fetch_xray_asset(xray_asset_name(), socks_port).await
}

/// Любой архив последнего релиза Xray (например, `Xray-linux-64.zip` для своего
/// сервера) — со сверкой SHA-256 по .dgst.
pub async fn fetch_xray_asset(asset: &str, socks_port: Option<u16>) -> Result<Vec<u8>, String> {
    if !asset.starts_with("Xray-") || !asset.ends_with(".zip") || !asset[5..].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
        return Err(trs!("странное имя архива Xray").into());
    }
    let url = format!("https://github.com/XTLS/Xray-core/releases/latest/download/{asset}");
    // https_only — в том числе для редиректов GitHub на его CDN.
    let mut b = reqwest::Client::builder().timeout(Duration::from_secs(180)).https_only(true);
    if let Some(p) = socks_port {
        b = b.proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{p}")).map_err(|e| e.to_string())?,
        );
    }
    let client = b.build().map_err(|e| e.to_string())?;
    let get = |u: String| {
        let client = client.clone();
        async move {
            let r = client
                .get(&u)
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .map_err(|e| tr!("GitHub недоступен: {e}"))?;
            read_capped(r, MAX_CORE_ZIP).await
        }
    };
    // Рядом с архивом Xray публикует .dgst с хешами — сверяем SHA-256,
    // чтобы не поставить битый или подменённый по дороге архив.
    let (zip, dgst) = tokio::join!(get(url.clone()), get(format!("{url}.dgst")));
    let (zip, dgst) = (zip?, dgst?);
    let want = parse_dgst(&String::from_utf8_lossy(&dgst)).ok_or(trs!("в .dgst нет SHA2-256"))?;
    let got = sha256_hex(&zip);
    if got != want {
        return Err(tr!("архив ядра не сошёлся с хешем GitHub (ждали {want}, пришло {got}) — не ставлю"));
    }
    Ok(zip)
}

/// SHA-256 из .dgst-файла Xray ("SHA2-256= <hex>").
pub fn parse_dgst(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        let v = v.trim().to_ascii_lowercase();
        (k.trim().eq_ignore_ascii_case("SHA2-256") && v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit())).then_some(v)
    })
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Распаковать архив ядра в папку. Возвращает список файлов.
pub fn install_core_zip(bytes: &[u8], dir: &Path) -> Result<Vec<String>, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    crate::runner::release_core(); // с правами администратора ядро закрыто от записи
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| e.to_string())?;
    let mut files = Vec::new();
    for i in 0..zip.len() {
        let mut f = zip.by_index(i).map_err(|e| e.to_string())?;
        if f.is_dir() {
            continue;
        }
        // enclosed_name защищает от "../../" в архиве (zip slip). Берём только
        // известные файлы и только из корня архива.
        let Some(rel) = f.enclosed_name() else { continue };
        let Some(name) = rel.to_str().filter(|n| CORE_FILES.contains(n)) else { continue };
        let out = dir.join(name);
        // Размер из заголовка архива — не доверяем: читаем с потолком.
        let mut buf = Vec::new();
        (&mut f).take(MAX_CORE_ZIP as u64 + 1).read_to_end(&mut buf).map_err(|e| e.to_string())?;
        if buf.len() > MAX_CORE_ZIP {
            return Err(tr!("{name} в архиве подозрительно большой"));
        }
        std::fs::write(&out, &buf).map_err(|e| format!("{}: {e}", out.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Только «исполняемый или нет»: SUID/SGID и прочие биты из архива не переносим.
            let mode = if f.unix_mode().is_some_and(|m| m & 0o111 != 0) { 0o755 } else { 0o644 };
            let _ = std::fs::set_permissions(&out, std::fs::Permissions::from_mode(mode));
        }
        files.push(rel.display().to_string());
    }
    // Свежие хеши: с правами администратора ядро сверяется с ними перед каждым запуском.
    let _ = crate::runner::record_core(dir); // не записалось — сверка запомнит при первом запуске
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(list: &[(&str, bool, u64, i64)]) -> HashMap<String, Observation> {
        list.iter()
            .map(|(t, alive, delay, last_try)| (t.to_string(), Observation { alive: *alive, delay: *delay, last_try: *last_try }))
            .collect()
    }

    #[test]
    fn dgst_and_sha256() {
        let d = "MD5= e8\nSHA1= 0c\nSHA2-256= FCE33E81CCCF50E7AAB572B175519A50B5E0F9D2F5C8D1ED73012EA5C9AD4D58\nSHA2-512= de";
        assert_eq!(parse_dgst(d).as_deref(), Some("fce33e81cccf50e7aab572b175519a50b5e0f9d2f5c8d1ed73012ea5c9ad4d58"));
        assert_eq!(parse_dgst("SHA2-256= xyz"), None);
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    /// HWID уходит только когда включён у подписки.
    #[tokio::test(flavor = "current_thread")]
    async fn hwid_header_only_when_asked() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let mut b = [0u8; 2048];
                let n = s.read(&mut b).unwrap_or(0);
                let _ = tx.send(String::from_utf8_lossy(&b[..n]).to_lowercase());
                let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
            }
        });
        let url = format!("http://127.0.0.1:{port}/s");
        fetch_subscription_full(&url, None, None).await.unwrap();
        let plain = rx.recv().unwrap();
        assert!(!plain.contains("x-hwid") && !plain.contains("x-device"), "без галочки — ни слова об устройстве");
        fetch_subscription_full(&url, None, Some("11111111-2222-4333-8444-555555555555")).await.unwrap();
        let with = rx.recv().unwrap();
        assert!(with.contains("x-hwid: 11111111-2222-4333-8444-555555555555"));
        assert!(with.contains("x-device-os: windows"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn subscription_refuses_https_to_http_redirect() {
        use std::io::{Read, Write};
        // «https»-сервер не поднять без сертификата, поэтому проверяем саму
        // политику: http → http разрешено, а после https — запрет (см. Policy::custom).
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for (n, s) in l.incoming().flatten().enumerate() {
                let mut s = s;
                let mut b = [0u8; 1024];
                let _ = s.read(&mut b);
                if n == 0 {
                    let _ = write!(s, "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/b\r\nContent-Length: 0\r\n\r\n");
                } else {
                    let _ = write!(s, "HTTP/1.1 200 OK\r\nSubscription-Userinfo: upload=1; download=2; total=30; expire=1767225600\r\nContent-Length: 2\r\n\r\nok");
                }
            }
        });
        assert_eq!(fetch_subscription(&format!("http://127.0.0.1:{port}/a"), None).await.unwrap(), "ok");
        let (_, usage) = fetch_subscription_full(&format!("http://127.0.0.1:{port}/a"), None, None).await.unwrap();
        assert_eq!(usage, Some(crate::store::SubUsage { upload: 1, download: 2, total: 30, expire: 1767225600 }));
        let u = |s: &str| url::Url::parse(s).unwrap();
        assert!(redirect_verdict(&[u("https://a.com/s")], &u("http://b.com/s")).is_err(), "https → http нельзя");
        assert!(redirect_verdict(&[u("https://a.com/s")], &u("https://b.com/s")).is_ok());
        assert!(redirect_verdict(&[u("http://a.com/s")], &u("http://b.com/s")).is_ok(), "http и был");
        assert!(redirect_verdict(&vec![u("http://a.com/"); 10], &u("http://a.com/")).is_err());
    }

    #[test]
    fn core_zip_only_known_files() {
        use std::io::Write;
        let mut buf = Vec::new();
        {
            let mut z = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            let o = zip::write::SimpleFileOptions::default();
            for (name, data) in [
                ("xray.exe", &b"MZ-xray"[..]),
                ("geoip.dat", b"ip"),
                ("evil.dll", b"MZ-evil"),
                ("../escape.exe", b"MZ-escape"),
                ("sub/xray.exe", b"MZ-nested"),
            ] {
                z.start_file(name, o).unwrap();
                z.write_all(data).unwrap();
            }
            z.finish().unwrap();
        }
        let dir = std::env::temp_dir().join(format!("rxvpn-zip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut files = install_core_zip(&buf, &dir).unwrap();
        files.sort();
        assert_eq!(files, ["geoip.dat", "xray.exe"]);
        assert_eq!(std::fs::read(dir.join("xray.exe")).unwrap(), b"MZ-xray", "из корня, не из подпапки");
        assert!(!dir.join("evil.dll").exists() && !dir.parent().unwrap().join("escape.exe").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pick_alive_rules() {
        let tags = ["node-0", "node-1", "node-2"];
        let o = obs(&[("node-0", true, 50, 100), ("node-1", true, 20, 100), ("node-2", false, 99_999_999, 100)]);
        let none = HashMap::new();
        assert_eq!(pick_alive(&o, tags, &none, None).as_deref(), Some("node-1"), "самый быстрый живой");
        assert_eq!(pick_alive(&o, tags, &none, Some("node-1")).as_deref(), Some("node-0"), "кроме текущего");

        // С node-0 ушли в момент 150, а Xray последний раз проверял его в 100 —
        // «жив» устарел, возвращаться нельзя: ни пинг-понга, ни ложной надежды.
        let bad: HashMap<String, i64> = [("node-0".to_string(), 150)].into();
        assert_eq!(pick_alive(&o, tags, &bad, Some("node-1")), None);

        // Xray перепроверил node-0 после ухода (200 > 150) и он ответил — можно.
        let o2 = obs(&[("node-0", true, 50, 200), ("node-1", true, 20, 100)]);
        assert_eq!(pick_alive(&o2, tags, &bad, Some("node-1")).as_deref(), Some("node-0"));

        // Перепроверил, но мёртв — нельзя.
        let o3 = obs(&[("node-0", false, 99_999_999, 200)]);
        assert_eq!(pick_alive(&o3, tags, &bad, None), None);
    }
}
