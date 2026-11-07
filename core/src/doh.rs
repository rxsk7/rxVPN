//! DNS без подмены для режима «Без VPN»: локальный DNS-сервер (UDP и TCP на
//! 127.0.0.1:53 и [::1]:53), который пересылает запросы по DNS-over-HTTPS
//! (RFC 8484, `application/dns-message`) в Cloudflare, Google или свой сервер.
//! Windows на время работы смотрит в него (`sysdns.rs`) — и провайдер больше
//! не может подсунуть заглушку вместо адреса сайта.
//!
//! Безопасность:
//! - сертификат DoH-сервера проверяется (webpki-roots, имя из адреса);
//! - адрес DoH-сервера закреплён заранее (`pins`): сам он через нас не резолвится
//!   (иначе петля), и DNS провайдера его подменить не может;
//! - слушаем только loopback: в локальную сеть сервер не виден;
//! - запросы разбираются строго (один вопрос, без сжатия в вопросе, ≤ 512/4096 байт),
//!   ответ должен быть ответом на ТОТ ЖЕ вопрос — иначе SERVFAIL;
//! - кэш — не больше `CACHE_MAX` записей, TTL ≤ суток.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

/// Сколько ответов держим в кэше.
const CACHE_MAX: usize = 4096;
/// TTL в кэше не дольше суток; отрицательный ответ без TTL — 60 с.
const TTL_MAX: u32 = 86_400;
const TTL_NEG: u32 = 60;
/// Одновременных запросов наружу.
const INFLIGHT: usize = 64;
/// Одновременных TCP-клиентов.
const TCP_MAX: usize = 128;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_IDLE: Duration = Duration::from_secs(10);
/// Ответ DoH больше этого — не DNS.
const RESP_MAX: usize = 65_535;

/// Встроенные DoH-сервера: (ключ, имя для окна, адрес, закреплённые IP).
pub const PROVIDERS: &[(&str, &str, &str, &[IpAddr])] = &[
    (
        "cloudflare",
        "Cloudflare",
        "https://cloudflare-dns.com/dns-query",
        &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1))],
    ),
    (
        "google",
        "Google",
        "https://dns.google/dns-query",
        &[IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))],
    ),
];

/// Имя DoH-сервера для окна и лога (без пути и ключа).
pub fn provider_label(key: &str, custom_url: &str) -> String {
    match PROVIDERS.iter().find(|p| p.0 == key) {
        Some(p) => p.1.to_string(),
        None => url::Url::parse(custom_url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_else(|| trs!("свой").into()),
    }
}

/// Проверка своего адреса DoH: https, имя или IP, без логина в адресе.
pub fn validate_url(s: &str) -> Result<(), String> {
    let u = url::Url::parse(s.trim()).map_err(|_| trs!("Адрес DoH кривой — нужен вид https://сервер/dns-query").to_string())?;
    if u.scheme() != "https" {
        return Err(trs!("Адрес DoH — только https://").into());
    }
    if s.len() > 300 || !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
        return Err(trs!("Адрес DoH: без логина, пароля и #").into());
    }
    match u.host() {
        Some(url::Host::Domain(d)) if crate::tgproxy::valid_domain(d) => Ok(()),
        Some(url::Host::Ipv4(_) | url::Host::Ipv6(_)) => Ok(()),
        _ => Err(trs!("Адрес DoH: нет имени сервера").into()),
    }
}

/// Куда ходить: адрес DoH и закреплённые IP его сервера (порт — из адреса).
#[derive(Clone, Debug)]
pub struct Upstream {
    pub url: String,
    pub host: String,
    pub pins: Vec<SocketAddr>,
}

/// Собрать `Upstream` из настроек. Свой адрес по имени резолвится здесь —
/// ДО того, как системный DNS станет нашим (иначе резолвить его было бы некому).
pub async fn upstream(key: &str, custom_url: &str) -> Result<Upstream, String> {
    let (url, fixed): (String, Vec<IpAddr>) = match PROVIDERS.iter().find(|p| p.0 == key) {
        Some(p) => (p.2.to_string(), p.3.to_vec()),
        None => {
            validate_url(custom_url)?;
            (custom_url.trim().to_string(), Vec::new())
        }
    };
    let u = url::Url::parse(&url).map_err(|e| e.to_string())?;
    let port = u.port_or_known_default().unwrap_or(443);
    let host = u.host_str().ok_or(trs!("нет имени сервера DoH"))?.trim_start_matches('[').trim_end_matches(']').to_string();
    let mut ips = fixed;
    if ips.is_empty() {
        if let Ok(ip) = host.parse::<IpAddr>() {
            ips.push(ip);
        } else {
            let found = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host.as_str(), port)))
                .await
                .map_err(|_| tr!("DoH: адрес {host} не нашёлся за 5 с"))?
                .map_err(|e| tr!("DoH: адрес {host} не нашёлся: {e}"))?;
            // Свой DoH «в локалке» или на самом компе — это не DoH, а петля или подмена.
            ips.extend(found.map(|a| a.ip()).filter(|ip| !ip.is_loopback() && !ip.is_unspecified()).take(4));
            if ips.is_empty() {
                return Err(tr!("DoH: у {host} нет годного адреса"));
            }
        }
    }
    Ok(Upstream { url, host, pins: ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect() })
}

/// Счётчики для окна.
#[derive(Default, Debug)]
pub struct Stats {
    pub queries: AtomicU64,
    pub cached: AtomicU64,
    pub failed: AtomicU64,
    pub last_error: Mutex<String>,
}

pub struct Config {
    pub upstream: Upstream,
    /// Где слушать. Пусто — 127.0.0.1:53 и [::1]:53. Порт 0 — свободный (тесты):
    /// TCP тогда на том же порту, что и UDP.
    pub listen: Vec<SocketAddr>,
    /// Доверять ещё и этому корневому сертификату (PEM). Только для тестов со
    /// своим DoH-сервером: из настроек сюда ничего не попадает.
    pub extra_root_pem: Option<Vec<u8>>,
}

pub struct Running {
    pub stats: Arc<Stats>,
    /// Где реально слушаем (с портами).
    pub addrs: Vec<SocketAddr>,
    pub label: String,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Running {
    pub fn stop(&mut self) {
        for t in self.tasks.drain(..) {
            t.abort();
        }
    }
    /// Слушаем и на IPv6 (тогда системный DNS IPv6 тоже ставим на ::1).
    pub fn has_v6(&self) -> bool {
        self.addrs.iter().any(|a| a.is_ipv6())
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Entry {
    resp: Vec<u8>,
    ttl_offs: Vec<usize>,
    ttl: u32,
    at: Instant,
}

struct Shared {
    client: reqwest::Client,
    url: String,
    stats: Arc<Stats>,
    cache: Mutex<HashMap<Vec<u8>, Entry>>,
    sem: Semaphore,
}

/// Запустить. Порт 53 занят (другой DNS-прокси) — ошибка, ничего не меняем.
pub async fn start(cfg: Config) -> Result<Running, String> {
    let mut b = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .timeout(UPSTREAM_TIMEOUT)
        .connect_timeout(Duration::from_secs(4))
        .pool_max_idle_per_host(8)
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&cfg.upstream.host, &cfg.upstream.pins);
    if let Some(pem) = &cfg.extra_root_pem {
        b = b.add_root_certificate(reqwest::Certificate::from_pem(pem).map_err(|e| e.to_string())?);
    }
    let client = b.build().map_err(|e| e.to_string())?;
    let stats = Arc::new(Stats::default());
    let shared = Arc::new(Shared {
        client,
        url: cfg.upstream.url.clone(),
        stats: stats.clone(),
        cache: Mutex::new(HashMap::new()),
        sem: Semaphore::new(INFLIGHT),
    });
    let listen = if cfg.listen.is_empty() {
        vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53), SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53)]
    } else {
        cfg.listen.clone()
    };
    let mut tasks = Vec::new();
    let mut addrs = Vec::new();
    for (i, want) in listen.iter().enumerate() {
        if !want.ip().is_loopback() {
            return Err(trs!("DoH: слушать можно только 127.0.0.1 / ::1").into());
        }
        let udp = match UdpSocket::bind(want).await {
            Ok(s) => s,
            // IPv6 на компе выключен — работаем по IPv4.
            Err(_) if want.is_ipv6() && i > 0 => continue,
            Err(e) => return Err(port_err(want, &e)),
        };
        let at = udp.local_addr().map_err(|e| e.to_string())?;
        let tcp = TcpListener::bind(at).await.map_err(|e| port_err(&at, &e))?;
        addrs.push(at);
        tasks.push(tokio::spawn(udp_loop(Arc::new(udp), shared.clone())));
        tasks.push(tokio::spawn(tcp_loop(tcp, shared.clone())));
    }
    let label = cfg.upstream.host.clone();
    Ok(Running { stats, addrs, label, tasks })
}

fn port_err(a: &SocketAddr, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::AddrInUse || e.raw_os_error() == Some(10048) {
        tr!("DoH: порт {a} уже занят другой программой (DNS-прокси, AdGuard, Docker?) — закрой её или выключи галочку")
    } else {
        tr!("DoH: не открылся {a}: {e}")
    }
}

async fn udp_loop(sock: Arc<UdpSocket>, sh: Arc<Shared>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else {
            // Windows отдаёт ошибку (10054) на UDP после «порт недоступен» у клиента — не повод умирать.
            tokio::time::sleep(Duration::from_millis(5)).await;
            continue;
        };
        let q = buf[..n].to_vec();
        let (sock, sh) = (sock.clone(), sh.clone());
        tokio::spawn(async move {
            if let Some(resp) = answer(&sh, &q, true).await {
                let _ = sock.send_to(&resp, from).await;
            }
        });
    }
}

async fn tcp_loop(l: TcpListener, sh: Arc<Shared>) {
    let conns = Arc::new(Semaphore::new(TCP_MAX));
    loop {
        let Ok((s, _)) = l.accept().await else {
            tokio::time::sleep(Duration::from_millis(5)).await;
            continue;
        };
        let Ok(permit) = conns.clone().try_acquire_owned() else { continue };
        let sh = sh.clone();
        tokio::spawn(async move {
            let _p = permit;
            let _ = tcp_conn(s, sh).await;
        });
    }
}

async fn tcp_conn(mut s: TcpStream, sh: Arc<Shared>) -> std::io::Result<()> {
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(TCP_IDLE, s.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => return Ok(()),
        }
        let n = u16::from_be_bytes(len) as usize;
        let mut q = vec![0u8; n];
        tokio::time::timeout(TCP_IDLE, s.read_exact(&mut q)).await.map_err(|_| std::io::ErrorKind::TimedOut)??;
        let Some(resp) = answer(&sh, &q, false).await else { return Ok(()) };
        let mut out = Vec::with_capacity(resp.len() + 2);
        out.extend_from_slice(&(resp.len() as u16).to_be_bytes());
        out.extend_from_slice(&resp);
        s.write_all(&out).await?;
    }
}

// ---------------- разбор DNS ----------------

/// Вопрос из запроса: ключ для кэша (имя в нижнем регистре + тип + класс),
/// где кончается вопрос, сколько байт клиент примет по UDP.
#[derive(Debug, PartialEq, Eq)]
pub struct Question {
    pub key: Vec<u8>,
    pub end: usize,
    pub udp_max: usize,
}

fn u16_at(m: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*m.get(i)?, *m.get(i + 1)?]))
}

/// Имя в вопросе (без сжатия): конец и само имя в нижнем регистре.
fn question_name(m: &[u8], mut i: usize) -> Option<(Vec<u8>, usize)> {
    let mut name = Vec::new();
    loop {
        let l = *m.get(i)? as usize;
        if l == 0 {
            name.push(0);
            return (name.len() <= 255).then_some((name, i + 1));
        }
        if l > 63 {
            return None; // сжатие или мусор
        }
        name.push(l as u8);
        name.extend(m.get(i + 1..i + 1 + l)?.iter().map(u8::to_ascii_lowercase));
        i += 1 + l;
    }
}

/// Пропустить имя в записи (со сжатием).
fn skip_name(m: &[u8], mut i: usize) -> Option<usize> {
    for _ in 0..128 {
        let l = *m.get(i)?;
        match l & 0xc0 {
            0x00 if l == 0 => return Some(i + 1),
            0x00 => i += 1 + l as usize,
            0xc0 => {
                m.get(i + 1)?;
                return Some(i + 2);
            }
            _ => return None,
        }
    }
    None
}

/// Разобрать запрос клиента. None — не обычный запрос (тогда FORMERR).
pub fn parse_query(m: &[u8]) -> Option<Question> {
    if m.len() < 12 || m.len() > 4096 {
        return None;
    }
    let flags = u16_at(m, 2)?;
    let (qd, an, ns, ar) = (u16_at(m, 4)?, u16_at(m, 6)?, u16_at(m, 8)?, u16_at(m, 10)?);
    // QR=0, opcode=0 (QUERY), ровно один вопрос, без ответов.
    if flags & 0x8000 != 0 || (flags >> 11) & 0xf != 0 || qd != 1 || an != 0 || ns != 0 || ar > 1 {
        return None;
    }
    let (name, i) = question_name(m, 12)?;
    let (qtype, qclass) = (u16_at(m, i)?, u16_at(m, i + 2)?);
    let end = i + 4;
    let mut key = name;
    key.extend_from_slice(&qtype.to_be_bytes());
    key.extend_from_slice(&qclass.to_be_bytes());
    // EDNS0: размер UDP — из класса записи OPT.
    let mut udp_max = 512;
    if ar == 1 {
        let j = skip_name(m, end)?;
        if u16_at(m, j)? == 41 {
            udp_max = (u16_at(m, j + 2)? as usize).clamp(512, 4096);
        }
    }
    Some(Question { key, end, udp_max })
}

/// Ответ сервера: тот же ли вопрос, rcode, где лежат TTL и минимальный TTL.
struct Parsed {
    rcode: u8,
    ttl_offs: Vec<usize>,
    min_ttl: Option<u32>,
}

fn parse_response(m: &[u8], key: &[u8]) -> Option<Parsed> {
    if m.len() < 12 {
        return None;
    }
    let flags = u16_at(m, 2)?;
    if flags & 0x8000 == 0 || u16_at(m, 4)? != 1 {
        return None;
    }
    let (name, i) = question_name(m, 12)?;
    let mut k = name;
    k.extend_from_slice(m.get(i..i + 4)?);
    if k != key {
        return None; // ответ не на наш вопрос
    }
    let records = u16_at(m, 6)? as usize + u16_at(m, 8)? as usize + u16_at(m, 10)? as usize;
    let mut j = i + 4;
    let mut ttl_offs = Vec::new();
    let mut min_ttl: Option<u32> = None;
    for _ in 0..records {
        j = skip_name(m, j)?;
        let rtype = u16_at(m, j)?;
        let ttl = u32::from_be_bytes(m.get(j + 4..j + 8)?.try_into().ok()?);
        let rdlen = u16_at(m, j + 8)? as usize;
        if rtype != 41 {
            ttl_offs.push(j + 4);
            min_ttl = Some(min_ttl.map_or(ttl, |t| t.min(ttl)));
        }
        j += 10 + rdlen;
        if j > m.len() {
            return None;
        }
    }
    Some(Parsed { rcode: (flags & 0xf) as u8, ttl_offs, min_ttl })
}

/// Ответ-ошибка на запрос: заголовок + вопрос, RCODE.
fn error_reply(q: &[u8], end: Option<usize>, rcode: u8) -> Option<Vec<u8>> {
    if q.len() < 12 {
        return None;
    }
    let mut r = match end {
        Some(e) => q[..e].to_vec(),
        None => q[..12].to_vec(),
    };
    let rd = r[2] & 0x01;
    r[2] = 0x80 | (q[2] & 0x78) | rd; // QR, opcode как был, RD как был
    r[3] = 0x80 | (rcode & 0xf); // RA
    r[4..6].copy_from_slice(&(if end.is_some() { 1u16 } else { 0 }).to_be_bytes());
    r[6..12].fill(0);
    Some(r)
}

/// Не помещается в UDP — только заголовок и вопрос с флагом TC (клиент спросит по TCP).
fn truncate(resp: &[u8], qend: usize) -> Vec<u8> {
    let mut r = resp[..qend.min(resp.len())].to_vec();
    r[2] |= 0x02;
    r[6..12].fill(0);
    r
}

/// Ответ на запрос клиента (None — не отвечать: совсем мусор).
async fn answer(sh: &Shared, q: &[u8], udp: bool) -> Option<Vec<u8>> {
    sh.stats.queries.fetch_add(1, Ordering::Relaxed);
    let Some(qq) = parse_query(q) else {
        return error_reply(q, None, 1); // FORMERR
    };
    let id = [q[0], q[1]];
    let fit = |mut r: Vec<u8>| {
        r[0..2].copy_from_slice(&id);
        if udp && r.len() > qq.udp_max {
            truncate(&r, qq.end)
        } else {
            r
        }
    };
    // Кэш.
    let hit = {
        let mut c = sh.cache.lock().unwrap();
        match c.get(&qq.key) {
            Some(e) if e.at.elapsed().as_secs() < e.ttl as u64 => {
                let left = e.ttl - e.at.elapsed().as_secs() as u32;
                let mut r = e.resp.clone();
                for &o in &e.ttl_offs {
                    r[o..o + 4].copy_from_slice(&left.to_be_bytes());
                }
                Some(r)
            }
            Some(_) => {
                c.remove(&qq.key);
                None
            }
            None => None,
        }
    };
    if let Some(r) = hit {
        sh.stats.cached.fetch_add(1, Ordering::Relaxed);
        return Some(fit(r));
    }
    let _permit = sh.sem.acquire().await.ok()?;
    // Наружу — с ID 0 (RFC 8484: так ответы кэшируются и у них).
    let mut body = q.to_vec();
    body[0..2].copy_from_slice(&[0, 0]);
    let mut last = String::new();
    for _ in 0..2 {
        match ask(sh, &body).await {
            Ok(resp) => match parse_response(&resp, &qq.key) {
                Some(p) => {
                    if p.rcode == 0 || p.rcode == 3 {
                        let ttl = match p.min_ttl {
                            Some(t) => t.min(TTL_MAX),
                            None => TTL_NEG,
                        };
                        if ttl > 0 {
                            let mut c = sh.cache.lock().unwrap();
                            if c.len() >= CACHE_MAX {
                                c.retain(|_, e| e.at.elapsed().as_secs() < e.ttl as u64);
                                if c.len() >= CACHE_MAX {
                                    c.clear();
                                }
                            }
                            c.insert(qq.key.clone(), Entry { resp: resp.clone(), ttl_offs: p.ttl_offs, ttl, at: Instant::now() });
                        }
                    }
                    return Some(fit(resp));
                }
                None => last = trs!("DoH прислал ответ не на тот вопрос").into(),
            },
            Err(e) => last = e,
        }
    }
    sh.stats.failed.fetch_add(1, Ordering::Relaxed);
    *sh.stats.last_error.lock().unwrap() = last;
    error_reply(q, Some(qq.end), 2) // SERVFAIL
}

async fn ask(sh: &Shared, body: &[u8]) -> Result<Vec<u8>, String> {
    let r = sh
        .client
        .post(&sh.url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(body.to_vec())
        .send()
        .await
        .map_err(|e| crate::net::explain(&e))?;
    if !r.status().is_success() {
        return Err(tr!("DoH ответил {}", r.status()));
    }
    let ct = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    if !ct.starts_with("application/dns-message") {
        return Err(trs!("DoH ответил не DNS (страница вместо ответа?)").into());
    }
    let b = crate::net::read_capped(r, RESP_MAX).await?;
    Ok(b.to_vec())
}

// ---------------- для тестов и проверок ----------------

/// Запрос A/AAAA для имени (ID и тип — свои), с EDNS0 на `udp` байт или без.
pub fn build_query(id: u16, name: &str, qtype: u16, edns: Option<u16>) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, if edns.is_some() { 1 } else { 0 }]);
    for l in name.trim_end_matches('.').split('.') {
        m.push(l.len() as u8);
        m.extend_from_slice(l.as_bytes());
    }
    m.push(0);
    m.extend_from_slice(&qtype.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    if let Some(size) = edns {
        m.extend_from_slice(&[0, 0, 41]);
        m.extend_from_slice(&size.to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
    m
}

/// Адреса A из ответа (для тестов и самопроверки).
pub fn answer_ips(m: &[u8]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let Some((_, i)) = question_name(m, 12) else { return out };
    let Some(an) = u16_at(m, 6) else { return out };
    let mut j = i + 4;
    for _ in 0..an {
        let Some(k) = skip_name(m, j) else { break };
        let (Some(t), Some(len)) = (u16_at(m, k), u16_at(m, k + 8)) else { break };
        let d = k + 10;
        match (t, len) {
            (1, 4) => {
                if let Some(b) = m.get(d..d + 4) {
                    out.push(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])));
                }
            }
            (28, 16) => {
                if let Some(b) = m.get(d..d + 16) {
                    out.push(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b).unwrap())));
                }
            }
            _ => {}
        }
        j = d + len as usize;
    }
    out
}

/// TTL первой записи ответа (тесты кэша).
pub fn first_ttl(m: &[u8]) -> Option<u32> {
    let (_, i) = question_name(m, 12)?;
    let k = skip_name(m, i + 4)?;
    Some(u32::from_be_bytes(m.get(k + 4..k + 8)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_parsing() {
        let q = build_query(0x1234, "WWW.Example.COM", 1, Some(1232));
        let p = parse_query(&q).unwrap();
        assert_eq!(p.udp_max, 1232);
        assert_eq!(&p.key[..4], b"\x03www");
        assert!(p.key.windows(7).any(|w| w == b"example"), "имя в нижнем регистре");
        assert_eq!(parse_query(&build_query(1, "a.ru", 28, None)).unwrap().udp_max, 512);
        // Мусор, ответы, несколько вопросов, сжатие в вопросе — не запрос.
        assert!(parse_query(b"\x00\x01").is_none());
        let mut resp = q.clone();
        resp[2] |= 0x80;
        assert!(parse_query(&resp).is_none());
        let mut two = q.clone();
        two[5] = 2;
        assert!(parse_query(&two).is_none());
        let mut ptr = build_query(1, "a.ru", 1, None);
        ptr[12] = 0xc0;
        assert!(parse_query(&ptr).is_none());
        // Длинная метка — мимо.
        let long = build_query(1, &"a".repeat(64), 1, None);
        assert!(parse_query(&long).is_none());
    }

    fn reply(q: &[u8], ips: &[[u8; 4]], ttl: u32) -> Vec<u8> {
        let p = parse_query(q).unwrap();
        let mut r = q[..p.end].to_vec();
        r[2] = 0x81;
        r[3] = 0x80;
        r[6..8].copy_from_slice(&(ips.len() as u16).to_be_bytes());
        r[10..12].fill(0);
        for ip in ips {
            r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
            r.extend_from_slice(&ttl.to_be_bytes());
            r.extend_from_slice(&[0, 4]);
            r.extend_from_slice(ip);
        }
        r
    }

    #[test]
    fn response_checks() {
        let q = build_query(7, "site.ru", 1, None);
        let key = parse_query(&q).unwrap().key;
        let r = reply(&q, &[[1, 2, 3, 4], [5, 6, 7, 8]], 300);
        let p = parse_response(&r, &key).unwrap();
        assert_eq!((p.rcode, p.min_ttl, p.ttl_offs.len()), (0, Some(300), 2));
        assert_eq!(answer_ips(&r).len(), 2);
        // Ответ на другой вопрос — отвергаем (подмена/путаница кэша).
        let other = reply(&build_query(7, "evil.ru", 1, None), &[[6, 6, 6, 6]], 300);
        assert!(parse_response(&other, &key).is_none());
        // Обрезанный ответ — отвергаем.
        assert!(parse_response(&r[..r.len() - 3], &key).is_none());
        // Усечение для UDP: только вопрос, TC.
        let t = truncate(&r, parse_query(&q).unwrap().end);
        assert!(t[2] & 0x02 != 0 && answer_ips(&t).is_empty());
        // SERVFAIL с вопросом.
        let e = error_reply(&q, Some(parse_query(&q).unwrap().end), 2).unwrap();
        assert_eq!((e[3] & 0xf, e[0], e[1], u16_at(&e, 4)), (2, 0, 7, Some(1)));
    }

    #[test]
    fn custom_url_rules() {
        assert!(validate_url("https://dns.example.com/dns-query").is_ok());
        assert!(validate_url("https://9.9.9.9/dns-query").is_ok());
        assert!(validate_url("https://[2620:fe::fe]/dns-query").is_ok());
        assert!(validate_url("http://dns.example.com/dns-query").is_err());
        assert!(validate_url("https://user:pw@dns.example.com/").is_err());
        assert!(validate_url("dns.example.com").is_err());
        assert_eq!(provider_label("custom", "https://dns.nextdns.io/abc"), "dns.nextdns.io");
        assert_eq!(provider_label("google", ""), "Google");
    }
}
