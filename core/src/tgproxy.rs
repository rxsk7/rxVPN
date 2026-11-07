//! «Telegram без VPN»: локальный MTProto-прокси, который ведёт Telegram не на его
//! сервера (их режут по IP — zapret тут бессилен), а через веб-вход по WebSocket,
//! как браузерную версию. Идея и протокол — Flowseal/tg-ws-proxy (MIT).
//!
//! ```text
//! Telegram Desktop ──obfuscated2, секрет dd…──▶ 127.0.0.1:1443 (rxvpn)
//!     ├─ TLS + WebSocket /apiws ─▶ kwsN.web.telegram.org (адрес веб-входа своего ДЦ)
//!     ├─ не вышло / другой ДЦ: то же через Cloudflare-домен kwsN.<домен>
//!     └─ не вышло и так: напрямую TCP к ДЦ (как Telegram без прокси)
//! ```
//!
//! rxvpn снимает с потока только «обфускацию» (AES-CTR с ключами из первых 64 байт)
//! и накладывает свою. Внутри — MTProto, зашифрованный ключом аккаунта, который
//! Telegram согласовал с сервером (RSA-ключи серверов вшиты в приложение): ни rxvpn,
//! ни Cloudflare, ни владелец домена переписку не прочитают и не подменят.
//! Видят они только твой IP и объём трафика.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type Ctr = ctr::Ctr128BE<Aes256>;

const HANDSHAKE_LEN: usize = 64;
const SKIP_LEN: usize = 8;
const PREKEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const PROTO_TAG_POS: usize = 56;
const DC_IDX_POS: usize = 60;

const TAG_ABRIDGED: [u8; 4] = [0xef; 4];
const TAG_INTERMEDIATE: [u8; 4] = [0xee; 4];
const TAG_SECURE: [u8; 4] = [0xdd; 4];

/// Порт по умолчанию (как у tg-ws-proxy: Telegram запоминает прокси с портом).
pub const DEFAULT_PORT: u16 = 1443;
/// Веб-вход Telegram (kwsN.web.telegram.org) по ДЦ. Подключаемся по адресу, а
/// сертификат проверяем по имени: DNS провайдера тут не участвует. ДЦ 2 и 4 —
/// адрес Telegram Web по умолчанию; 1, 3 и 5 — как отвечают сейчас (Telegram их
/// не публикует; не ответят — дальше Cloudflare или напрямую).
const WEB_IPS: &[(u16, Ipv4Addr)] = &[
    (1, Ipv4Addr::new(149, 154, 174, 100)),
    (2, Ipv4Addr::new(149, 154, 167, 220)),
    (3, Ipv4Addr::new(149, 154, 174, 100)),
    (4, Ipv4Addr::new(149, 154, 167, 220)),
    (5, Ipv4Addr::new(149, 154, 170, 100)),
];
/// Адреса ДЦ — для запасного пути напрямую.
const DC_IPS: &[(u16, Ipv4Addr)] = &[
    (1, Ipv4Addr::new(149, 154, 175, 50)),
    (2, Ipv4Addr::new(149, 154, 167, 51)),
    (3, Ipv4Addr::new(149, 154, 175, 100)),
    (4, Ipv4Addr::new(149, 154, 167, 91)),
    (5, Ipv4Addr::new(149, 154, 171, 5)),
    (203, Ipv4Addr::new(91, 105, 192, 100)),
];
const DC_TEST_IPS: &[(u16, Ipv4Addr)] = &[
    (1, Ipv4Addr::new(149, 154, 175, 10)),
    (2, Ipv4Addr::new(149, 154, 167, 40)),
    (3, Ipv4Addr::new(149, 154, 175, 117)),
];

/// Больше одновременных соединений не держим (Telegram Desktop открывает 10–30).
const MAX_CONNS: usize = 128;
/// Пакет MTProto больше не бывает (файлы идут кусками до 1 МБ); больше — не копим.
const WS_MAX_MESSAGE: usize = 2 * 1024 * 1024;
/// Служебные кадры WebSocket (ping/pong/close) по RFC 6455 — не длиннее 125 байт.
const WS_MAX_CONTROL: usize = 125;
/// Всё подключение наружу (все пути по очереди) — не дольше этого.
/// Укладывается: веб 5 с (медиа — 2 × 5), Cloudflare 2 × 4, напрямую 5.
const UPSTREAM_DEADLINE: Duration = Duration::from_secs(25);
/// Путь не ответил — столько его не пробуем (не тратим на него время каждого соединения).
const PATH_PAUSE: Duration = Duration::from_secs(120);
/// Как браузер с Telegram Web: веб-вход ждёт именно такое.
const ORIGIN: &str = "https://web.telegram.org";
const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const CF_TIMEOUT: Duration = Duration::from_secs(4);
const CF_TRIES: usize = 2;

// ---------------- домены Cloudflare ----------------

/// Общие Cloudflare-домены сообщества tg-ws-proxy (там же в коде — в таком же
/// «перевёрнутом» виде, чтобы их не вылавливали поиском). Свой домен надёжнее.
const CF_ENC: &[&str] = &[
    "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com", "twdmbzcm.com",
    "awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com", "bxaxtxmrw.com", "dmohrsgmohcrwb.com",
    "vwbmtmoi.com", "khgrre.com", "ulihssf.com", "tmhqsdqmfpmk.com", "xwuwoqbm.com",
    "orgcnunpj.com", "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com",
];
/// Свежий список — Flowseal обновляет его, когда домены перестают работать.
pub const CF_LIST_URL: &str = "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";

/// Расшифровка как в tg-ws-proxy: буквы сдвинуты назад на их число, «.com» → «.co.uk».
fn decode_cf(s: &str) -> String {
    let Some(p) = s.strip_suffix(".com") else { return s.to_string() };
    let n = p.chars().filter(|c| c.is_ascii_alphabetic()).count() as u32;
    let shift = |c: char, base: u8| ((((c as u8 - base) as u32 + 26 * 8 - n % 26) % 26) as u8 + base) as char;
    let out: String = p
        .chars()
        .map(|c| match c {
            'a'..='z' => shift(c, b'a'),
            'A'..='Z' => shift(c, b'A'),
            _ => c,
        })
        .collect();
    out + ".co.uk"
}

/// Домен годится: буквы, цифры, дефисы, точки; не IP; не длиннее 253.
pub fn valid_domain(d: &str) -> bool {
    let labels: Vec<&str> = d.split('.').collect();
    d.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && labels.last().is_some_and(|t| t.len() >= 2 && t.chars().any(|c| c.is_ascii_alphabetic()))
}

pub fn default_cf_domains() -> Vec<String> {
    CF_ENC.iter().map(|d| decode_cf(d)).collect()
}

/// Список с GitHub: по строке, # — комментарий. Кривые строки пропускаем, не
/// больше 64 доменов. Меньше трёх годных — считаем, что список сломан.
pub fn parse_cf_list(text: &str) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let d = decode_cf(&line.to_ascii_lowercase());
        if valid_domain(&d) && !out.contains(&d) {
            out.push(d);
        }
        if out.len() >= 64 {
            break;
        }
    }
    (out.len() >= 3).then_some(out)
}

/// Скачать свежий список (`proxy` — socks5h://… работающего VPN, если есть).
pub async fn fetch_cf_list(proxy: Option<&str>) -> Result<Vec<String>, String> {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .https_only(true)
        .redirect(reqwest::redirect::Policy::limited(3));
    if let Some(p) = proxy {
        b = b.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?);
    }
    let resp = b.build().map_err(|e| e.to_string())?.get(CF_LIST_URL).send().await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body = crate::net::read_capped(resp, 64 * 1024).await?;
    parse_cf_list(&String::from_utf8_lossy(&body)).ok_or_else(|| trs!("в списке нет годных доменов").into())
}

// ---------------- обфускация (obfuscated2) ----------------

fn ctr(key: &[u8], iv: &[u8]) -> Ctr {
    Ctr::new(key.into(), iv.into())
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Что Telegram прислал в первых 64 байтах.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Hello {
    pub dc: i16,
    pub tag: [u8; 4],
}

/// Разобрать начало соединения клиента. None — не наш секрет (или не Telegram).
pub(crate) fn parse_hello(init: &[u8; HANDSHAKE_LEN], secret: &[u8; 16]) -> Option<Hello> {
    let key = sha256(&[&init[SKIP_LEN..SKIP_LEN + PREKEY_LEN], secret]);
    let iv = &init[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut buf = *init;
    ctr(&key, iv).apply_keystream(&mut buf);
    let tag: [u8; 4] = buf[PROTO_TAG_POS..PROTO_TAG_POS + 4].try_into().ok()?;
    if tag != TAG_ABRIDGED && tag != TAG_INTERMEDIATE && tag != TAG_SECURE {
        return None;
    }
    let dc = i16::from_le_bytes([buf[DC_IDX_POS], buf[DC_IDX_POS + 1]]);
    Some(Hello { dc, tag })
}

/// Начало соединения к Telegram от нас: случайное, с тегом протокола и номером ДЦ.
pub(crate) fn relay_init(tag: [u8; 4], dc_idx: i16) -> [u8; HANDSHAKE_LEN] {
    let mut rnd = [0u8; HANDSHAKE_LEN];
    loop {
        getrandom::getrandom(&mut rnd).expect("нет источника случайных чисел");
        let start: [u8; 4] = rnd[..4].try_into().unwrap();
        let reserved_start = [*b"HEAD", *b"POST", *b"GET ", TAG_INTERMEDIATE, TAG_SECURE, [0x16, 0x03, 0x01, 0x02], *b"OPTI"];
        if rnd[0] != 0xef && !reserved_start.contains(&start) && rnd[4..8] != [0, 0, 0, 0] {
            break;
        }
    }
    let mut enc = rnd;
    ctr(&rnd[SKIP_LEN..SKIP_LEN + PREKEY_LEN], &rnd[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]).apply_keystream(&mut enc);
    let mut tail = [0u8; 8];
    tail[..4].copy_from_slice(&tag);
    tail[4..6].copy_from_slice(&dc_idx.to_le_bytes());
    getrandom::getrandom(&mut tail[6..]).expect("нет источника случайных чисел");
    let mut out = rnd;
    for i in 0..8 {
        let ks = enc[PROTO_TAG_POS + i] ^ rnd[PROTO_TAG_POS + i];
        out[PROTO_TAG_POS + i] = tail[i] ^ ks;
    }
    out
}

/// Четыре шифра: от клиента / к клиенту, к Telegram / от Telegram.
pub(crate) struct Crypto {
    pub clt_dec: Ctr,
    pub clt_enc: Ctr,
    pub tg_enc: Ctr,
    pub tg_dec: Ctr,
}

impl Crypto {
    pub(crate) fn new(init: &[u8; HANDSHAKE_LEN], secret: &[u8; 16], relay: &[u8; HANDSHAKE_LEN]) -> Self {
        let pk_iv = &init[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
        let mut rev: Vec<u8> = pk_iv.to_vec();
        rev.reverse();
        let mut clt_dec = ctr(&sha256(&[&pk_iv[..PREKEY_LEN], secret]), &pk_iv[PREKEY_LEN..]);
        let clt_enc = ctr(&sha256(&[&rev[..PREKEY_LEN], secret]), &rev[PREKEY_LEN..]);
        clt_dec.apply_keystream(&mut [0u8; HANDSHAKE_LEN]); // первые 64 байта клиента уже прочитаны

        let r = &relay[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
        let mut rrev: Vec<u8> = r.to_vec();
        rrev.reverse();
        let mut tg_enc = ctr(&r[..PREKEY_LEN], &r[PREKEY_LEN..]);
        let tg_dec = ctr(&rrev[..PREKEY_LEN], &rrev[PREKEY_LEN..]);
        tg_enc.apply_keystream(&mut [0u8; HANDSHAKE_LEN]); // а наши 64 — уже отправлены
        Crypto { clt_dec, clt_enc, tg_enc, tg_dec }
    }
}

/// Нарезка потока на пакеты MTProto: веб-вход ждёт по пакету на сообщение WebSocket.
pub(crate) struct Splitter {
    tag: [u8; 4],
    cipher: Vec<u8>,
    plain: Vec<u8>,
    off: bool,
}

impl Splitter {
    pub(crate) fn new(tag: [u8; 4]) -> Self {
        Splitter { tag, cipher: Vec::new(), plain: Vec::new(), off: false }
    }

    /// Длина следующего пакета: None — ещё не пришёл целиком; Some(0) — не понять.
    fn next_len(&self, at: usize) -> Option<usize> {
        let p = &self.plain[at..];
        if p.is_empty() {
            return None;
        }
        let (head, body) = if self.tag == TAG_ABRIDGED {
            if p[0] & 0x7f == 0x7f {
                if p.len() < 4 {
                    return None;
                }
                (4, u32::from_le_bytes([p[1], p[2], p[3], 0]) as usize * 4)
            } else {
                (1, (p[0] & 0x7f) as usize * 4)
            }
        } else {
            if p.len() < 4 {
                return None;
            }
            (4, (u32::from_le_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff) as usize)
        };
        if body == 0 || body > WS_MAX_MESSAGE {
            return Some(0);
        }
        (p.len() >= head + body).then_some(head + body)
    }

    pub(crate) fn split(&mut self, cipher: &[u8], plain: &[u8]) -> Vec<Vec<u8>> {
        if self.off {
            return vec![cipher.to_vec()];
        }
        self.cipher.extend_from_slice(cipher);
        self.plain.extend_from_slice(plain);
        let mut parts = Vec::new();
        let mut at = 0;
        while at < self.cipher.len() {
            match self.next_len(at) {
                None => break,
                Some(0) => {
                    // Не разобрать (чужой протокол) — дальше шлём как есть.
                    parts.push(self.cipher[at..].to_vec());
                    at = self.cipher.len();
                    self.off = true;
                }
                Some(n) => {
                    parts.push(self.cipher[at..at + n].to_vec());
                    at += n;
                }
            }
        }
        self.cipher.drain(..at);
        self.plain.drain(..at);
        if self.cipher.len() > WS_MAX_MESSAGE {
            // Пакет больше разумного — не копим память, шлём как есть.
            parts.push(std::mem::take(&mut self.cipher));
            self.plain.clear();
            self.off = true;
        }
        parts
    }

    pub(crate) fn flush(&mut self) -> Option<Vec<u8>> {
        self.plain.clear();
        (!self.cipher.is_empty()).then(|| std::mem::take(&mut self.cipher))
    }
}

// ---------------- WebSocket (клиент, только то, что нужно) ----------------

trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
type BoxIo = Box<dyn Io>;

/// Что сервер WebSocket должен вернуть в Sec-WebSocket-Accept на наш ключ (RFC 6455).
fn ws_accept(key: &str) -> String {
    use base64::Engine;
    let mut d = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    d.update(key.as_bytes());
    d.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64::engine::general_purpose::STANDARD.encode(d.finish().as_ref())
}

/// Рукопожатие WebSocket. Ошибка — с кодом ответа (302 — у ДЦ нет веб-входа).
async fn ws_handshake(io: &mut BoxIo, host: &str, path: &str) -> Result<(), String> {
    let mut key = [0u8; 16];
    getrandom::getrandom(&mut key).map_err(|e| e.to_string())?;
    use base64::Engine;
    let key = base64::engine::general_purpose::STANDARD.encode(key);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\
         Origin: {ORIGIN}\r\nUser-Agent: {BROWSER_UA}\r\n\r\n"
    );
    io.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    // Заголовки ответа — до пустой строки, не больше 16 КБ. Читаем по байту:
    // после них сразу идут кадры WebSocket, лишнего забирать нельзя.
    let mut head = Vec::with_capacity(512);
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 16 * 1024 {
            return Err(trs!("слишком длинный ответ").into());
        }
        let b = io.read_u8().await.map_err(|e| e.to_string())?;
        head.push(b);
    }
    let text = String::from_utf8_lossy(&head);
    let status = text.split_whitespace().nth(1).unwrap_or("");
    if status != "101" {
        return Err(tr!("ответ {}", status.chars().filter(char::is_ascii_digit).take(3).collect::<String>()));
    }
    let accept = text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case("sec-websocket-accept").then(|| v.trim().to_string())
    });
    if accept.as_deref() != Some(ws_accept(&key).as_str()) {
        return Err(trs!("не тот ответ WebSocket").into());
    }
    Ok(())
}

fn ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 14);
    f.push(0x80 | opcode);
    let n = payload.len();
    if n < 126 {
        f.push(0x80 | n as u8);
    } else if n <= 0xffff {
        f.push(0x80 | 126);
        f.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        f.push(0x80 | 127);
        f.extend_from_slice(&(n as u64).to_be_bytes());
    }
    let mut mask = [0u8; 4];
    let _ = getrandom::getrandom(&mut mask);
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

type WsWriter = Arc<tokio::sync::Mutex<tokio::io::WriteHalf<BoxIo>>>;

async fn ws_send(w: &WsWriter, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
    let frame = ws_frame(opcode, payload);
    let mut w = w.lock().await;
    w.write_all(&frame).await
}

/// Следующее сообщение с данными. None — сервер закрыл соединение.
async fn ws_recv(r: &mut tokio::io::ReadHalf<BoxIo>, w: &WsWriter, pong: &Arc<std::sync::atomic::AtomicBool>) -> std::io::Result<Option<Vec<u8>>> {
    let mut msg: Vec<u8> = Vec::new();
    loop {
        let mut h = [0u8; 2];
        r.read_exact(&mut h).await?;
        let (fin, opcode) = (h[0] & 0x80 != 0, h[0] & 0x0f);
        let masked = h[1] & 0x80 != 0;
        let len = match h[1] & 0x7f {
            126 => r.read_u16().await? as usize,
            127 => usize::try_from(r.read_u64().await?).unwrap_or(usize::MAX),
            n => n as usize,
        };
        if len > WS_MAX_MESSAGE || msg.len() + len > WS_MAX_MESSAGE || (opcode >= 0x8 && len > WS_MAX_CONTROL) {
            return Err(std::io::Error::other(trs!("слишком большое сообщение WebSocket")));
        }
        let mut mask = [0u8; 4];
        if masked {
            r.read_exact(&mut mask).await?;
        }
        let mut data = vec![0u8; len];
        r.read_exact(&mut data).await?;
        if masked {
            data.iter_mut().enumerate().for_each(|(i, b)| *b ^= mask[i % 4]);
        }
        match opcode {
            0x0..=0x2 => {
                msg.extend_from_slice(&data);
                if fin {
                    return Ok(Some(msg));
                }
            }
            0x8 => {
                if let Ok(mut g) = w.try_lock() {
                    let _ = g.write_all(&ws_frame(0x8, &data[..data.len().min(2)])).await;
                }
                return Ok(None);
            }
            // Ответ на ping — отдельной задачей: ждать замок здесь, пока отправка
            // встала на полном сокете, значит застрять в обе стороны. Не больше
            // одного ответа в очереди (сервер, сыплющий ping, память не съест).
            0x9 => {
                if !pong.swap(true, Ordering::SeqCst) {
                    let (w, pong, frame) = (w.clone(), pong.clone(), ws_frame(0xA, &data));
                    tokio::spawn(async move {
                        let _ = w.lock().await.write_all(&frame).await;
                        pong.store(false, Ordering::SeqCst);
                    });
                }
            }
            0xA => {}
            _ => return Err(std::io::Error::other(trs!("неизвестный кадр WebSocket"))),
        }
    }
}

// ---------------- подключение ----------------

/// Тесты: куда «резолвить» имя.
#[cfg(test)]
type Resolve = Arc<dyn Fn(&str) -> Option<SocketAddr> + Send + Sync>;

/// Как подключаться наружу. В тестах — без TLS, на локальные адреса.
#[derive(Clone)]
pub(crate) enum Dial {
    Tls(Arc<rustls::ClientConfig>),
    #[cfg(test)]
    Plain(Resolve),
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

async fn tcp(addr: SocketAddr, t: Duration) -> Result<TcpStream, String> {
    let s = tokio::time::timeout(t, TcpStream::connect(addr)).await.map_err(|_| trs!("нет ответа").to_string())?.map_err(|e| e.to_string())?;
    let _ = s.set_nodelay(true);
    Ok(s)
}

/// WebSocket к `host` (сертификат проверяется по нему); `ip` — куда подключаться
/// (None — по DNS).
async fn ws_open(dial: &Dial, ip: Option<IpAddr>, host: &str, path: &str, t: Duration) -> Result<BoxIo, String> {
    let mut io: BoxIo = match dial {
        Dial::Tls(cfg) => {
            let addr = match ip {
                Some(ip) => SocketAddr::new(ip, 443),
                None => tokio::time::timeout(t, tokio::net::lookup_host((host, 443)))
                    .await
                    .map_err(|_| trs!("DNS не ответил").to_string())?
                    .map_err(|e| e.to_string())?
                    .find(|a| public_ip(&a.ip()))
                    .ok_or(trs!("DNS: нет адреса в интернете"))?,
            };
            let s = tcp(addr, t).await?;
            let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
            let tls = tokio::time::timeout(t, tokio_rustls::TlsConnector::from(cfg.clone()).connect(name, s))
                .await
                .map_err(|_| trs!("TLS: нет ответа").to_string())?
                .map_err(|e| format!("TLS: {e}"))?;
            Box::new(tls)
        }
        #[cfg(test)]
        Dial::Plain(resolve) => Box::new(tcp(resolve(host).ok_or(trs!("нет такого"))?, t).await?),
    };
    tokio::time::timeout(t, ws_handshake(&mut io, host, path)).await.map_err(|_| trs!("WebSocket: нет ответа").to_string())??;
    Ok(io)
}

/// Каким путём пошло соединение.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    Web,
    Cloudflare,
    Direct,
}

/// Счётчики для окна.
#[derive(Default)]
pub struct Stats {
    pub active: AtomicUsize,
    pub total: AtomicU64,
    pub web: AtomicU64,
    pub cloudflare: AtomicU64,
    pub direct: AtomicU64,
    pub failed: AtomicU64,
    pub bad_secret: AtomicU64,
    pub last_error: Mutex<String>,
}

pub(crate) struct Shared {
    pub secret: [u8; 16],
    pub cf: RwLock<Vec<String>>,
    pub cf_on: bool,
    pub dial: Dial,
    pub stats: Arc<Stats>,
    /// Какой Cloudflare-домен сработал последним (с него и начинаем).
    pub cf_last: Mutex<Option<String>>,
    /// Когда веб-вход ДЦ / Cloudflare последний раз не ответили (пауза PATH_PAUSE).
    pub web_down: Mutex<std::collections::HashMap<u16, std::time::Instant>>,
    pub cf_down: Mutex<Option<std::time::Instant>>,
    /// Адреса ДЦ напрямую (в тестах — свои).
    pub dc_ips: Vec<(u16, SocketAddr)>,
    /// Адреса веб-входа по ДЦ (в тестах — свои).
    pub web_ips: Vec<(u16, IpAddr)>,
}

enum Upstream {
    Ws(BoxIo),
    Tcp(TcpStream),
}

async fn connect_upstream(sh: &Shared, dc: u16, media: bool, test: bool) -> Result<(Upstream, Route), String> {
    let path = if test { "/apiws_test" } else { "/apiws" };
    let ws_dc = if dc == 203 { 2 } else { dc };
    let mut errs: Vec<String> = Vec::new();
    // 1. Веб-вход Telegram.
    if let Some(&(_, ip)) = sh.web_ips.iter().find(|(d, _)| *d == ws_dc) {
        let hosts: Vec<String> = if media {
            vec![format!("kws{ws_dc}-1.web.telegram.org"), format!("kws{ws_dc}.web.telegram.org")]
        } else {
            vec![format!("kws{ws_dc}.web.telegram.org")]
        };
        let paused = sh.web_down.lock().unwrap().get(&ws_dc).is_some_and(|t| t.elapsed() < PATH_PAUSE);
        if !paused {
            for h in hosts {
                match tokio::time::timeout(CONNECT_TIMEOUT, ws_open(&sh.dial, Some(ip), &h, path, CONNECT_TIMEOUT))
                    .await
                    .unwrap_or_else(|_| Err(trs!("нет ответа").into()))
                {
                    Ok(io) => {
                        sh.web_down.lock().unwrap().remove(&ws_dc);
                        return Ok((Upstream::Ws(io), Route::Web));
                    }
                    Err(e) => errs.push(format!("{h}: {e}")),
                }
            }
            sh.web_down.lock().unwrap().insert(ws_dc, std::time::Instant::now());
        }
    }
    // 2. Через Cloudflare: сначала домен, что сработал последним.
    let cf_paused = sh.cf_down.lock().unwrap().is_some_and(|t| t.elapsed() < PATH_PAUSE);
    if sh.cf_on && !test && !cf_paused {
        let mut list = sh.cf.read().unwrap().clone();
        if let Some(last) = sh.cf_last.lock().unwrap().clone() {
            if let Some(i) = list.iter().position(|d| *d == last) {
                list.swap(0, i);
            }
        }
        for (n, d) in list.iter().take(CF_TRIES).enumerate() {
            let h = format!("kws{ws_dc}.{d}");
            match tokio::time::timeout(CF_TIMEOUT, ws_open(&sh.dial, None, &h, path, CF_TIMEOUT))
                .await
                .unwrap_or_else(|_| Err(trs!("нет ответа").into()))
            {
                Ok(io) => {
                    *sh.cf_last.lock().unwrap() = Some(d.clone());
                    *sh.cf_down.lock().unwrap() = None;
                    return Ok((Upstream::Ws(io), Route::Cloudflare));
                }
                // Домены в лог не пишем: лог выкладывают в чаты, а их там ищут.
                Err(e) => errs.push(format!("Cloudflare №{}: {e}", n + 1)),
            }
        }
        // Не ответил ни один — следующий раз начнём с другого и сделаем паузу.
        let mut last = sh.cf_last.lock().unwrap();
        *last = list.get(CF_TRIES).cloned().or_else(|| list.first().cloned());
        *sh.cf_down.lock().unwrap() = Some(std::time::Instant::now());
    }
    // 3. Напрямую, как Telegram без прокси.
    let table: Vec<(u16, SocketAddr)> = if test {
        DC_TEST_IPS.iter().map(|(d, ip)| (*d, SocketAddr::new(IpAddr::V4(*ip), 443))).collect()
    } else {
        sh.dc_ips.clone()
    };
    if let Some((_, addr)) = table.iter().find(|(d, _)| *d == dc) {
        match tcp(*addr, CONNECT_TIMEOUT).await {
            Ok(s) => return Ok((Upstream::Tcp(s), Route::Direct)),
            Err(e) => errs.push(format!("{addr}: {e}")),
        }
    }
    Err(if errs.is_empty() { tr!("неизвестный ДЦ {dc}") } else { errs.join("; ") })
}

/// Клиент закрыл соединение (пока ждём сервер, его данные не трогаем — только смотрим).
async fn client_gone(cl: &TcpStream) {
    let mut b = [0u8; 1];
    loop {
        if cl.readable().await.is_err() {
            return;
        }
        match cl.peek(&mut b).await {
            Ok(0) | Err(_) => return,
            // Telegram уже прислал следующий пакет — он подождёт в сокете.
            Ok(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

/// Адрес из DNS чужого домена годится, только если он в интернете, а не в
/// домашней сети или на этом компе.
fn public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_broadcast()
                || o[0] == 0
                || o[0] == 100 && (64..128).contains(&o[1])
                || o[0] == 192 && o[1] == 0 && o[2] == 0
                || o[0] == 198 && (18..20).contains(&o[1])
                || o[0] >= 224)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            !(v.is_loopback() || v.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || v.is_multicast())
                && v.to_ipv4_mapped().is_none_or(|m| public_ip(&IpAddr::V4(m)))
        }
    }
}

/// Одно соединение Telegram от начала до конца.
async fn handle(mut cl: TcpStream, sh: Arc<Shared>) -> Result<Route, String> {
    let _ = cl.set_nodelay(true);
    let mut init = [0u8; HANDSHAKE_LEN];
    tokio::time::timeout(Duration::from_secs(10), cl.read_exact(&mut init))
        .await
        .map_err(|_| trs!("клиент молчит").to_string())?
        .map_err(|e| e.to_string())?;
    let Some(hello) = parse_hello(&init, &sh.secret) else {
        sh.stats.bad_secret.fetch_add(1, Ordering::Relaxed);
        // Не наш клиент: молча читаем до конца, ничего не отвечаем.
        let _ = tokio::time::timeout(Duration::from_secs(10), tokio::io::copy(&mut cl, &mut tokio::io::sink())).await;
        return Err(trs!("чужой секрет").into());
    };
    let media = hello.dc < 0;
    let mut dc = hello.dc.unsigned_abs();
    let test = dc >= 10000;
    if test {
        dc -= 10000;
    }
    let dc_idx = if media { -(dc as i16) } else { dc as i16 };
    let relay = relay_init(hello.tag, dc_idx);
    let mut c = Crypto::new(&init, &sh.secret, &relay);
    // Наружу — не дольше UPSTREAM_DEADLINE и только пока Telegram ждёт: ушёл —
    // бросаем (иначе медленные пути копили бы занятые места).
    let (up, route) = tokio::select! {
        r = tokio::time::timeout(UPSTREAM_DEADLINE, connect_upstream(&sh, dc, media, test)) => {
            r.map_err(|_| trs!("ни один путь не ответил вовремя").to_string())??
        }
        _ = client_gone(&cl) => return Err(trs!("Telegram закрыл соединение, не дождавшись").into()),
    };
    match route {
        Route::Web => sh.stats.web.fetch_add(1, Ordering::Relaxed),
        Route::Cloudflare => sh.stats.cloudflare.fetch_add(1, Ordering::Relaxed),
        Route::Direct => sh.stats.direct.fetch_add(1, Ordering::Relaxed),
    };
    let (mut cr, mut cw) = cl.into_split();
    let mut buf = vec![0u8; 64 * 1024];
    match up {
        Upstream::Ws(io) => {
            let (mut wr, ww) = tokio::io::split(io);
            let ww: WsWriter = Arc::new(tokio::sync::Mutex::new(ww));
            ws_send(&ww, 0x2, &relay).await.map_err(|e| e.to_string())?;
            let ww2 = ww.clone();
            let (mut clt_dec, mut tg_enc) = (c.clt_dec, c.tg_enc);
            let mut split = Splitter::new(hello.tag);
            let upward = async move {
                loop {
                    let n = cr.read(&mut buf).await?;
                    if n == 0 {
                        if let Some(tail) = split.flush() {
                            ws_send(&ww2, 0x2, &tail).await?;
                        }
                        return Ok::<_, std::io::Error>(());
                    }
                    let mut plain = buf[..n].to_vec();
                    clt_dec.apply_keystream(&mut plain);
                    let mut cipher = plain.clone();
                    tg_enc.apply_keystream(&mut cipher);
                    for part in split.split(&cipher, &plain) {
                        ws_send(&ww2, 0x2, &part).await?;
                    }
                }
            };
            let downward = async {
                let pong = Arc::new(std::sync::atomic::AtomicBool::new(false));
                while let Some(mut data) = ws_recv(&mut wr, &ww, &pong).await? {
                    c.tg_dec.apply_keystream(&mut data);
                    c.clt_enc.apply_keystream(&mut data);
                    cw.write_all(&data).await?;
                }
                Ok::<_, std::io::Error>(())
            };
            tokio::select! {
                _ = upward => {}
                _ = downward => {}
            }
        }
        Upstream::Tcp(s) => {
            let (mut tr, mut tw) = s.into_split();
            tw.write_all(&relay).await.map_err(|e| e.to_string())?;
            let (mut clt_dec, mut tg_enc) = (c.clt_dec, c.tg_enc);
            let upward = async move {
                loop {
                    let n = cr.read(&mut buf).await?;
                    if n == 0 {
                        return Ok::<_, std::io::Error>(());
                    }
                    clt_dec.apply_keystream(&mut buf[..n]);
                    tg_enc.apply_keystream(&mut buf[..n]);
                    tw.write_all(&buf[..n]).await?;
                }
            };
            let downward = async {
                let mut b = vec![0u8; 64 * 1024];
                loop {
                    let n = tr.read(&mut b).await?;
                    if n == 0 {
                        return Ok::<_, std::io::Error>(());
                    }
                    c.tg_dec.apply_keystream(&mut b[..n]);
                    c.clt_enc.apply_keystream(&mut b[..n]);
                    cw.write_all(&b[..n]).await?;
                }
            };
            tokio::select! {
                _ = upward => {}
                _ = downward => {}
            }
        }
    }
    Ok(route)
}

// ---------------- сервер ----------------

/// Настройки запуска.
#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub secret: [u8; 16],
    /// Запасной путь через Cloudflare.
    pub cf_on: bool,
    /// Свои домены (пусто — общие).
    pub cf_domains: Vec<String>,
}

/// Работающий прокси. Пока живёт — принимает соединения; уронили — всё закрыто.
pub struct Running {
    stop: tokio::sync::watch::Sender<bool>,
    pub stats: Arc<Stats>,
    pub port: u16,
    shared: Arc<Shared>,
    accept: Option<tokio::task::JoinHandle<()>>,
}

impl Running {
    /// Остановить и дождаться, пока порт освободится (чтобы сразу занять его снова).
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        if let Some(t) = self.accept.take() {
            let _ = t.await;
        }
    }

    /// Обновить общие Cloudflare-домены (свежий список с GitHub).
    pub fn set_cf_domains(&self, list: Vec<String>) {
        *self.shared.cf.write().unwrap() = list;
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
    }
}

pub fn new_secret() -> [u8; 16] {
    let mut s = [0u8; 16];
    getrandom::getrandom(&mut s).expect("нет источника случайных чисел");
    s
}

pub fn secret_from_hex(h: &str) -> Option<[u8; 16]> {
    if h.len() != 32 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut s = [0u8; 16];
    for (i, b) in s.iter_mut().enumerate() {
        *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(s)
}

pub fn secret_hex(s: &[u8; 16]) -> String {
    s.iter().map(|b| format!("{b:02x}")).collect()
}

/// Ссылка для Telegram: открыть — и он сам предложит добавить прокси.
/// «dd» — режим со случайной добивкой (так трафик к прокси не узнать по длинам).
pub fn link(port: u16, secret: &[u8; 16]) -> String {
    format!("tg://proxy?server=127.0.0.1&port={port}&secret=dd{}", secret_hex(secret))
}

/// Запустить прокси на 127.0.0.1:`port` (только этот комп, из сети не достучаться).
pub async fn start(cfg: Config, log: impl Fn(String) + Send + Sync + 'static) -> Result<Running, String> {
    let dial = Dial::Tls(tls_config());
    let dc_ips = DC_IPS.iter().map(|(d, ip)| (*d, SocketAddr::new(IpAddr::V4(*ip), 443))).collect();
    let web_ips = WEB_IPS.iter().map(|(d, ip)| (*d, IpAddr::V4(*ip))).collect();
    start_with(cfg, dial, dc_ips, web_ips, log).await
}

pub(crate) async fn start_with(
    cfg: Config,
    dial: Dial,
    dc_ips: Vec<(u16, SocketAddr)>,
    web_ips: Vec<(u16, IpAddr)>,
    log: impl Fn(String) + Send + Sync + 'static,
) -> Result<Running, String> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, cfg.port)).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            tr!("порт {} занят (другой tg-ws-proxy?) — закрой его или поменяй порт", cfg.port)
        } else {
            tr!("не открыть порт {}: {e}", cfg.port)
        }
    })?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let stats = Arc::new(Stats::default());
    let cf = if cfg.cf_domains.is_empty() { default_cf_domains() } else { cfg.cf_domains.clone() };
    let shared = Arc::new(Shared {
        secret: cfg.secret,
        cf: RwLock::new(cf),
        cf_on: cfg.cf_on,
        dial,
        stats: stats.clone(),
        cf_last: Mutex::new(None),
        web_down: Mutex::new(std::collections::HashMap::new()),
        cf_down: Mutex::new(None),
        dc_ips,
        web_ips,
    });
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let sh = shared.clone();
    let log = Arc::new(log);
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNS));
    let accept = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                a = listener.accept() => a,
                _ = stopped.changed() => break,
            };
            let Ok((sock, peer)) = accepted else { continue };
            // Только с этого компа (слушаем 127.0.0.1, но проверим ещё раз).
            if !peer.ip().is_loopback() {
                continue;
            }
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue; // перебор соединений — новое просто закрываем
            };
            let (sh, log, mut stop) = (sh.clone(), log.clone(), stopped.clone());
            tokio::spawn(async move {
                let _permit = permit;
                sh.stats.total.fetch_add(1, Ordering::Relaxed);
                sh.stats.active.fetch_add(1, Ordering::Relaxed);
                let r = tokio::select! {
                    r = handle(sock, sh.clone()) => r,
                    _ = stop.changed() => Ok(Route::Direct),
                };
                sh.stats.active.fetch_sub(1, Ordering::Relaxed);
                if let Err(e) = r {
                    if e != trs!("чужой секрет") {
                        sh.stats.failed.fetch_add(1, Ordering::Relaxed);
                        let mut last = sh.stats.last_error.lock().unwrap();
                        // В лог — только новые ошибки, не по каждому соединению.
                        if *last != e {
                            log(tr!("Telegram: не подключился — {e}"));
                            *last = e;
                        }
                    }
                }
            });
        }
    });
    Ok(Running { stop, stats, port, shared, accept: Some(accept) })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Клиентская сторона obfuscated2 — как её делает Telegram Desktop с секретом:
    /// первые 56 байт — открытые случайные, последние 8 (тег и ДЦ) — зашифрованы.
    struct Client {
        init: [u8; 64],
        enc: Ctr,
        dec: Ctr,
    }

    fn client(secret: &[u8; 16], tag: [u8; 4], dc: i16) -> Client {
        let mut init = [0u8; 64];
        loop {
            getrandom::getrandom(&mut init).unwrap();
            if init[0] != 0xef && init[4..8] != [0; 4] {
                break;
            }
        }
        init[56..60].copy_from_slice(&tag);
        init[60..62].copy_from_slice(&dc.to_le_bytes());
        let mut rev = init[8..56].to_vec();
        rev.reverse();
        let mut enc = ctr(&sha256(&[&init[8..40], secret]), &init[40..56]);
        let dec = ctr(&sha256(&[&rev[..32], secret]), &rev[32..]);
        let mut e = init;
        enc.apply_keystream(&mut e);
        init[56..64].copy_from_slice(&e[56..64]);
        Client { init, enc, dec }
    }

    /// Сторона Telegram: разбирает наше начало (без секрета) и шифры для ответа.
    fn server(relay: &[u8; 64]) -> (Hello, Ctr, Ctr) {
        let mut dec = ctr(&relay[8..40], &relay[40..56]);
        let mut rev = relay[8..56].to_vec();
        rev.reverse();
        let enc = ctr(&rev[..32], &rev[32..]);
        let mut d = *relay;
        dec.apply_keystream(&mut d);
        let hello = Hello { tag: d[56..60].try_into().unwrap(), dc: i16::from_le_bytes([d[60], d[61]]) };
        (hello, dec, enc)
    }

    #[test]
    fn decode_cf_domains() {
        assert_eq!(decode_cf("virkgj.com"), "pclead.co.uk");
        assert_eq!(decode_cf("zaewayzmplad.com"), "noskomnadzor.co.uk"); // сверено с _dd() из tg-ws-proxy
        let all = default_cf_domains();
        assert_eq!(all.len(), CF_ENC.len());
        assert!(all.iter().all(|d| valid_domain(d) && d.ends_with(".co.uk")), "{all:?}");
        let parsed = parse_cf_list("# c\nvirkgj.com\n\nbad domain\nvmmzovy.com\nmkuosckvso.com\n").unwrap();
        assert_eq!(parsed.len(), 3);
        assert!(parse_cf_list("virkgj.com\n").is_none(), "меньше трёх — список сломан");
        for bad in ["a", "-a.com", "a..b", "1.2.3.4", "a_b.com", "x.c", "a.b/c.com"] {
            assert!(!valid_domain(bad), "{bad}");
        }
    }

    #[test]
    fn only_public_ips_from_dns() {
        for ok in ["104.16.1.1", "149.154.167.220", "2606:4700::1"] {
            assert!(public_ip(&ok.parse().unwrap()), "{ok}");
        }
        for bad in ["127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "0.1.2.3", "192.0.0.8", "198.18.0.1", "224.0.0.1", "::1", "fd00::1", "fe80::1", "::ffff:192.168.1.1"] {
            assert!(!public_ip(&bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn secret_and_link() {
        let s = new_secret();
        assert_eq!(secret_from_hex(&secret_hex(&s)), Some(s));
        assert!(secret_from_hex("zz").is_none());
        assert!(secret_from_hex(&"g".repeat(32)).is_none());
        assert!(link(1443, &[0xab; 16]).starts_with("tg://proxy?server=127.0.0.1&port=1443&secret=ddabab"));
    }

    #[test]
    fn handshake_and_reencrypt() {
        let secret = new_secret();
        for (tag, dc) in [(TAG_SECURE, 2i16), (TAG_INTERMEDIATE, -4), (TAG_ABRIDGED, 10003)] {
            let mut c = client(&secret, tag, dc);
            assert_eq!(parse_hello(&c.init, &secret), Some(Hello { dc, tag }));
            assert_eq!(parse_hello(&c.init, &new_secret()), None, "чужой секрет не проходит");
            let relay = relay_init(tag, dc);
            let (h, mut sdec, mut senc) = server(&relay);
            assert_eq!(h, Hello { dc, tag }, "Telegram видит тот же протокол и ДЦ");
            let mut cr = Crypto::new(&c.init, &secret, &relay);
            // клиент → Telegram
            let msg = b"hello mtproto".to_vec();
            let mut wire = msg.clone();
            c.enc.apply_keystream(&mut wire);
            cr.clt_dec.apply_keystream(&mut wire);
            cr.tg_enc.apply_keystream(&mut wire);
            sdec.apply_keystream(&mut wire);
            assert_eq!(wire, msg);
            // Telegram → клиент
            let back = b"answer".to_vec();
            let mut wire = back.clone();
            senc.apply_keystream(&mut wire);
            cr.tg_dec.apply_keystream(&mut wire);
            cr.clt_enc.apply_keystream(&mut wire);
            c.dec.apply_keystream(&mut wire);
            assert_eq!(wire, back);
        }
        // Наше начало не похоже на HTTP/TLS и не начинается с 0xef.
        for _ in 0..200 {
            let r = relay_init(TAG_SECURE, 2);
            assert_ne!(r[0], 0xef);
            assert!(!r.starts_with(b"GET ") && !r.starts_with(b"POST") && r[4..8] != [0; 4]);
        }
    }

    #[test]
    fn splitter_cuts_packets() {
        // intermediate: 4 байта длины + тело
        let mut sp = Splitter::new(TAG_INTERMEDIATE);
        let mut plain = Vec::new();
        for n in [8u32, 12, 4] {
            plain.extend_from_slice(&n.to_le_bytes());
            plain.extend(std::iter::repeat_n(n as u8, n as usize));
        }
        let cipher: Vec<u8> = plain.iter().map(|b| b ^ 0x55).collect();
        // Приходит кусками: первый пакет и половина второго, потом остальное.
        let a = sp.split(&cipher[..18], &plain[..18]);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].len(), 12);
        let b = sp.split(&cipher[18..], &plain[18..]);
        assert_eq!(b.iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 8]);
        assert!(sp.flush().is_none());
        // abridged: длина/4 в первом байте, 0x7f — длинная форма
        let mut sp = Splitter::new(TAG_ABRIDGED);
        let mut p = vec![2u8];
        p.extend([1; 8]);
        p.extend([0x7f, 1, 0, 0]);
        p.extend([2; 4]);
        let parts = sp.split(&p, &p);
        assert_eq!(parts.iter().map(Vec::len).collect::<Vec<_>>(), vec![9, 8]);
        // мусор (нулевая длина) — дальше без нарезки
        let mut sp = Splitter::new(TAG_SECURE);
        let parts = sp.split(&[0, 0, 0, 0, 9, 9], &[0, 0, 0, 0, 9, 9]);
        assert_eq!(parts, vec![vec![0, 0, 0, 0, 9, 9]]);
        assert_eq!(sp.split(&[1, 2], &[1, 2]), vec![vec![1, 2]]);
        // незаконченный хвост отдаётся при закрытии
        let mut sp = Splitter::new(TAG_INTERMEDIATE);
        assert!(sp.split(&[10, 0, 0, 0, 1], &[10, 0, 0, 0, 1]).is_empty());
        assert_eq!(sp.flush(), Some(vec![10, 0, 0, 0, 1]));
    }

    /// Поддельный веб-вход Telegram: WebSocket без TLS, отвечает эхом по пакетам.
    async fn fake_web(hosts: Arc<Mutex<Vec<String>>>, frames: Arc<AtomicUsize>, reject: &'static str) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                let (hosts, frames) = (hosts.clone(), frames.clone());
                tokio::spawn(async move {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        head.push(s.read_u8().await.unwrap());
                    }
                    let text = String::from_utf8(head).unwrap();
                    let host = text.lines().find_map(|l| l.strip_prefix("Host: ")).unwrap().to_string();
                    let key = text.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")).unwrap().to_string();
                    assert!(text.starts_with("GET /apiws HTTP/1.1\r\n"), "{text}");
                    assert!(text.contains("\r\nOrigin: https://web.telegram.org\r\n") && text.contains("Sec-WebSocket-Protocol: binary"));
                    hosts.lock().unwrap().push(host.clone());
                    if host.contains(reject) {
                        s.write_all(b"HTTP/1.1 302 Found\r\nLocation: https://x/\r\n\r\n").await.unwrap();
                        return;
                    }
                    let ok = format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                        if host.contains("badaccept") { "AAAA".to_string() } else { ws_accept(&key) }
                    );
                    s.write_all(ok.as_bytes()).await.unwrap();
                    if host.contains("badaccept") {
                        return;
                    }
                    let (mut r, w) = tokio::io::split(Box::new(s) as BoxIo);
                    let w: WsWriter = Arc::new(tokio::sync::Mutex::new(w));
                    let pong = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let first = ws_recv(&mut r, &w, &pong).await.unwrap().unwrap();
                    let (hello, mut dec, mut enc) = server(&first.try_into().unwrap());
                    assert_eq!(hello.tag, TAG_INTERMEDIATE);
                    while let Ok(Some(mut m)) = ws_recv(&mut r, &w, &pong).await {
                        frames.fetch_add(1, Ordering::SeqCst);
                        dec.apply_keystream(&mut m);
                        // ровно один пакет на сообщение
                        let n = u32::from_le_bytes(m[..4].try_into().unwrap()) as usize;
                        assert_eq!(m.len(), 4 + n);
                        enc.apply_keystream(&mut m);
                        // ответ — без маски, как настоящий сервер
                        let mut f = vec![0x82, m.len() as u8];
                        f.extend_from_slice(&m);
                        w.lock().await.write_all(&f).await.unwrap();
                    }
                });
            }
        });
        addr
    }

    /// Поддельный ДЦ напрямую: obfuscated2 по TCP, эхо.
    async fn fake_dc() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut init = [0u8; 64];
                    s.read_exact(&mut init).await.unwrap();
                    let (_, mut dec, mut enc) = server(&init);
                    let mut b = [0u8; 1024];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 {
                            break;
                        }
                        dec.apply_keystream(&mut b[..n]);
                        enc.apply_keystream(&mut b[..n]);
                        s.write_all(&b[..n]).await.unwrap();
                    }
                });
            }
        });
        addr
    }

    async fn roundtrip(port: u16, secret: &[u8; 16], dc: i16) -> Vec<u8> {
        let mut c = client(secret, TAG_INTERMEDIATE, dc);
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(&c.init).await.unwrap();
        // два пакета одной записью — веб-вход должен получить их по отдельности
        let mut plain = Vec::new();
        for n in [8u32, 20] {
            plain.extend_from_slice(&n.to_le_bytes());
            plain.extend(std::iter::repeat_n(n as u8, n as usize));
        }
        let mut wire = plain.clone();
        c.enc.apply_keystream(&mut wire);
        s.write_all(&wire).await.unwrap();
        let mut back = vec![0u8; plain.len()];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut back)).await.unwrap().unwrap();
        c.dec.apply_keystream(&mut back);
        assert_eq!(back, plain);
        back
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn proxy_end_to_end() {
        let hosts = Arc::new(Mutex::new(Vec::new()));
        let frames = Arc::new(AtomicUsize::new(0));
        let web = fake_web(hosts.clone(), frames.clone(), "kws4-1.").await;
        let dc = fake_dc().await;
        let resolve: Resolve = Arc::new(move |h: &str| {
            (h.ends_with(".web.telegram.org") || h.ends_with(".example.co.uk")).then_some(web)
        });
        // Сервер ответил на рукопожатие не тем ключом — не принимаем.
        let bad = ws_open(&Dial::Plain(resolve.clone()), None, "kws2.badaccept.example.co.uk", "/apiws", Duration::from_secs(3)).await;
        assert_eq!(bad.err().as_deref(), Some("не тот ответ WebSocket"));
        let secret = new_secret();
        let cfg = Config { port: 0, secret, cf_on: true, cf_domains: vec!["cf.example.co.uk".into()] };
        let lo = IpAddr::V4(Ipv4Addr::LOCALHOST);
        // Веб-вход в тесте — только у ДЦ 2 и 4 (ДЦ 3 пойдёт через Cloudflare).
        let p = start_with(cfg, Dial::Plain(resolve), vec![(3, dc), (2, dc)], vec![(2, lo), (4, lo)], |_| {}).await.unwrap();

        // ДЦ 2 — веб-вход, по сообщению на пакет
        roundtrip(p.port, &secret, 2).await;
        assert_eq!(hosts.lock().unwrap().last().unwrap(), "kws2.web.telegram.org");
        assert_eq!(frames.load(Ordering::SeqCst), 2);
        // медиа ДЦ 4: kws4-1 отказал (302) — следующий kws4
        roundtrip(p.port, &secret, -4).await;
        let h = hosts.lock().unwrap().clone();
        assert_eq!(&h[h.len() - 2..], ["kws4-1.web.telegram.org", "kws4.web.telegram.org"]);
        // ДЦ 3 — веб-входа нет: через Cloudflare-домен
        roundtrip(p.port, &secret, 3).await;
        assert_eq!(hosts.lock().unwrap().last().unwrap(), "kws3.cf.example.co.uk");
        assert_eq!(p.stats.web.load(Ordering::SeqCst), 2);
        assert_eq!(p.stats.cloudflare.load(Ordering::SeqCst), 1);
        drop(p);

        // Без Cloudflare ДЦ 3 — напрямую
        let resolve: Resolve = Arc::new(|_: &str| None);
        let cfg = Config { port: 0, secret, cf_on: false, cf_domains: vec![] };
        let p = start_with(cfg, Dial::Plain(resolve), vec![(3, dc)], vec![], |_| {}).await.unwrap();
        roundtrip(p.port, &secret, 3).await;
        assert_eq!(p.stats.direct.load(Ordering::SeqCst), 1);

        // Чужой секрет — ни байта в ответ
        let mut c = client(&new_secret(), TAG_INTERMEDIATE, 2);
        let mut s = TcpStream::connect(("127.0.0.1", p.port)).await.unwrap();
        s.write_all(&c.init).await.unwrap();
        let mut junk = vec![1u8; 32];
        c.enc.apply_keystream(&mut junk);
        s.write_all(&junk).await.unwrap();
        let mut b = [0u8; 1];
        assert!(tokio::time::timeout(Duration::from_millis(500), s.read(&mut b)).await.is_err(), "молчит");
        assert_eq!(p.stats.bad_secret.load(Ordering::SeqCst), 1);

        // Остановили — порт закрыт сразу и его можно занять снова
        let port = p.port;
        p.shutdown().await;
        assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
        let cfg = Config { port, secret, cf_on: false, cf_domains: vec![] };
        let again = start_with(cfg, Dial::Plain(Arc::new(|_: &str| None)), vec![], vec![], |_| {}).await;
        assert!(again.is_ok(), "порт свободен после shutdown");
    }
}
