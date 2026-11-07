//! «Почему не открывается сайт»: по шагам выясняем, что именно с ним сделал
//! провайдер, и говорим по-человечески, что включить.
//!
//! - DNS провайдера против DNS-over-HTTPS (Cloudflare / Google): подмена адреса;
//! - TCP до настоящего адреса сайта: блокировка по IP;
//! - TLS с именем сайта и с посторонним именем на тот же адрес: блокировка по имени (DPI);
//! - страница целиком (до 64 КБ): «замедлялка» с обрывом на 16–20 КБ;
//! - обычный HTTP: заглушка РКН;
//! - то же через VPN (если подключён): поможет ли VPN.
//!
//! Все проверки — только к самому сайту, DNS-сервисам и ya.ru (есть ли интернет).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
/// Сколько читать страницы: обрыв «замедлялки» — на 16–20 КБ.
const READ_MAX: usize = 64 * 1024;
/// Постороннее имя для TLS на тот же адрес: отвечает ли сервер вообще.
const NEUTRAL_SNI: &str = "www.google.com";
const CONTROL_URL: &str = "https://ya.ru/";

/// Адрес сайта из того, что ввёл человек: «site.ru», «https://site.ru/page», «сайт.рф».
pub fn normalize(input: &str) -> Result<String, String> {
    let t = input.trim();
    if t.is_empty() {
        return Err(trs!("Впиши адрес сайта").into());
    }
    let with_scheme = if t.contains("://") { t.to_string() } else { format!("https://{t}") };
    let url = url::Url::parse(&with_scheme).map_err(|_| tr!("«{}» — не похоже на адрес сайта", short(t, 60)))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(trs!("Нужен адрес сайта (http/https)").into());
    }
    let host = match url.host() {
        Some(url::Host::Domain(d)) => d.trim_end_matches('.').to_ascii_lowercase(),
        Some(_) => return Err(trs!("Впиши имя сайта, а не IP-адрес").into()),
        None => return Err(trs!("В адресе нет имени сайта").into()),
    };
    let fine = host.contains('.')
        && host.len() <= 253
        && host.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    if !fine {
        return Err(tr!("«{}» — не похоже на адрес сайта", short(t, 60)));
    }
    Ok(host)
}

fn short(s: &str, n: usize) -> String {
    let mut out: String = s.chars().take(n).collect();
    if s.chars().count() > n {
        out.push('…');
    }
    out
}

// ---------------- что выяснили ----------------

/// Ответ DNS-over-HTTPS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Doh {
    Ips(Vec<IpAddr>),
    /// Такого сайта нет (NXDOMAIN).
    NoSuch,
    /// DoH не ответил (его тоже могут резать).
    Failed,
}

/// TLS-рукопожатие.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tls {
    Ok,
    /// Сервер ответил, но не тем (чужой сертификат, отказ по имени) — путь открыт.
    Answered,
    /// Соединение оборвали посреди рукопожатия — так режет ТСПУ.
    Reset,
    Timeout,
    Other(String),
}

impl Tls {
    fn reached(&self) -> bool {
        matches!(self, Tls::Ok | Tls::Answered)
    }
}

/// Загрузка страницы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetch {
    /// Ответил (код HTTP).
    Ok(u16),
    /// Начал отдавать и замолчал (сколько байт успело прийти).
    Stall(usize),
    Fail(String),
}

impl Fetch {
    fn works(&self) -> bool {
        matches!(self, Fetch::Ok(c) if *c < 500)
    }
}

/// Все наблюдения разом — по ним решаем (отдельно, чтобы проверять тестами).
#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// ya.ru открылся: интернет есть.
    pub control_ok: bool,
    /// Адреса от DNS провайдера (системного).
    pub sys_ips: Vec<IpAddr>,
    pub doh: Option<Doh>,
    /// TCP до настоящего адреса (DoH, если ответил).
    pub tcp_ok: Option<bool>,
    pub tls_host: Option<Tls>,
    pub tls_neutral: Option<Tls>,
    /// Страница по настоящему адресу.
    pub https: Option<Fetch>,
    /// Страница по адресу от провайдера (если он другой).
    pub https_sys: Option<Fetch>,
    /// По обычному HTTP — заглушка РКН.
    pub stub: bool,
    /// Через VPN (None — VPN не подключён).
    pub vpn: Option<Fetch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Works,
    VpnRejected,
    DnsSpoof,
    Stub,
    IpBlock,
    SniBlock,
    Throttle,
    SiteDown,
    NoSuchSite,
    Offline,
    Unclear,
}

/// Что предложить кнопками: «vpn», «zapret», «direct».
pub fn decide(f: &Facts) -> (Verdict, Vec<&'static str>) {
    let vpn_ok = f.vpn.as_ref().is_some_and(Fetch::works);
    let vpn_failed = f.vpn.as_ref().is_some_and(|v| !v.works());
    let bogus = !f.sys_ips.is_empty() && f.sys_ips.iter().all(|ip| !public(ip));
    if !f.control_ok && !vpn_ok && f.doh != Some(Doh::NoSuch) && f.https.as_ref().is_none_or(|h| !h.works()) {
        return (Verdict::Offline, vec![]);
    }
    if f.doh == Some(Doh::NoSuch) && f.sys_ips.is_empty() {
        return (Verdict::NoSuchSite, vec![]);
    }
    let direct_ok = f.https.as_ref().is_some_and(Fetch::works);
    if direct_ok {
        // Браузер берёт адрес у провайдера: по нему не открывается (или там
        // заглушка), по настоящему — да. Иначе сайт работает, что бы ни было по HTTP.
        let spoofed = f.https_sys.as_ref().is_some_and(|h| !h.works()) || (f.stub && f.https_sys.is_some());
        if bogus || spoofed {
            return (Verdict::DnsSpoof, vec!["vpn"]);
        }
        if vpn_failed {
            return (Verdict::VpnRejected, vec!["direct"]);
        }
        return (Verdict::Works, vec![]);
    }
    if f.stub {
        return (Verdict::Stub, vec!["vpn"]);
    }
    if bogus {
        return (Verdict::DnsSpoof, vec!["vpn"]);
    }
    if f.tcp_ok == Some(false) {
        return if vpn_failed { (Verdict::SiteDown, vec![]) } else { (Verdict::IpBlock, vec!["vpn"]) };
    }
    let host_cut = matches!(f.tls_host, Some(Tls::Reset | Tls::Timeout));
    if host_cut && f.tls_neutral.as_ref().is_some_and(Tls::reached) {
        return (Verdict::SniBlock, vec!["zapret", "vpn"]);
    }
    if host_cut {
        // Ни своё имя, ни постороннее не проходят — режут сам адрес.
        return if vpn_failed { (Verdict::SiteDown, vec![]) } else { (Verdict::IpBlock, vec!["vpn"]) };
    }
    if matches!(f.https, Some(Fetch::Stall(_))) {
        return (Verdict::Throttle, vec!["zapret", "vpn"]);
    }
    if matches!(f.https, Some(Fetch::Ok(_))) {
        return (Verdict::SiteDown, vec![]);
    }
    (Verdict::Unclear, if vpn_ok { vec!["vpn"] } else { vec![] })
}

/// Заголовок и что делать — человеческими словами.
pub fn explain(v: Verdict, host: &str, vpn_tested: bool) -> (String, String) {
    let (t, a) = match v {
        Verdict::Works => (
            trs!("Открывается напрямую — провайдер его не трогает").to_string(),
            trs!("Дело не в блокировке. Попробуй обновить страницу без кэша (Ctrl+F5), другой браузер или выключи блокировщик рекламы").to_string(),
        ),
        Verdict::VpnRejected => (
            trs!("Напрямую открывается, а через VPN — нет").to_string(),
            trs!("Сайт не пускает иностранные адреса (так делают банки и госсайты). Пусти его напрямую — VPN для него не нужен").to_string(),
        ),
        Verdict::DnsSpoof => (
            trs!("Провайдер подменяет адрес сайта (DNS)").to_string(),
            trs!("Настоящий адрес рабочий, но браузер получает от провайдера другой. Пусти сайт через VPN — там DNS свой").to_string(),
        ),
        Verdict::Stub => (
            trs!("Провайдер показывает заглушку «доступ ограничен»").to_string(),
            trs!("Сайт в реестре блокировок. Надёжно поможет VPN").to_string(),
        ),
        Verdict::IpBlock => (
            trs!("Заблокирован по IP-адресу").to_string(),
            trs!("До сервера сайта не достучаться вообще — zapret тут не поможет, нужен VPN").to_string(),
        ),
        Verdict::SniBlock => (
            trs!("Режут по имени сайта (DPI)").to_string(),
            trs!("Сервер доступен, но провайдер обрывает соединение, увидев имя сайта. Поможет zapret (без VPN) или VPN").to_string(),
        ),
        Verdict::Throttle => (
            trs!("Замедление: страница обрывается на первых килобайтах").to_string(),
            trs!("Так режут YouTube и Discord: соединение есть, а данные не идут. Поможет zapret (без VPN) или VPN").to_string(),
        ),
        Verdict::SiteDown => (
            trs!("Сайт не работает сам").to_string(),
            if vpn_tested {
                trs!("Не открывается ни напрямую, ни через VPN — похоже, он лежит. Попробуй позже").to_string()
            } else {
                trs!("Сервер отвечает ошибкой или молчит — похоже, проблема на стороне сайта. Подключи VPN и проверь ещё раз, чтобы убедиться").to_string()
            },
        ),
        Verdict::NoSuchSite => (tr!("Сайта {host} не существует"), trs!("Проверь, нет ли опечатки в адресе").to_string()),
        Verdict::Offline => (
            trs!("Нет интернета").to_string(),
            trs!("Не открывается даже ya.ru. Проверь подключение к сети").to_string(),
        ),
        Verdict::Unclear => (
            trs!("Однозначно сказать не получилось").to_string(),
            trs!("Подробности — в шагах выше. Чаще всего помогает VPN").to_string(),
        ),
    };
    (t, a)
}

// ---------------- проверки ----------------

/// Один шаг проверки — для окна (по мере готовности).
#[derive(Debug, Clone, Serialize)]
pub struct Step {
    pub key: &'static str,
    pub title: &'static str,
    /// true — хорошо, false — плохо, None — не проверялось / нейтрально.
    pub ok: Option<bool>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub host: String,
    pub steps: Vec<Step>,
    pub verdict: Verdict,
    pub title: String,
    pub advice: String,
    /// Что предложить: «vpn», «zapret», «direct».
    pub actions: Vec<&'static str>,
}

/// Адрес в интернете (не домашний, не «никуда»): подставной ответ DNS часто такой.
fn public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private() || v.is_loopback() || v.is_link_local() || v.is_broadcast() || o[0] == 0 || o[0] >= 224
                || o[0] == 100 && (64..128).contains(&o[1])
                || o[0] == 198 && (o[1] == 18 || o[1] == 19)
                || o[..3] == [192, 0, 0])
        }
        IpAddr::V6(v) => !(v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xfe00) == 0xfc00),
    }
}

fn client(timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(UA)
}

fn err_text(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        trs!("нет ответа").into()
    } else if e.is_connect() {
        trs!("не подключиться").into()
    } else {
        let mut s = e.to_string();
        let mut src = std::error::Error::source(e);
        while let Some(x) = src {
            s = x.to_string();
            src = x.source();
        }
        short(&s, 120)
    }
}

/// Загрузить страницу, дочитав до 64 КБ (обрыв посередине — «замедлялка»).
async fn fetch(c: &reqwest::Client, url: &str) -> Fetch {
    match c.get(url).send().await {
        Err(e) => Fetch::Fail(err_text(&e)),
        Ok(mut r) => {
            let status = r.status().as_u16();
            let mut got = 0usize;
            loop {
                match r.chunk().await {
                    Ok(Some(ch)) => {
                        got += ch.len();
                        if got >= READ_MAX {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => return if got > 0 { Fetch::Stall(got) } else { Fetch::Fail(err_text(&e)) },
                }
            }
            Fetch::Ok(status)
        }
    }
}

/// DoH: Cloudflare и Google наперегонки, первый ответивший.
async fn doh(host: &str) -> Doh {
    let ask = |url: String| async move {
        let c = client(Duration::from_secs(5)).https_only(true).build().ok()?;
        let r = c.get(url).header("accept", "application/dns-json").send().await.ok()?;
        let body = crate::net::read_capped(r, 64 * 1024).await.ok()?;
        let v: serde_json::Value = serde_json::from_slice(&body).ok()?;
        match v["Status"].as_u64()? {
            3 => Some(Doh::NoSuch),
            0 => {
                let ips: Vec<IpAddr> = v["Answer"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter(|x| x["type"].as_u64() == Some(1))
                            .filter_map(|x| x["data"].as_str()?.parse().ok())
                            .collect()
                    })
                    .unwrap_or_default();
                Some(if ips.is_empty() { Doh::NoSuch } else { Doh::Ips(ips) })
            }
            _ => None,
        }
    };
    let a = Box::pin(ask(format!("https://cloudflare-dns.com/dns-query?name={host}&type=A")));
    let b = Box::pin(ask(format!("https://dns.google/resolve?name={host}&type=A")));
    match futures_first(a, b).await {
        Some(d) => d,
        None => Doh::Failed,
    }
}

/// Первый непустой результат из двух.
async fn futures_first<T, A, B>(a: A, b: B) -> Option<T>
where
    A: std::future::Future<Output = Option<T>> + Unpin,
    B: std::future::Future<Output = Option<T>> + Unpin,
{
    let (mut a, mut b) = (a, b);
    tokio::select! {
        r = &mut a => match r { Some(x) => Some(x), None => b.await },
        r = &mut b => match r { Some(x) => Some(x), None => a.await },
    }
}

async fn system_dns(host: &str) -> Vec<IpAddr> {
    let r = tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, 443))).await;
    let mut ips: Vec<IpAddr> = match r {
        Ok(Ok(it)) => it.map(|a| a.ip()).filter(IpAddr::is_ipv4).collect(),
        _ => Vec::new(),
    };
    ips.dedup();
    ips
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

async fn tcp(ip: IpAddr) -> Result<tokio::net::TcpStream, Tls> {
    match tokio::time::timeout(Duration::from_secs(4), tokio::net::TcpStream::connect(SocketAddr::new(ip, 443))).await {
        Err(_) => Err(Tls::Timeout),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Err(Tls::Other(trs!("порт закрыт").into())),
        Ok(Err(e)) => Err(Tls::Other(short(&e.to_string(), 80))),
        Ok(Ok(s)) => Ok(s),
    }
}

/// TLS-рукопожатие с именем `sni` на адрес `ip`.
async fn tls(ip: IpAddr, sni: &str) -> Tls {
    let s = match tcp(ip).await {
        Ok(s) => s,
        Err(t) => return t,
    };
    let Ok(name) = rustls::pki_types::ServerName::try_from(sni.to_string()) else { return Tls::Other(trs!("имя").into()) };
    let conn = tokio_rustls::TlsConnector::from(tls_config()).connect(name, s);
    match tokio::time::timeout(Duration::from_secs(5), conn).await {
        Err(_) => Tls::Timeout,
        Ok(Ok(_)) => Tls::Ok,
        Ok(Err(e)) => {
            let inner = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>());
            match (e.kind(), inner) {
                (_, Some(rustls::Error::InvalidCertificate(_) | rustls::Error::AlertReceived(_))) => Tls::Answered,
                (std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::UnexpectedEof, _) => {
                    Tls::Reset
                }
                _ => Tls::Other(short(&e.to_string(), 80)),
            }
        }
    }
}

/// Заглушка РКН по обычному HTTP (через DNS провайдера, как браузер). Только
/// к адресу в интернете: имя, которое ведёт в домашнюю сеть или на этот комп, не трогаем.
async fn stub_check(host: &str) -> Option<bool> {
    let ip = system_dns(host).await.into_iter().find(public)?;
    let c = client(Duration::from_secs(6)).resolve(host, SocketAddr::new(ip, 80)).build().ok()?;
    let r = c.get(format!("http://{host}/")).send().await.ok()?;
    let loc = r.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_ascii_lowercase();
    let body = crate::net::read_capped(r, 256 * 1024).await.unwrap_or_default();
    let text = String::from_utf8_lossy(&body[..body.len().min(64 * 1024)]).to_lowercase();
    Some(is_stub(&loc, &text))
}

/// Признаки страницы-заглушки провайдера: переадресация на неё или короткая
/// страница с текстом про блокировку. Длинная — это сам сайт: «Роскомнадзор» и
/// «149-ФЗ» есть в подвале почти любого российского СМИ.
pub fn is_stub(location: &str, body: &str) -> bool {
    const LOC: &[&str] = &["warning.rt.ru", "blocked.", "zapret", "rkn.gov.ru", "eais", "block.", "/blocked", "stop.", "fz139"];
    // i18n-skip-begin: текст страниц-заглушек провайдера — признак блокировки, не текст окна.
    const BODY: &[&str] = &[
        "rkn.gov.ru",
        "eais.rkn",
        "blocklist.rkn",
        "доступ ограничен",
        "доступ к ресурсу ограничен",
        "ограничен доступ",
        "заблокирован по решению",
        "единый реестр",
        "149-фз",
        "роскомнадзор",
    ];
    // i18n-skip-end
    LOC.iter().any(|m| location.contains(m)) || (body.len() < 16 * 1024 && BODY.iter().any(|m| body.contains(m)))
}

/// Проверить сайт. `vpn_proxy` — socks5h://127.0.0.1:порт работающего VPN (None — не подключён).
/// `sys_doh` — системный DNS сейчас наш DoH (режим «Без VPN» с «DNS без подмены»):
/// имя DoH-сервера. Тогда «DNS провайдера» в проверке — это уже DoH, и расхождение
/// с Cloudflare/Google (у CDN адреса разные) подменой не считается.
pub async fn run(input: &str, vpn_proxy: Option<String>, sys_doh: Option<&str>, step: impl Fn(&Step) + Send + Sync) -> Result<Report, String> {
    let host = normalize(input)?;
    let url = format!("https://{host}/");
    let mut steps: Vec<Step> = Vec::new();
    let mut f = Facts::default();
    let emit = |s: Step, steps: &mut Vec<Step>| {
        step(&s);
        steps.push(s);
    };

    // 1. Параллельно: есть ли интернет, DNS провайдера, DoH, заглушка, через VPN.
    let control = async {
        let c = client(Duration::from_secs(6)).build().ok()?;
        Some(fetch(&c, CONTROL_URL).await.works())
    };
    let vpn = async {
        let p = vpn_proxy.as_deref()?;
        let c = client(Duration::from_secs(12)).proxy(reqwest::Proxy::all(p).ok()?).build().ok()?;
        Some(fetch(&c, &url).await)
    };
    let (control, sys_ips, doh_r, stub, vpn) = tokio::join!(control, system_dns(&host), doh(&host), stub_check(&host), vpn);
    f.control_ok = control == Some(true);
    f.sys_ips = sys_ips;
    f.doh = Some(doh_r.clone());
    f.stub = stub == Some(true);
    f.vpn = vpn;

    emit(
        Step { key: "net", title: trs!("Интернет"), ok: Some(f.control_ok), detail: if f.control_ok { trs!("ya.ru открывается").into() } else { trs!("даже ya.ru не открывается").into() } },
        &mut steps,
    );
    let ips_text = |ips: &[IpAddr]| ips.iter().take(3).map(|i| i.to_string()).collect::<Vec<_>>().join(", ");
    let doh_ips: Vec<IpAddr> = match &doh_r {
        Doh::Ips(v) => v.clone(),
        _ => Vec::new(),
    };
    let dns_detail = match (&doh_r, f.sys_ips.is_empty()) {
        (_, false) if sys_doh.is_some() => tr!("через DoH rxvpn ({}): {} — провайдер DNS не видит и не подменяет",
            sys_doh.unwrap_or(""),
            ips_text(&f.sys_ips)
        ),
        (Doh::Ips(_), true) if sys_doh.is_some() => tr!("DoH rxvpn ({}) не дал адрес — смотри «Ещё → Лог»", sys_doh.unwrap_or("")),
        (Doh::NoSuch, true) => trs!("такого имени нет").to_string(),
        (_, true) => trs!("провайдер не дал адрес").to_string(),
        (Doh::Ips(d), false) if f.sys_ips.iter().any(|i| d.contains(i)) => tr!("адрес совпадает с настоящим: {}", ips_text(&f.sys_ips)),
        (Doh::Ips(d), false) => tr!("у провайдера {}, настоящий {}", ips_text(&f.sys_ips), ips_text(d)),
        (Doh::Failed, false) => tr!("{} (сверить не с чем: DNS-over-HTTPS не ответил)", ips_text(&f.sys_ips)),
        (Doh::NoSuch, false) => tr!("{} (по DNS-over-HTTPS такого имени нет)", ips_text(&f.sys_ips)),
    };
    let dns_bad = f.sys_ips.iter().any(|ip| !public(ip)) || (f.sys_ips.is_empty() && !doh_ips.is_empty());
    emit(Step { key: "dns", title: "DNS", ok: Some(!dns_bad && !f.sys_ips.is_empty()), detail: dns_detail }, &mut steps);

    // 2. По настоящему адресу (DoH; не ответил — провайдерский): IP, TLS, страница.
    //    Только адреса в интернете — к домашней сети и самому компу не подключаемся.
    let target = doh_ips.iter().find(|i| public(i)).or(f.sys_ips.iter().find(|i| public(i))).copied();
    if let Some(ip) = target {
        let host_tls = tls(ip, &host).await;
        f.tcp_ok = Some(!matches!(host_tls, Tls::Timeout | Tls::Other(_)) || {
            // TLS не вышел — проверим, есть ли вообще TCP.
            tcp(ip).await.is_ok()
        });
        emit(
            Step {
                key: "ip",
                title: trs!("Сервер сайта"),
                ok: f.tcp_ok,
                detail: if f.tcp_ok == Some(true) { tr!("{ip} доступен") } else { tr!("{ip} не отвечает") },
            },
            &mut steps,
        );
        if f.tcp_ok == Some(true) {
            let tls_detail = match &host_tls {
                Tls::Ok => trs!("рукопожатие прошло").to_string(),
                Tls::Answered => trs!("сервер ответил, но сертификат не для этого имени").to_string(),
                Tls::Reset => trs!("соединение оборвали, увидев имя сайта").to_string(),
                Tls::Timeout => trs!("после имени сайта — тишина").to_string(),
                Tls::Other(e) => e.clone(),
            };
            emit(Step { key: "tls", title: trs!("Защищённое соединение"), ok: Some(host_tls.reached()), detail: tls_detail }, &mut steps);
            if !host_tls.reached() {
                let n = tls(ip, NEUTRAL_SNI).await;
                emit(
                    Step {
                        key: "sni",
                        title: trs!("Тот же сервер под другим именем"),
                        ok: Some(n.reached()),
                        detail: if n.reached() { trs!("отвечает — значит, режут именно по имени сайта").into() } else { trs!("тоже не отвечает").into() },
                    },
                    &mut steps,
                );
                f.tls_neutral = Some(n);
            }
            f.tls_host = Some(host_tls);
        }
        if f.tls_host.as_ref().is_some_and(Tls::reached) {
            let pinned = |a: IpAddr| client(Duration::from_secs(10)).resolve(&host, SocketAddr::new(a, 443)).build().ok();
            // Системный DNS — наш DoH: его адрес не «провайдерский», сверять как подмену незачем.
            let sys_other = f.sys_ips.iter().find(|i| sys_doh.is_none() && public(i) && !doh_ips.is_empty() && !doh_ips.contains(i)).copied();
            let (https, https_sys) = tokio::join!(
                async {
                    match pinned(ip) {
                        Some(c) => fetch(&c, &url).await,
                        None => Fetch::Fail(trs!("клиент").into()),
                    }
                },
                async {
                    let a = sys_other?;
                    Some(fetch(&pinned(a)?, &url).await)
                }
            );
            let page_detail = match &https {
                Fetch::Ok(c) if *c < 500 => tr!("загрузилась (код {c})"),
                Fetch::Ok(c) => tr!("сервер ответил ошибкой {c}"),
                Fetch::Stall(n) => tr!("оборвалась на {} КБ", n / 1024),
                Fetch::Fail(e) => e.clone(),
            };
            emit(Step { key: "page", title: trs!("Страница целиком"), ok: Some(https.works()), detail: page_detail }, &mut steps);
            f.https = Some(https);
            f.https_sys = https_sys;
        }
    }
    emit(
        Step {
            key: "stub",
            title: trs!("Заглушка провайдера"),
            ok: stub.map(|s| !s),
            detail: match stub {
                Some(true) => trs!("по обычному HTTP — страница «доступ ограничен»").into(),
                Some(false) => trs!("нет").into(),
                None => trs!("по обычному HTTP сайт не ответил").into(),
            },
        },
        &mut steps,
    );
    if let Some(v) = &f.vpn {
        emit(
            Step {
                key: "vpn",
                title: trs!("Через VPN"),
                ok: Some(v.works()),
                detail: match v {
                    Fetch::Ok(c) if *c < 500 => trs!("открывается").into(),
                    Fetch::Ok(c) => tr!("ошибка {c}"),
                    Fetch::Stall(n) => tr!("оборвалось на {} КБ", n / 1024),
                    Fetch::Fail(e) => e.clone(),
                },
            },
            &mut steps,
        );
    }

    let (verdict, actions) = decide(&f);
    let (title, advice) = explain(verdict, &host, f.vpn.is_some());
    Ok(Report { host, steps, verdict, title, advice, actions })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn normalize_input() {
        assert_eq!(normalize("Example.COM").unwrap(), "example.com");
        assert_eq!(normalize(" https://www.example.com/path?q=1 ").unwrap(), "www.example.com");
        assert_eq!(normalize("сайт.рф").unwrap(), "xn--80aswg.xn--p1ai");
        for bad in ["", "1.2.3.4", "localhost", "ftp://x.com", "a b.com", "http://[::1]/"] {
            assert!(normalize(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn system_doh_is_not_spoof() {
        // DoH rxvpn дал 104.16.1.1, Cloudflare в проверке — 104.16.2.2 (CDN): адрес от
        // системы не сверяется как «провайдерский» (https_sys нет) — сайт «работает».
        let f = Facts {
            control_ok: true,
            sys_ips: vec![ip("104.16.1.1")],
            doh: Some(Doh::Ips(vec![ip("104.16.2.2")])),
            tcp_ok: Some(true),
            tls_host: Some(Tls::Ok),
            https: Some(Fetch::Ok(200)),
            https_sys: None,
            ..Default::default()
        };
        assert_eq!(decide(&f).0, Verdict::Works);
    }

    #[test]
    fn verdicts() {
        let base = Facts { control_ok: true, sys_ips: vec![ip("93.184.216.34")], doh: Some(Doh::Ips(vec![ip("93.184.216.34")])), ..Default::default() };
        let ok = Facts { tcp_ok: Some(true), tls_host: Some(Tls::Ok), https: Some(Fetch::Ok(200)), ..base.clone() };
        assert_eq!(decide(&ok).0, Verdict::Works);
        // Через VPN не пускает
        let v = Facts { vpn: Some(Fetch::Ok(403)), ..ok.clone() };
        assert_eq!(decide(&v).0, Verdict::Works, "403 — тоже ответ");
        let v = Facts { vpn: Some(Fetch::Fail("x".into())), ..ok.clone() };
        assert_eq!(decide(&v), (Verdict::VpnRejected, vec!["direct"]));
        // DNS подменён: провайдер даёт локальный адрес
        let v = Facts { sys_ips: vec![ip("10.10.34.34")], ..ok.clone() };
        assert_eq!(decide(&v).0, Verdict::DnsSpoof);
        // DNS подменён: по адресу провайдера не открывается, по настоящему — да
        let v = Facts { https_sys: Some(Fetch::Fail("x".into())), ..ok.clone() };
        assert_eq!(decide(&v).0, Verdict::DnsSpoof);
        // Заглушка: только если по HTTPS сайт не открылся
        let v = Facts { stub: true, ..base.clone() };
        assert_eq!(decide(&v), (Verdict::Stub, vec!["vpn"]));
        let v = Facts { stub: true, ..ok.clone() };
        assert_eq!(decide(&v).0, Verdict::Works, "по HTTPS открылся — работает");
        let v = Facts { stub: true, https_sys: Some(Fetch::Ok(200)), ..ok.clone() };
        assert_eq!(decide(&v).0, Verdict::DnsSpoof, "у провайдера другой адрес и там заглушка");
        // По IP
        let v = Facts { tcp_ok: Some(false), ..base.clone() };
        assert_eq!(decide(&v), (Verdict::IpBlock, vec!["vpn"]));
        let v = Facts { tcp_ok: Some(false), vpn: Some(Fetch::Fail("x".into())), ..base.clone() };
        assert_eq!(decide(&v).0, Verdict::SiteDown);
        // По имени (DPI)
        let v = Facts { tcp_ok: Some(true), tls_host: Some(Tls::Reset), tls_neutral: Some(Tls::Answered), ..base.clone() };
        assert_eq!(decide(&v), (Verdict::SniBlock, vec!["zapret", "vpn"]));
        let v = Facts { tcp_ok: Some(true), tls_host: Some(Tls::Timeout), tls_neutral: Some(Tls::Timeout), ..base.clone() };
        assert_eq!(decide(&v).0, Verdict::IpBlock);
        // Замедление
        let v = Facts { tcp_ok: Some(true), tls_host: Some(Tls::Ok), https: Some(Fetch::Stall(17_000)), ..base.clone() };
        assert_eq!(decide(&v), (Verdict::Throttle, vec!["zapret", "vpn"]));
        // Сайт сломан
        let v = Facts { https: Some(Fetch::Ok(502)), tcp_ok: Some(true), tls_host: Some(Tls::Ok), ..base.clone() };
        assert_eq!(decide(&v).0, Verdict::SiteDown);
        // Нет такого сайта / нет интернета
        let v = Facts { control_ok: true, doh: Some(Doh::NoSuch), ..Default::default() };
        assert_eq!(decide(&v).0, Verdict::NoSuchSite);
        let v = Facts { control_ok: false, doh: Some(Doh::Failed), ..Default::default() };
        assert_eq!(decide(&v).0, Verdict::Offline);
        // Нет интернета у ya.ru, но через VPN — есть: это не «нет интернета»
        let v = Facts { control_ok: false, vpn: Some(Fetch::Ok(200)), tcp_ok: Some(false), ..base.clone() };
        assert_eq!(decide(&v).0, Verdict::IpBlock);
    }

    #[test]
    fn stub_pages() {
        assert!(is_stub("http://warning.rt.ru/?id=1", ""));
        assert!(is_stub("", "<html>Доступ к ресурсу ограничен на основании ... rkn.gov.ru"));
        assert!(!is_stub("https://www.example.com/", "<html>hello</html>"));
        let media = format!("<html>{}<footer>Свидетельство Роскомнадзора ЭЛ № ФС77</footer>", "новости ".repeat(4000));
        assert!(!is_stub("", &media.to_lowercase()), "подвал СМИ — не заглушка");
    }
}

#[cfg(test)]
mod live {
    /// Живая проверка (сеть нужна): cargo test -p rxvpn-core --lib diag::live -- --ignored --nocapture
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn live_report() {
        let site = std::env::var("DIAG_SITE").unwrap_or_else(|_| "example.com".into());
        let r = super::run(&site, None, None, |s| println!("  {:<6} {:?} {}", s.key, s.ok, s.detail)).await.unwrap();
        println!("{:?}: {} — {}", r.verdict, r.title, r.advice);
    }
}
