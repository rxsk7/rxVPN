//! Проверки подключения: «Мой IP», утечка DNS, скорость.
//!
//! Всё, что «через VPN», ходит через служебный вход probe — он всегда идёт
//! в сервер, мимо правил. Иначе в «Только блок.» проверка ушла бы напрямую
//! и показала бы провайдера, а не VPN.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;

/// Ответы сервисов проверки маленькие; больше — читать не будем.
const SMALL: usize = 1 << 20;

async fn small_text(r: reqwest::Response) -> Result<String, String> {
    crate::net::read_capped(r, SMALL).await.map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn client(proxy: Option<&str>, timeout: Duration) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder().timeout(timeout).connect_timeout(Duration::from_secs(8));
    b = match proxy {
        Some(p) => b.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?),
        None => b.no_proxy(),
    };
    b.build().map_err(|e| e.to_string())
}

// ---------------- Мой IP ----------------

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct IpInfo {
    pub ip: String,
    /// Название страны (по-русски, если сервис умеет), иначе код.
    pub country: String,
    /// Двухбуквенный код: "NL".
    pub country_code: String,
    pub city: String,
    /// Провайдер / хостинг.
    pub isp: String,
    /// Флаг-эмодзи из кода страны.
    pub flag: String,
}

/// Сервисы «какой у меня IP» — по очереди, пока какой-то не ответит.
/// Названия стран по-русски — у ipwho.is (lang=ru) и из нашей таблицы country_ru.
pub const IP_SERVICES: &[&str] = &[
    // Сначала https: ответ по http мог бы подделать провайдер или сервер VPN.
    "https://ipwho.is/?lang=ru",
    "https://ipinfo.io/json",
    "http://ip-api.com/json/?lang=ru&fields=status,message,country,countryCode,city,isp,org,as,query",
];

/// Страны, которые чаще всего встречаются у VPN и DNS, — по-русски.
/// Остальные остаются как прислал сервис.
pub fn country_ru(code: &str) -> Option<&'static str> {
    Some(match code {
        "RU" => trs!("Россия"), "NL" => trs!("Нидерланды"), "DE" => trs!("Германия"), "FI" => trs!("Финляндия"),
        "SE" => trs!("Швеция"), "NO" => trs!("Норвегия"), "DK" => trs!("Дания"), "EE" => trs!("Эстония"),
        "LV" => trs!("Латвия"), "LT" => trs!("Литва"), "PL" => trs!("Польша"), "CZ" => trs!("Чехия"),
        "AT" => trs!("Австрия"), "CH" => trs!("Швейцария"), "FR" => trs!("Франция"), "GB" => trs!("Великобритания"),
        "IE" => trs!("Ирландия"), "ES" => trs!("Испания"), "IT" => trs!("Италия"), "PT" => trs!("Португалия"),
        "BE" => trs!("Бельгия"), "LU" => trs!("Люксембург"), "RO" => trs!("Румыния"), "BG" => trs!("Болгария"),
        "MD" => trs!("Молдова"), "UA" => trs!("Украина"), "BY" => trs!("Беларусь"), "KZ" => trs!("Казахстан"),
        "UZ" => trs!("Узбекистан"), "KG" => trs!("Киргизия"), "AM" => trs!("Армения"), "GE" => trs!("Грузия"),
        "AZ" => trs!("Азербайджан"), "TR" => trs!("Турция"), "AE" => trs!("ОАЭ"), "IL" => trs!("Израиль"),
        "US" => trs!("США"), "CA" => trs!("Канада"), "JP" => trs!("Япония"), "KR" => trs!("Южная Корея"),
        "SG" => trs!("Сингапур"), "HK" => trs!("Гонконг"), "CN" => trs!("Китай"), "IN" => trs!("Индия"),
        "AU" => trs!("Австралия"), "BR" => trs!("Бразилия"), "RS" => trs!("Сербия"), "HU" => trs!("Венгрия"),
        "GR" => trs!("Греция"), "CY" => trs!("Кипр"), "IS" => trs!("Исландия"),
        _ => return None,
    })
}

pub fn flag(code: &str) -> String {
    let c = code.trim().to_ascii_uppercase();
    if c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()) {
        return String::new();
    }
    c.bytes().filter_map(|b| char::from_u32(0x1F1E6 + (b - b'A') as u32)).collect()
}

fn s(v: &Value) -> Option<String> {
    v.as_str().map(str::trim).filter(|x| !x.is_empty()).map(str::to_string)
}

/// Разобрать ответ любого из IP_SERVICES.
pub fn parse_ip_info(v: &Value) -> Option<IpInfo> {
    if v["status"].as_str().is_some_and(|st| st != "success") || v["success"] == Value::Bool(false) {
        return None;
    }
    let ip = s(&v["query"]).or_else(|| s(&v["ip"]))?;
    let raw_country = s(&v["country"]).unwrap_or_default();
    let code = s(&v["countryCode"])
        .or_else(|| s(&v["country_code"]))
        .or_else(|| (raw_country.len() == 2).then(|| raw_country.clone()))
        .unwrap_or_default()
        .to_ascii_uppercase();
    let country = if raw_country.chars().count() > 2 {
        raw_country
    } else {
        country_ru(&code).map(str::to_string).unwrap_or_else(|| code.clone())
    };
    // ipinfo: "org": "AS210644 Aeza International Ltd" — номер AS убираем.
    let strip_as = |x: String| match x.split_once(' ') {
        Some((a, rest)) if a.starts_with("AS") && a[2..].chars().all(|c| c.is_ascii_digit()) => rest.to_string(),
        _ => x,
    };
    let isp = s(&v["isp"])
        .or_else(|| s(&v["connection"]["isp"]))
        .or_else(|| s(&v["connection"]["org"]))
        .or_else(|| s(&v["org"]).map(strip_as))
        .or_else(|| s(&v["organization"]))
        .unwrap_or_default();
    Some(IpInfo {
        ip,
        flag: flag(&code),
        country,
        country_code: code,
        city: s(&v["city"]).unwrap_or_default(),
        isp,
    })
}

/// Внешний IP: `proxy` — "socks5h://127.0.0.1:порт" (через VPN) или None (напрямую).
pub async fn my_ip(proxy: Option<&str>, services: &[&str]) -> Result<IpInfo, String> {
    let c = client(proxy, Duration::from_secs(8))?;
    let mut answered = false;
    for url in services {
        if let Ok(r) = c.get(*url).header("User-Agent", "curl/8").send().await {
            answered = true;
            let body = crate::net::read_capped(r, SMALL).await.unwrap_or_default();
            if let Some(i) = serde_json::from_slice::<Value>(&body).ok().as_ref().and_then(parse_ip_info) {
                return Ok(i);
            }
        }
    }
    Err(if answered {
        trs!("сервисы ответили что-то непонятное").into()
    } else if proxy.is_some() {
        trs!("ни один сервис не ответил через VPN").into()
    } else {
        trs!("ни один сервис не ответил — нет интернета?").into()
    })
}

// ---------------- утечка IPv6 ----------------

/// Сервисы, доступные только по IPv6 (отвечают адресом текстом).
pub const IPV6_SERVICES: &[&str] = &["https://api6.ipify.org/", "https://ipv6.icanhazip.com/"];

/// IPv6, с которым видят сайты при прямом запросе (в TUN он сам идёт в туннель).
/// None — по IPv6 никуда не подключиться.
pub async fn seen_ipv6(services: &[&str]) -> Option<std::net::Ipv6Addr> {
    let c = client(None, Duration::from_secs(6)).ok()?;
    for url in services {
        if let Ok(r) = c.get(*url).header("User-Agent", "curl/8").send().await {
            let body = crate::net::read_capped(r, 256).await.unwrap_or_default();
            if let Ok(ip) = String::from_utf8_lossy(&body).trim().parse::<std::net::Ipv6Addr>() {
                return Some(ip);
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum V6Verdict {
    /// IPv6 не работает — утечки через него нет.
    NoIpv6,
    /// TUN: IPv6 идёт через VPN.
    Tunneled,
    /// TUN включён, а сайты видят IPv6 сетевой карты — утечка.
    Leak,
    /// Без TUN: программы без прокси ходят по IPv6 напрямую (так и задумано).
    Direct,
}

/// Тот же /64, что у адреса сетевой карты (у IPv6 нет NAT: адрес — твой).
fn same_net(a: &std::net::Ipv6Addr, b: &std::net::Ipv6Addr) -> bool {
    a.segments()[..4] == b.segments()[..4]
}

pub fn ipv6_verdict(seen: Option<std::net::Ipv6Addr>, local: &[std::net::Ipv6Addr], tun: bool) -> V6Verdict {
    match seen {
        None => V6Verdict::NoIpv6,
        Some(ip) if tun && local.iter().any(|l| same_net(l, &ip)) => V6Verdict::Leak,
        Some(_) if tun => V6Verdict::Tunneled,
        Some(_) => V6Verdict::Direct,
    }
}

// ---------------- утечка DNS ----------------

/// Запасной сервис — bash.ws (как dnsleaktest.com): берём id, резолвим N поддоменов
/// `{i}.{id}.bash.ws`, и сервис говорит, какие DNS-серверы к нему за ними пришли.
#[derive(Debug, Clone)]
pub struct LeakApi {
    pub base: String,
    pub domain: String,
}

impl Default for LeakApi {
    fn default() -> Self {
        Self { base: "https://bash.ws".into(), domain: "bash.ws".into() }
    }
}

/// Как заставить DNS сработать.
#[derive(Debug, Clone)]
pub enum Trigger {
    /// Режим «Прокси»: HTTP-запросы на поддомены через HTTP-вход rxvpn —
    /// ровно как браузер. Домен резолвит Xray или сервер.
    Proxy(String),
    /// TUN или без VPN: обычный системный резолвер Windows.
    System,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct DnsServer {
    pub ip: String,
    pub country: String,
    pub country_code: String,
    pub asn: String,
    pub flag: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct DnsLeak {
    /// Кто резолвил наши поддомены.
    pub servers: Vec<DnsServer>,
    /// Через какой IP мы ходили к самому сервису.
    pub seen_ip: Option<DnsServer>,
    /// Вывод сервиса как есть (англ.).
    pub conclusion: Option<String>,
}

fn dns_server(v: &Value) -> DnsServer {
    let code = s(&v["country"]).filter(|c| c.len() == 2).unwrap_or_default().to_ascii_uppercase();
    DnsServer {
        ip: s(&v["ip"]).unwrap_or_default(),
        country: country_ru(&code)
            .map(str::to_string)
            .or_else(|| s(&v["country_name"]))
            .unwrap_or_else(|| code.clone()),
        flag: flag(&code),
        country_code: code,
        asn: s(&v["asn"]).unwrap_or_default(),
    }
}

/// Ответ `/dnsleak/test/{id}?json=2`: список записей с type ip/dns/conclusion/error.
pub fn parse_dnsleak(v: &Value) -> Result<DnsLeak, String> {
    let list = v.as_array().ok_or(trs!("сервис ответил не списком"))?;
    let mut out = DnsLeak::default();
    for r in list {
        match r["type"].as_str() {
            Some("dns") => out.servers.push(dns_server(r)),
            Some("ip") => out.seen_ip = Some(dns_server(r)),
            Some("conclusion") => out.conclusion = s(&r["ip"]).or_else(|| s(&r["text"])),
            Some("error") => return Err(s(&r["text"]).unwrap_or_else(|| trs!("ошибка сервиса").into())),
            _ => {}
        }
    }
    Ok(out)
}

pub async fn dns_leak(api: &LeakApi, api_proxy: Option<&str>, trigger: Trigger) -> Result<DnsLeak, String> {
    let c = client(api_proxy, Duration::from_secs(10))?;
    // bash.ws отдаёт API только «консольным» клиентам, как их скрипту dnsleaktest
    // (curl). Запрос без User-Agent сайт считает браузером и отвечает страницей.
    let get = |url: String| c.get(url).header("User-Agent", "curl/8.5.0").header("Accept", "*/*");
    let id = get(format!("{}/id", api.base))
        .send()
        .await
        .map_err(|e| tr!("сервис проверки DNS недоступен: {}", crate::net::explain(&e)))?;
    let id = small_text(id).await?.trim().to_string();
    if id.is_empty() || id.len() > 64 || !id.chars().all(|ch| ch.is_ascii_alphanumeric()) {
        return Err(if id.contains('<') {
            trs!("bash.ws (сервис проверки DNS) вместо ответа прислал веб-страницу — у них что-то поменялось, проверка временно не работает").into()
        } else {
            trs!("сервис проверки DNS вернул странный id").into()
        });
    }
    // Чтобы сервис знал, с какого IP мы пришли (покажет рядом с DNS).
    let _ = get(format!("{}/myip/test/{id}", api.base)).send().await;

    let hosts: Vec<String> = (1..=10).map(|i| format!("{i}.{id}.{}", api.domain)).collect();
    let mut set = tokio::task::JoinSet::new();
    match trigger {
        Trigger::Proxy(p) => {
            let t = client(Some(&p), Duration::from_secs(4))?;
            for h in hosts {
                let t = t.clone();
                set.spawn(async move {
                    let _ = t.get(format!("http://{h}/")).send().await;
                });
            }
        }
        Trigger::System => {
            for h in hosts {
                set.spawn(async move {
                    let _ = tokio::task::spawn_blocking(move || {
                        use std::net::ToSocketAddrs;
                        let _ = (h.as_str(), 80).to_socket_addrs();
                    })
                    .await;
                });
            }
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(6), async { while set.join_next().await.is_some() {} }).await;
    set.abort_all();
    tokio::time::sleep(Duration::from_millis(800)).await;

    let resp = get(format!("{}/dnsleak/test/{id}?json=2", api.base))
        .send()
        .await
        .map_err(|e| crate::net::explain(&e))?;
    let text = small_text(resp).await?;
    let v: Value = serde_json::from_str(&text).map_err(|_| trs!("сервис проверки DNS ответил не JSON").to_string())?;
    parse_dnsleak(&v)
}

/// ipleak.net (AirVPN): каждый запрос на `{сессия}-{метка}.ipleak.net` резолвит
/// чей-то DNS-сервер, их авторитетный DNS это видит, а ответ
/// `/dnsdetection/?mode=json` перечисляет всех, кто резолвил за эту сессию:
/// `{"session": "...", "ip": {"1.2.3.4": 2, ...}}`. Страна — `/json/{ip}`.
#[derive(Debug, Clone)]
pub struct IpleakApi {
    /// "https" (в живом тесте — "http").
    pub scheme: String,
    /// Зона поддоменов: "ipleak.net".
    pub zone: String,
    /// Откуда брать страну адреса: "https://ipleak.net".
    pub geo: String,
}

impl Default for IpleakApi {
    fn default() -> Self {
        Self { scheme: "https".into(), zone: "ipleak.net".into(), geo: "https://ipleak.net".into() }
    }
}

/// Сервис проверки DNS. Пробуются по очереди: первый ответивший и выигрывает.
#[derive(Debug, Clone)]
pub enum LeakService {
    Ipleak(IpleakApi),
    BashWs(LeakApi),
}

impl LeakService {
    pub fn name(&self) -> &str {
        match self {
            LeakService::Ipleak(a) => &a.zone,
            LeakService::BashWs(a) => &a.domain,
        }
    }
}

/// Порядок по умолчанию: ipleak.net (работает), bash.ws — запасной
/// (с осени 2026 вместо API отдаёт страницу, но вдруг починят).
pub fn leak_services() -> Vec<LeakService> {
    vec![LeakService::Ipleak(IpleakApi::default()), LeakService::BashWs(LeakApi::default())]
}

/// Больше DNS-серверов не показываем (и не спрашиваем про страну).
const MAX_RESOLVERS: usize = 12;

/// Все сервисы по очереди. Ok — (результат, имя ответившего сервиса).
pub async fn dns_leak_any(list: &[LeakService], api_proxy: Option<&str>, trigger: Trigger) -> Result<(DnsLeak, String), String> {
    let mut errs = Vec::new();
    for svc in list {
        let r = match svc {
            LeakService::Ipleak(a) => ipleak(a, api_proxy, trigger.clone()).await,
            LeakService::BashWs(a) => dns_leak(a, api_proxy, trigger.clone()).await,
        };
        match r {
            // Пустой список — тоже неудача: вдруг следующий сервис увидит.
            Ok(l) if !l.servers.is_empty() => return Ok((l, svc.name().to_string())),
            Ok(_) => errs.push(tr!("{}: не увидел ни одного DNS-сервера", svc.name())),
            Err(e) => errs.push(format!("{}: {e}", svc.name())),
        }
    }
    Err(tr!("Проверка DNS не удалась: не ответил ни один сервис ({}). Проверь интернет и попробуй через пару минут",
        errs.join("; ")
    ))
}

fn hex_id(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    if getrandom::getrandom(&mut b).is_err() {
        // Без случайности сессию угадают и подмешают чужие DNS — лучше честно упасть ниже.
        return String::new();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Ответ /dnsdetection/: адреса резолверов (только настоящие IP).
pub fn parse_ipleak_dns(v: &Value, session: &str) -> Result<Vec<String>, String> {
    if v["session"].as_str() != Some(session) {
        return Err(trs!("ответ от чужой сессии").into());
    }
    let map = v["ip"].as_object().ok_or(trs!("в ответе нет списка DNS-серверов"))?;
    Ok(map
        .keys()
        .filter_map(|k| k.trim().parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.to_string())
        .collect())
}

/// Ответ /json/{ip}: страна и сеть адреса.
pub fn parse_ipleak_geo(v: &Value, ip: &str) -> DnsServer {
    let code = s(&v["country_code"]).filter(|c| c.len() == 2).unwrap_or_default().to_ascii_uppercase();
    let asn = match (v["as_number"].as_u64(), s(&v["isp_name"])) {
        (Some(n), Some(isp)) => format!("AS{n} {isp}"),
        (Some(n), None) => format!("AS{n}"),
        (None, Some(isp)) => isp,
        _ => String::new(),
    };
    DnsServer {
        ip: ip.to_string(),
        country: country_ru(&code).map(str::to_string).or_else(|| s(&v["country_name"])).unwrap_or_else(|| code.clone()),
        flag: flag(&code),
        country_code: code,
        asn: asn.chars().take(80).collect(),
    }
}

async fn ipleak(api: &IpleakApi, api_proxy: Option<&str>, trigger: Trigger) -> Result<DnsLeak, String> {
    let session = hex_id(20);
    if session.len() != 40 {
        return Err(trs!("нет случайных чисел для сессии").into());
    }
    // Запросы на поддомены — тем же путём, что браузер (или программа в TUN):
    // кто их резолвит, тот и попадёт в ответ.
    let t = match &trigger {
        Trigger::Proxy(p) => client(Some(p), Duration::from_secs(8))?,
        Trigger::System => client(None, Duration::from_secs(8))?,
    };
    let url = |label: &str| format!("{}://{session}-{label}.{}/dnsdetection/?mode=json", api.scheme, api.zone);
    async fn hit(c: reqwest::Client, url: String, session: String) -> Result<Vec<String>, String> {
        let r = c.get(url).send().await.map_err(|e| crate::net::explain(&e))?;
        let text = small_text(r).await?;
        let v: Value = serde_json::from_str(&text).map_err(|_| trs!("ответил не JSON (вместо API — страница?)").to_string())?;
        parse_ipleak_dns(&v, &session)
    }
    let mut seen: Vec<String> = Vec::new();
    let mut last_err = None;
    let mut add = |r: Result<Vec<String>, String>, seen: &mut Vec<String>| match r {
        Ok(list) => {
            for ip in list {
                if !seen.contains(&ip) && seen.len() < MAX_RESOLVERS {
                    seen.push(ip);
                }
            }
        }
        Err(e) => last_err = Some(e),
    };
    // Волна разом (разные резолверы у провайдера), потом пара запросов следом:
    // их ответ уже знает про всех из первой волны.
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        set.spawn(hit(t.clone(), url(&hex_id(4)), session.clone()));
    }
    let wave = async {
        let mut out = Vec::new();
        while let Some(r) = set.join_next().await {
            out.push(r.unwrap_or_else(|e| Err(e.to_string())));
        }
        out
    };
    let results = tokio::time::timeout(Duration::from_secs(10), wave).await.unwrap_or_default();
    for r in results {
        add(r, &mut seen);
    }
    tokio::time::sleep(Duration::from_millis(600)).await;
    for _ in 0..2 {
        add(hit(t.clone(), url(&hex_id(4)), session.clone()).await, &mut seen);
    }
    let c = client(api_proxy, Duration::from_secs(10))?;
    if seen.is_empty() {
        // Запросы «как браузер» не дошли (сайт закрыт маршрутом?) — спросим служебным путём.
        add(hit(c.clone(), url(&hex_id(4)), session.clone()).await, &mut seen);
    }
    if seen.is_empty() {
        return Err(last_err.unwrap_or_else(|| trs!("не увидел ни одного DNS-сервера").into()));
    }
    // Страны: параллельно, по одному запросу на адрес. Не ответил — просто адрес.
    let geo = |ip: Option<String>| {
        let c = c.clone();
        let base = api.geo.clone();
        async move {
            let u = match &ip {
                Some(ip) => format!("{base}/json/{ip}"),
                None => format!("{base}/json/"),
            };
            let r = c.get(u).send().await.ok()?;
            let v: Value = serde_json::from_str(&small_text(r).await.ok()?).ok()?;
            let ip = ip.or_else(|| s(&v["ip"]).filter(|x| x.parse::<std::net::IpAddr>().is_ok()))?;
            Some(parse_ipleak_geo(&v, &ip))
        }
    };
    let mut set = tokio::task::JoinSet::new();
    for (i, ip) in seen.iter().enumerate() {
        let f = geo(Some(ip.clone()));
        set.spawn(async move { (i, f.await) });
    }
    let me = geo(None);
    let (mut found, seen_ip) = tokio::join!(
        async {
            let mut out: Vec<Option<DnsServer>> = vec![None; seen.len()];
            let _ = tokio::time::timeout(Duration::from_secs(10), async {
                while let Some(Ok((i, d))) = set.join_next().await {
                    out[i] = d;
                }
            })
            .await;
            out
        },
        tokio::time::timeout(Duration::from_secs(10), me)
    );
    let servers = seen
        .iter()
        .enumerate()
        .map(|(i, ip)| found[i].take().unwrap_or_else(|| DnsServer { ip: ip.clone(), ..Default::default() }))
        .collect();
    Ok(DnsLeak { servers, seen_ip: seen_ip.ok().flatten(), conclusion: None })
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Verdict {
    /// ok / warn / info
    pub level: &'static str,
    pub text: String,
}

/// Человеческий вывод. `blocked_mode` — «Только блок.»: там обычные сайты
/// и их DNS напрямую по задумке.
pub fn leak_verdict(leak: &DnsLeak, connected: bool, blocked_mode: bool) -> Verdict {
    let ru: Vec<&DnsServer> = leak.servers.iter().filter(|d| d.country_code == "RU").collect();
    if leak.servers.is_empty() {
        return Verdict { level: "warn", text: trs!("DNS-серверы не определились — попробуй ещё раз").into() };
    }
    if !connected {
        return Verdict { level: "info", text: trs!("Без VPN твои DNS-запросы видят эти серверы").into() };
    }
    if ru.is_empty() {
        return Verdict { level: "ok", text: trs!("Утечки нет: DNS-запросы видят только серверы за границей").into() };
    }
    if blocked_mode {
        return Verdict {
            level: "info",
            text: trs!("В «Только блок.» обычные сайты и их DNS идут напрямую — так и задумано. Заблокированные резолвятся через VPN").into(),
        };
    }
    let who: Vec<String> = ru.iter().map(|d| format!("{} ({})", d.ip, d.asn)).collect();
    Verdict {
        level: "warn",
        text: tr!("Утечка: DNS-запросы видит сервер в России — {}. Проверь «DNS через VPN» в настройках; в режиме «Прокси» программы без прокси резолвят через провайдера — для них включи TUN",
            who.join(", ")
        ),
    }
}

// ---------------- скорость ----------------

#[derive(Debug, Clone)]
pub struct SpeedUrls {
    /// Скачивание: `{bytes}` заменится на размер куска.
    pub down: String,
    /// Запасной: просто большой файл.
    pub down_fallback: Option<String>,
    /// Загрузка: POST.
    pub up: Option<String>,
}

impl Default for SpeedUrls {
    fn default() -> Self {
        Self {
            down: "https://speed.cloudflare.com/__down?bytes={bytes}".into(),
            down_fallback: Some("https://proof.ovh.net/files/100Mb.dat".into()),
            up: Some("https://speed.cloudflare.com/__up".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
pub struct SpeedProgress {
    /// "down" / "up"
    pub phase: &'static str,
    pub mbps: f64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SpeedResult {
    pub down_mbps: f64,
    pub up_mbps: Option<f64>,
    /// Сколько трафика ушло на проверку.
    pub down_bytes: u64,
    pub up_bytes: u64,
    pub up_error: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct SpeedLimits {
    pub down_secs: f64,
    pub up_secs: f64,
    pub down_max_bytes: u64,
    pub up_max_bytes: u64,
    /// Параллельных потоков: один поток через далёкий сервер упирается в
    /// задержку и показывает меньше, чем канал может.
    pub streams: usize,
}

impl Default for SpeedLimits {
    fn default() -> Self {
        Self { down_secs: 8.0, up_secs: 6.0, down_max_bytes: 200 << 20, up_max_bytes: 50 << 20, streams: 4 }
    }
}

const CHUNK: u64 = 25_000_000;
const UP_CHUNK: usize = 2 << 20;

fn mbps(bytes: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        0.0
    } else {
        (bytes as f64 * 8.0 / 1e6 / secs * 10.0).round() / 10.0
    }
}

/// Скорость скачивания и загрузки. `proxy` — через VPN, None — напрямую.
pub async fn speedtest(
    proxy: Option<&str>,
    urls: &SpeedUrls,
    lim: SpeedLimits,
    progress: impl Fn(SpeedProgress) + Send + Sync + 'static,
) -> Result<SpeedResult, String> {
    let progress = Arc::new(progress);
    let c = client(proxy, Duration::from_secs(60))?;

    // Сначала один короткий запрос: понять, жив ли основной адрес, и выбрать.
    let probe = urls.down.replace("{bytes}", "1000");
    let down_url = match c.get(&probe).send().await.and_then(|r| r.error_for_status()) {
        Ok(_) => urls.down.replace("{bytes}", &CHUNK.to_string()),
        Err(e) => match &urls.down_fallback {
            Some(f) => f.clone(),
            None => return Err(crate::net::explain(&e)),
        },
    };

    let (down_bytes, down_secs) = run_streams(lim.streams, lim.down_secs, lim.down_max_bytes, "down", true, progress.clone(), {
        let c = c.clone();
        move |m: Arc<Meter>| {
            let (c, url) = (c.clone(), down_url.clone());
            async move {
                while !m.stopped() {
                    let mut r = c.get(&url).send().await.and_then(|r| r.error_for_status()).map_err(|e| crate::net::explain(&e))?;
                    while let Some(chunk) = r.chunk().await.map_err(|e| e.to_string())? {
                        m.add(chunk.len() as u64);
                        if m.stopped() {
                            return Ok(());
                        }
                    }
                }
                Ok(())
            }
        }
    })
    .await?;
    if down_bytes == 0 {
        return Err(trs!("ничего не скачалось").into());
    }

    let mut res = SpeedResult {
        down_mbps: mbps(down_bytes, down_secs),
        up_mbps: None,
        down_bytes,
        up_bytes: 0,
        up_error: None,
    };
    if let Some(up) = &urls.up {
        // Bytes клонируется без копирования — одно тело на все запросы.
        let body = bytes::Bytes::from(vec![0u8; UP_CHUNK]);
        let up = up.clone();
        // Загрузку считаем от старта: «первый байт» тут — конец первого POST.
        let r = run_streams(lim.streams, lim.up_secs, lim.up_max_bytes, "up", false, progress.clone(), {
            let c = c.clone();
            move |m: Arc<Meter>| {
                let (c, url, body) = (c.clone(), up.clone(), body.clone());
                async move {
                    while !m.stopped() {
                        c.post(&url)
                            .header("Content-Type", "application/octet-stream")
                            .body(body.clone())
                            .send()
                            .await
                            .and_then(|r| r.error_for_status())
                            .map_err(|e| crate::net::explain(&e))?;
                        m.add(UP_CHUNK as u64);
                    }
                    Ok(())
                }
            }
        })
        .await;
        match r {
            Ok((b, secs)) if b > 0 => {
                res.up_mbps = Some(mbps(b, secs));
                res.up_bytes = b;
            }
            Ok(_) => res.up_error = Some(trs!("загрузка не успела").into()),
            Err(e) => res.up_error = Some(e),
        }
    }
    Ok(res)
}

/// Сколько качаем через каждый сервер в «Проверить скорость всех».
pub const QUICK_BYTES: u64 = 3_000_000;
/// Меньше этого скачалось — скорость не считаем (по паре пакетов врёт).
const QUICK_MIN: u64 = 256 * 1024;

/// Быстрый замер одного сервера: скачать до `max_bytes` одним потоком и
/// посчитать Мбит/с с первого байта (ожидание ответа — это задержка, она
/// меряется отдельно). Не успел за `timeout`, но скачал хотя бы 256 КБ —
/// скорость по тому, что успел. Возвращает (Мбит/с, скачано байт).
pub async fn quick_speed(proxy: &str, url: &str, max_bytes: u64, timeout: Duration) -> Result<(f64, u64), String> {
    let c = client(Some(proxy), timeout + Duration::from_secs(2))?;
    let url = url.replace("{bytes}", &max_bytes.to_string());
    let t0 = Instant::now();
    let work = async {
        let mut r = c.get(&url).send().await.and_then(|r| r.error_for_status()).map_err(|e| crate::net::explain(&e))?;
        let mut got = 0u64;
        let mut first: Option<Instant> = None;
        let mut first_len = 0u64;
        loop {
            match tokio::time::timeout(timeout.saturating_sub(t0.elapsed()), r.chunk()).await {
                Err(_) => break, // время вышло — считаем по скачанному
                Ok(Err(e)) if got < QUICK_MIN => return Err(crate::net::explain(&e)),
                Ok(Err(_)) | Ok(Ok(None)) => break,
                Ok(Ok(Some(ch))) => {
                    // Время — с первого куска, байты — после него: иначе первый кусок
                    // «прилетел бы за 0 секунд» и завысил скорость.
                    if first.is_none() {
                        first = Some(Instant::now());
                        first_len = ch.len() as u64;
                    }
                    got += ch.len() as u64;
                    if got >= max_bytes {
                        break;
                    }
                }
            }
        }
        Ok::<_, String>((got, got - first_len, first.map(|f| f.elapsed().as_secs_f64()).unwrap_or(0.0)))
    };
    let (got, measured, secs) = work.await?;
    if got < QUICK_MIN || measured == 0 || secs <= 0.0 {
        return Err(if got == 0 { trs!("ничего не скачалось").into() } else { tr!("за {}с скачалось всего {} КБ", timeout.as_secs(), got >> 10) });
    }
    Ok((mbps(measured, secs), got))
}

/// Счётчик байт для потоков проверки скорости.
struct Meter {
    total: AtomicU64,
    /// Когда пришёл первый байт: нс от t0 (0 — ещё не пришёл).
    first_ns: AtomicU64,
    t0: Instant,
    stop: AtomicBool,
    /// Потолок объёма: потоки сами останавливаются, как только набрали его.
    max: u64,
}

impl Meter {
    fn add(&self, n: u64) {
        if self.first_ns.load(Ordering::Relaxed) == 0 {
            let ns = (self.t0.elapsed().as_nanos() as u64).max(1);
            let _ = self.first_ns.compare_exchange(0, ns, Ordering::Relaxed, Ordering::Relaxed);
        }
        self.total.fetch_add(n, Ordering::Relaxed);
    }
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed) || self.total.load(Ordering::Relaxed) >= self.max
    }
    /// Секунд замера: с первого байта (скачивание — ожидание ответа это пинг,
    /// а не скорость) или со старта (загрузка). None — байтов ещё не было.
    fn secs(&self, from_first: bool) -> Option<f64> {
        let f = self.first_ns.load(Ordering::Relaxed);
        if f == 0 {
            return None;
        }
        let all = self.t0.elapsed().as_secs_f64();
        Some(if from_first { all - f as f64 / 1e9 } else { all })
    }
}

/// Запустить `streams` потоков на `secs` секунд или до `max_bytes`,
/// раз в 250 мс сообщать скорость. Возвращает (байт, секунд замера).
async fn run_streams<F, Fut>(
    streams: usize,
    secs: f64,
    max_bytes: u64,
    phase: &'static str,
    from_first: bool,
    progress: Arc<impl Fn(SpeedProgress) + Send + Sync + 'static>,
    worker: F,
) -> Result<(u64, f64), String>
where
    F: Fn(Arc<Meter>) -> Fut,
    Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    let m = Arc::new(Meter {
        total: AtomicU64::new(0),
        first_ns: AtomicU64::new(0),
        t0: Instant::now(),
        stop: AtomicBool::new(false),
        max: max_bytes,
    });
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..streams.max(1) {
        set.spawn(worker(m.clone()));
    }
    let mut err: Option<String> = None;
    let mut last_report = Instant::now();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            r = set.join_next(), if !set.is_empty() => {
                if let Some(Ok(Err(e))) = r { err.get_or_insert(e); }
                if set.is_empty() { break; }
            }
        }
        let b = m.total.load(Ordering::Relaxed);
        match m.secs(from_first) {
            Some(dt) => {
                if last_report.elapsed() >= Duration::from_millis(250) && dt > 0.3 {
                    progress(SpeedProgress { phase, mbps: mbps(b, dt), bytes: b });
                    last_report = Instant::now();
                }
                if dt >= secs || b >= max_bytes {
                    break;
                }
            }
            None if m.t0.elapsed().as_secs_f64() > secs + 7.0 => break, // так и не пошло
            None => {}
        }
    }
    m.stop.store(true, Ordering::Relaxed);
    set.abort_all();
    let b = m.total.load(Ordering::Relaxed);
    match m.secs(from_first) {
        Some(dt) if b > 0 => Ok((b, dt.max(0.001))),
        _ => Err(err.unwrap_or_else(|| trs!("сервер не отдал ни байта").into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ip_services_formats() {
        let ipapi = json!({"status":"success","country":"Нидерланды","countryCode":"NL","city":"Амстердам",
            "isp":"Aeza International Ltd","org":"Aeza","as":"AS210644 Aeza International Ltd","query":"79.137.195.200"});
        let i = parse_ip_info(&ipapi).unwrap();
        assert_eq!((i.ip.as_str(), i.country.as_str(), i.country_code.as_str()), ("79.137.195.200", "Нидерланды", "NL"));
        assert_eq!(i.isp, "Aeza International Ltd");
        assert_eq!(i.flag, "🇳🇱");

        let ipwho = json!({"ip":"5.1.2.3","success":true,"country":"Россия","country_code":"RU","city":"Магадан",
            "connection":{"asn":12389,"org":"Rostelecom","isp":"PJSC Rostelecom"}});
        let i = parse_ip_info(&ipwho).unwrap();
        assert_eq!((i.country.as_str(), i.isp.as_str(), i.flag.as_str()), ("Россия", "PJSC Rostelecom", "🇷🇺"));

        let ipinfo = json!({"ip":"1.1.1.1","city":"Helsinki","country":"FI","org":"AS24940 Hetzner Online GmbH"});
        let i = parse_ip_info(&ipinfo).unwrap();
        assert_eq!((i.country.as_str(), i.country_code.as_str(), i.isp.as_str()), ("Финляндия", "FI", "Hetzner Online GmbH"));

        assert!(parse_ip_info(&json!({"status":"fail","message":"reserved range","query":"127.0.0.1"})).is_none());
        assert!(parse_ip_info(&json!({"success":false,"ip":"x"})).is_none());
        assert!(parse_ip_info(&json!({"foo":1})).is_none());
        assert_eq!(flag("xx1"), "");
    }

    #[test]
    fn dnsleak_format() {
        // Формат как в dnsleaktest.sh (bash.ws, json=2).
        let v = json!([
            {"ip":"79.137.195.200","country":"NL","country_name":"Netherlands","asn":"AS210644 Aeza","type":"ip"},
            {"ip":"162.158.1.1","country":"NL","country_name":"Netherlands","asn":"AS13335 Cloudflare","type":"dns"},
            {"ip":"172.70.2.2","country":"DE","country_name":"Germany","asn":"AS13335 Cloudflare","type":"dns"},
            {"ip":"DNS is not leaking.","type":"conclusion"}
        ]);
        let l = parse_dnsleak(&v).unwrap();
        assert_eq!(l.servers.len(), 2);
        assert_eq!(l.servers[1].flag, "🇩🇪");
        assert_eq!(l.servers[1].country, "Германия");
        assert_eq!(l.seen_ip.as_ref().unwrap().ip, "79.137.195.200");
        assert_eq!(l.conclusion.as_deref(), Some("DNS is not leaking."));
        assert_eq!(leak_verdict(&l, true, false).level, "ok");

        let mut ru = l.clone();
        ru.servers.push(DnsServer { ip: "77.88.8.8".into(), country_code: "RU".into(), asn: "AS13238 Yandex".into(), ..Default::default() });
        let w = leak_verdict(&ru, true, false);
        assert_eq!(w.level, "warn");
        assert!(w.text.contains("77.88.8.8"));
        assert_eq!(leak_verdict(&ru, true, true).level, "info", "в «Только блок.» так задумано");
        assert_eq!(leak_verdict(&ru, false, false).level, "info");
        assert_eq!(leak_verdict(&DnsLeak::default(), true, false).level, "warn");

        assert!(parse_dnsleak(&json!([{"type":"error","text":"Invalid id"}])).is_err());
        assert!(parse_dnsleak(&json!({"a":1})).is_err());
    }

    #[test]
    fn ipleak_format() {
        let sess = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
        let v = json!({"session": sess, "ip": {"172.253.82.90": 1, "74.114.31.219": 3, "not-an-ip": 1, "2a00:1450::1": 1}});
        let mut got = parse_ipleak_dns(&v, sess).unwrap();
        got.sort();
        assert_eq!(got, ["172.253.82.90", "2a00:1450::1", "74.114.31.219"]);
        assert!(parse_ipleak_dns(&v, "другая").is_err(), "чужую сессию не берём");
        assert!(parse_ipleak_dns(&json!({"session": sess}), sess).is_err());
        assert!(parse_ipleak_dns(&json!({"ip": {"1.1.1.1": 1}}), sess).is_err(), "без сессии — не берём");
        assert!(parse_ipleak_dns(&json!("<html>"), sess).is_err());
        let g = parse_ipleak_geo(&json!({"as_number": 13238, "isp_name": "YANDEX LLC", "country_code": "RU", "country_name": "Russia", "ip": "77.88.8.8"}), "77.88.8.8");
        assert_eq!((g.country.as_str(), g.flag.as_str(), g.asn.as_str()), ("Россия", "🇷🇺", "AS13238 YANDEX LLC"));
        let g = parse_ipleak_geo(&json!({"country_code": "ZZZ"}), "1.1.1.1");
        assert_eq!((g.ip.as_str(), g.country_code.as_str(), g.asn.as_str()), ("1.1.1.1", "", ""));
        assert_eq!(hex_id(20).len(), 40);
        assert_ne!(hex_id(20), hex_id(20));
        assert_eq!(leak_services()[0].name(), "ipleak.net");
    }

    #[test]
    fn ipv6_verdicts() {
        let mine: std::net::Ipv6Addr = "2a02:6b8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap();
        let tmp: std::net::Ipv6Addr = "2a02:6b8:1:2:1111:2222:3333:4444".parse().unwrap();
        let vpn: std::net::Ipv6Addr = "2001:db8:9::1".parse().unwrap();
        assert_eq!(ipv6_verdict(None, &[mine], true), V6Verdict::NoIpv6);
        assert_eq!(ipv6_verdict(Some(tmp), &[mine], true), V6Verdict::Leak, "временный адрес той же сети");
        assert_eq!(ipv6_verdict(Some(vpn), &[mine], true), V6Verdict::Tunneled);
        assert_eq!(ipv6_verdict(Some(mine), &[mine], false), V6Verdict::Direct);
    }
}
