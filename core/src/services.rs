//! Какие сервисы работают через сервер: страна выхода и доступность ChatGPT,
//! Gemini, YouTube Premium, Netflix. Только обычные GET-запросы, как браузер,
//! без входа в аккаунты. Признаки взяты из открытого RegionRestrictionCheck и
//! со временем могут устареть — тогда сервис покажется «не понять».

use std::time::Duration;

use serde::Serialize;

const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
const READ_MAX: usize = 1 << 20;

/// Сервис: ключ, название, его сайты (для правила «через этот сервер»).
pub const SERVICES: &[(&str, &str, &[&str])] = &[
    ("chatgpt", "ChatGPT", &["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "sora.com"]),
    ("gemini", "Gemini", &["gemini.google.com", "bard.google.com", "aistudio.google.com", "generativelanguage.googleapis.com"]),
    (
        "youtube",
        "YouTube Premium",
        &["youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "ggpht.com", "youtubei.googleapis.com"],
    ),
    ("netflix", "Netflix", &["netflix.com", "netflix.net", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net"]),
];

/// Сайты сервиса по ключу.
pub fn service_sites(key: &str) -> Option<&'static [&'static str]> {
    SERVICES.iter().find(|s| s.0 == key).map(|s| s.2)
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ServiceResult {
    pub key: &'static str,
    pub name: &'static str,
    /// true — работает, false — нет, None — не понять (сеть, признаки устарели).
    pub ok: Option<bool>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Report {
    /// IP и страна (код, название, флаг), которые видят сайты.
    pub ip: String,
    pub country: String,
    pub country_name: String,
    pub flag: String,
    pub services: Vec<ServiceResult>,
}

fn client(proxy: &str) -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(proxy).ok()?)
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::custom(|a| {
            // Только https и только к самим сервисам: запросы выходят с сервера
            // человека, и чужая переадресация не должна гонять его по любым адресам.
            let ok = a.previous().len() < 5 && a.url().scheme() == "https" && a.url().host_str().is_some_and(allowed_host);
            if ok {
                a.follow()
            } else {
                a.stop()
            }
        }))
        .user_agent(UA)
        .build()
        .ok()
}

/// Куда можно переходить по переадресации.
const REDIRECT_OK: &[&str] = &["openai.com", "chatgpt.com", "google.com", "youtube.com", "netflix.com", "cloudflare.com"];

fn allowed_host(h: &str) -> bool {
    let h = h.trim_end_matches('.').to_ascii_lowercase();
    REDIRECT_OK.iter().any(|d| h == *d || h.ends_with(&format!(".{d}")))
}

/// Ответ страницы: (код, итоговый адрес, текст до 1 МБ).
async fn get(c: &reqwest::Client, url: &str, headers: &[(&str, &str)]) -> Option<(u16, String, String)> {
    let mut rq = c.get(url).header("accept-language", "en-US,en;q=0.9");
    for (k, v) in headers {
        rq = rq.header(*k, *v);
    }
    let r = rq.send().await.ok()?;
    let (status, final_url) = (r.status().as_u16(), r.url().to_string());
    let body = crate::net::read_capped(r, READ_MAX).await.unwrap_or_default();
    Some((status, final_url, String::from_utf8_lossy(&body).into_owned()))
}

/// «ip=…» и «loc=…» из https://www.cloudflare.com/cdn-cgi/trace. Что не похоже
/// на IP и код страны — пусто.
pub fn parse_trace(text: &str) -> (String, String) {
    let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).unwrap_or("").trim().to_string();
    let ip = field("ip=").parse::<std::net::IpAddr>().map(|ip| ip.to_string()).unwrap_or_default();
    let loc = field("loc=");
    let loc = if loc.len() == 2 && loc.bytes().all(|b| b.is_ascii_uppercase()) { loc } else { String::new() };
    (ip, loc)
}

/// Решения по ответам — отдельно от сети, чтобы проверять тестами.
pub fn judge_chatgpt(api: Option<&str>, ios: Option<&str>) -> (Option<bool>, String) {
    let (Some(api), Some(ios)) = (api, ios) else { return (None, trs!("не ответил").into()) };
    let blocked_api = api.to_ascii_lowercase().contains("unsupported_country");
    let blocked_app = ios.contains("VPN");
    match (blocked_api, blocked_app) {
        (false, false) => (Some(true), trs!("работает").into()),
        (true, true) => (Some(false), trs!("недоступен в этой стране").into()),
        (false, true) => (Some(false), trs!("только в браузере, приложение — нет").into()),
        (true, false) => (Some(false), trs!("только в приложении на телефоне").into()),
    }
}

pub fn judge_gemini(page: Option<&str>) -> (Option<bool>, String) {
    match page {
        None => (None, trs!("не ответил").into()),
        Some(p) if p.contains("45631641,null,true") => (Some(true), trs!("работает").into()),
        Some(_) => (Some(false), trs!("недоступен в этой стране").into()),
    }
}

pub fn judge_youtube(page: Option<&str>) -> (Option<bool>, String) {
    let Some(p) = page else { return (None, trs!("не ответил").into()) };
    let region = p
        .split("\"INNERTUBE_CONTEXT_GL\":\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .filter(|r| r.len() == 2)
        .map(|r| tr!(" (регион {r})"))
        .unwrap_or_default();
    if p.contains("www.google.cn") || p.to_ascii_lowercase().contains("premium is not available in your country") {
        (Some(false), tr!("Premium недоступен{region}"))
    } else if p.to_ascii_lowercase().contains("ad-free") {
        (Some(true), tr!("работает{region}"))
    } else {
        (None, trs!("не понять по странице").into())
    }
}

pub fn judge_netflix(a: Option<(u16, &str)>, b: Option<(u16, &str)>) -> (Option<bool>, String) {
    let (Some(a), Some(b)) = (a, b) else { return (None, trs!("не ответил").into()) };
    let oh = |x: &str| x.contains("Oh no!");
    if a.0 == 403 && b.0 == 403 {
        return (Some(false), trs!("Netflix не пускает этот IP").into());
    }
    if oh(a.1) && oh(b.1) {
        return (Some(false), trs!("только собственные сериалы Netflix").into());
    }
    let region = a
        .1
        .split("\"countryName\":\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .filter(|r| !r.is_empty() && r.len() < 40)
        .map(|r| format!(" ({r})"))
        .unwrap_or_default();
    if a.0 == 200 || b.0 == 200 {
        (Some(true), tr!("работает{region}"))
    } else {
        (None, tr!("ответ {}", a.0))
    }
}

/// Проверить всё через прокси `proxy` (socks5h://127.0.0.1:порт временного Xray).
pub async fn probe(proxy: &str) -> Report {
    let Some(c) = client(proxy) else { return Report::default() };
    let trace = async { get(&c, "https://www.cloudflare.com/cdn-cgi/trace", &[]).await };
    let chatgpt = async {
        let api = get(
            &c,
            "https://api.openai.com/compliance/cookie_requirements",
            &[("authorization", "Bearer null"), ("origin", "https://platform.openai.com"), ("referer", "https://platform.openai.com/")],
        );
        let ios = get(&c, "https://ios.chat.openai.com/", &[]);
        let (api, ios) = tokio::join!(api, ios);
        judge_chatgpt(api.as_ref().map(|x| x.2.as_str()), ios.as_ref().map(|x| x.2.as_str()))
    };
    let gemini = async { judge_gemini(get(&c, "https://gemini.google.com/", &[]).await.as_ref().map(|x| x.2.as_str())) };
    let youtube = async { judge_youtube(get(&c, "https://www.youtube.com/premium", &[]).await.as_ref().map(|x| x.2.as_str())) };
    let netflix = async {
        let (a, b) = tokio::join!(get(&c, "https://www.netflix.com/title/81280792", &[]), get(&c, "https://www.netflix.com/title/70143836", &[]));
        judge_netflix(a.as_ref().map(|x| (x.0, x.2.as_str())), b.as_ref().map(|x| (x.0, x.2.as_str())))
    };
    let (trace, chatgpt, gemini, youtube, netflix) = tokio::join!(trace, chatgpt, gemini, youtube, netflix);
    let (ip, country) = trace.map(|t| parse_trace(&t.2)).unwrap_or_default();
    let mut services = Vec::new();
    for ((key, name, _), (ok, detail)) in SERVICES.iter().zip([chatgpt, gemini, youtube, netflix]) {
        services.push(ServiceResult { key, name, ok, detail });
    }
    let country_name = crate::checks::country_ru(&country).map(str::to_string).unwrap_or_else(|| country.clone());
    let flag = crate::checks::flag(&country);
    Report { ip, country, country_name, flag, services }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn judges() {
        assert_eq!(parse_trace("fl=1\nip=203.0.113.5\nts=1\nloc=NL\n"), ("203.0.113.5".into(), "NL".into()));
        assert_eq!(parse_trace("ip=<b>x</b>\nloc=T1\n"), (String::new(), String::new()));
        assert_eq!(judge_chatgpt(Some("{\"cookie_requirements\":1}"), Some("<html>ok</html>")).0, Some(true));
        assert_eq!(judge_chatgpt(Some("{\"error\":\"unsupported_country\"}"), Some("Please disable VPN")).0, Some(false));
        assert_eq!(judge_chatgpt(None, Some("x")).0, None);
        assert_eq!(judge_gemini(Some("...45631641,null,true...")).0, Some(true));
        assert_eq!(judge_gemini(Some("<html>")).0, Some(false));
        let (ok, d) = judge_youtube(Some("\"INNERTUBE_CONTEXT_GL\":\"NL\" ... Ad-free videos"));
        assert_eq!((ok, d.as_str()), (Some(true), "работает (регион NL)"));
        assert_eq!(judge_youtube(Some("Premium is not available in your country")).0, Some(false));
        assert_eq!(judge_netflix(Some((200, "\"countryName\":\"Netherlands\"")), Some((200, ""))).1, "работает (Netherlands)");
        assert_eq!(judge_netflix(Some((200, "Oh no!")), Some((200, "Oh no!"))).0, Some(false));
        assert_eq!(service_sites("chatgpt").unwrap()[0], "openai.com");
        assert!(service_sites("nope").is_none());
        assert!(allowed_host("www.netflix.com") && allowed_host("chatgpt.com.") && allowed_host("CONSENT.GOOGLE.COM"));
        assert!(!allowed_host("evilnetflix.com") && !allowed_host("127.0.0.1") && !allowed_host("netflix.com.evil.io"));
    }
}
