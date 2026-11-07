//! Режим белых списков (мобильный интернет, с весны 2026): при ограничении
//! открыт только согласованный список сервисов (госуслуги, банки, Яндекс, VK…),
//! всё остальное — закрыто по адресам. Обычный VPN-сервер тогда не отвечает.
//!
//! rxvpn обходы не придумывает: он замечает режим и переключается на сервер,
//! который человек сам пометил «для белых списков» (обычно каскад через
//! российский сервер на «белом» адресе), а когда режим кончился — обратно.
//!
//! Признак режима: напрямую открываются сайты из белого списка и не открывается
//! ни один обычный. Обычные проверяем по IP (Cloudflare, Google, Quad9 — у них
//! сертификаты на сами IP): так не нужен DNS, а DNS через упавший VPN дал бы
//! «обычные не открываются» и ложную тревогу.

use std::time::Duration;

use serde::Serialize;

/// Из белого списка (по данным Минцифры), домены .ru: их DNS всегда «местный».
pub const LISTED: &[&str] = &["https://www.gosuslugi.ru/", "https://ya.ru/", "https://www.sberbank.ru/"];
/// Обычные, точно не из белого списка: три по IP (DNS не нужен) и два по имени
/// (на случай, если какой-то IP режут и без белых списков). Открылся хоть
/// один — интернет обычный.
pub const ORDINARY: &[&str] = &["https://1.1.1.1/", "https://8.8.8.8/", "https://9.9.9.9/", "https://github.com/", "https://www.wikipedia.org/"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Похоже на белые списки.
    Whitelist,
    /// Интернет обычный (VPN-сервер не отвечает сам по себе).
    Normal,
    /// Ничего не открывается — нет сети вообще.
    Offline,
    /// Не понять (открылся один «белый» сайт из трёх и ни одного обычного).
    Unclear,
}

/// `listed` — сколько «белых» открылось, `ordinary` — сколько обычных.
pub fn verdict(listed: usize, ordinary: usize) -> Verdict {
    match (listed, ordinary) {
        (_, o) if o > 0 => Verdict::Normal,
        (0, 0) => Verdict::Offline,
        (l, 0) if l >= 2 => Verdict::Whitelist,
        _ => Verdict::Unclear,
    }
}

impl Verdict {
    pub fn text(self) -> &'static str {
        match self {
            Verdict::Whitelist => trs!("похоже на белые списки: открываются только разрешённые сайты"),
            Verdict::Normal => trs!("интернет обычный, белых списков нет"),
            Verdict::Offline => trs!("сети нет совсем"),
            Verdict::Unclear => trs!("не понять — сеть ведёт себя странно"),
        }
    }
}

/// Открывается ли сайт: любой ответ HTTP после настоящего TLS (подмена
/// провайдером не пройдёт проверку сертификата).
async fn opens(c: &reqwest::Client, url: &str) -> bool {
    c.get(url).send().await.is_ok()
}

/// Проверить напрямую. `direct` — SOCKS-вход Xray прямо в интернет
/// (socks5://127.0.0.1:порт; в TUN иначе проверка ушла бы в туннель), None — без прокси.
pub async fn detect(direct: Option<&str>) -> Result<(Verdict, usize, usize), String> {
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(6))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36");
    b = match direct {
        Some(p) => b.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?),
        None => b.no_proxy(),
    };
    let c = b.build().map_err(|e| e.to_string())?;
    let all: Vec<_> = LISTED.iter().chain(ORDINARY).map(|u| opens(&c, u)).collect();
    let r = futures_util::future::join_all(all).await;
    let listed = r[..LISTED.len()].iter().filter(|x| **x).count();
    let ordinary = r[LISTED.len()..].iter().filter(|x| **x).count();
    Ok((verdict(listed, ordinary), listed, ordinary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts() {
        assert_eq!(verdict(3, 0), Verdict::Whitelist);
        assert_eq!(verdict(2, 0), Verdict::Whitelist);
        assert_eq!(verdict(1, 0), Verdict::Unclear);
        assert_eq!(verdict(0, 0), Verdict::Offline);
        assert_eq!(verdict(3, 1), Verdict::Normal);
        assert_eq!(verdict(0, 2), Verdict::Normal);
        let by_ip = ORDINARY.iter().filter(|u| u.trim_start_matches("https://").trim_end_matches('/').parse::<std::net::IpAddr>().is_ok()).count();
        assert!(by_ip >= 3, "обычные — в основном по IP, без DNS");
        assert!(LISTED.iter().all(|u| u.trim_end_matches('/').ends_with(".ru")));
    }
}
