//! Перенос на телефон: профиль маршрутов для Happ (iPhone и Android) —
//! чтобы на телефоне работало как на компе: «Обход РФ» / «Только блок.» / «Всё»,
//! свои сайты, реклама. Формат — https://www.happ.su/main/dev-docs/routing
//! (deeplink happ://routing/onadd/{base64 JSON}).

use base64::Engine;
use serde_json::{json, Value};

use crate::xray::{parse_rule, RouteMode, RuleTarget, Settings};

/// Списки runetfreedom (как у rxvpn для «Только блок.»): в них и обычные категории.
const GEO: &str = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release";

fn split(lines: &[String]) -> (Vec<String>, Vec<String>) {
    let (mut d, mut i) = (Vec::new(), Vec::new());
    for l in lines.iter().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        match parse_rule(l) {
            Ok(RuleTarget::Domain(x)) => d.push(x),
            Ok(RuleTarget::Ip(x)) => i.push(x),
            Err(_) => {}
        }
    }
    (d, i)
}

fn plain_ip(s: &str) -> Option<String> {
    s.trim().parse::<std::net::IpAddr>().ok().map(|i| i.to_string())
}

/// Профиль маршрутов Happ из настроек rxvpn.
pub fn happ_profile(s: &Settings, now: i64) -> Value {
    let (mut direct_d, mut direct_i) = split(&s.direct);
    let (mut proxy_d, mut proxy_i) = split(&s.proxy);
    // «Сайт → свой сервер»: Happ не умеет «через другой сервер» — эти сайты через VPN.
    for r in &s.site_servers {
        let (d, i) = split(&r.sites);
        proxy_d.extend(d);
        proxy_i.extend(i);
    }
    direct_i.insert(0, "geoip:private".into());
    let global = match s.route {
        RouteMode::BypassRu => {
            direct_d.splice(0..0, ["domain:ru".to_string(), "domain:su".into(), "domain:xn--p1ai".into()]);
            direct_i.push("geoip:ru".into());
            true
        }
        RouteMode::Global => true,
        RouteMode::Blocked => {
            proxy_d.insert(0, "geosite:ru-blocked".into());
            proxy_i.splice(0..0, ["geoip:ru-blocked".to_string(), "geoip:re-filter".into()]);
            false
        }
    };
    for v in [&mut direct_d, &mut direct_i, &mut proxy_d, &mut proxy_i] {
        let mut seen = std::collections::HashSet::new();
        v.retain(|x| seen.insert(x.clone()));
    }
    let remote_ip = plain_ip(&s.dns_remote).unwrap_or_else(|| "1.1.1.1".into());
    let direct_ip = plain_ip(&s.dns_direct).unwrap_or_else(|| "77.88.8.8".into());
    json!({
        "Name": "rxvpn",
        "GlobalProxy": if global { "true" } else { "false" },
        "RemoteDNSType": "DoU",
        "RemoteDNSDomain": "",
        "RemoteDNSIP": remote_ip,
        "DomesticDNSType": "DoU",
        "DomesticDNSDomain": "",
        "DomesticDNSIP": direct_ip,
        "Geoipurl": format!("{GEO}/geoip.dat"),
        "Geositeurl": format!("{GEO}/geosite.dat"),
        "LastUpdated": now.to_string(),
        "DnsHosts": {},
        "DirectSites": direct_d,
        "DirectIp": direct_i,
        "ProxySites": proxy_d,
        "ProxyIp": proxy_i,
        "BlockSites": if s.block_ads { vec!["geosite:category-ads-all"] } else { vec![] },
        "BlockIp": [],
        "DomainStrategy": "IPIfNonMatch",
        "FakeDNS": "false"
    })
}

/// Ссылка «добавить и включить» для Happ: открывается камерой телефона по QR.
pub fn happ_routing_link(s: &Settings, now: i64) -> String {
    let json = serde_json::to_string(&happ_profile(s, now)).unwrap();
    format!("happ://routing/onadd/{}", base64::engine::general_purpose::STANDARD.encode(json))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile() {
        let s = Settings {
            direct: vec!["sberbank.ru".into(), "95.163.0.0/16".into()],
            proxy: vec!["x.com".into()],
            block_ads: true,
            site_servers: vec![crate::xray::SiteServer { name: "ChatGPT".into(), sites: vec!["chatgpt.com".into()], server: "a".into(), ..Default::default() }],
            ..Default::default()
        };
        let p = happ_profile(&s, 5);
        assert_eq!(p["GlobalProxy"], "true");
        assert_eq!(p["DirectSites"][0], "domain:ru");
        assert!(p["DirectSites"].as_array().unwrap().contains(&json!("domain:sberbank.ru")));
        assert!(p["DirectIp"].as_array().unwrap().contains(&json!("95.163.0.0/16")));
        assert!(p["ProxySites"].as_array().unwrap().contains(&json!("domain:chatgpt.com")));
        assert_eq!(p["BlockSites"][0], "geosite:category-ads-all");
        let b = happ_profile(&Settings { route: RouteMode::Blocked, ..Default::default() }, 5);
        assert_eq!((b["GlobalProxy"].as_str(), b["ProxySites"][0].as_str()), (Some("false"), Some("geosite:ru-blocked")));
        let link = happ_routing_link(&s, 5);
        let b64 = link.strip_prefix("happ://routing/onadd/").unwrap();
        let back: Value = serde_json::from_slice(&base64::engine::general_purpose::STANDARD.decode(b64).unwrap()).unwrap();
        assert_eq!(back["Name"], "rxvpn");
    }
}
