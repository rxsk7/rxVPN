//! «Всё ли в порядке» — одна строка на главной. Только дешёвые проверки по
//! тому, что уже известно (время файлов, сохранённые результаты), без сети.

use serde::Serialize;

#[derive(Debug, Default, Clone)]
pub struct Inputs {
    /// Сколько дней ядру Xray (по времени файла). None — ядра нет.
    pub core_age_days: Option<i64>,
    pub core_missing: bool,
    /// Списки блокировок есть и старше недели.
    pub lists_stale: bool,
    /// Фоновая проверка zapret: стратегия перестала пробивать и замена не нашлась.
    pub zapret_broken: bool,
    /// (подписка, предупреждение от SubUsage::warning).
    pub subs: Vec<(String, String)>,
    /// Выбранный сервер «сдаёт» (stats.rs): имя.
    pub server_weak: Option<String>,
    /// Последняя проверка DNS нашла утечку.
    pub dns_leak: bool,
    /// Правила «Сайт → сервер», у которых нет сервера (сайты закрыты).
    pub closed_rules: usize,
    /// DNS Windows остался на DoH rxvpn (не вернулся после сбоя).
    pub dns_stuck: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Issue {
    /// "bad" — не работает; "warn" — стоит заняться.
    pub level: &'static str,
    pub text: String,
    /// Что нажать: core / lists / zapret / servers / subs / dns / sitesrv / dnsfix.
    pub action: &'static str,
    pub button: &'static str,
}

/// Ядро старше — предлагаем обновить (Xray выходит раз в 1–3 недели, ТСПУ меняется).
pub const CORE_OLD_DAYS: i64 = 60;

pub fn issues(i: &Inputs) -> Vec<Issue> {
    let mut v = Vec::new();
    let mut add = |level, text: String, action, button| v.push(Issue { level, text, action, button });
    if i.core_missing {
        add("bad", trs!("Ядро Xray не скачано — VPN не запустится").into(), "core", trs!("Скачать"));
    } else if let Some(d) = i.core_age_days.filter(|d| *d > CORE_OLD_DAYS) {
        add("warn", tr!("Ядру Xray {d} дн. — свежее лучше обходит блокировки"), "core", trs!("Обновить"));
    }
    if i.dns_stuck {
        add("bad", trs!("DNS Windows остался на rxvpn после сбоя — сайты открываются через запасные DNS").into(), "dnsfix", trs!("Вернуть DNS"));
    }
    if i.closed_rules > 0 {
        add("bad", tr!("Сайт → сервер: у {} правил(а) нет сервера — эти сайты закрыты", i.closed_rules), "sitesrv", trs!("Открыть"));
    }
    if i.zapret_broken {
        add("bad", trs!("zapret перестал пробивать YouTube/Discord, замена не нашлась").into(), "zapret", trs!("Подобрать"));
    }
    if let Some(n) = &i.server_weak {
        add("warn", tr!("Сервер «{n}» в последние сутки сдаёт"), "servers", trs!("Сменить"));
    }
    for (name, w) in &i.subs {
        add("warn", format!("«{name}»: {w}"), "subs", trs!("Открыть"));
    }
    if i.dns_leak {
        add("warn", trs!("Последняя проверка нашла утечку DNS").into(), "dns", trs!("Проверить"));
    }
    if i.lists_stale {
        add("warn", trs!("Списки блокировок старше недели").into(), "lists", trs!("Обновить"));
    }
    // Самое важное — первым: «bad» выше «warn».
    v.sort_by_key(|x| x.level != "bad");
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_and_quiet() {
        assert!(issues(&Inputs { core_age_days: Some(3), ..Default::default() }).is_empty(), "всё ок — пусто");
        let v = issues(&Inputs {
            core_age_days: Some(90),
            lists_stale: true,
            closed_rules: 2,
            subs: vec![("Провайдер".into(), "подписка кончается через 2 дня".into())],
            server_weak: Some("NL".into()),
            ..Default::default()
        });
        assert_eq!(v[0].action, "sitesrv", "закрытые сайты — первыми");
        assert_eq!(v.len(), 5);
        assert!(v.iter().any(|x| x.text.contains("90 дн.")));
        let m = issues(&Inputs { core_missing: true, core_age_days: Some(400), ..Default::default() });
        assert_eq!((m.len(), m[0].level), (1, "bad"));
        let d = issues(&Inputs { dns_stuck: true, lists_stale: true, ..Default::default() });
        assert_eq!((d[0].action, d[0].button), ("dnsfix", "Вернуть DNS"));
    }
}
