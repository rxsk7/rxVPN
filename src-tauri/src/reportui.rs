//! «Сообщить о проблеме»: собрать отчёт (без секретов — `rxvpn_core::report`),
//! показать его человеку, скопировать или сохранить ровно то, что показали.

use rxvpn_core::{tr, trs};
use super::*;
use rxvpn_core::report::{self, Secrets};
use rxvpn_core::xray::{AppsMode, TorMode};

fn route_name(r: RouteMode) -> &'static str {
    match r {
        RouteMode::BypassRu => trs!("Обход РФ"),
        RouteMode::Blocked => trs!("Только заблокированное"),
        RouteMode::Global => trs!("Всё через VPN"),
    }
}

fn action_name(a: &rxvpn_core::Action) -> &'static str {
    match a {
        rxvpn_core::Action::Proxy => trs!("через VPN"),
        rxvpn_core::Action::Direct => trs!("напрямую"),
        rxvpn_core::Action::Block => trs!("блок"),
    }
}

fn list(v: &[String]) -> String {
    const MAX: usize = 40;
    let mut s = v.iter().take(MAX).cloned().collect::<Vec<_>>().join(", ");
    if v.len() > MAX {
        s.push_str(&tr!(" … и ещё {}", v.len() - MAX));
    }
    s
}

/// Маршруты по строке: то, что человек настроил сам.
fn routes(s: &Settings) -> Vec<String> {
    let mut r = Vec::new();
    r.push(tr!("Режим маршрутов: {}{}", route_name(s.route), if s.block_ads { trs!(", реклама режется") } else { "" }));
    if !s.proxy.is_empty() {
        r.push(tr!("Свои сайты → через VPN: {}", list(&s.proxy)));
    }
    if !s.direct.is_empty() {
        r.push(tr!("Свои сайты → напрямую: {}", list(&s.direct)));
    }
    match s.apps_mode {
        AppsMode::Except if !s.apps_direct.is_empty() => r.push(tr!("Программы мимо VPN: {}", list(&s.apps_direct))),
        AppsMode::Only => r.push(tr!("Через VPN только программы: {}", list(&s.apps_proxy))),
        _ => {}
    }
    for (i, x) in s.rules.iter().enumerate() {
        let mut cond = Vec::new();
        if !x.sites.is_empty() {
            cond.push(tr!("сайты {}", list(&x.sites)));
        }
        if !x.apps.is_empty() {
            cond.push(tr!("программы {}", list(&x.apps)));
        }
        if !x.ports.is_empty() {
            cond.push(tr!("порты {}", x.ports));
        }
        if !x.network.is_empty() {
            cond.push(x.network.clone());
        }
        if !x.protocols.is_empty() {
            cond.push(tr!("протоколы {}", list(&x.protocols)));
        }
        r.push(tr!("Правило {}{}: {} → {}",
            i + 1,
            if x.enabled { "" } else { trs!(" (выключено)") },
            if cond.is_empty() { trs!("всё").into() } else { cond.join(trs!(" и ")) },
            action_name(&x.action)
        ));
    }
    for (i, x) in s.site_servers.iter().enumerate() {
        r.push(tr!("Сайт → сервер {}: {} → свой сервер{}",
            i + 1,
            list(&x.sites),
            if x.backup.is_empty() { "" } else { trs!(" (+ запасной)") }
        ));
    }
    if s.zapret_hybrid {
        let svc = s.hybrid_services.clone().unwrap_or_else(|| vec!["youtube".into(), "discord".into()]);
        r.push(tr!("Гибрид (мимо VPN через zapret): {}{}", list(&svc), if s.hybrid_sites.is_empty() { String::new() } else { tr!("; свои: {}", list(&s.hybrid_sites)) }));
    }
    if s.tor_mode != TorMode::Off {
        r.push(format!("Tor: {:?}{}", s.tor_mode, if s.tor_sites.is_empty() { String::new() } else { tr!("; сайты: {}", list(&s.tor_sites)) }));
    }
    if !s.hosts.is_empty() {
        r.push(tr!("Свои записи DNS: {}", list(&s.hosts)));
    }
    r.push(tr!("DNS: через VPN {}, напрямую {}{}", s.dns_remote, s.dns_direct, if s.dns_ipv6 { trs!(", с IPv6") } else { "" }));
    if s.fragment || s.udp_noise {
        r.push(tr!("Анти-DPI: {}{}", if s.fragment { tr!("фрагменты {} / {} мс", s.fragment_length, s.fragment_delay) } else { String::new() }, if s.udp_noise { trs!(", шум UDP") } else { "" }));
    }
    if !s.node_tweaks.is_empty() {
        r.push(tr!("Подобранный обход у серверов: {}", s.node_tweaks.len()));
    }
    if s.net_profiles {
        r.push(tr!("Профили по сети: доверенных сетей {}", s.trusted_nets.len()));
    }
    r
}

/// Режим, подключение и прочее «как сейчас».
fn state_lines(st: &AppState) -> Vec<(String, String)> {
    let connected = is_connected(st);
    let tun = st.tun_active.load(Ordering::SeqCst);
    let zapret_name = zapret_running_name(st);
    let hybrid = st.hybrid.lock().unwrap().is_some();
    let tg = tg_view(st);
    let active = if connected { active_node(st).map(|(id, _)| id) } else { None };
    let ping = st.ping.load(Ordering::SeqCst);
    let health: Vec<String> = view(st).health.into_iter().map(|i| i.text).collect();
    let d = dohui::doh_view(st); // до замка store: по одному замку за раз
    let s = st.store.lock().unwrap();
    let mode = if s.settings.zapret {
        trs!("Без VPN (zapret)")
    } else if s.settings.tun {
        trs!("Все программы (TUN)")
    } else {
        trs!("Браузер (системный прокси)")
    };
    let server = |id: &str| s.servers.iter().find(|n| n.id == id).map(|n| n.summary()).unwrap_or_else(|| "?".into());
    let mut v = vec![
        (trs!("Режим").to_string(), mode.to_string()),
        (trs!("Подключено").into(), if connected { tr!("да{}", if tun { ", TUN" } else { "" }) } else { trs!("нет").into() }),
        (trs!("Выбран").into(), if s.is_auto() { trs!("⚡ Авто").into() } else { s.selected.as_deref().map(server).unwrap_or_else(|| trs!("ничего").into()) }),
    ];
    if let Some(id) = &active {
        v.push((trs!("Трафик идёт через").into(), format!("{}{}", server(id), if ping > 0 { tr!(", {ping} мс") } else { String::new() })));
    }
    v.push((trs!("Серверов / подписок").into(), format!("{} / {}", s.servers.len(), s.subscriptions.len())));
    v.push(("Zapret".into(), match (&zapret_name, hybrid) {
        (Some(n), true) => tr!("гибрид, стратегия {n}"),
        (Some(n), false) => tr!("работает, стратегия {n}"),
        (None, _) if !s.settings.zapret_strategy.is_empty() => tr!("не запущен (выбрана {})", s.settings.zapret_strategy),
        (None, _) => trs!("не запущен").into(),
    }));
    v.push((trs!("Telegram без VPN").into(), if tg.running {
        tr!("работает: соединений {}, веб {}, Cloudflare {}, напрямую {}, сбоев {}{}", tg.total, tg.web, tg.cloudflare, tg.direct, tg.failed, if tg.last_error.is_empty() { String::new() } else { tr!("; последняя ошибка: {}", tg.last_error) })
    } else if s.settings.tg_proxy {
        trs!("включён, но не работает").into()
    } else {
        trs!("выключен").into()
    }));
    v.push((trs!("DNS без подмены").into(), {
        if d.running {
            tr!("работает ({}): запросов {}, из кэша {}, сбоев {}{}", d.label, d.queries, d.cached, d.failed, if d.last_error.is_empty() { String::new() } else { tr!("; последняя ошибка: {}", d.last_error) })
        } else if s.settings.doh_sys {
            tr!("включён ({}), сейчас не работает", rxvpn_core::doh::provider_label(&s.settings.doh_provider, &s.settings.doh_url))
        } else {
            trs!("выключен").into()
        }
    }));
    v.push((trs!("Белые списки").into(), format!("{}{}", if s.settings.wl_auto { trs!("следить") } else { trs!("выкл") }, if st.wl_prev.lock().unwrap().is_some() { trs!(", сейчас переключены") } else { "" })));
    v.push((trs!("Всё ли в порядке").into(), if health.is_empty() { trs!("да").into() } else { health.join("; ") }));
    v
}

/// Собрать отчёт. `error` — текст ошибки, если «Сообщить» нажали в окне ошибки.
#[tauri::command]
pub(crate) async fn problem_report(st: State<'_, AppState>, error: Option<String>) -> Res<String> {
    let core = st.paths.core.clone();
    let xray_version = tauri::async_runtime::spawn_blocking(move || {
        if !runner::xray_path(&core).exists() {
            return String::new();
        }
        match runner::xray_cli(&core, &["version"]) {
            Ok(out) => out.lines().next().unwrap_or("").split_whitespace().take(2).collect::<Vec<_>>().join(" "),
            Err(e) => tr!("не ответил: {e}"),
        }
    })
    .await
    .unwrap_or_default();
    let windows = tauri::async_runtime::spawn_blocking(winsys::windows_version).await.unwrap_or_default();
    let (secrets, routes_v) = {
        let s = st.store.lock().unwrap();
        (Secrets::from_store(&s), routes(&s.settings))
    };
    let mut secrets = secrets;
    secrets.add_env_user();
    let input = report::Input {
        app_version: env!("CARGO_PKG_VERSION").into(),
        xray_version,
        windows,
        admin: winsys::is_admin(),
        portable: st.paths.portable,
        state: state_lines(&st),
        routes: routes_v,
        checks: st.checks.lock().unwrap().clone(),
        log: st.log_buf.lock().unwrap().iter().cloned().collect(),
        error: error.map(|e| e.chars().take(4000).collect()),
        now: now(),
    };
    let text = report::build(&input, &secrets);
    *st.last_report.lock().unwrap() = Some(text.clone());
    Ok(text)
}

fn last(st: &AppState) -> Res<String> {
    st.last_report.lock().unwrap().clone().ok_or_else(|| trs!("Отчёт ещё не собран").into())
}

/// Скопировать показанный отчёт.
#[tauri::command]
pub(crate) async fn problem_report_copy(st: State<'_, AppState>) -> Res<()> {
    let text = last(&st)?;
    arboard::Clipboard::new().and_then(|mut c| c.set_text(text)).map_err(|e| tr!("буфер обмена: {e}"))
}

/// «Открыть на GitHub»: отчёт — в буфер (в ссылку он не влезет: у GitHub предел длины),
/// а в браузере — форма новой проблемы с заготовкой, куда его вставить.
#[tauri::command]
pub(crate) async fn problem_report_github(st: State<'_, AppState>) -> Res<()> {
    let repo = rxvpn_core::update::REPO.ok_or(trs!("в этой сборке нет адреса репозитория"))?;
    let text = last(&st)?;
    arboard::Clipboard::new().and_then(|mut c| c.set_text(text)).map_err(|e| tr!("буфер обмена: {e}"))?;
    let body = format!(
        "{}


{}


<details><summary>{}</summary>

```
{}
```

</details>
",
        trs!("**Что случилось:**"),
        trs!("**Что делал перед этим:**"),
        trs!("Отчёт rxvpn"),
        trs!("(вставь сюда отчёт: Ctrl+V — он уже скопирован)"),
    );
    let enc = |s: &str| s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect::<String>();
    let title = format!("rxvpn {}: ", env!("CARGO_PKG_VERSION"));
    let url = format!("https://github.com/{repo}/issues/new?title={}&body={}", enc(&title), enc(&body));
    winsys::open_issue_link(&url)
}

/// Сохранить показанный отчёт в файл (.txt, UTF-8 с BOM и CRLF — для Блокнота).
#[tauri::command]
pub(crate) async fn problem_report_save(app: AppHandle, st: State<'_, AppState>) -> Res<Option<String>> {
    let text = last(&st)?;
    let name = format!("rxvpn-report-{}.txt", rxvpn_core::backup::date(now()));
    let Some(path) = pick_file(&app, trs!("Сохранить отчёт rxvpn"), (trs!("Текст"), &["txt"]), Some(name)).await? else {
        return Ok(None);
    };
    let body = format!("\u{feff}{}", text.replace("\r\n", "\n").replace('\n', "\r\n"));
    std::fs::write(&path, body).map_err(|e| tr!("не записался файл: {e}"))?;
    log(&app, trs!("отчёт о проблеме сохранён"));
    Ok(Some(path.display().to_string()))
}
