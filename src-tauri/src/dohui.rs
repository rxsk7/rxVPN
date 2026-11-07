//! «DNS без подмены» в режиме «Без VPN»: локальный DoH (core/src/doh.rs) и
//! системный DNS Windows на него (core/src/sysdns.rs).
//!
//! Работает сам по состоянию (`doh_sync` раз в 3 с и по событиям):
//! - галочка включена, режим «Без VPN», zapret работает → DoH запущен, DNS Windows наш;
//! - VPN подключён, галочку сняли или режим другой → сразу вернуть DNS и погасить;
//! - zapret на минуту пропал (подбор стратегии, перезапуск) — 20 с ждём, не дёргаем DNS;
//! - «Отключить», выход, паника — вернуть сразу; прошлый запуск упал — вернуть при старте.

use rxvpn_core::{tr, trs};
use super::*;
use rxvpn_core::{doh, sysdns};

/// Сколько ждём, пока zapret поднимется снова (подбор, перезапуск), прежде чем вернуть DNS.
const IDLE_GRACE: Duration = Duration::from_secs(20);
/// Не включилось — столько не пробуем снова (ошибка уже сказана).
const FAIL_PAUSE: i64 = 120;

pub(crate) struct DohRun {
    run: doh::Running,
    label: String,
    /// Номера карт, где DNS наш (для «появилась новая карта»).
    ifaces: Vec<u32>,
}

#[derive(Serialize, Default)]
pub(crate) struct DohView {
    pub running: bool,
    pub label: String,
    pub queries: u64,
    pub cached: u64,
    pub failed: u64,
    pub last_error: String,
}

pub(crate) fn doh_view(st: &AppState) -> DohView {
    let Some((s, label)) = st.doh_info.lock().unwrap().clone() else { return DohView::default() };
    let last_error = s.last_error.lock().unwrap().clone();
    DohView {
        running: true,
        label,
        queries: s.queries.load(Ordering::Relaxed),
        cached: s.cached.load(Ordering::Relaxed),
        failed: s.failed.load(Ordering::Relaxed),
        last_error,
    }
}

/// Имя DoH-сервера, если системный DNS сейчас наш (для «Почему не открывается сайт»).
pub(crate) fn doh_label_applied(st: &AppState) -> Option<String> {
    let l = st.doh_info.lock().unwrap().as_ref().map(|x| x.1.clone())?;
    sysdns::pending(&st.paths.data).then_some(l)
}

/// Что должно быть: Some(true) — работать, Some(false) — погасить сразу,
/// None — zapret временно не работает (ждём `IDLE_GRACE`).
fn wanted(st: &AppState) -> Option<bool> {
    let (on, zmode) = {
        let s = st.store.lock().unwrap();
        (s.settings.doh_sys, s.settings.zapret)
    };
    if !on || !zmode || is_connected(st) || !cfg!(windows) {
        return Some(false);
    }
    if zapret_running(st) && st.hybrid.lock().unwrap().is_none() {
        Some(true)
    } else {
        None
    }
}

/// Привести в соответствие (один шаг).
pub(crate) async fn doh_sync(app: &AppHandle) {
    let st = app.state::<AppState>();
    let mut slot = st.doh.lock().await;
    match wanted(&st) {
        Some(true) => {
            *st.doh_idle_since.lock().unwrap() = None;
            if let Some(r) = slot.as_mut() {
                // DNS вернули без нас (паника в задаче, руками) — включаем заново.
                if !sysdns::pending(&st.paths.data) {
                    log(app, trs!("DNS без подмены: системный DNS вернулся сам — ставлю снова"));
                    *slot = None;
                    *st.doh_info.lock().unwrap() = None;
                } else {
                    new_ifaces(app, &st, r).await;
                    return;
                }
            }
            if unix_now() < st.doh_fail_until.load(Ordering::SeqCst) {
                return;
            }
            match start(app, &st).await {
                Ok(r) => {
                    *st.doh_info.lock().unwrap() = Some((r.run.stats.clone(), r.label.clone()));
                    *slot = Some(r);
                    changed(app);
                }
                Err(e) => {
                    st.doh_fail_until.store(unix_now() + FAIL_PAUSE, Ordering::SeqCst);
                    log(app, tr!("DNS без подмены не включился: {e}"));
                    let _ = app.emit("error-toast", tr!("DNS без подмены не включился: {e}"));
                    changed(app);
                }
            }
        }
        None => {
            if slot.is_none() {
                return;
            }
            let since = *st.doh_idle_since.lock().unwrap().get_or_insert_with(Instant::now);
            if since.elapsed() >= IDLE_GRACE {
                stop_locked(app, &st, &mut slot, trs!("zapret не работает")).await;
            }
        }
        Some(false) => {
            *st.doh_idle_since.lock().unwrap() = None;
            st.doh_fail_until.store(0, Ordering::SeqCst);
            if slot.is_some() || sysdns::pending(&st.paths.data) {
                stop_locked(app, &st, &mut slot, trs!("выключено")).await;
            }
        }
    }
}

async fn start(app: &AppHandle, st: &AppState) -> Res<DohRun> {
    if !winsys::is_admin() {
        return Err(trs!("нужны права администратора (как и для zapret)").into());
    }
    let (key, url) = {
        let s = st.store.lock().unwrap();
        (s.settings.doh_provider.clone(), s.settings.doh_url.clone())
    };
    // Прошлый раз не вернули (упал) — сначала вернуть: иначе свой DoH по имени
    // резолвить было бы некому, а «прежним DNS» записался бы наш 127.0.0.1.
    let data = st.paths.data.clone();
    if sysdns::pending(&data) {
        let d = data.clone();
        tauri::async_runtime::spawn_blocking(move || sysdns::restore(&d)).await.map_err(|e| e.to_string())??;
    }
    let up = doh::upstream(&key, &url).await?;
    let label = doh::provider_label(&key, &url);
    let run = doh::start(doh::Config { upstream: up, listen: Vec::new(), extra_root_pem: None }).await?;
    let v6 = run.has_v6();
    let d = data.clone();
    let saved = tauri::async_runtime::spawn_blocking(move || {
        let t = sysdns::targets(rxvpn_core::xray::TUN_NAME, v6);
        sysdns::apply(&d, t)
    })
    .await
    .map_err(|e| e.to_string())??;
    let names: Vec<String> = saved.ifaces.iter().map(|i| format!("«{}»", i.alias)).collect();
    log(
        app,
        tr!("DNS без подмены: Windows спрашивает DNS у rxvpn (127.0.0.1{}), rxvpn — у {label} по HTTPS; карты: {}. Прежние DNS — запасными",
            if v6 { ", ::1" } else { "" },
            names.join(", ")
        ),
    );
    Ok(DohRun { run, label, ifaces: saved.ifaces.iter().map(|i| i.index).collect() })
}

/// Подключилась новая карта (кабель вместо Wi-Fi) — и ей наш DNS.
async fn new_ifaces(app: &AppHandle, st: &AppState, r: &mut DohRun) {
    let v6 = r.run.has_v6();
    let known = r.ifaces.clone();
    let data = st.paths.data.clone();
    let added = tauri::async_runtime::spawn_blocking(move || {
        let mut added = Vec::new();
        for i in sysdns::targets(rxvpn_core::xray::TUN_NAME, v6) {
            if !known.contains(&i.index) {
                let (idx, alias) = (i.index, i.alias.clone());
                added.push((idx, alias, sysdns::add(&data, i)));
            }
        }
        added
    })
    .await
    .unwrap_or_default();
    for (idx, alias, res) in added {
        match res {
            Ok(()) => {
                r.ifaces.push(idx);
                log(app, tr!("DNS без подмены: новая сеть «{alias}» — DNS и ей"));
            }
            Err(e) => log(app, tr!("DNS без подмены: у «{alias}» DNS не поменялся ({e})")),
        }
    }
}

async fn stop_locked(app: &AppHandle, st: &AppState, slot: &mut Option<DohRun>, why: &str) {
    // Сначала вернуть DNS, потом гасить сервер: иначе на секунду первым был бы мёртвый 127.0.0.1.
    let data = st.paths.data.clone();
    let r = tauri::async_runtime::spawn_blocking(move || sysdns::restore(&data)).await.map_err(|e| e.to_string()).and_then(|r| r);
    match r {
        Ok(()) => {
            st.doh_stuck.store(false, Ordering::SeqCst);
            if slot.is_some() {
                log(app, tr!("DNS без подмены: {why} — DNS Windows вернул как было"));
            }
        }
        Err(e) => {
            st.doh_stuck.store(true, Ordering::SeqCst);
            log(app, tr!("DNS без подмены: {e}"));
            notify(app, trs!("DNS Windows не вернулся"), trs!("Открой rxvpn → «Всё ли в порядке» → «Вернуть DNS»"));
        }
    }
    *slot = None;
    *st.doh_info.lock().unwrap() = None;
    changed(app);
}

/// Вернуть DNS сейчас же («Отключить», выключили галочку).
pub(crate) async fn doh_stop_now(app: &AppHandle, why: &str) {
    let st = app.state::<AppState>();
    let mut slot = st.doh.lock().await;
    if slot.is_some() || sysdns::pending(&st.paths.data) {
        stop_locked(app, &st, &mut slot, why).await;
    }
}

/// Выход и паника: только вернуть DNS, синхронно (сервер умрёт с процессом).
pub(crate) fn doh_restore_blocking(data: &std::path::Path) {
    if sysdns::pending(data) {
        let _ = sysdns::restore(data);
    }
}

pub(crate) fn spawn_doh_watch(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        // Прошлый запуск упал, не вернув DNS, — вернуть сразу.
        let st = app.state::<AppState>();
        if sysdns::pending(&st.paths.data) {
            let data = st.paths.data.clone();
            let admin = winsys::is_admin();
            let r = tauri::async_runtime::spawn_blocking(move || if admin { sysdns::restore(&data) } else { Err(trs!("нет прав администратора").into()) })
                .await
                .map_err(|e| e.to_string())
                .and_then(|r| r);
            match r {
                Ok(()) => {
                    st.doh_stuck.store(false, Ordering::SeqCst);
                    log(&app, trs!("DNS без подмены: прошлый запуск закрылся, не вернув DNS Windows, — вернул как было"));
                }
                Err(e) => {
                    st.doh_stuck.store(true, Ordering::SeqCst);
                    log(&app, tr!("DNS Windows остался на rxvpn после прошлого запуска ({e}). Интернет работает через прежние DNS (запасные), но лучше вернуть: «Всё ли в порядке» → «Вернуть DNS»"));
                }
            }
            changed(&app);
        }
        loop {
            doh_sync(&app).await;
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

/// Галочка и выбор сервера DoH.
#[tauri::command]
pub(crate) async fn doh_set(app: AppHandle, st: State<'_, AppState>, on: bool, provider: String, url: String) -> Res<View> {
    let url = url.trim().to_string();
    let next = {
        let mut n = st.store.lock().unwrap().settings.clone();
        (n.doh_sys, n.doh_provider, n.doh_url) = (on, provider, url);
        n
    };
    validate_settings(&next)?;
    if on && next.doh_provider == "custom" && next.doh_url.is_empty() {
        return Err(trs!("Впиши адрес своего DoH: https://сервер/dns-query").into());
    }
    let changed_server = {
        let mut s = st.store.lock().unwrap();
        let c = s.settings.doh_provider != next.doh_provider || s.settings.doh_url != next.doh_url;
        (s.settings.doh_sys, s.settings.doh_provider, s.settings.doh_url) = (next.doh_sys, next.doh_provider.clone(), next.doh_url.clone());
        c
    };
    persist(&st);
    st.doh_fail_until.store(0, Ordering::SeqCst);
    // Сменили сервер на ходу — перезапуск с новым.
    if !on || changed_server {
        doh_stop_now(&app, if on { trs!("сменил сервер DoH") } else { trs!("выключено") }).await;
    }
    if on && !next.zapret {
        log(&app, trs!("DNS без подмены включится в режиме «Без VPN» (с VPN DNS и так через него)"));
    }
    doh_sync(&app).await;
    Ok(view(&st))
}

/// «Вернуть DNS» после сбоя (нужны права администратора).
#[tauri::command]
pub(crate) async fn doh_restore(app: AppHandle, st: State<'_, AppState>) -> Res<View> {
    if !winsys::is_admin() {
        return Err(NEED_ADMIN.into());
    }
    // Работает и сейчас — «Вернуть» значит «выключить»: иначе через 3 с поставился бы снова.
    let running_now = st.doh.lock().await.is_some();
    if running_now {
        st.store.lock().unwrap().settings.doh_sys = false;
        persist(&st);
    }
    doh_stop_now(&app, trs!("вернуть DNS")).await;
    let data = st.paths.data.clone();
    tauri::async_runtime::spawn_blocking(move || sysdns::restore(&data)).await.map_err(|e| e.to_string())??;
    st.doh_stuck.store(false, Ordering::SeqCst);
    log(&app, trs!("DNS Windows вернул как было"));
    Ok(view(&st))
}
