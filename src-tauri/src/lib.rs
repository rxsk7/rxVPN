//! Tauri-обёртка: команды, которые дёргает интерфейс (ui/app.js), трей,
//! автозапуск, монитор (скорость, проверка связи, «Авто») и уведомления.

mod dohui;
mod notify;
mod pauseui;
mod reportui;
mod updui;
mod vpsui;
mod warpui;

use rxvpn_core::{tr, trs};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rxvpn_core::batch::{self, TestResult};
use rxvpn_core::checks;
use rxvpn_core::filter;
use rxvpn_core::geodata::{self, ListsInfo};
use rxvpn_core::runner::{self, XrayProcess};
use rxvpn_core::services;
use rxvpn_core::tgproxy;
use rxvpn_core::zapret;
use rxvpn_core::{
    auto_tag, build_config, build_run_config, build_test_config, net, qr, site_routes, site_tags, sysproxy,
    validate_settings, winsys, ImportResult, Node, RouteMode, RunOpts, Settings, Store,
    Subscription, Upstream, PROBE_URLS_HTTP,
};
use serde::Serialize;
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, State, Wry};

/// Ошибка-сигнал для интерфейса: для TUN и zapret нужен перезапуск от администратора.
const NEED_ADMIN: &str = "NEED_ADMIN";
/// Порт «замка» от второго запуска (и канал «покажи окно» между копиями).
const LOCK_PORT: u16 = 47389;
const TRAY_ON: &[u8] = include_bytes!("../icons/tray-on.png");
const TRAY_OFF: &[u8] = include_bytes!("../icons/tray-off.png");
const APP_ICON: &[u8] = include_bytes!("../icons/128x128.png");

struct Paths {
    data: PathBuf,
    store: PathBuf,
    core: PathBuf,
    /// Движок zapret (winws) и его рабочая папка.
    zapret_bin: PathBuf,
    /// Портативный режим: всё хранится в папке `data` рядом с rxvpn.exe.
    portable: bool,
    /// Это защищённая копия в Program Files (rxvpn.exe, ядро и движок zapret там, куда
    /// пишет только администратор). С правами администратора rxvpn работает только так.
    protected: bool,
    /// Папка программы.
    app_dir: PathBuf,
}

/// Что запущено сейчас.
#[derive(Clone)]
struct RunInfo {
    gen: u64,
    /// «Авто»: все сервера в одном Xray, трафик — через выбранный.
    auto: bool,
    /// тег исходящего -> (id сервера, имя). Для одного сервера тег "proxy".
    nodes: Vec<(String, String, String)>,
    /// Через какой исходящий идёт трафик в этом запуске ("proxy" или "node-N").
    active: String,
    /// «Сайт → свой сервер»: их исходящие (кроме active) — тоже трафик VPN.
    extra: Vec<String>,
    metrics_port: u16,
    probe_port: u16,
    /// Вход «прямо в интернет» (проверка белых списков, мимо VPN и TUN) и его пароль.
    direct_port: u16,
    direct_pass: String,
}

impl RunInfo {
    fn name_of(&self, tag: &str) -> String {
        self.nodes
            .iter()
            .find(|(t, ..)| t == tag)
            .map(|(_, _, n)| n.clone())
            .unwrap_or_else(|| tag.to_string())
    }
    fn id_of(&self, tag: &str) -> Option<String> {
        self.nodes.iter().find(|(t, ..)| t == tag).map(|(_, id, _)| id.clone())
    }
}

struct AppState {
    paths: Paths,
    /// Автопроверка выпуска (`--smoke`, dev/release.py): см. `smoke_ready`.
    smoke: bool,
    /// «Пауза» (pauseui.rs): VPN выключен на время, потом включится сам.
    pause: Mutex<Option<pauseui::Pause>>,
    pause_gen: AtomicU64,
    store: Mutex<Store>,
    proc: Mutex<Option<XrayProcess>>,
    /// Счётчик запусков. Нужен, чтобы отличить "мы сами остановили ядро"
    /// от "ядро упало": при падении номер не меняется. По нему же
    /// останавливаются фоновые задачи прошлого подключения.
    gen: AtomicU64,
    /// Какой адрес мы прописали в системный прокси (чтобы убрать за собой).
    proxy_set: Mutex<Option<String>>,
    run: Mutex<Option<RunInfo>>,
    /// Через какой исходящий идёт трафик прямо сейчас ("proxy" или "node-N").
    active_tag: Mutex<Option<String>>,
    /// Последняя задержка текущего сервера, мс (0 — неизвестно / не отвечает).
    ping: AtomicU64,
    /// Результаты «Проверить все»: id -> мс. «Авто» начинает с лучшего.
    last_test: Mutex<HashMap<String, u64>>,
    /// Текущее подключение идёт через TUN.
    tun_active: AtomicBool,
    /// Идёт «Проверить все».
    testing: AtomicBool,
    /// Идёт «Проверить скорость всех» и её «Стоп».
    speed_all_busy: AtomicBool,
    speed_all_cancel: Arc<AtomicBool>,
    /// Качаются списки блокировок.
    lists_busy: AtomicBool,
    /// Идёт проверка скорости.
    speed_busy: AtomicBool,
    /// «Авто» между перезапусками: какой сервер выбран (id) — его и берём
    /// при следующем запуске; с каких ушли из-за сбоя (id → unix-время);
    /// «ничего не отвечает» уже сказали (чтобы не повторять).
    auto_prefer: Mutex<Option<String>>,
    auto_bad: Mutex<HashMap<String, i64>>,
    auto_down: AtomicBool,
    /// Последние строки лога: окно забирает их при загрузке, иначе то, что
    /// случилось до него (например, ошибка автоподключения), потеряется.
    log_buf: Mutex<std::collections::VecDeque<String>>,
    /// Zapret (режим «без VPN»): запущенный winws и счётчик запусков (как `gen`).
    zapret: Mutex<Option<ZapretRun>>,
    zgen: AtomicU64,
    /// Гибрид работает: как запущен winws рядом с VPN (для перезапуска и подбора).
    hybrid: Mutex<Option<zapret::Hybrid>>,
    /// «Telegram без VPN»: работающий прокси (запуск/остановка — по одному) и его
    /// счётчики с портом для окна (без ожидания замка).
    tg: tokio::sync::Mutex<Option<tgproxy::Running>>,
    tg_info: Mutex<Option<(Arc<tgproxy::Stats>, u16)>>,
    /// Идёт «Почему не открывается сайт».
    diag_busy: AtomicBool,
    /// Идёт проверка сервисов через сервер.
    svc_busy: AtomicBool,
    /// Идёт операция со своим сервером (установка, друзья…).
    vps_busy: AtomicBool,
    /// Tor на Arti (живёт между перезапусками Xray: подключение к сети Tor — долгое).
    tor: Mutex<Option<rxvpn_core::tor::Running>>,
    /// Белые списки: на помеченный сервер ушли сами — откуда (id выбранного до этого).
    wl_prev: Mutex<Option<String>>,
    wl_busy: AtomicBool,
    /// Для «Всё ли в порядке»: zapret перестал пробивать; последняя проверка DNS — утечка.
    zapret_broken: AtomicBool,
    /// Kill switch (режим «Все программы»): фильтры WFP держатся, пока он здесь (core/src/killswitch.rs).
    kill: Mutex<Option<rxvpn_core::killswitch::KillSwitch>>,
    /// Запасные протоколы того же сервера, уже пробованные после сбоя (сброс — reset_auto).
    fallback_tried: Mutex<std::collections::HashSet<String>>,
    /// Трафик по программам: сессия ETW, пока открыто окно (app_traffic / app_traffic_stop).
    app_traffic: Mutex<Option<rxvpn_core::apptraffic::AppTraffic>>,
    dns_leak: AtomicBool,
    /// «Разрешить IPv6» включено, но при последнем подключении IPv6 у сетевых карт не было —
    /// программам выдаётся только IPv4 (см. start_core).
    ipv6_off: AtomicBool,
    /// Стабильность серверов (data\stats.json) и есть ли несохранённое.
    stats: Mutex<rxvpn_core::stats::Stats>,
    stats_dirty: AtomicBool,
    /// state.json зашифрован под другой учёткой/на другом компе: не сохраняем
    /// поверх него, чтобы ничего не потерять.
    state_locked: AtomicBool,
    /// Настоящая сетевая карта (узнаём, пока TUN не поднят).
    phys_iface: Mutex<Option<u32>>,
    /// Запуск zapret и подбор — по одному (трей и окно могут нажать одновременно).
    zop: tokio::sync::Mutex<()>,
    /// Идёт подбор стратегии; «Стоп»; результаты последнего подбора.
    ztesting: AtomicBool,
    zcancel: Arc<AtomicBool>,
    zresults: Mutex<Vec<zapret::Score>>,
    /// Запуск VPN — по одному (`start_core_ex`).
    core_op: Mutex<()>,
    /// До какого времени (unix) фоновая проверка не подбирает заново.
    zquiet_until: std::sync::atomic::AtomicI64,
    /// После перезапуска от администратора: что сделать окну («zapret-test»).
    startup_action: Mutex<Option<String>>,
    /// О какой подписке в какой день уже предупредили (id → номер дня).
    sub_warned: Mutex<HashMap<String, i64>>,
    /// «DNS без подмены» (dohui.rs): работающий DoH, его счётчики для окна,
    /// с какого момента zapret не работает, пауза после ошибки, DNS не вернулся.
    doh: tokio::sync::Mutex<Option<dohui::DohRun>>,
    doh_info: Mutex<Option<(Arc<rxvpn_core::doh::Stats>, String)>>,
    doh_idle_since: Mutex<Option<Instant>>,
    doh_fail_until: std::sync::atomic::AtomicI64,
    doh_stuck: AtomicBool,
    /// Итоги последних проверок (по одной на вид) — для «Сообщить о проблеме».
    checks: Mutex<Vec<rxvpn_core::report::CheckNote>>,
    /// Отчёт, показанный человеку: копируется и сохраняется именно он.
    last_report: Mutex<Option<String>>,
}

const LOG_KEEP: usize = 500;

/// Строка в лог: в буфер и в окно.
fn emit_log(app: &AppHandle, line: String) {
    {
        let st = app.state::<AppState>();
        let mut b = st.log_buf.lock().unwrap();
        if b.len() >= LOG_KEEP {
            b.pop_front();
        }
        b.push_back(line.clone());
    }
    let _ = app.emit("log", line);
}

// Правило: никогда не держим два Mutex одновременно — так не будет дедлоков.

#[derive(Serialize)]
struct ServerView {
    id: String,
    name: String,
    summary: String,
    address: String,
    port: u16,
    sub_id: Option<String>,
    group: Option<String>,
    /// Стабильность за 7 дней (None — мало проверок).
    stab: Option<rxvpn_core::stats::Score>,
    /// Скорость по последним замерам, Мбит/с (None — не мерили).
    mbps: Option<f32>,
    /// Скрыт фильтром — почему (None — виден).
    hidden: Option<filter::Hide>,
}

/// Один значок состояния защиты: ok — зелёный, warn — жёлтый, bad — красный.
#[derive(Serialize)]
struct ShieldItem {
    level: &'static str,
    text: String,
    /// Подсказка при наведении: что это значит.
    hint: String,
}

/// Что защищено прямо сейчас — честно, по состоянию программы, без догадок. Только пока
/// VPN подключён: без него защищать нечего (про закрытый kill switch'ем интернет говорит
/// сама главная).
fn shield(s: &Settings, connected: bool, tun: bool, kill_on: bool, dns_leak: bool, v6_off: bool) -> Vec<ShieldItem> {
    let mut v = Vec::new();
    if !connected {
        return v;
    }
    let mut add = |level: &'static str, text: &str, hint: &str| v.push(ShieldItem { level, text: text.into(), hint: hint.into() });
    if tun {
        // Что именно идёт через VPN, решает маршрут: «Все программы» — это про программы, а не про сайты.
        match s.route {
            RouteMode::Global => add("ok", trs!("Всё через VPN"), trs!("Маршрут «Всё»: через VPN идут все программы, игры и службы Windows, на любые сайты")),
            RouteMode::BypassRu => add("ok", trs!("Всё через VPN, кроме РФ"), trs!("Маршрут «Обход РФ»: все программы, игры и службы Windows идут через VPN, а российские сайты — напрямую, с твоим IP")),
            RouteMode::Blocked => add("warn", trs!("Через VPN — только заблокированное"), trs!("Маршрут «Только блок.»: через VPN идут только сайты, заблокированные в РФ, — из любых программ. Всё остальное — напрямую, с твоим IP")),
        }
        if kill_on && s.zapret_hybrid {
            add("ok", trs!("Kill switch включён"), trs!("Упадёт VPN — программы не выйдут в интернет напрямую. Сайты «мимо VPN» идут через zapret, как и раньше. Локальная сеть работает"));
        } else if kill_on {
            add("ok", trs!("Kill switch включён"), trs!("Упадёт VPN — программы не выйдут в интернет напрямую. Локальная сеть работает"));
        } else if s.kill_switch {
            add("bad", trs!("Kill switch снят"), trs!("Он включён в настройках, но сейчас не работает. Упадёт VPN — трафик пойдёт напрямую"));
        } else {
            add("warn", trs!("Kill switch выключен"), trs!("Упадёт VPN — программы пойдут в интернет напрямую. Включается в настройках"));
        }
    } else {
        add("warn", trs!("Через VPN — только браузер"), trs!("Режим «Браузер»: через VPN идут программы, которые слушаются системного прокси Windows. Игры и остальные программы — напрямую. Всё целиком — режим «Все программы»"));
    }
    if dns_leak {
        add("bad", trs!("DNS идёт мимо VPN"), trs!("Последняя проверка нашла утечку: провайдер видит имена сайтов. Открой «Мой IP и утечки»"));
    } else if tun {
        add("ok", trs!("DNS через VPN"), trs!("Имена сайтов узнаются внутри туннеля — провайдер их не видит"));
    }
    if v6_off && s.dns_ipv6 {
        add("warn", trs!("IPv6 выключен: у провайдера его нет"), trs!("В настройках стоит «Разрешить IPv6», но у твоей сети нет IPv6-адреса. С ним программы рвали бы соединения, поэтому rxvpn выдаёт им только IPv4. Сними галку в настройках — и значок пропадёт"));
    }
    v
}

#[derive(Serialize, Default)]
struct TgView {
    running: bool,
    port: u16,
    link: String,
    active: usize,
    total: u64,
    web: u64,
    cloudflare: u64,
    direct: u64,
    failed: u64,
    last_error: String,
}

fn tg_view(st: &AppState) -> TgView {
    let info = st.tg_info.lock().unwrap().clone();
    let Some((s, port)) = info else { return TgView::default() };
    let secret = st.store.lock().unwrap().settings.tg_secret.clone();
    let link = tgproxy::secret_from_hex(&secret).map(|k| tgproxy::link(port, &k)).unwrap_or_default();
    let last_error = s.last_error.lock().unwrap().clone();
    TgView {
        running: true,
        port,
        link,
        active: s.active.load(Ordering::Relaxed),
        total: s.total.load(Ordering::Relaxed),
        web: s.web.load(Ordering::Relaxed),
        cloudflare: s.cloudflare.load(Ordering::Relaxed),
        direct: s.direct.load(Ordering::Relaxed),
        failed: s.failed.load(Ordering::Relaxed),
        last_error,
    }
}

#[derive(Serialize)]
struct View {
    servers: Vec<ServerView>,
    /// «Скрыть мёртвые», «убрать дубли».
    list_filter: filter::ListFilter,
    /// Язык, на котором сейчас говорит программа ("ru"/"en"); выбор пользователя — settings.lang.
    lang: &'static str,
    subscriptions: Vec<Subscription>,
    settings: Settings,
    selected: Option<String>,
    /// Выбран «Авто».
    auto: bool,
    connected: bool,
    /// Сервер, через который идёт трафик сейчас (в «Авто» меняется сам).
    active_id: Option<String>,
    active_name: Option<String>,
    tun_active: bool,
    is_admin: bool,
    testing: bool,
    /// Идёт «Проверить скорость всех».
    speed_all: bool,
    lists: Option<ListsInfo>,
    lists_busy: bool,
    core_installed: bool,
    /// sing-box для серверов TUIC скачан.
    singbox_installed: bool,
    core_dir: String,
    data_dir: String,
    portable: bool,
    /// Можно ли просить права администратора (Windows; с правами работает защищённая копия).
    admin_ok: bool,
    /// Работает zapret (режим «без VPN») и с какой стратегией.
    zapret_active: bool,
    zapret_name: Option<String>,
    zapret_testing: bool,
    /// «Telegram без VPN»: работает ли, ссылка для Telegram, счётчики соединений.
    tg: TgView,
    /// «DNS без подмены» (режим «Без VPN»).
    doh: dohui::DohView,
    /// Свои сервера («Свой сервер»), без секретов.
    vps: Vec<vpsui::VpsView>,
    /// Tor: (готов ли, строка для окна). None — Arti не работает.
    tor: Option<(bool, String)>,
    /// Белые списки: на помеченный сервер ушли сами (вернёмся, когда режим кончится).
    wl_switched: bool,
    /// «Всё ли в порядке» на главной: пусто — всё ок.
    health: Vec<rxvpn_core::health::Issue>,
    /// VPN + zapret для YouTube и Discord.
    hybrid_active: bool,
    is_windows: bool,
    /// Kill switch включён: без VPN интернет закрыт (кроме локальной сети).
    kill_on: bool,
    /// Что сейчас защищено — строка значков на главной (пусто — не подключено).
    shield: Vec<ShieldItem>,
    /// Есть версия новее (проверенная) — плашка на главной.
    update: Option<updui::UpdateBrief>,
    /// Пауза: идёт ли и до какого unix-времени (None внутри — до включения вручную).
    paused: bool,
    pause_until: Option<i64>,
}

#[derive(Serialize, Clone)]
struct Stats {
    up_speed: u64,
    down_speed: u64,
    up_total: u64,
    down_total: u64,
    /// Задержка текущего сервера по последней проверке, мс.
    ping: Option<u64>,
}

#[derive(Serialize, Clone)]
struct AutoStatus {
    active_id: Option<String>,
    /// id сервера -> задержка (None — не отвечает / ещё не проверен).
    delays: Vec<(String, Option<u64>)>,
}

type Res<T> = Result<T, String>;

fn log(app: &AppHandle, msg: impl AsRef<str>) {
    emit_log(app, format!("[rxvpn] {}", msg.as_ref()));
}

/// Уведомление Windows (если не выключены) + строка в лог.
fn notify(app: &AppHandle, title: impl AsRef<str>, body: impl AsRef<str>) {
    let (title, body) = (title.as_ref(), body.as_ref());
    log(app, format!("{title}: {body}"));
    let on = app.state::<AppState>().store.lock().unwrap().settings.notifications;
    if on {
        notify::show(title, body);
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn is_connected(st: &AppState) -> bool {
    st.proc
        .lock()
        .unwrap()
        .as_mut()
        .map(|p| p.is_running())
        .unwrap_or(false)
}

fn persist(st: &AppState) {
    if st.state_locked.load(Ordering::SeqCst) {
        return; // зашифрованный чужой учёткой state.json не затираем
    }
    let s = st.store.lock().unwrap();
    let _ = s.save(&st.paths.store);
    // Копия с правами — снимок охраняемых настроек рядом с собой (см. guard_settings).
    if st.paths.protected && winsys::is_admin() {
        let _ = rxvpn_core::guard::save(&st.paths.app_dir, &s);
    }
}

/// При запуске копии с правами: охраняемые настройки (DoH всей Windows, прокси в
/// локальную сеть, DNS, своя папка zapret) поменялись не ею — спросить. «Нет» (по
/// умолчанию) — вернуть из снимка. Итог сразу сохраняется (и в state.json, и в снимок).
fn guard_settings(paths: &Paths, store: &mut Store) -> bool {
    use rxvpn_core::guard;
    let trusted = guard::load(&paths.app_dir);
    let changes = guard::diff(&store.settings, trusted.as_ref());
    let servers = guard::servers_changed(store, trusted.as_ref());
    let mut dirty = false;
    if !changes.is_empty() && !winsys::confirm_box("rxvpn", &guard::prompt(&changes)) {
        guard::revert(&mut store.settings, trusted.as_ref());
        dirty = true;
    }
    // Сервера из снимка не вернуть (там только отпечаток): «Нет» — не подключаться самому.
    let servers_refused = servers && !winsys::confirm_box("rxvpn", &guard::prompt_servers());
    if servers_refused {
        store.settings.auto_connect = false;
        store.settings.connect_apps.clear();
        store.settings.net_profiles = false;
        dirty = true;
    }
    if dirty {
        let _ = store.save(&paths.store);
    }
    let _ = if servers_refused {
        guard::save_keeping_servers(&paths.app_dir, store, trusted.as_ref())
    } else {
        guard::save(&paths.app_dir, store)
    };
    servers_refused
}

/// Итог проверки — для отчёта «Сообщить о проблеме» (по одному на вид).
fn note_check(st: &AppState, kind: &str, text: impl Into<String>) {
    let mut c = st.checks.lock().unwrap();
    c.retain(|x| x.kind != kind);
    c.push(rxvpn_core::report::CheckNote { kind: kind.into(), at: now(), text: text.into() });
}

/// Результат проверки сервера — в копилку стабильности.
fn stat(st: &AppState, id: &str, ms: Option<u64>) {
    st.stats.lock().unwrap().record(id, unix_now(), ms);
    st.stats_dirty.store(true, Ordering::SeqCst);
}

/// Сервера, чья последняя проверка (за сутки) не прошла — для «скрыть мёртвые».
/// Отдельно от замка store: его берут после.
fn dead_ids(st: &AppState) -> std::collections::HashSet<String> {
    let now = unix_now();
    let s = st.stats.lock().unwrap();
    s.dead.keys().filter(|id| s.is_dead(id, now)).cloned().collect()
}

/// Видимые с учётом фильтров сервера (для «Авто», «Скорость всех», трея).
fn visible_servers(st: &AppState) -> Vec<Node> {
    let dead = dead_ids(st);
    filter::visible(&st.store.lock().unwrap(), |id| dead.contains(id))
}

/// Сохранить стабильность, если есть новое (заодно забыть удалённые сервера).
fn save_stats(st: &AppState) {
    if !st.stats_dirty.swap(false, Ordering::SeqCst) {
        return;
    }
    let ids: Vec<String> = st.store.lock().unwrap().servers.iter().map(|n| n.id.clone()).collect();
    let keep: std::collections::HashSet<&str> = ids.iter().map(String::as_str).collect();
    let mut s = st.stats.lock().unwrap();
    s.prune(unix_now(), &keep);
    let _ = s.save(&st.paths.data.join("stats.json"));
}

/// Включили шифрование — зашифровать и страховочные копии в data\backups.
fn seal_backups(dir: &std::path::Path) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if !e.file_type().is_ok_and(|t| t.is_file()) || p.extension().is_none_or(|x| x != "json") {
            continue;
        }
        let Ok(data) = std::fs::read(&p) else { continue };
        if rxvpn_core::store::unseal(&data).is_some() {
            continue; // уже зашифрован
        }
        if let Ok(sealed) = rxvpn_core::store::seal(&data) {
            let tmp = p.with_extension("json.tmp");
            if std::fs::write(&tmp, sealed).is_ok() {
                let _ = std::fs::rename(&tmp, &p);
            }
        }
    }
}

/// (id, имя) сервера, через который идёт трафик сейчас.
fn active_node(st: &AppState) -> Option<(String, String)> {
    let info = st.run.lock().unwrap().clone()?;
    let tag = st.active_tag.lock().unwrap().clone()?;
    Some((info.id_of(&tag)?, info.name_of(&tag)))
}

/// Порт служебного входа, если подключены: через него качаем подписки,
/// ядро и списки — всегда через VPN, какие бы правила ни стояли.
fn probe_proxy(st: &AppState) -> Option<u16> {
    if !is_connected(st) {
        return None;
    }
    st.run.lock().unwrap().as_ref().map(|r| r.probe_port)
}

fn view(st: &AppState) -> View {
    let connected = is_connected(st);
    let zapret_name = zapret_running_name(st);
    let hybrid = st.hybrid.lock().unwrap().is_some(); // до замка store: по одному замку за раз
    let tg = tg_view(st); // он сам берёт замок store — до нашего
    let doh = dohui::doh_view(st);
    let dns_stuck = st.doh_stuck.load(Ordering::SeqCst) && st.doh_info.lock().unwrap().is_none();
    let tor = st.tor.lock().unwrap().as_ref().map(|r| r.status());
    let wl_switched = st.wl_prev.lock().unwrap().is_some();
    let core_installed = runner::xray_path(&st.paths.core).exists();
    let active = if connected { active_node(st) } else { None };
    let now = unix_now();
    let (scores, speeds): (HashMap<String, rxvpn_core::stats::Score>, HashMap<String, f32>) = {
        let ids: Vec<String> = st.store.lock().unwrap().servers.iter().map(|n| n.id.clone()).collect();
        let stats = st.stats.lock().unwrap();
        (
            ids.iter().filter_map(|id| stats.score(id, now).map(|sc| (id.clone(), sc))).collect(),
            ids.iter().filter_map(|id| stats.speed(id, now).map(|v| (id.clone(), v))).collect(),
        )
    };
    let core_age_days = std::fs::metadata(runner::xray_path(&st.paths.core))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|d| (d.as_secs() / 86_400) as i64);
    let lists_stale = geodata::present(&st.paths.core) && geodata::stale(&st.paths.core, 7);
    let dead = dead_ids(st);
    let s = st.store.lock().unwrap();
    let hidden = filter::hidden(&s, |id| dead.contains(id));
    let health = rxvpn_core::health::issues(&rxvpn_core::health::Inputs {
        core_age_days,
        core_missing: !core_installed,
        lists_stale,
        zapret_broken: st.zapret_broken.load(Ordering::SeqCst),
        subs: s.subscriptions.iter().filter_map(|x| { let u = x.usage?; Some((x.name.clone(), u.warning(now)?, u.ended(now))) }).collect(),
        server_weak: if s.is_auto() { None } else { s.selected_node().filter(|n| scores.get(&n.id).is_some_and(|sc| sc.degraded)).map(|n| n.name.clone()) },
        dns_leak: st.dns_leak.load(Ordering::SeqCst),
        closed_rules: site_routes(&s.settings, &s.servers).iter().filter(|r| r.node.is_none()).count(),
        dns_stuck,
    });
    // Замок kill берём один раз и отпускаем до сборки View: временные значения внутри
    // литерала структуры живут до его конца, второй lock() там же — взаимная блокировка
    // (окно навсегда застывало пустым: get_view не отвечал).
    let kill_on = st.kill.lock().unwrap().is_some();
    let tun_now = st.tun_active.load(Ordering::SeqCst);
    let dns_leak = st.dns_leak.load(Ordering::SeqCst);
    let paused = pauseui::current(st);
    View {
        health,
        servers: s
            .servers
            .iter()
            .map(|n| ServerView {
                id: n.id.clone(),
                name: n.name.clone(),
                summary: if n.plain() { format!("{} · ⚠ {}", n.summary(), trs!("без шифрования")) } else { n.summary() },
                address: n.address.clone(),
                port: n.port,
                sub_id: n.sub_id.clone(),
                group: n.group.clone(),
                stab: scores.get(&n.id).copied(),
                mbps: speeds.get(&n.id).copied(),
                hidden: hidden.get(&n.id).copied(),
            })
            .collect(),
        list_filter: s.list_filter,
        lang: rxvpn_core::i18n::lang().code(),
        subscriptions: s.subscriptions.clone(),
        settings: s.settings.clone(),
        selected: s.selected.clone(),
        auto: s.is_auto(),
        connected,
        active_id: active.as_ref().map(|a| a.0.clone()),
        active_name: active.map(|a| a.1),
        tun_active: connected && st.tun_active.load(Ordering::SeqCst),
        is_admin: winsys::is_admin(),
        testing: st.testing.load(Ordering::SeqCst),
        speed_all: st.speed_all_busy.load(Ordering::SeqCst),
        lists: geodata::info(&st.paths.core),
        lists_busy: st.lists_busy.load(Ordering::SeqCst),
        core_installed,
        singbox_installed: rxvpn_core::singbox::installed(&st.paths.core),
        core_dir: st.paths.core.display().to_string(),
        data_dir: st.paths.data.display().to_string(),
        portable: st.paths.portable,
        admin_ok: cfg!(windows),
        zapret_active: zapret_name.is_some() && !(connected && hybrid),
        hybrid_active: connected && zapret_name.is_some() && hybrid,
        zapret_name,
        zapret_testing: st.ztesting.load(Ordering::SeqCst),
        is_windows: cfg!(windows),
        kill_on,
        shield: shield(&s.settings, connected, tun_now, kill_on, dns_leak, st.ipv6_off.load(Ordering::SeqCst)),
        update: updui::found(),
        paused: paused.is_some(),
        pause_until: paused.and_then(|p| p.until),
        tg,
        doh,
        vps: vpsui::views(&s),
        tor,
        wl_switched,
    }
}

/// Состояние поменялось не из окна (трей, падение ядра, автоподключение,
/// «Авто» переключился) — обновить трей и сказать окну перечитать данные.
fn changed(app: &AppHandle) {
    refresh_tray(app);
    let _ = app.emit("state-changed", ());
}

// ---------------- запуск / остановка ----------------

fn stop_core(st: &AppState) {
    stop_core_ex(st, false);
}

/// Системный прокси, оставленный на время перезапуска ядра (смена сервера, «Авто»,
/// настройки). Раньше прокси снимался на эти секунды, и браузер ходил напрямую — с
/// настоящим IP. Теперь он смотрит на закрытый локальный порт и ждёт. Перезапуск не
/// удался (Drop, пока не `keep`) — прокси снимаем: rxvpn показывает «отключено», и
/// интернет без VPN в этот момент — уже не сюрприз.
struct ProxyHold<'a> {
    st: &'a AppState,
    armed: bool,
}

impl ProxyHold<'_> {
    /// Новое ядро поднялось — прокси остаётся.
    fn keep(mut self) {
        self.armed = false;
    }
}

impl Drop for ProxyHold<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(addr) = self.st.proxy_set.lock().unwrap().take() {
            if sysproxy::current().as_deref() == Some(addr.as_str()) {
                let _ = sysproxy::disable();
            }
        }
    }
}

/// `keep_proxy` — не трогать системный прокси (см. `ProxyHold`).
fn stop_core_ex(st: &AppState, keep_proxy: bool) {
    st.gen.fetch_add(1, Ordering::SeqCst);
    let p = st.proc.lock().unwrap().take();
    if let Some(mut p) = p {
        p.stop();
    }
    *st.run.lock().unwrap() = None;
    *st.active_tag.lock().unwrap() = None;
    st.ping.store(0, Ordering::SeqCst);
    st.tun_active.store(false, Ordering::SeqCst);
    if keep_proxy {
        return;
    }
    let addr = st.proxy_set.lock().unwrap().take();
    if let Some(addr) = addr {
        // Выключаем, только если там всё ещё наш адрес — вдруг человек
        // уже включил другой VPN.
        if sysproxy::current().as_deref() == Some(addr.as_str()) {
            let _ = sysproxy::disable();
        }
    }
}

/// Горячая клавиша «Подключить / Отключить»: снять прошлую, поставить из настроек (пусто — нет).
fn apply_hotkey(app: &AppHandle, keys: &str) -> Res<()> {
    use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut};
    let gs = app.global_shortcut();
    let _ = gs.unregister_all();
    let keys = keys.trim();
    if keys.is_empty() {
        return Ok(());
    }
    let sc: Shortcut = keys.parse().map_err(|_| tr!("Горячая клавиша «{keys}» не распознана — например Ctrl+Alt+V"))?;
    gs.register(sc).map_err(|e| tr!("Горячая клавиша «{keys}» занята другой программой ({e})"))
}

/// Автоподключение: запустилась программа из списка — подключиться. Только на запуске
/// (переход «не было → есть»): отключился вручную, пока она открыта, — не лезем обратно.
fn spawn_app_watch(app: AppHandle) {
    std::thread::spawn(move || {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut first = true;
        loop {
            std::thread::sleep(Duration::from_secs(4));
            let st = app.state::<AppState>();
            let want: Vec<String> = st.store.lock().unwrap().settings.connect_apps.iter().map(|a| a.to_ascii_lowercase()).collect();
            if want.is_empty() {
                seen.clear();
                continue;
            }
            let now: std::collections::HashSet<String> = winsys::list_processes()
                .into_iter()
                .map(|p| p.to_ascii_lowercase())
                .filter(|p| want.contains(p))
                .collect();
            // Уже открытые при старте rxvpn — не повод подключаться (это делает «Автоподключение»).
            let started: Vec<&String> = if first { Vec::new() } else { now.difference(&seen).collect() };
            first = false;
            if let Some(name) = started.first() {
                if !running(&st) && !st.ztesting.load(Ordering::SeqCst) {
                    log(&app, tr!("автоподключение: запущена {name} — подключаюсь"));
                    connect_in_background(app.clone(), true, false);
                }
            }
            seen = now;
        }
    });
}

/// Снять kill switch (интернет снова без ограничений). Не был включён — ничего.
fn kill_off(app: &AppHandle, st: &AppState, why: &str) {
    if st.kill.lock().unwrap().take().is_some() {
        log(app, tr!("kill switch выключен: {why}"));
    }
}

/// Прошлый rxvpn умер с включённым kill switch (упал, сняли в диспетчере задач) — блокировка
/// осталась и держит интернет закрытым. Перенимаем её: на главной появляется «интернет
/// закрыт» и кнопка «Открыть интернет без VPN», подключение работает как обычно. Kill switch
/// с тех пор выключили в настройках или перенять не вышло — снимаем.
fn kill_adopt(app: &AppHandle) {
    if !rxvpn_core::killswitch::leftover() {
        return;
    }
    let st = app.state::<AppState>();
    if !winsys::is_admin() {
        notify(app, trs!("rxvpn: интернет закрыт"), trs!("Прошлый rxvpn закрылся с ошибкой, kill switch держит интернет закрытым. Запусти rxvpn от администратора или перезагрузи компьютер."));
        return;
    }
    let want = {
        let s = st.store.lock().unwrap();
        s.settings.tun && s.settings.kill_switch
    };
    let adopted = want && {
        let xray = runner::xray_path(&st.paths.core);
        match std::env::current_exe().map_err(|e| e.to_string()).and_then(|me| rxvpn_core::killswitch::KillSwitch::enable(&[xray.as_path(), me.as_path()])) {
            Ok(ks) => {
                *st.kill.lock().unwrap() = Some(ks);
                true
            }
            Err(e) => {
                log(app, tr!("kill switch: блокировку прошлого запуска перенять не вышло ({e}) — снимаю"));
                false
            }
        }
    };
    if adopted {
        notify(app, trs!("rxvpn: интернет закрыт"), trs!("Прошлый rxvpn закрылся с ошибкой, kill switch не пустил трафик мимо VPN. Подключись снова или сними блокировку в окне."));
        return;
    }
    match rxvpn_core::killswitch::clear() {
        Ok(()) => log(app, trs!("kill switch: снята блокировка, оставшаяся от прошлого запуска")),
        Err(e) => notify(app, trs!("rxvpn: интернет закрыт"), e),
    }
}

/// Гибрид «Через zapret, мимо VPN» при kill switch. Сайты гибрида Xray шлёт напрямую, winws
/// перехватывает эти пакеты на сетевой карте и отправляет заново — уже от имени ядра Windows
/// («System»), и без разрешения kill switch их режет. Разрешаем узко: «System», та же карта,
/// только порты стратегии. Гибрид не работает (или winws умер) — разрешение снимается.
/// Зовётся после всего, что меняет kill switch, гибрид или winws.
fn kill_reinject_sync(app: &AppHandle, st: &AppState) {
    // По одному замку за раз.
    let iface = st.hybrid.lock().unwrap().as_ref().and_then(|h| h.iface);
    let wf = st.zapret.lock().unwrap().as_ref().map(|z| z.wf.clone());
    let want = match (iface, wf) {
        (Some(i), Some(Some(wf))) => winsys::iface_alias(i)
            .and_then(|a| rxvpn_core::killswitch::interface_luid(&a))
            .map(|luid| (rxvpn_core::killswitch::Reinject { luid, tcp: wf.tcp, udp: wf.udp }, wf.raw)),
        (Some(_), Some(None)) => {
            log(app, trs!("kill switch: порты стратегии zapret не разобраны — сайты «мимо VPN» при kill switch закрыты"));
            None
        }
        _ => None,
    };
    let r = st.kill.lock().unwrap().as_mut().map(|k| k.allow_reinject(want.as_ref().map(|(r, _)| r)));
    match (r, want) {
        (Some(Err(e)), _) => log(app, tr!("kill switch: пакеты zapret не пропущены ({e}) — сайты «мимо VPN» закрыты")),
        (Some(Ok(())), Some((_, raw))) => {
            log(app, trs!("kill switch: сайты «мимо VPN» идут через zapret, остальное без VPN закрыто"));
            if raw {
                log(app, trs!("kill switch: стратегия zapret перехватывает не только по портам (--wf-raw-part) — эта часть при kill switch не пройдёт"));
            }
        }
        _ => {}
    }
}

/// Включить kill switch после запуска Xray в TUN (или оставить включённым при перезапуске
/// «Авто») и пустить через него новый адаптер туннеля, как только тот появится.
/// С гибридом «Через zapret, мимо VPN» — плюс узкое разрешение для пакетов, которые winws
/// отправил заново (`kill_reinject_sync`).
fn kill_arm(app: &AppHandle, st: &AppState, gen: u64) {
    {
        let mut k = st.kill.lock().unwrap();
        if k.is_none() {
            let xray = runner::xray_path(&st.paths.core);
            let me = match std::env::current_exe() {
                Ok(p) => p,
                Err(e) => return log(app, tr!("kill switch не включился: {e}")),
            };
            match rxvpn_core::killswitch::KillSwitch::enable(&[xray.as_path(), me.as_path()]) {
                Ok(ks) => {
                    *k = Some(ks);
                    log(app, trs!("kill switch включён: без VPN программы в интернет не выйдут (локальная сеть — можно)"));
                }
                Err(e) => {
                    drop(k);
                    log(app, tr!("kill switch не включился: {e} — VPN работает без него"));
                    let _ = app.emit("error-toast", tr!("Kill switch не включился: {e}. VPN работает без него"));
                    return;
                }
            }
        }
    }
    kill_reinject_sync(app, st);
    // Адаптер туннеля Xray создаёт сам — ждём его и пускаем через kill switch.
    let a = app.clone();
    std::thread::spawn(move || {
        let st = a.state::<AppState>();
        for _ in 0..80 {
            if st.gen.load(Ordering::SeqCst) != gen {
                return; // этот запуск уже заменили
            }
            if let Some(luid) = rxvpn_core::killswitch::interface_luid(rxvpn_core::xray::TUN_NAME) {
                let r = st.kill.lock().unwrap().as_mut().map(|k| k.allow_interface(luid));
                if let Some(Err(e)) = r {
                    log(&a, tr!("kill switch: туннель не пропущен ({e}) — интернет закрыт, переподключись"));
                }
                return;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        log(&a, trs!("kill switch: адаптер туннеля не появился за 20 секунд — интернет закрыт, переподключись"));
    });
}

/// Несколько разных свободных локальных портов (служебных).
fn free_ports(n: usize) -> Res<Vec<u16>> {
    let ls: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string()))
        .collect::<Res<_>>()?;
    ls.iter().map(|l| l.local_addr().map(|a| a.port()).map_err(|e| e.to_string())).collect()
}

/// Перед проверкой серверов отдельным (пробным) Xray. Пока работает TUN, весь трафик компа
/// уходит в туннель — и пробный Xray тоже: он проверял бы сервера через текущий VPN. Поэтому
/// привязываем его к настоящей сетевой карте, как основной Xray. Kill switch его пропускает:
/// он разрешает xray.exe по пути к файлу. Карту не нашли — честно отказываем.
fn probe_bind(st: &AppState) -> Res<()> {
    if !(is_connected(st) && st.tun_active.load(Ordering::SeqCst)) {
        batch::set_bind(None);
        return Ok(());
    }
    let tun = rxvpn_core::xray::TUN_NAME;
    let idx = winsys::gateway_interface(tun).or_else(|| winsys::physical_interface(tun)).or(*st.phys_iface.lock().unwrap());
    match idx.and_then(winsys::iface_alias).filter(|a| !a.eq_ignore_ascii_case(tun)) {
        Some(alias) => {
            batch::set_bind(Some(alias));
            Ok(())
        }
        None => Err(trs!("Не нашёл сетевую карту, через которую идёт интернет, — проверка пошла бы через текущий VPN и показала неправду. Отключись на минуту").into()),
    }
}

/// Сервера, которые Xray вообще согласен запустить (по одному, `xray run -test`).
/// Нужно для «Авто»: один кривой сервер из подписки иначе ломает весь конфиг.
fn usable_nodes(st: &AppState, nodes: &[Node]) -> (Vec<Node>, Vec<String>) {
    let mut good = Vec::new();
    let mut bad = Vec::new();
    for n in nodes {
        let cfg = build_test_config(&[(n, 1)]);
        if runner::test_config(&st.paths.core, cfg.to_string().as_bytes()).is_ok() {
            good.push(n.clone());
        } else {
            bad.push(n.name.clone());
        }
    }
    (good, bad)
}

/// Как быть с гибридом (zapret для YouTube и Discord рядом с VPN) при запуске.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HybridStart {
    /// Как в настройках. Во время подбора — нет: там свой winws.
    Auto,
    /// Подбор возвращает VPN как было — ему можно и во время подбора.
    FromPicker,
    /// Подбор рядом с VPN: маршруты гибрида включить, winws запустит сам подбор.
    PlanOnly,
    /// Без гибрида: проверка перед подключением не прошла (уже сказали почему).
    Skip,
}

/// `allow_tun = false` — подключиться через прокси, даже если в настройках TUN
/// (автозапуск без прав администратора).
fn start_core(app: &AppHandle, st: &AppState, allow_tun: bool) -> Res<()> {
    start_core_ex(app, st, allow_tun, HybridStart::Auto).map(|_| ())
}

/// `start_core` из асинхронной команды: в отдельном потоке, не занимая рантайм.
async fn start_core_blocking(app: &AppHandle, allow_tun: bool) -> Res<()> {
    let a = app.clone();
    tauri::async_runtime::spawn_blocking(move || start_core(&a, a.state::<AppState>().inner(), allow_tun))
        .await
        .map_err(|e| e.to_string())?
}

/// Возвращает план гибрида, если его маршруты включены (для `PlanOnly`).
fn start_core_ex(app: &AppHandle, st: &AppState, allow_tun: bool, how: HybridStart) -> Res<Option<zapret::Hybrid>> {
    // По одному: «Авто», смена сервера и подбор могут перезапускать VPN одновременно,
    // и один запуск убил бы ядро другого. Внутри никто сюда снова не заходит.
    let _one = st.core_op.lock().unwrap_or_else(|e| e.into_inner());
    let dead = dead_ids(st);
    let (want_auto, mut nodes, mut settings, site_nodes, any_servers) = {
        let s = st.store.lock().unwrap();
        // «Авто» — только из видимых: фильтры подписок, без мёртвых и дублей.
        let nodes: Vec<Node> = if s.is_auto() {
            filter::visible(&s, |id| dead.contains(id))
        } else {
            s.selected_node().cloned().into_iter().collect()
        };
        // Сервера из «Сайт → свой сервер» (без повторов).
        let mut site_nodes: Vec<Node> = Vec::new();
        for r in &s.settings.site_servers {
            for n in s.servers.iter().filter(|n| rxvpn_core::xray::site_server_is(r, n) || rxvpn_core::xray::site_backup_is(r, n)) {
                if !site_nodes.iter().any(|x| x.id == n.id) {
                    site_nodes.push(n.clone());
                }
            }
        }
        (s.is_auto(), nodes, s.settings.clone(), site_nodes, !s.servers.is_empty())
    };
    if nodes.is_empty() {
        return Err(match (want_auto, any_servers) {
            (true, true) => trs!("Фильтр скрыл все сервера — поправь «Фильтр» у подписки"),
            (true, false) => trs!("Нет серверов для «Авто»"),
            _ => trs!("Сначала выбери сервер"),
        }
        .into());
    }
    if !allow_tun {
        settings.tun = false;
    }
    // «Разрешить IPv6» включено, а у сетевых карт нет IPv6-адреса из интернета: программы
    // получали бы IPv6-адреса сайтов и шли по ним первыми, а соединения «напрямую» рвались
    // (браузер откатывается на IPv4 сам, Spotify и многие другие — нет). Выдаём только IPv4.
    let v6_off = settings.dns_ipv6 && winsys::local_ipv6(rxvpn_core::xray::TUN_NAME).is_empty();
    if v6_off {
        settings.dns_ipv6 = false;
        if !st.ipv6_off.load(Ordering::SeqCst) {
            log(app, trs!("IPv6 разрешён в настройках, но у провайдера его нет — выдаю программам только IPv4"));
        }
    }
    st.ipv6_off.store(v6_off, Ordering::SeqCst);
    if !runner::xray_path(&st.paths.core).exists() {
        return Err(trs!("Ядро Xray не скачано. Открой настройки → «Скачать ядро»").into());
    }
    if settings.route == RouteMode::Blocked && !geodata::present(&st.paths.core) {
        return Err(trs!("Для «Только заблокированное» нужны списки блокировок: \
                    открой «Правила» → «Обновить списки»")
            .into());
    }
    if settings.tun && !winsys::is_admin() {
        // Проверяем ДО остановки: текущее подключение продолжает работать.
        return Err(NEED_ADMIN.into());
    }

    let was_connected = is_connected(st);
    // Перезапуск в том же режиме «Браузер»: прокси не снимаем — без окна трафика напрямую.
    let hold_proxy = was_connected && settings.system_proxy && !settings.tun && st.proxy_set.lock().unwrap().is_some();
    stop_core_ex(st, hold_proxy);
    let proxy_hold = ProxyHold { st, armed: hold_proxy };
    stop_zapret(st); // zapret-без-VPN и VPN вместе не работают (гибрид поднимем ниже заново)

    for p in [settings.socks_port, settings.http_port] {
        if !runner::port_free(p) {
            return Err(tr!("Порт {p} занят. Закрой Happ/v2rayN или поменяй порт в настройках"
            ));
        }
    }
    // Все порты — одним разом и мимо порта входа tor-up работающей Arti: иначе два
    // входа Xray могли бы получить один порт.
    let busy_up = st.tor.lock().unwrap().as_ref().map(|r| r.upstream);
    let mut ports = free_ports(5)?;
    ports.retain(|p| Some(*p) != busy_up);
    let (metrics_port, probe_port, direct_port, spare_up) = (ports[0], ports[1], ports[2], ports[3]);
    let direct_pass: String = rxvpn_core::vps::plan::random(16).iter().map(|b| format!("{b:02x}")).collect();
    let tor = ensure_tor(app, st, &settings, spare_up);
    std::fs::create_dir_all(&st.paths.data).map_err(|e| e.to_string())?;

    // Гибрид: zapret для YouTube и Discord рядом с VPN. До Xray: в TUN номер
    // настоящей сетевой карты надо узнать, пока туннеля нет. Не вышло — YouTube
    // и Discord в этот раз идут через VPN, как обычно (маршрут «мимо VPN» —
    // только если zapret для них правда работает).
    let want_hybrid = settings.zapret_hybrid && !settings.zapret && how != HybridStart::Skip;
    settings.zapret_hybrid = false;
    let mut planned = None;
    if want_hybrid {
        // Сервера для сайтов тоже: winws не должен трогать и их соединения.
        let all: Vec<Node> = nodes.iter().chain(&site_nodes).cloned().collect();
        let r = hybrid_plan(st, &all, settings.tun, !was_connected).and_then(|h| match how {
            HybridStart::PlanOnly => Ok(h),
            _ if how == HybridStart::Auto && st.ztesting.load(Ordering::SeqCst) => Err(trs!("идёт подбор стратегии").into()),
            _ => start_hybrid_with(app, st, h.clone()).map(|_| h),
        });
        match r {
            Ok(h) => {
                settings.zapret_hybrid = true;
                planned = Some(h);
            }
            Err(e) => {
                log(app, tr!("гибрид: zapret не включился — сайты «мимо VPN» пока через VPN ({e})"));
                if how != HybridStart::PlanOnly {
                    let _ = app.emit("error-toast", tr!("Zapret для сайтов «мимо VPN» не включился: {e}. Пока они идут через VPN"));
                }
            }
        }
    }

    let my_gen = st.gen.fetch_add(1, Ordering::SeqCst) + 1;
    // Каждая попытка: 0 — запускается, 1 — подключение записано, 2 — умерла до этого.
    // Xray, не принявший конфиг, умирает внутри XrayProcess::start, и on_exit
    // успевает сработать раньше, чем start вернёт ошибку: это не «упал во время
    // работы» (уведомление, сброс), а неудачный запуск — его обработает вызывающий,
    // и «Авто» сможет попробовать без кривого сервера.
    let launch = |nodes: &[Node], with_sites: bool| -> Res<(XrayProcess, RunInfo, Arc<std::sync::atomic::AtomicU8>)> {
        let armed = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let armed_cb = armed.clone();
        let auto = nodes.len() > 1;
        // «Авто»: тот, на ком уже были (перезапуск из-за настроек или сбоя),
        // иначе — самый быстрый по «Проверить все», иначе первый.
        let prefer = {
            let want = st.auto_prefer.lock().unwrap().clone();
            // Среди проверенных — сначала надёжные (≥95% за неделю, потом ≥80%),
            // из них лучший по задержке и скорости (`stats::auto_key`): самый
            // быстрый на секунду, но падающий, — хуже; близкий, но 2 Мбит/с — тоже.
            let t = st.last_test.lock().unwrap().clone();
            let stats = st.stats.lock().unwrap();
            let now = unix_now();
            want.and_then(|id| nodes.iter().position(|n| n.id == id))
                .or_else(|| {
                    nodes
                        .iter()
                        .enumerate()
                        .filter_map(|(i, n)| t.get(&n.id).map(|ms| (i, stats.auto_key(&n.id, now, *ms))))
                        .min_by_key(|x| x.1)
                        .map(|x| x.0)
                })
                .unwrap_or(0)
        };
        let up = if auto { Upstream::Auto { nodes, prefer } } else { Upstream::Single(&nodes[0]) };
        // Без серверов для сайтов (не запустились) — эти сайты закрыты, а не идут мимо.
        let mut routes = site_routes(&settings, &site_nodes);
        if !with_sites {
            routes.iter_mut().for_each(|r| {
                r.node = None;
                r.backup = None;
            });
        }
        let opts = RunOpts { metrics_port: Some(metrics_port), probe_port: Some(probe_port), sites: &routes, tor, direct: Some((direct_port, &direct_pass)) };
        let cfg = build_run_config(&up, &settings, &opts);
        let active = if auto { auto_tag(prefer) } else { "proxy".to_string() };
        let mut extra: Vec<String> = Vec::new();
        for t in site_tags(&up, &routes) {
            if t != active && t != "block" && !extra.contains(&t) {
                extra.push(t);
            }
        }
        let app_line = app.clone();
        let app_exit = app.clone();
        // Конфиг — через stdin: файл в папке data можно было бы подменить до того,
        // как его прочтёт xray (а он бывает от администратора).
        let proc = XrayProcess::start(
            &st.paths.core,
            &serde_json::to_vec(&cfg).unwrap(),
            move |line| {
                emit_log(&app_line, line);
            },
            move || {
                if armed_cb.compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                    return; // умер, не начав работать
                }
                let st = app_exit.state::<AppState>();
                if st.gen.load(Ordering::SeqCst) == my_gen {
                    // Мы его не останавливали — значит упал. Убираем прокси,
                    // иначе у человека пропадёт интернет. И zapret гибрида:
                    // без VPN он не нужен, а окно показало бы «Без VPN · zapret».
                    stop_core(st.inner());
                    if st.hybrid.lock().unwrap().is_some() {
                        stop_zapret(st.inner());
                    }
                    if st.kill.lock().unwrap().is_some() {
                        // Kill switch держит интернет закрытым — ничего не утекает мимо VPN.
                        log(&app_exit, trs!("kill switch: Xray остановился — интернет закрыт, пока не подключишься снова или не снимешь блокировку"));
                        let _ = app_exit.emit("core-exit", trs!("Xray остановился. Kill switch закрыл интернет, чтобы ничего не ушло мимо VPN"));
                        notify(&app_exit, trs!("rxvpn: интернет закрыт"), trs!("VPN упал, kill switch не пустил трафик мимо него. Подключись снова или сними блокировку в окне."));
                    } else {
                        let _ = app_exit.emit("core-exit", trs!("Ядро Xray остановилось само — смотри лог"));
                        notify(&app_exit, trs!("rxvpn отключился"), trs!("Ядро Xray остановилось. Открой окно — причина в логе."));
                    }
                    changed(&app_exit);
                }
            },
        );
        let proc = proc?;
        let info = RunInfo {
            gen: my_gen,
            auto,
            nodes: nodes
                .iter()
                .enumerate()
                .map(|(i, n)| {
                    let tag = if auto { auto_tag(i) } else { "proxy".to_string() };
                    (tag, n.id.clone(), n.name.clone())
                })
                .collect(),
            active,
            extra,
            metrics_port,
            probe_port,
            direct_port,
            direct_pass: direct_pass.clone(),
        };
        if auto {
            *st.auto_prefer.lock().unwrap() = Some(nodes[prefer].id.clone());
        }
        Ok((proc, info, armed))
    };

    // Есть ли сервера для сайтов, которые надо запускать (а не только закрытые правила).
    let want_sites = site_routes(&settings, &site_nodes).iter().any(|r| r.node.is_some());
    let sites_down = || {
        log(app, trs!("«Сайт → сервер»: Xray не принял сервер для сайтов — эти сайты закрыты, пока его не поменяешь"));
        let _ = app.emit("error-toast", trs!("Сервер из «Сайт → сервер» не запустился — эти сайты закрыты. Выбери для них другой сервер"));
    };
    let mut started = launch(&nodes, want_sites);
    if started.is_err() && want_sites {
        // Сначала проверим сервера для сайтов: один быстрый запуск без них.
        let r = launch(&nodes, false);
        if r.is_ok() {
            sites_down();
        }
        started = r;
    }
    if started.is_err() && nodes.len() > 1 {
        // В «Авто» виноват может быть один сервер — отсеиваем и пробуем снова.
        let (good, bad) = usable_nodes(st, &nodes);
        if !good.is_empty() && !bad.is_empty() {
            log(app, tr!("«Авто»: Xray не принимает эти сервера, пропускаю: {}", bad.join(", ")));
            nodes = good;
            started = launch(&nodes, want_sites);
            if started.is_err() && want_sites {
                let r = launch(&nodes, false);
                if r.is_ok() {
                    sites_down();
                }
                started = r;
            }
        }
    }
    let (proc, info, armed) = match started {
        Ok(x) => x,
        Err(e) => {
            stop_zapret(st); // VPN не поднялся — zapret гибрида без него не нужен
            return Err(e);
        }
    };

    *st.proc.lock().unwrap() = Some(proc);
    st.tun_active.store(settings.tun, Ordering::SeqCst);
    *st.active_tag.lock().unwrap() = Some(info.active.clone());
    *st.run.lock().unwrap() = Some(info.clone());
    // С этого момента падение — это «упал во время работы» (on_exit всё уберёт).
    let died_early = armed.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_err();

    // В TUN весь трафик и так идёт через VPN — системный прокси не нужен.
    if settings.system_proxy && !settings.tun {
        let addr = format!("127.0.0.1:{}", settings.http_port);
        match sysproxy::enable(&addr) {
            Ok(()) => *st.proxy_set.lock().unwrap() = Some(addr),
            Err(e) => log(app, tr!("системный прокси не выставлен: {e}")),
        }
    }
    proxy_hold.keep();

    // Ядро могло упасть ровно в момент, пока мы ставили прокси.
    if died_early || st.gen.load(Ordering::SeqCst) != my_gen {
        stop_core(st);
        if st.hybrid.lock().unwrap().is_some() {
            stop_zapret(st);
        }
        return Err(trs!("Ядро упало сразу после запуска — смотри лог").into());
    }

    spawn_monitor(app.clone(), info.clone());
    if settings.tun && settings.kill_switch {
        kill_arm(app, st, my_gen);
    } else {
        kill_off(app, st, trs!("режим без kill switch"));
    }
    for r in &settings.site_servers {
        if rxvpn_core::xray::validate_site_server(r).is_ok() && !site_nodes.iter().any(|n| rxvpn_core::xray::site_server_is(r, n)) {
            if site_nodes.iter().any(|n| rxvpn_core::xray::site_backup_is(r, n)) {
                log(app, tr!("«{}» (Сайт → сервер): основного сервера больше нет — сайты идут через запасной", r.name));
            } else {
                log(app, tr!("«{}» (Сайт → сервер): сервера больше нет — эти сайты закрыты, выбери другой", r.name));
            }
        }
    }
    let mode = if settings.tun { "TUN" } else { trs!("прокси") };
    if info.auto {
        log(app, tr!("подключено: «Авто» по {} серверам ({mode}), сейчас — «{}»", info.nodes.len(), info.name_of(&info.active)));
    } else {
        log(app, tr!("подключено: {} ({mode})", info.nodes[0].2));
    }
    Ok(planned)
}

/// Tor нужен — Arti работает (запустить, если нет), не нужен — остановить.
/// Возвращает (порт SOCKS Arti, порт входа `tor-up`). Не запустилась — None:
/// то, что шло бы через Tor, в этом запуске закрыто (Xray отправит в блок).
fn ensure_tor(app: &AppHandle, st: &AppState, s: &Settings, spare_up: u16) -> Option<(u16, u16)> {
    let mut t = st.tor.lock().unwrap();
    if s.tor_mode == rxvpn_core::xray::TorMode::Off {
        if t.take().is_some() {
            log(app, trs!("Tor выключен"));
        }
        return None;
    }
    // Порт входа tor-up занят чужим (или поменялась изоляция) — заводим Arti заново.
    if let Some(r) = t.as_ref() {
        if !runner::port_free(r.upstream) || r.isolate != s.tor_isolate {
            *t = None;
        }
    }
    if t.is_none() {
        let up = spare_up;
        let a = app.clone();
        let logf: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |m| log(&a, m));
        match rxvpn_core::tor::start(tauri::async_runtime::handle().inner(), &st.paths.data.join("tor"), up, s.tor_isolate, logf) {
            Ok(r) => {
                log(app, trs!("Tor: запускаю Arti, подключаюсь к сети Tor через VPN (первый раз — до минуты)…"));
                *t = Some(r);
            }
            Err(e) => {
                log(app, tr!("{e} — сайты для Tor пока закрыты"));
                let _ = app.emit("error-toast", tr!("{e}. Сайты для Tor пока закрыты"));
                return None;
            }
        }
    }
    t.as_ref().map(|r| (r.port, r.upstream))
}

/// Лучшая живая замена (правила — в `net::pick_alive_by`): среди живых — по
/// надёжности за неделю, задержке и скорости (`stats::auto_key`).
fn best_alive(st: &AppState, v: &net::Vars, info: &RunInfo, bad: &HashMap<String, i64>, exclude: Option<&str>) -> Option<String> {
    let stats = st.stats.lock().unwrap();
    let now = unix_now();
    net::pick_alive_by(&v.observatory, info.nodes.iter().map(|(t, ..)| t.as_str()), bad, exclude, |tag, delay| match info.id_of(tag) {
        Some(id) => stats.auto_key(&id, now, delay),
        None => rxvpn_core::stats::auto_key(delay, None, None),
    })
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// «Авто»: начать сначала — забыть выбранный сервер и сбои (новое подключение
/// человеком, отключение, выбор другого сервера).
fn reset_auto(st: &AppState) {
    // Человек сам выбрал/подключил/отключил — «вернуться после белых списков» забываем.
    *st.wl_prev.lock().unwrap() = None;
    *st.auto_prefer.lock().unwrap() = None;
    st.auto_bad.lock().unwrap().clear();
    st.auto_down.store(false, Ordering::SeqCst);
    st.fallback_tried.lock().unwrap().clear();
}

/// Сбои «Авто» в тегах текущего запуска (храним по id — теги node-N могут
/// поменяться, если список серверов изменился).
fn bad_tags(st: &AppState, info: &RunInfo) -> HashMap<String, i64> {
    let b = st.auto_bad.lock().unwrap();
    info.nodes.iter().filter_map(|(t, id, _)| b.get(id).map(|v| (t.clone(), *v))).collect()
}

fn mark_bad(st: &AppState, info: &RunInfo, tag: &str) {
    if let Some(id) = info.id_of(tag) {
        st.auto_bad.lock().unwrap().insert(id, unix_now());
    }
}

/// «Авто»: перейти на другой сервер — перезапуском Xray с ним в роли выбранного
/// (около секунды; соединения через упавший сервер и так оборваны).
/// `from` — с какого ушли из-за сбоя (для уведомления), None — тихо.
async fn switch_to(app: &AppHandle, info: &RunInfo, tag: &str, from: Option<&str>) {
    let st = app.state::<AppState>();
    if st.gen.load(Ordering::SeqCst) != info.gen {
        return; // пока решали — отключились или переподключились
    }
    let Some(id) = info.id_of(tag) else { return };
    *st.auto_prefer.lock().unwrap() = Some(id);
    let (name, old) = (info.name_of(tag), from.map(|f| info.name_of(f)));
    let allow_tun = st.tun_active.load(Ordering::SeqCst);
    let app2 = app.clone();
    let r = tauri::async_runtime::spawn_blocking(move || {
        let st = app2.state::<AppState>();
        start_core(&app2, st.inner(), allow_tun)
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r);
    match (r, old) {
        (Ok(()), Some(old)) => notify(app, tr!("Переключился на «{name}»"), tr!("«{old}» перестал отвечать")),
        (Ok(()), None) => log(app, tr!("«Авто»: переключился на «{name}»")),
        (Err(e), _) => notify(app, trs!("rxvpn не переключился"), &e),
    }
    changed(app);
}

/// Фоновая жизнь подключения: раз в секунду скорость (и задержки «Авто»),
/// отдельно — проверка связи и переключение сервера.
fn spawn_monitor(app: AppHandle, info: RunInfo) {
    let latest: Arc<Mutex<Option<net::Vars>>> = Arc::new(Mutex::new(None));

    // --- скорость и задержки ---
    let (app1, info1, latest1) = (app.clone(), info.clone(), latest.clone());
    tauri::async_runtime::spawn(async move {
        let client = net::local_client();
        let mut last: HashMap<String, (u64, u64, Instant)> = HashMap::new();
        let mut seen_try: HashMap<String, i64> = HashMap::new();
        let (mut up_total, mut down_total) = (0u64, 0u64);
        let mut tick = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let st = app1.state::<AppState>();
            if st.gen.load(Ordering::SeqCst) != info1.gen {
                let _ = app1.emit("stats", Stats { up_speed: 0, down_speed: 0, up_total: 0, down_total: 0, ping: None });
                break;
            }
            let Some(v) = net::fetch_vars(&client, info1.metrics_port).await else { continue };
            let active = st.active_tag.lock().unwrap().clone();
            let (mut us, mut ds) = (0, 0);
            let t = Instant::now();
            // Трафик VPN: выбранный сервер и сервера «Сайт → свой сервер».
            for tag in active.iter().chain(info1.extra.iter().filter(|t| Some(*t) != active.as_ref())) {
                if let (Some((u, d)), Some((lu, ld, lt))) = (v.traffic.get(tag), last.get(tag)) {
                    let dt = t.duration_since(*lt).as_secs_f64().max(0.2);
                    let (du, dd) = (u.saturating_sub(*lu), d.saturating_sub(*ld));
                    up_total += du;
                    down_total += dd;
                    us += (du as f64 / dt) as u64;
                    ds += (dd as f64 / dt) as u64;
                }
            }
            for (tag, (u, d)) in &v.traffic {
                last.insert(tag.clone(), (*u, *d, t));
            }
            let ping = Some(st.ping.load(Ordering::SeqCst)).filter(|p| *p > 0);
            let _ = app1.emit("stats", Stats { up_speed: us, down_speed: ds, up_total, down_total, ping });
            // Замеры «Авто» — в стабильность (новый замер — новое last_try).
            for (tag, id, _) in &info1.nodes {
                if let Some(o) = v.observatory.get(tag).filter(|o| o.last_try > 0) {
                    if seen_try.insert(tag.clone(), o.last_try) != Some(o.last_try) {
                        stat(&st, id, o.alive.then_some(o.delay));
                    }
                }
            }
            if tick % 600 == 599 {
                save_stats(&st);
            }
            if info1.auto && tick.is_multiple_of(2) {
                let delays = info1
                    .nodes
                    .iter()
                    .map(|(tag, id, _)| (id.clone(), v.observatory.get(tag).filter(|o| o.alive).map(|o| o.delay)))
                    .collect();
                let active_id = active.and_then(|t| info1.id_of(&t));
                let _ = app1.emit("auto-status", AutoStatus { active_id, delays });
            }
            tick += 1;
            *latest1.lock().unwrap() = Some(v);
        }
    });

    // --- проверка связи и «Авто» ---
    // Сервер этого запуска известен сразу (info.active). Переключение —
    // перезапуск, после него этот цикл заканчивается и начинается новый.
    tauri::async_runtime::spawn(async move {
        let probe_url = format!("socks5h://127.0.0.1:{}", info.probe_port);
        let active = info.active.clone();
        let name = info.name_of(&active);
        let mut next = Instant::now() + Duration::from_secs(8);
        let mut fails = 0u32;
        let mut checked_down = 0u64;
        let mut obs_checked = !info.auto;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let st = app.state::<AppState>();
            if st.gen.load(Ordering::SeqCst) != info.gen {
                break;
            }
            let Some(v) = latest.lock().unwrap().clone() else { continue };
            let down = st.auto_down.load(Ordering::SeqCst);

            // «Авто»: первые замеры Xray — если выбранный мёртв, а другой жив,
            // сразу на живой, не дожидаясь своих проверок.
            if !obs_checked {
                if let Some(o) = v.observatory.get(&active).filter(|o| o.last_try > 0) {
                    obs_checked = true;
                    if !o.alive {
                        if let Some(best) = best_alive(&st, &v, &info, &bad_tags(&st, &info), Some(&active)) {
                            mark_bad(&st, &info, &active);
                            switch_to(&app, &info, &best, None).await;
                            break;
                        }
                    }
                }
            }

            if Instant::now() < next {
                continue;
            }
            // По серверу недавно шли данные — значит, он жив, лишний раз не дёргаем.
            let down_now = v.traffic.get(&active).map(|x| x.1).unwrap_or(0);
            let busy = down_now.saturating_sub(checked_down) > 32 * 1024;
            checked_down = down_now;
            let res = if busy {
                Ok(None)
            } else {
                net::tunnel_alive(&probe_url, PROBE_URLS_HTTP, Duration::from_secs(6))
                    .await
                    .map(Some)
            };
            if st.gen.load(Ordering::SeqCst) != info.gen {
                break;
            }
            match res {
                Ok(ms) => {
                    if let Some(ms) = ms {
                        st.ping.store(ms.max(1), Ordering::SeqCst);
                        if !info.auto {
                            if let Some(id) = info.id_of(&active) {
                                stat(&st, &id, Some(ms));
                            }
                        }
                    }
                    fails = 0;
                    if st.auto_down.swap(false, Ordering::SeqCst) {
                        notify(&app, trs!("Связь восстановлена"), tr!("«{name}» снова отвечает"));
                    }
                    next = Instant::now() + Duration::from_secs(20);
                }
                Err(e) => {
                    fails += 1;
                    st.ping.store(0, Ordering::SeqCst);
                    if !info.auto && fails == 2 {
                        if let Some(id) = info.id_of(&active) {
                            stat(&st, &id, None);
                        }
                    }
                    // Пока всё лежит — проверяем реже, не долбим сеть каждые 4 с.
                    next = Instant::now() + Duration::from_secs(if down { 15 } else { 4 });
                    if fails < 2 {
                        continue;
                    }
                    if fails == 2 && !down {
                        log(&app, tr!("проверка связи через «{name}» не прошла: {e}"));
                        // Может, это белые списки? Проверяем напрямую, рядом с «Авто».
                        let (a, i) = (app.clone(), info.clone());
                        tauri::async_runtime::spawn(async move { wl_react(&a, &i).await });
                    }
                    if info.auto {
                        let fresh = latest.lock().unwrap().clone().unwrap_or(v);
                        if let Some(best) = best_alive(&st, &fresh, &info, &bad_tags(&st, &info), Some(&active)) {
                            mark_bad(&st, &info, &active);
                            // Уведомляем только о первом переключении; если связи
                            // нет вообще — одно «ничего не отвечает», а не пачка.
                            let from = (!down).then_some(active.as_str());
                            switch_to(&app, &info, &best, from).await;
                            break;
                        } else if !down {
                            mark_bad(&st, &info, &active);
                            notify(&app, trs!("Ни один сервер не отвечает"), trs!("Проверь интернет. rxvpn сам переключится, когда какой-то сервер оживёт."));
                            st.auto_down.store(true, Ordering::SeqCst);
                        }
                    } else if !down {
                        // Тот же сервер другим протоколом (VLESS не пускают — пробуем Hysteria2 и т.п.).
                        // Каждый вариант — один раз, пока человек сам не выберет/подключит заново.
                        let sib = info.id_of(&active).and_then(|cid| {
                            let mut tried = st.fallback_tried.lock().unwrap();
                            tried.insert(cid.clone());
                            let s = st.store.lock().unwrap();
                            s.same_server_other_protocol(&cid, &tried).map(|n| (n.id.clone(), n.name.clone()))
                        });
                        if let Some((sid, sname)) = sib {
                            st.fallback_tried.lock().unwrap().insert(sid.clone());
                            st.store.lock().unwrap().selected = Some(sid);
                            persist(&st);
                            log(&app, tr!("«{name}» не отвечает — пробую тот же сервер другим протоколом: «{sname}»"));
                            notify(&app, tr!("«{name}» не отвечает"), tr!("Пробую тот же сервер другим протоколом: «{sname}»"));
                            let a = app.clone();
                            let tun = st.tun_active.load(Ordering::SeqCst);
                            tauri::async_runtime::spawn(async move {
                                if let Err(e) = start_core_blocking(&a, tun || winsys::is_admin()).await {
                                    log(&a, tr!("запасной протокол не запустился: {e}"));
                                }
                                refresh_tray(&a);
                                changed(&a);
                            });
                            break;
                        }
                        notify(
                            &app,
                            tr!("«{name}» не отвечает"),
                            trs!("Сервер упал или его заблокировали. Выбери «⚡ Авто» — rxvpn будет переключаться на рабочий сам."),
                        );
                        st.auto_down.store(true, Ordering::SeqCst);
                    }
                }
            }
        }
    });
}

/// Сервер для белых списков, если задан и есть в списке.
fn wl_node(s: &Store) -> Option<(String, String)> {
    let st = &s.settings;
    if st.wl_server.is_empty() {
        return None;
    }
    s.servers
        .iter()
        .find(|n| n.id == st.wl_server && n.sub_id.as_deref().unwrap_or("") == st.wl_server_sub)
        .map(|n| (n.id.clone(), n.name.clone()))
}

/// Проверка белых списков напрямую: через вход Xray «direct-probe» (мимо VPN и
/// TUN), без подключения — сама по себе.
async fn wl_detect(st: &AppState) -> Res<(rxvpn_core::whitelist::Verdict, usize, usize)> {
    let direct = if is_connected(st) { st.run.lock().unwrap().as_ref().map(|r| format!("socks5://rxvpn:{}@127.0.0.1:{}", r.direct_pass, r.direct_port)) } else { None };
    rxvpn_core::whitelist::detect(direct.as_deref()).await
}

/// VPN перестал отвечать: если это белые списки и есть помеченный сервер —
/// перейти на него и следить, когда режим кончится.
async fn wl_react(app: &AppHandle, info: &RunInfo) {
    let st = app.state::<AppState>();
    let (target, prev) = {
        let s = st.store.lock().unwrap();
        if !s.settings.wl_auto {
            return;
        }
        let t = wl_node(&s);
        if t.as_ref().is_some_and(|t| info.nodes.iter().any(|(_, id, _)| *id == t.0)) && !info.auto {
            return; // уже на нём
        }
        (t, s.selected.clone())
    };
    if st.wl_prev.lock().unwrap().is_some() || st.wl_busy.swap(true, Ordering::SeqCst) {
        return;
    }
    let _busy = Busy(&st.wl_busy);
    let Ok((v, l, o)) = wl_detect(&st).await else { return };
    log(app, tr!("белые списки? {} (разрешённых открылось {l}/3, обычных {o}/5)", v.text()));
    if v != rxvpn_core::whitelist::Verdict::Whitelist || st.gen.load(Ordering::SeqCst) != info.gen {
        return;
    }
    let Some(prev) = prev else { return };
    // Сервер для белых списков не выбран — ищем сами среди всех: какой пробивается.
    let target = match target {
        Some(t) => t,
        None => match wl_find(app, &prev).await {
            Some(t) if st.gen.load(Ordering::SeqCst) == info.gen => t,
            Some(_) => return,
            None => {
                notify(
                    app,
                    trs!("Похоже на белые списки"),
                    trs!("Ни один сервер сейчас не пробивается. Нужен мост: свой VPS в российском облаке — Сервера → Свой сервер → «Мост для белых списков»"),
                );
                return;
            }
        },
    };
    {
        // Пока проверяли, человек мог отключиться или выбрать другой сервер.
        let conn = is_connected(&st);
        let mut s = st.store.lock().unwrap();
        if st.gen.load(Ordering::SeqCst) != info.gen || !conn || s.selected.as_deref() != Some(prev.as_str()) {
            return;
        }
        *st.wl_prev.lock().unwrap() = Some(prev.clone());
        s.selected = Some(target.0.clone());
    }
    persist(&st);
    let tun = st.tun_active.load(Ordering::SeqCst);
    let a = app.clone();
    let r = tauri::async_runtime::spawn_blocking(move || start_core(&a, a.state::<AppState>().inner(), tun)).await.map_err(|e| e.to_string()).and_then(|r| r);
    match r {
        Ok(()) => notify(app, trs!("Похоже на белые списки"), tr!("Открываются только разрешённые сайты — переключился на «{}». Вернусь сам, когда режим кончится", target.1)),
        Err(e) => notify(app, trs!("Белые списки: не переключился"), &e),
    }
    changed(app);
    refresh_tray(app);
    // Раз в 5 минут — не кончился ли режим.
    let a = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            let st = a.state::<AppState>();
            if st.wl_prev.lock().unwrap().as_deref() != Some(prev.as_str()) {
                return; // человек сам что-то выбрал
            }
            let Ok((v, ..)) = wl_detect(&st).await else { continue };
            if v != rxvpn_core::whitelist::Verdict::Normal {
                continue;
            }
            let back = {
                let mut s = st.store.lock().unwrap();
                if st.wl_prev.lock().unwrap().take().is_none() {
                    return;
                }
                let ok = prev == rxvpn_core::AUTO_ID || s.servers.iter().any(|n| n.id == prev);
                if ok {
                    s.selected = Some(prev.clone());
                }
                ok.then(|| if prev == rxvpn_core::AUTO_ID { trs!("«Авто»").to_string() } else { s.servers.iter().find(|n| n.id == prev).map(|n| format!("«{}»", n.name)).unwrap_or_default() })
            };
            persist(&st);
            if let Some(name) = back {
                if is_connected(&st) {
                    let tun = st.tun_active.load(Ordering::SeqCst);
                    let a2 = a.clone();
                    let _ = tauri::async_runtime::spawn_blocking(move || start_core(&a2, a2.state::<AppState>().inner(), tun)).await;
                }
                notify(&a, trs!("Белые списки кончились"), tr!("Обычный интернет вернулся — снова {name}"));
            }
            changed(&a);
            refresh_tray(&a);
            return;
        }
    });
}

/// Белые списки, а свой сервер для них не выбран: проверить все сервера (кроме текущего)
/// и взять самый быстрый из пробившихся. Нашёлся — запомнить его сервером для белых списков.
async fn wl_find(app: &AppHandle, cur: &str) -> Option<(String, String)> {
    let st = app.state::<AppState>();
    if !runner::xray_path(&st.paths.core).exists() || st.testing.swap(true, Ordering::SeqCst) {
        return None;
    }
    let (nodes, mask, tweaks) = {
        let s = st.store.lock().unwrap();
        let nodes: Vec<_> = filter::checkable(&s).into_iter().filter(|n| n.id != cur).take(150).collect();
        (nodes, rxvpn_core::xray::finalmask(&s.settings), s.settings.node_tweaks.clone())
    };
    let _ = probe_bind(&st);
    log(app, tr!("белые списки: ищу сервер, который пробивается (проверяю {})", nodes.len()));
    let r = batch::test_all(&st.paths.core, &nodes, mask, tweaks, |_| {}).await;
    st.testing.store(false, Ordering::SeqCst);
    let (ms, id) = r.ok()?.into_iter().filter_map(|x| x.ms.map(|m| (m, x.id))).min()?;
    let n = nodes.iter().find(|n| n.id == id)?;
    {
        let mut s = st.store.lock().unwrap();
        if s.settings.wl_server.is_empty() {
            s.settings.wl_server = n.id.clone();
            s.settings.wl_server_sub = n.sub_id.clone().unwrap_or_default();
        }
    }
    persist(&st);
    log(app, tr!("белые списки: пробивается «{}» ({ms} мс) — запомнил его", n.name));
    Some((n.id.clone(), n.name.clone()))
}

/// «Проверить сейчас» в окне «Белые списки».
#[tauri::command]
async fn wl_check(st: State<'_, AppState>) -> Res<String> {
    if st.diag_busy.swap(true, Ordering::SeqCst) {
        return Err(trs!("Проверка уже идёт").into());
    }
    let _busy = Busy(&st.diag_busy);
    let (v, l, o) = wl_detect(&st).await?;
    let t = tr!("{} (разрешённых открылось {l} из 3, обычных — {o} из 5)", v.text());
    let mut c = t.chars();
    Ok(c.next().map(|f| f.to_uppercase().chain(c).collect()).unwrap_or(t))
}

/// Подключение «в фоне» (трей, автозапуск): ошибки — уведомлением, NEED_ADMIN — диалогом.
fn connect_in_background(app: AppHandle, allow_tun: bool, from_autostart: bool) {
    std::thread::spawn(move || {
        let st = app.state::<AppState>();
        reset_auto(st.inner());
        let hidden = app
            .get_webview_window("main")
            .and_then(|w| w.is_visible().ok())
            .is_none_or(|v| !v);
        let zapret_mode = st.store.lock().unwrap().settings.zapret;
        match connect_any_blocking(&app, allow_tun) {
            Ok(()) => {
                if hidden {
                    let what = if let Some(n) = zapret_running_name(st.inner()) {
                        tr!("Zapret без VPN: «{n}»")
                    } else if st.store.lock().unwrap().is_auto() { trs!("«Авто»").to_string() } else {
                        st.run.lock().unwrap().as_ref().map(|r| r.nodes[0].2.clone()).unwrap_or_default()
                    };
                    notify(&app, trs!("rxvpn подключён"), what);
                }
            }
            Err(e) if e == NEED_ADMIN && from_autostart && zapret_mode => {
                // UAC при входе в Windows не спросишь, а VPN человек не просил.
                notify(&app, trs!("Zapret не включился"), trs!("Нужны права администратора: открой rxvpn и нажми «Подключить»"));
            }
            Err(e) if e == NEED_ADMIN && from_autostart => {
                // При входе в Windows UAC не спросишь — подключаемся через прокси.
                log(&app, trs!("TUN требует прав администратора — при автозапуске подключаюсь в режиме прокси"));
                if let Err(e) = start_core(&app, st.inner(), false) {
                    notify(&app, trs!("rxvpn не подключился"), e);
                }
            }
            Err(e) if e == NEED_ADMIN => {
                show_main(&app);
                let _ = app.emit("need-admin", ());
            }
            Err(e) => {
                if hidden {
                    notify(&app, trs!("rxvpn не подключился"), &e);
                } else {
                    log(&app, tr!("не подключился: {e}"));
                    let _ = app.emit("error-toast", e);
                }
            }
        }
        changed(&app);
    });
}

// ---------------- zapret (режим «без VPN») ----------------

/// Запущенный winws: процесс + открытые (заблокированные от подмены) файлы движка.
struct ZapretRun {
    proc: runner::EngineProcess,
    _lock: zapret::EngineLock,
    name: String,
    /// Порты, которые перехватывает winws, — для kill switch в гибриде. None — не разобрались.
    wf: Option<zapret::WfPorts>,
}

/// Имя стратегии, если zapret работает.
fn zapret_running_name(st: &AppState) -> Option<String> {
    let mut z = st.zapret.lock().unwrap();
    let z = z.as_mut()?;
    z.proc.is_running().then(|| z.name.clone())
}

fn zapret_running(st: &AppState) -> bool {
    zapret_running_name(st).is_some()
}

/// Подключено хоть что-то: VPN или zapret.
fn running(st: &AppState) -> bool {
    is_connected(st) || zapret_running(st)
}

fn stop_zapret(st: &AppState) {
    st.zgen.fetch_add(1, Ordering::SeqCst);
    st.zapret_broken.store(false, Ordering::SeqCst);
    let z = st.zapret.lock().unwrap().take();
    if let Some(mut z) = z {
        z.proc.stop();
    }
    *st.hybrid.lock().unwrap() = None;
    // winws больше нет — пропускать его пакеты через kill switch незачем.
    if let Some(k) = st.kill.lock().unwrap().as_mut() {
        let _ = k.allow_reinject(None);
    }
}

fn zengine(st: &AppState) -> PathBuf {
    st.paths.zapret_bin.join("engine")
}

fn zrun(st: &AppState) -> PathBuf {
    st.paths.zapret_bin.join("run")
}

/// Настройки zapret одним куском.
#[derive(Clone)]
struct ZapretCfg {
    root: PathBuf,
    /// Стратегии rxvpn (встроенные или обновлённые с GitHub), а не своя папка.
    builtin: bool,
    strategy: String,
    game: bool,
    targets: Vec<String>,
    /// Гибрид: имена сервисов и своих сайтов (в список winws) и что проверять при подборе.
    hybrid_hosts: Vec<String>,
    hybrid_targets: Vec<(String, String)>,
}

/// Папка стратегий rxvpn: встроенные Flowseal или скачанные кнопкой «Обновить».
fn zstrategies(st: &AppState) -> PathBuf {
    st.paths.data.join("zapret").join("strategies")
}

fn zapret_cfg(st: &AppState) -> ZapretCfg {
    let dir = st.store.lock().unwrap().settings.zapret_dir.clone();
    let builtin = dir.is_empty();
    let s = st.store.lock().unwrap();
    ZapretCfg {
        root: if builtin { zstrategies(st) } else { PathBuf::from(dir) },
        builtin,
        strategy: s.settings.zapret_strategy.clone(),
        game: s.settings.zapret_game_filter,
        targets: s.settings.zapret_targets.clone(),
        hybrid_hosts: rxvpn_core::xray::hybrid_hosts(&s.settings),
        hybrid_targets: rxvpn_core::xray::hybrid_targets(&s.settings),
    }
}

/// Встроенные стратегии разложены (при первом запуске и после обновления rxvpn).
fn zapret_ready(c: &ZapretCfg) -> Res<()> {
    if c.builtin {
        zapret::ensure_builtin(&c.root, unix_now()).map(|_| ())
    } else if !c.root.is_dir() {
        Err(tr!("Zapret: папки «{}» больше нет — выбери заново или вернись к встроенным стратегиям", c.root.display()))
    } else {
        Ok(())
    }
}

/// Другие обходчики DPI на WinDivert: вдвоём они портят друг другу пакеты.
fn dpi_conflict() -> Option<String> {
    let procs = winsys::list_processes();
    ["winws.exe", "winws2.exe", "goodbyedpi.exe"]
        .into_iter()
        .find(|n| procs.iter().any(|p| p.eq_ignore_ascii_case(n)))
        .map(str::to_string)
}

/// Официальный движок в data\zapret\engine. Сначала — из папки человека (если
/// он там официальный: его версия лучше всего подходит к его стратегиям), иначе
/// уже скачанный, иначе — с GitHub. Хеши сверяются всегда.
async fn ensure_engine(app: &AppHandle, st: &AppState, root: &Path) -> Res<String> {
    let engine = zengine(st);
    let have = zapret::engine_check(&engine).ok();
    let (r, e) = (root.to_path_buf(), engine.clone());
    let from_folder = tauri::async_runtime::spawn_blocking(move || {
        let bin = zapret::engine_dir_in(&r)?;
        let v = zapret::engine_check(&bin).ok()?;
        if zapret::engine_check(&e).ok().as_deref() == Some(v.as_str()) {
            return Some(Ok(v));
        }
        Some(zapret::engine_from_folder(&bin, &e))
    })
    .await
    .map_err(|e| e.to_string())?;
    match from_folder {
        Some(Ok(v)) => {
            if have.as_deref() != Some(v.as_str()) {
                log(app, tr!("zapret: взял официальный winws {v} из папки (хеши сверены)"));
            }
            return Ok(v);
        }
        Some(Err(e)) => log(app, tr!("zapret: движок из папки не скопировался: {e}")),
        None => {}
    }
    if let Some(v) = have {
        return Ok(v);
    }
    log(app, trs!("zapret: качаю официальный движок bol-van/zapret v72.13 (~8 МБ) с GitHub…"));
    let proxy = probe_proxy(st).map(|p| format!("socks5h://127.0.0.1:{p}"));
    let v = zapret::engine_download(&engine, proxy.as_deref())
        .await
        .map_err(|e| tr!("Zapret: движок не скачался — {e}"))?;
    log(app, tr!("zapret: движок {v} установлен, хеши совпали с официальными"));
    Ok(v)
}

/// Общие проверки перед запуском zapret (и перед подбором). Гасит прошлый
/// winws (файлы движка могут обновиться) и готовит движок.
async fn zapret_preflight(app: &AppHandle, st: &AppState, need_strategy: bool) -> Res<ZapretCfg> {
    if !cfg!(windows) {
        return Err(trs!("Zapret работает только в Windows").into());
    }
    let c = zapret_cfg(st);
    let c2 = c.clone();
    tauri::async_runtime::spawn_blocking(move || zapret_ready(&c2)).await.map_err(|e| e.to_string())??;
    if need_strategy && c.strategy.is_empty() {
        return Err(trs!("Zapret: сначала подбери стратегию — «Подобрать лучшую»").into());
    }
    if !winsys::is_admin() {
        return Err(NEED_ADMIN.into());
    }
    stop_zapret(st);
    ensure_engine(app, st, &c.root).await?;
    if let Some(n) = dpi_conflict() {
        return Err(tr!("Уже запущен {n} — другой zapret или GoodbyeDPI. Вдвоём они мешают друг другу: \
             останови его (у Flowseal — service.bat → «Remove Services», или закрой его окно) и попробуй снова"
        ));
    }
    Ok(c)
}

/// Запуск winws со стратегией: файлы — в рабочую папку, движок — сверка хешей
/// и блокировка файлов прямо перед запуском.
fn launch_winws(
    app: &AppHandle,
    c: &ZapretCfg,
    engine: &Path,
    run: &Path,
    s: &zapret::Strategy,
    hybrid: Option<&zapret::Hybrid>,
    on_exit: impl Fn() + Send + Sync + 'static,
) -> Res<ZapretRun> {
    let args = match hybrid {
        Some(h) => zapret::prepare_hybrid(&c.root, s, run, h)?,
        None => zapret::prepare(&c.root, s, run)?,
    };
    // Свои сайты zapret (окно Zapret, «Почему не открывается») — в список стратегии.
    // И сайты гибрида (Twitch, свои): winws должен обходить блокировку и для них.
    let mut mine: Vec<String> = c
        .targets
        .iter()
        .filter_map(|t| rxvpn_core::xray::zapret_target(t))
        .map(|u| u.trim_start_matches("https://").to_string())
        .collect();
    mine.extend(c.hybrid_hosts.iter().cloned());
    zapret::add_user_hosts(run, &mine);
    let (_ver, lock) = zapret::engine_lock(engine)?;
    let wf = zapret::wf_ports(&args);
    let app_line = app.clone();
    // Текущая папка — рабочая: пути к спискам в аргументах относительные.
    let proc = runner::EngineProcess::start(
        &engine.join("winws.exe"),
        &args,
        run,
        Duration::from_millis(1500),
        move |line| emit_log(&app_line, format!("[zapret] {line}")),
        on_exit,
    )?;
    Ok(ZapretRun { proc, _lock: lock, name: s.name.clone(), wf })
}

/// Включить zapret с выбранной стратегией (VPN при этом выключается).
fn start_zapret(app: &AppHandle, st: &AppState, c: &ZapretCfg) -> Res<()> {
    let scan = zapret::scan(&c.root, c.game)?;
    let s = scan
        .strategies
        .iter()
        .find(|s| s.name == c.strategy)
        .cloned()
        .ok_or_else(|| tr!("Zapret: стратегии «{}» в папке больше нет — подбери заново", c.strategy))?;
    stop_core(st);
    kill_off(app, st, trs!("режим «Без VPN»"));
    stop_zapret(st);
    let my = st.zgen.fetch_add(1, Ordering::SeqCst) + 1;
    let a = app.clone();
    let z = launch_winws(app, c, &zengine(st), &zrun(st), &s, None, move || {
        let st = a.state::<AppState>();
        if st.zgen.load(Ordering::SeqCst) == my {
            // Мы его не останавливали — значит упал. Пусто — умер ещё при запуске:
            // это ошибка запуска, о ней скажет start_zapret.
            let dead = st.zapret.lock().unwrap().take();
            if dead.is_some() {
                drop(dead);
                notify(&a, trs!("Zapret остановился"), trs!("winws завершился сам — причина в логе"));
                changed(&a);
            }
        }
    })?;
    {
        // Проверка и запись — под одним замком: stop_zapret берёт этот же замок,
        // так что «Отключить» не проскочит между ними.
        let mut slot = st.zapret.lock().unwrap();
        if st.zgen.load(Ordering::SeqCst) != my {
            // Пока запускали, нажали «Отключить» (или включили VPN) — не включаем.
            drop(slot);
            drop(z);
            return Err(trs!("Zapret: запуск отменён").into());
        }
        *slot = Some(z);
    }
    if !zapret_running(st) {
        stop_zapret(st);
        return Err(trs!("winws завершился сразу после запуска — смотри лог").into());
    }
    log(app, tr!("zapret включён: «{}» (без VPN)", s.name));
    for n in &s.notes {
        log(app, format!("zapret: {n}"));
    }
    spawn_zapret_watch(app.clone(), my);
    Ok(())
}

/// Адреса VPN-серверов (IP или по DNS) — winws их соединения не трогает.
/// Со всеми цепочками (`xray::server_hosts`), не больше 16 потоков DNS и не
/// дольше 3 секунд: подписка может быть на сотню серверов.
fn resolve_servers(nodes: &[Node]) -> Vec<std::net::IpAddr> {
    use std::net::{IpAddr, ToSocketAddrs};
    let mut out: Vec<IpAddr> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    for n in nodes.iter().take(256) {
        for h in rxvpn_core::xray::server_hosts(n) {
            match h.parse::<IpAddr>() {
                Ok(ip) => out.push(ip),
                Err(_) => names.push(h),
            }
        }
    }
    names.sort();
    names.dedup();
    names.truncate(256);
    let workers = names.len().min(16);
    let queue = Arc::new(Mutex::new(names));
    let (tx, rx) = std::sync::mpsc::channel::<Vec<IpAddr>>();
    for _ in 0..workers {
        let (q, tx) = (queue.clone(), tx.clone());
        std::thread::spawn(move || loop {
            let Some(host) = q.lock().unwrap().pop() else { break };
            let ips = (host.as_str(), 443).to_socket_addrs().map(|a| a.map(|x| x.ip()).collect()).unwrap_or_default();
            if tx.send(ips).is_err() {
                break; // время вышло, ответ уже не ждут
            }
        });
    }
    drop(tx);
    let deadline = Instant::now() + Duration::from_secs(3);
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(ips) => out.extend(ips),
            Err(_) => break, // все ответили (канал закрыт) или время вышло
        }
    }
    queue.lock().unwrap().clear(); // не успевшие — не спрашиваем
    out.sort();
    out.dedup();
    out
}

/// Гибрид: как запускать winws рядом с VPN (VPN запускает вызывающий).
/// `fresh` — туннеля сейчас точно нет: лучший путь в интернет — сетевая карта.
fn hybrid_plan(st: &AppState, nodes: &[Node], tun: bool, fresh: bool) -> Res<zapret::Hybrid> {
    if !cfg!(windows) {
        return Err(trs!("zapret работает только в Windows").into());
    }
    if !winsys::is_admin() {
        return Err(trs!("нужны права администратора").into());
    }
    let iface = if tun {
        // Карту спрашиваем каждый раз (Wi-Fi могли сменить на кабель), но не
        // туннель: его отличаем по имени. Не узнали — последняя известная.
        let now = if fresh { winsys::best_interface() } else { winsys::physical_interface(rxvpn_core::xray::TUN_NAME) };
        let mut cached = st.phys_iface.lock().unwrap();
        if now.is_some() {
            *cached = now;
        }
        Some(cached.ok_or(trs!("не нашёл сетевую карту"))?)
    } else {
        None
    };
    Ok(zapret::Hybrid { iface, exclude: resolve_servers(nodes) })
}

fn start_hybrid_with(app: &AppHandle, st: &AppState, h: zapret::Hybrid) -> Res<()> {
    let c = zapret_cfg(st);
    if c.strategy.is_empty() {
        return Err(trs!("стратегия zapret не выбрана — «Подобрать лучшую»").into());
    }
    zapret_ready(&c)?;
    if let Some(n) = dpi_conflict() {
        return Err(tr!("уже запущен {n} (другой zapret или GoodbyeDPI)"));
    }
    let scan = zapret::scan(&c.root, c.game)?;
    let s = scan
        .strategies
        .iter()
        .find(|s| s.name == c.strategy)
        .cloned()
        .ok_or_else(|| tr!("стратегии «{}» больше нет", c.strategy))?;
    stop_zapret(st);
    let my = st.zgen.fetch_add(1, Ordering::SeqCst) + 1;
    let a = app.clone();
    let z = launch_winws(app, &c, &zengine(st), &zrun(st), &s, Some(&h), move || {
        let st = a.state::<AppState>();
        if st.zgen.load(Ordering::SeqCst) == my {
            let dead = st.zapret.lock().unwrap().take();
            if dead.is_some() {
                drop(dead);
                kill_reinject_sync(&a, &st);
                notify(&a, trs!("Zapret остановился"), trs!("Сайты «мимо VPN» идут без обхода — переподключись, причина в логе"));
                changed(&a);
            }
        }
    })?;
    {
        let mut slot = st.zapret.lock().unwrap();
        if st.zgen.load(Ordering::SeqCst) != my {
            drop(slot);
            drop(z);
            return Err(trs!("запуск отменён").into());
        }
        *slot = Some(z);
    }
    if !zapret_running(st) {
        stop_zapret(st);
        return Err(trs!("winws завершился сразу после запуска — смотри лог").into());
    }
    *st.hybrid.lock().unwrap() = Some(h.clone());
    kill_reinject_sync(app, st);
    log(
        app,
        tr!("гибрид: zapret «{}» для сайтов «мимо VPN»{}, VPN-серверов в исключениях: {}",
            s.name,
            h.iface.map(|i| tr!(", сетевая карта #{i}")).unwrap_or_default(),
            h.exclude.len()
        ),
    );
    spawn_zapret_watch(app.clone(), my);
    Ok(())
}

/// Подключиться в выбранном режиме: Xray (прокси/TUN) или zapret.
async fn connect_any(app: &AppHandle, allow_tun: bool) -> Res<()> {
    let st = app.state::<AppState>();
    // Подключаемся — значит, пауза больше не нужна (и её таймер ничего не включит).
    pauseui::clear(&st);
    // Подбор сам включает и выключает winws и VPN — не мешаем ему.
    if st.ztesting.load(Ordering::SeqCst) {
        return Err(trs!("Идёт подбор стратегии zapret — дождись конца или нажми «Стоп»").into());
    }
    let (zmode, hybrid) = {
        let s = st.store.lock().unwrap();
        (s.settings.zapret, s.settings.zapret_hybrid)
    };
    if !zmode {
        let mut how = HybridStart::Auto;
        // Запуск zapret и фоновый подбор — по одному (подбор ждать не станет).
        let mut _one = None;
        if hybrid && cfg!(windows) {
            // Гибрид: права, стратегия и движок — до VPN (движок может качаться).
            if !winsys::is_admin() {
                return Err(NEED_ADMIN.into());
            }
            _one = Some(st.zop.lock().await);
            if let Err(e) = zapret_preflight(app, &st, true).await {
                if e == NEED_ADMIN {
                    return Err(e);
                }
                // Из-за zapret VPN не отменяем: YouTube и Discord пока через него.
                log(app, tr!("гибрид: {e}"));
                let _ = app.emit("error-toast", tr!("Zapret для сайтов «мимо VPN» не включился: {e}. Пока они идут через VPN"));
                how = HybridStart::Skip;
            }
        }
        // В отдельном потоке: запуск может ждать другой (core_op) и идти секундами.
        let a = app.clone();
        return tauri::async_runtime::spawn_blocking(move || {
            start_core_ex(&a, a.state::<AppState>().inner(), allow_tun, how).map(|_| ())
        })
        .await
        .map_err(|e| e.to_string())?;
    }
    let _one = st.zop.lock().await;
    let c = zapret_preflight(app, &st, true).await?;
    let a = app.clone();
    tauri::async_runtime::spawn_blocking(move || start_zapret(&a, a.state::<AppState>().inner(), &c))
        .await
        .map_err(|e| e.to_string())?
}

/// То же из обычного потока (трей, автозапуск).
fn connect_any_blocking(app: &AppHandle, allow_tun: bool) -> Res<()> {
    tauri::async_runtime::block_on(connect_any(app, allow_tun))
}

/// Подбор: каждая стратегия — настоящий winws.
struct Winws {
    app: AppHandle,
    cfg: ZapretCfg,
    engine: PathBuf,
    run: PathBuf,
    /// Подбор рядом с работающим VPN (гибрид).
    hybrid: Option<zapret::Hybrid>,
}

impl zapret::Launcher for Winws {
    fn start(&self, s: &zapret::Strategy) -> Result<Box<dyn Send>, String> {
        let z = launch_winws(&self.app, &self.cfg, &self.engine, &self.run, s, self.hybrid.as_ref(), || {})?;
        Ok(Box::new(z))
    }
}

#[derive(Serialize)]
struct ZStrategy {
    name: String,
    file: String,
    notes: Vec<String>,
}

#[derive(Serialize)]
struct ZapretView {
    /// Своя папка ("" — стратегии rxvpn).
    dir: String,
    builtin: bool,
    /// Какие стратегии rxvpn сейчас разложены (версия Flowseal, встроенные или с GitHub).
    source: Option<zapret::Source>,
    builtin_version: &'static str,
    strategies: Vec<ZStrategy>,
    skipped: Vec<String>,
    scan_error: Option<String>,
    engine: String,
    engine_warn: Option<String>,
    selected: String,
    running: Option<String>,
    testing: bool,
    results: Vec<zapret::Score>,
    game_filter: bool,
    targets: Vec<String>,
    is_admin: bool,
    windows: bool,
}

fn zapret_view(st: &AppState) -> ZapretView {
    let c = zapret_cfg(st);
    let installed = zapret::engine_check(&zengine(st)).ok();
    let (scan, scan_error) = match zapret_ready(&c).and_then(|_| zapret::scan(&c.root, c.game)) {
        Ok(s) => (s, None),
        Err(e) => (zapret::Scan::default(), Some(e)),
    };
    let source = if c.builtin { zapret::source_of(&c.root) } else { None };
    let engine = match (&scan.engine_version, &installed) {
        (Some(v), _) if c.builtin => tr!("Движок: официальный winws {v} из сборки Flowseal (хеш сверен)"),
        (Some(v), _) => tr!("Движок: официальный winws {v} из твоей папки (хеш сверен)"),
        (None, Some(v)) => tr!("Движок: официальный winws {v}, уже скачан"),
        (None, None) => trs!("Движок: при первом запуске скачаю официальный zapret v72.13 с GitHub (~8 МБ)").into(),
    };
    let engine_warn = scan.engine_problem.as_ref().filter(|p| p.contains(trs!("не совпадает")) /* все тексты подмены движка: см. zapret::engine_check — в en.json «does not match» */).map(|p| {
        tr!("⚠ {p}. Его не запускаю (беру официальный). И сам .bat из этой папки лучше не запускай.")
    });
    ZapretView {
        dir: if c.builtin { String::new() } else { c.root.display().to_string() },
        builtin: c.builtin,
        source,
        builtin_version: zapret::BUILTIN_VERSION,
        strategies: scan
            .strategies
            .into_iter()
            .map(|s| ZStrategy { name: s.name, file: s.file, notes: s.notes })
            .collect(),
        skipped: scan.skipped,
        scan_error,
        engine,
        engine_warn,
        selected: c.strategy,
        running: zapret_running_name(st),
        testing: st.ztesting.load(Ordering::SeqCst),
        results: st.zresults.lock().unwrap().clone(),
        game_filter: c.game,
        targets: c.targets,
        is_admin: winsys::is_admin(),
        windows: cfg!(windows),
    }
}

async fn zapret_view_async(app: &AppHandle) -> Res<ZapretView> {
    let a = app.clone();
    tauri::async_runtime::spawn_blocking(move || zapret_view(a.state::<AppState>().inner()))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn zapret_get(app: AppHandle) -> Res<ZapretView> {
    zapret_view_async(&app).await
}

/// Выбрать папку zapret (системный диалог) и сразу её разобрать.
#[tauri::command]
async fn zapret_pick_folder(app: AppHandle, st: State<'_, AppState>) -> Res<Option<ZapretView>> {
    use tauri_plugin_dialog::DialogExt;
    let a = app.clone();
    let picked = tauri::async_runtime::spawn_blocking(move || {
        let mut d = a.dialog().file().set_title(trs!("Папка zapret (Flowseal zapret-discord-youtube или zapret-win-bundle)"));
        if let Some(w) = a.get_webview_window("main") {
            d = d.set_parent(&w);
        }
        d.blocking_pick_folder().map(|p| p.into_path().map_err(|e| e.to_string())).transpose()
    })
    .await
    .map_err(|e| e.to_string())??;
    let Some(dir) = picked else { return Ok(None) };
    let text = dir.display().to_string();
    if !rxvpn_core::xray::local_dir(&text) {
        return Err(trs!("Нужна папка на этом компе (C:\\…), не сетевая").into());
    }
    let game = st.store.lock().unwrap().settings.zapret_game_filter;
    let d2 = dir.clone();
    let scan = tauri::async_runtime::spawn_blocking(move || zapret::scan(&d2, game))
        .await
        .map_err(|e| e.to_string())??;
    if scan.strategies.is_empty() {
        let why = scan.skipped.first().map(|s| format!(": {s}")).unwrap_or_default();
        return Err(tr!("В папке нет годных стратегий zapret{why}"));
    }
    {
        let mut s = st.store.lock().unwrap();
        if s.settings.zapret_dir != text {
            *st.zresults.lock().unwrap() = Vec::new();
        }
        let keep = scan.strategies.iter().any(|x| x.name == s.settings.zapret_strategy);
        if !keep {
            s.settings.zapret_strategy.clear();
        }
        s.settings.zapret_dir = text.clone();
    }
    persist(&st);
    // Стратегии поменялись — фоновая проверка снова может подбирать.
    st.zquiet_until.store(0, Ordering::SeqCst);
    log(&app, tr!("zapret: папка {text} — стратегий {}", scan.strategies.len()));
    Ok(Some(zapret_view_async(&app).await?))
}

/// Выбрать стратегию вручную. Если zapret работает — перезапустить с ней.
#[tauri::command]
async fn zapret_select(app: AppHandle, st: State<'_, AppState>, name: String) -> Res<ZapretView> {
    // Стратегии или выбор поменялись — фоновая проверка снова может подбирать.
    st.zquiet_until.store(0, Ordering::SeqCst);
    let c = zapret_cfg(&st);
    let n2 = name.clone();
    let exists = tauri::async_runtime::spawn_blocking(move || {
        zapret_ready(&c)?;
        zapret::scan(&c.root, c.game).map(|s| s.strategies.iter().any(|x| x.name == n2))
    })
    .await
    .map_err(|e| e.to_string())??;
    if !exists {
        return Err(tr!("Стратегии «{name}» в папке нет"));
    }
    st.store.lock().unwrap().settings.zapret_strategy = name;
    persist(&st);
    if zapret_running(&st) {
        let r = connect_any(&app, true).await;
        refresh_tray(&app);
        r?;
    }
    zapret_view_async(&app).await
}

#[tauri::command]
fn zapret_cancel(st: State<'_, AppState>) {
    st.zcancel.store(true, Ordering::SeqCst);
}

/// Вернуться к стратегиям rxvpn (встроенные / обновлённые) вместо своей папки.
#[tauri::command]
async fn zapret_use_builtin(app: AppHandle, st: State<'_, AppState>) -> Res<ZapretView> {
    // Стратегии или выбор поменялись — фоновая проверка снова может подбирать.
    st.zquiet_until.store(0, Ordering::SeqCst);
    if st.ztesting.load(Ordering::SeqCst) {
        return Err(trs!("Идёт подбор — дождись конца").into());
    }
    let was = {
        let mut s = st.store.lock().unwrap();
        std::mem::take(&mut s.settings.zapret_dir)
    };
    if !was.is_empty() {
        *st.zresults.lock().unwrap() = Vec::new();
    }
    keep_strategy_if_present(&app).await;
    persist(&st);
    if !was.is_empty() {
        restart_zapret_if_running(&app).await?;
    }
    zapret_view_async(&app).await
}

/// Выбранной стратегии в новом наборе нет — сбросить выбор (подберём заново).
async fn keep_strategy_if_present(app: &AppHandle) {
    let a = app.clone();
    let _ = tauri::async_runtime::spawn_blocking(move || {
        let st = a.state::<AppState>();
        let c = zapret_cfg(st.inner());
        let names: Vec<String> = zapret_ready(&c)
            .and_then(|_| zapret::scan(&c.root, c.game))
            .map(|s| s.strategies.into_iter().map(|x| x.name).collect())
            .unwrap_or_default();
        let mut s = st.store.lock().unwrap();
        if !names.contains(&s.settings.zapret_strategy) {
            s.settings.zapret_strategy.clear();
        }
    })
    .await;
}

/// «Обновить стратегии»: последний релиз Flowseal с GitHub (через VPN, если подключён).
/// Из архива берётся только текст и данные; движок — только официальный по хешам.
#[tauri::command]
async fn zapret_update(app: AppHandle, st: State<'_, AppState>) -> Res<ZapretView> {
    // Стратегии или выбор поменялись — фоновая проверка снова может подбирать.
    st.zquiet_until.store(0, Ordering::SeqCst);
    if st.ztesting.load(Ordering::SeqCst) {
        return Err(trs!("Идёт подбор — дождись конца").into());
    }
    log(&app, trs!("zapret: качаю последние стратегии Flowseal с GitHub…"));
    let proxy = probe_proxy(&st).map(|p| format!("socks5h://127.0.0.1:{p}"));
    // Качаем без замка: пока идёт загрузка, zapret можно включать и выключать.
    let (tag, bytes) = zapret::fetch_flowseal(proxy.as_deref()).await?;
    let _one = st.zop.lock().await;
    let dir = zstrategies(&st);
    let now = unix_now();
    let src = tauri::async_runtime::spawn_blocking(move || zapret::install_strategies(&bytes, &dir, Some(&tag), true, now))
        .await
        .map_err(|e| e.to_string())??;
    log(&app, tr!("zapret: стратегии Flowseal {} установлены", src.version));
    let was_custom = !std::mem::take(&mut st.store.lock().unwrap().settings.zapret_dir).is_empty();
    if was_custom {
        *st.zresults.lock().unwrap() = Vec::new();
    }
    keep_strategy_if_present(&app).await;
    persist(&st);
    drop(_one);
    // Работает zapret — перезапускаем со свежими списками.
    restart_zapret_if_running(&app).await?;
    zapret_view_async(&app).await
}

/// Стратегии поменялись, а zapret работает — перезапустить с новыми.
async fn restart_zapret_if_running(app: &AppHandle) -> Res<()> {
    let st = app.state::<AppState>();
    if !zapret_running(&st) {
        return Ok(());
    }
    let r = connect_any(app, true).await;
    refresh_tray(app);
    r.map_err(|e| tr!("Стратегии на месте, но zapret не перезапустился: {e}"))
}

#[derive(Serialize)]
struct ZTestResult {
    /// Выбранная и включённая стратегия.
    best: Option<String>,
    started: bool,
    /// false — плохая новость (ничего не помогло): окно покажет красным.
    fine: bool,
    message: String,
    view: ZapretView,
}

/// «Подобрать лучшую»: прогнать все стратегии, лучшую — запомнить и включить.
#[tauri::command]
async fn zapret_test(app: AppHandle, st: State<'_, AppState>) -> Res<ZTestResult> {
    if !cfg!(windows) {
        return Err(trs!("Zapret работает только в Windows").into());
    }
    if !winsys::is_admin() {
        return Err(NEED_ADMIN.into());
    }
    if st.ztesting.swap(true, Ordering::SeqCst) {
        return Err(trs!("Подбор уже идёт").into());
    }
    struct Done<'a>(&'a AtomicBool);
    impl Drop for Done<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }
    let done = Done(&st.ztesting);
    let Ok(_one) = st.zop.try_lock() else {
        return Err(trs!("Zapret как раз запускается — нажми ещё раз через пару секунд").into());
    };
    st.zcancel.store(false, Ordering::SeqCst);
    changed(&app);
    let r = zapret_test_run(&app, &st).await;
    match &r {
        Ok((best, _, _, msg)) => note_check(&st, trs!("подбор zapret"), format!("{} — {msg}", best.as_deref().unwrap_or(trs!("ничего не подошло")))),
        Err(e) => note_check(&st, trs!("подбор zapret"), e.clone()),
    }
    drop(done);
    changed(&app);
    let (best, started, fine, message) = r?;
    Ok(ZTestResult { best, started, fine, message, view: zapret_view_async(&app).await? })
}

async fn zapret_test_run(app: &AppHandle, st: &AppState) -> Res<(Option<String>, bool, bool, String)> {
    let gen_before = st.gen.load(Ordering::SeqCst);
    let was_hybrid = st.hybrid.lock().unwrap().clone();
    let was_zapret = zapret_running(st) && was_hybrid.is_none();
    let was_vpn = is_connected(st);
    // Подбор из гибрида (VPN + zapret для YouTube): лучшую — в гибрид, а не в режим «без VPN».
    let hybrid_ctx = {
        let s = st.store.lock().unwrap();
        s.settings.zapret_hybrid && !s.settings.zapret
    };
    // Подбор не начался (движок не скачался, папка пуста…), а winws уже погашен —
    // вернуть zapret как был.
    let prepared = async {
        let c = zapret_preflight(app, st, false).await?;
        let (root, game) = (c.root.clone(), c.game);
        let scan = tauri::async_runtime::spawn_blocking(move || zapret::scan(&root, game))
            .await
            .map_err(|e| e.to_string())??;
        if scan.strategies.is_empty() {
            let why = scan.skipped.first().map(|s| format!(": {s}")).unwrap_or_default();
            return Err(tr!("В папке нет годных стратегий{why}"));
        }
        Ok((c, scan))
    }
    .await;
    let (c, scan) = match prepared {
        Ok(x) => x,
        Err(e) => {
            restore_zapret(app, was_hybrid, was_zapret, gen_before).await;
            return Err(e);
        }
    };
    // Гибрид при работающем VPN: подбираем рядом с ним, VPN не выключаем —
    // иначе на несколько минут всё пошло бы напрямую с настоящего IP.
    let keep_vpn: Option<zapret::Hybrid> = match (hybrid_ctx && was_vpn, was_hybrid.clone()) {
        (true, Some(h)) => Some(h),
        (true, None) => {
            // VPN шёл без гибрида (стратегии ещё не было) — перезапускаем его с
            // маршрутами гибрида, winws запустит подбор.
            let a = app.clone();
            let r = tauri::async_runtime::spawn_blocking(move || {
                start_core_ex(&a, a.state::<AppState>().inner(), true, HybridStart::PlanOnly)
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r);
            match r {
                Ok(Some(plan)) => Some(plan),
                // VPN работает как обычно, но гибриду нужна сетевая карта, а её не нашли.
                Ok(None) => {
                    changed(app);
                    return Err(trs!("Не нашёл сетевую карту для гибрида — рядом с VPN подобрать не выйдет. \
                                Отключи VPN и нажми «Подобрать лучшую» ещё раз")
                        .into());
                }
                Err(e) => {
                    changed(app);
                    return Err(tr!("VPN не переподключился для подбора: {e}"));
                }
            }
        }
        _ => None,
    };
    // Какой запуск VPN несёт маршруты гибрида: переподключат — у нового их нет.
    let vpn_gen = st.gen.load(Ordering::SeqCst);
    if keep_vpn.is_some() {
        log(app, trs!("zapret: подбираю для сайтов «мимо VPN», VPN работает как обычно"));
        changed(app);
    } else if is_connected(st) {
        stop_core(st);
        kill_off(app, st, trs!("подбор zapret проверяет сайты напрямую"));
        log(app, trs!("zapret: на время подбора VPN выключен — сайты проверяю напрямую"));
        changed(app);
    }
    // «Отключить» или переподключение во время подбора (stop_zapret меняет zgen) —
    // в конце ничего не включаем (кроме гибрида у переподключившегося VPN).
    let gen_at_start = st.zgen.load(Ordering::SeqCst);
    // Для гибрида важны только YouTube и Discord: остальное идёт через VPN.
    // Гибрид: только его сервисы и свои сайты (остальное идёт через VPN).
    let mut targets: Vec<(String, String)> = if hybrid_ctx && !c.hybrid_targets.is_empty() {
        c.hybrid_targets.clone()
    } else {
        zapret::DEFAULT_TARGETS.iter().map(|(n, u)| (n.to_string(), u.to_string())).collect()
    };
    for t in c.targets.iter().filter(|t| !hybrid_ctx && !t.trim().is_empty() && !t.trim_start().starts_with('#')) {
        if let Some(u) = rxvpn_core::xray::zapret_target(t) {
            if !targets.iter().any(|x| x.1 == u) {
                targets.push((u.trim_start_matches("https://").to_string(), u));
            }
        }
    }
    log(app, tr!("zapret: подбираю — стратегий {}, сайтов {}…", scan.strategies.len(), targets.len()));
    let launcher =
        Arc::new(Winws { app: app.clone(), cfg: c.clone(), engine: zengine(st), run: zrun(st), hybrid: keep_vpn.clone() });
    let a = app.clone();
    let scores = zapret::pick_best(
        launcher,
        &scan.strategies,
        &targets,
        Duration::from_secs(4),
        Duration::from_millis(500),
        st.zcancel.clone(),
        move |done, total, sc| {
            let who = if sc.name.is_empty() { trs!("без zapret").to_string() } else { format!("«{}»", sc.name) };
            let res = match &sc.error {
                Some(e) => tr!("не запустилась: {}", e.lines().last().unwrap_or(e)),
                None => tr!("{} из {}", sc.ok, sc.total),
            };
            log(&a, format!("zapret: {who} — {res}"));
            let _ = a.emit("zapret-progress", serde_json::json!({ "done": done, "total": total, "score": sc }));
        },
    )
    .await;
    let cancelled = st.zcancel.load(Ordering::SeqCst);
    *st.zresults.lock().unwrap() = scores.clone();
    let base = scores[0].clone();
    let best = zapret::best(&scores).cloned();
    let (message, pick, fine) = match &best {
        Some(b) if b.ok > base.ok && !cancelled => (
            tr!("Лучшая — «{}»: {} из {} проверок (без zapret — {})", b.name, b.ok, b.total, base.ok),
            Some(b.name.clone()),
            true,
        ),
        _ if cancelled => (trs!("Подбор остановлен — ничего не менял").to_string(), None, true),
        _ if base.ok == base.total => (trs!("Всё открывается и без zapret — сейчас он не нужен").to_string(), None, true),
        _ => (
            tr!("Ни одна стратегия не открыла больше, чем без zapret ({} из {}). Попробуй другую папку \
                 (свежий Flowseal) или включи «Игровой фильтр»; если не помогает — провайдер режет по IP, тут нужен VPN",
                base.ok, base.total
            ),
            None,
            false,
        ),
    };
    let interrupted = st.zgen.load(Ordering::SeqCst) != gen_at_start;
    if interrupted {
        log(app, format!("zapret: {message}"));
        let msg = match &pick {
            Some(name) => {
                st.store.lock().unwrap().settings.zapret_strategy = name.clone();
                persist(st);
                tr!("Лучшая — «{name}», запомнил. Не включаю: во время подбора отключились или переподключились")
            }
            None => message.clone(),
        };
        // Переподключились (сервер, «Авто») — тот запуск гибрид не включил: включаем.
        if hybrid_ctx {
            reenable_hybrid(app).await;
        }
        return Ok((None, false, pick.is_some() || fine, msg));
    }
    log(app, format!("zapret: {message}"));
    if pick.is_some() {
        st.zquiet_until.store(0, Ordering::SeqCst); // новая стратегия — фоновая проверка снова в деле
    }
    if let Some(name) = pick.clone().filter(|_| hybrid_ctx) {
        st.store.lock().unwrap().settings.zapret_strategy = name;
        persist(st);
    }
    // Подбирали рядом с VPN: он работает, осталось включить winws гибрида
    // (новую стратегию или прежнюю).
    if let Some(h) = keep_vpn {
        let has = !zapret_cfg(st).strategy.is_empty();
        let a = app.clone();
        // Чем кончилось: гибрид работает / VPN выключен / VPN работает без гибрида.
        #[derive(PartialEq)]
        enum Back {
            Hybrid,
            VpnOff,
            NoHybrid,
        }
        let r = tauri::async_runtime::spawn_blocking(move || {
            let st = a.state::<AppState>();
            let st = st.inner();
            let off = |e: String| {
                if is_connected(st) {
                    e
                } else {
                    tr!("{e} — VPN выключен")
                }
            };
            if !is_connected(st) {
                Ok(Back::VpnOff)
            } else if st.gen.load(Ordering::SeqCst) != vpn_gen {
                // VPN успели переподключить (без маршрутов гибрида) — поднимаем целиком.
                start_core_ex(&a, st, true, HybridStart::FromPicker)
                    .map(|_| if st.hybrid.lock().unwrap().is_some() { Back::Hybrid } else { Back::NoHybrid })
                    .map_err(|e| off(tr!("VPN не переподключился ({e})")))
            } else if has {
                start_hybrid_with(&a, st, h).map(|_| Back::Hybrid).map_err(|e| drop_hybrid_routes(&a, st, e, vpn_gen))
            } else {
                // Стратегии нет и не нашлось — обычные маршруты VPN, без «мимо VPN».
                let m = drop_hybrid_routes(&a, st, String::new(), vpn_gen);
                if is_connected(st) { Ok(Back::NoHybrid) } else { Err(m) }
            }
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r);
        changed(app);
        return match r {
            Ok(Back::Hybrid) if pick.is_some() => Ok((pick, true, true, tr!("{message} — для сайтов «мимо VPN», VPN работает"))),
            Ok(Back::VpnOff) if pick.is_some() => Ok((pick, false, true, tr!("{message}. Включится вместе с VPN"))),
            Ok(Back::NoHybrid) if pick.is_some() => {
                Ok((pick, false, false, tr!("{message}. VPN работает, а zapret не включился — смотри лог")))
            }
            Ok(_) => Ok((None, false, fine, message)),
            Err(e) => Err(tr!("{message}, но zapret не включился: {e}")),
        };
    }
    if pick.is_some() && hybrid_ctx {
        if was_vpn {
            let a = app.clone();
            let r = tauri::async_runtime::spawn_blocking(move || {
                start_core_ex(&a, a.state::<AppState>().inner(), true, HybridStart::FromPicker)
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r);
            changed(app);
            r.map_err(|e| tr!("{message}, но VPN не подключился обратно: {e}"))?;
            let on = st.hybrid.lock().unwrap().is_some();
            let tail = if on { trs!("для сайтов «мимо VPN», VPN работает") } else { trs!("VPN работает, но zapret не включился — смотри лог") };
            return Ok((pick, on, on, format!("{message} — {tail}")));
        }
        return Ok((pick, false, true, tr!("{message}. Включится вместе с VPN")));
    }
    if let Some(name) = pick.clone() {
        {
            let mut s = st.store.lock().unwrap();
            s.settings.zapret_strategy = name;
            s.settings.zapret = true;
        }
        persist(st);
        let c2 = zapret_cfg(st);
        let a = app.clone();
        tauri::async_runtime::spawn_blocking(move || start_zapret(&a, a.state::<AppState>().inner(), &c2))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| tr!("{message}, но не запустилась: {e}"))?;
        return Ok((pick, true, true, tr!("{message}. Включил (режим «Без VPN»)")));
    }
    // Ничего не выбрали — вернуть как было.
    let back = if was_zapret && !hybrid_ctx {
        let c2 = zapret_cfg(st);
        let a = app.clone();
        tauri::async_runtime::spawn_blocking(move || start_zapret(&a, a.state::<AppState>().inner(), &c2))
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r)
            .map_err(|e| tr!("zapret не включился обратно: {e}"))
    } else if was_vpn {
        let a = app.clone();
        tauri::async_runtime::spawn_blocking(move || {
            start_core_ex(&a, a.state::<AppState>().inner(), true, HybridStart::FromPicker).map(|_| ())
        })
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r)
        .map_err(|e| tr!("VPN не подключился обратно: {e}"))
    } else {
        Ok(())
    };
    changed(app);
    match back {
        Ok(()) => Ok((None, false, fine, message)),
        Err(e) => {
            log(app, &e);
            Ok((None, false, false, format!("{message}. {e}")))
        }
    }
}

/// winws гибрида не поднялся: VPN без маршрута «мимо VPN» (иначе YouTube и
/// Discord шли бы напрямую без обхода). Не вышло и это — VPN выключаем совсем,
/// чтобы окно не показывало того, чего нет. Возвращает, что сказать человеку.
/// `vpn_gen` — запуск VPN, у которого убираем: отключились или переподключились —
/// не трогаем (иначе включили бы VPN после «Отключить»).
fn drop_hybrid_routes(app: &AppHandle, st: &AppState, why: String, vpn_gen: u64) -> String {
    let why = if why.is_empty() { String::new() } else { format!("{why}. ") };
    if !is_connected(st) {
        return tr!("{why}VPN выключен");
    }
    if st.gen.load(Ordering::SeqCst) != vpn_gen {
        return tr!("{why}VPN переподключился");
    }
    match start_core_ex(app, st, true, HybridStart::Skip) {
        Ok(_) => tr!("{why}сайты «мимо VPN» пока через VPN"),
        Err(e) => {
            stop_core(st);
            stop_zapret(st);
            changed(app);
            log(app, tr!("VPN не переподключился: {e} — выключен"));
            tr!("{why}VPN не переподключился ({e}) — он выключен")
        }
    }
}

/// Подбор прервали переподключением VPN (сервер, «Авто»): тот запуск гибрид не
/// включил (шёл подбор) — включаем теперь. Отключились или сменили режим — ничего.
async fn reenable_hybrid(app: &AppHandle) {
    let a = app.clone();
    let _ = tauri::async_runtime::spawn_blocking(move || {
        let st = a.state::<AppState>();
        let st = st.inner();
        let (zmode, hyb) = {
            let s = st.store.lock().unwrap();
            (s.settings.zapret, s.settings.zapret_hybrid)
        };
        if hyb && !zmode && is_connected(st) && st.hybrid.lock().unwrap().is_none() {
            let tun = st.tun_active.load(Ordering::SeqCst) || winsys::is_admin();
            if let Err(e) = start_core_ex(&a, st, tun, HybridStart::FromPicker) {
                log(&a, tr!("VPN не переподключился: {e}"));
            }
        }
    })
    .await;
    changed(app);
}

/// Подбор не начался, а winws уже погашен: вернуть zapret как был (гибрид — к
/// работающему VPN, «без VPN» — сам по себе).
async fn restore_zapret(app: &AppHandle, hybrid: Option<zapret::Hybrid>, was_zapret: bool, vpn_gen: u64) {
    let a = app.clone();
    let _ = tauri::async_runtime::spawn_blocking(move || {
        let st = a.state::<AppState>();
        let st = st.inner();
        if zapret_running(st) {
            return; // и не гасили (ошибка случилась раньше)
        }
        match hybrid {
            Some(_) if is_connected(st) && st.gen.load(Ordering::SeqCst) != vpn_gen => {
                // VPN успели переподключить (без маршрутов гибрида) — поднимаем целиком.
                if let Err(e) = start_core_ex(&a, st, true, HybridStart::FromPicker) {
                    log(&a, tr!("VPN не переподключился: {e}"));
                }
            }
            Some(h) if is_connected(st) => {
                if let Err(e) = start_hybrid_with(&a, st, h) {
                    let m = drop_hybrid_routes(&a, st, e, vpn_gen);
                    log(&a, tr!("гибрид: {m}"));
                }
            }
            None if was_zapret && !is_connected(st) => {
                if let Err(e) = start_zapret(&a, st, &zapret_cfg(st)) {
                    log(&a, tr!("zapret не включился обратно: {e}"));
                }
            }
            _ => {}
        }
    })
    .await;
    changed(app);
}

// ---------------- самопроверка zapret ----------------

/// Флажок «занято» с гарантированным снятием (и при раннем выходе).
struct Busy<'a>(&'a AtomicBool);
impl Drop for Busy<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Пока zapret работает (сам или в гибриде), раз в 2 часа (первый раз — через
/// 15 минут) проверяем YouTube и Discord. Два провала подряд при живом интернете —
/// стратегию «перестало пробивать» (провайдер поменял настройки), подбираем заново.
/// Задача живёт, пока не сменился запуск zapret (`my` — его номер).
fn spawn_zapret_watch(app: AppHandle, my: u64) {
    tauri::async_runtime::spawn(async move {
        let mut wait = Duration::from_secs(15 * 60);
        let mut strikes = 0;
        loop {
            let t0 = Instant::now();
            while t0.elapsed() < wait {
                tokio::time::sleep(Duration::from_secs(15)).await;
                if app.state::<AppState>().zgen.load(Ordering::SeqCst) != my {
                    return;
                }
            }
            let st = app.state::<AppState>();
            let on = st.store.lock().unwrap().settings.zapret_autocheck;
            // Недавний подбор ничего лучше не нашёл — провайдер режет так, что
            // стратегии не помогают: не гоняем подбор и уведомления по кругу.
            let quiet = st.zquiet_until.load(Ordering::SeqCst) > unix_now();
            if !on || quiet || st.ztesting.load(Ordering::SeqCst) {
                wait = Duration::from_secs(2 * 3600);
                strikes = 0;
                continue;
            }
            if !zapret_running(&st) {
                return; // winws упал сам — об этом уже сказали, проверять нечего
            }
            let h = zapret_health().await;
            if st.zgen.load(Ordering::SeqCst) != my {
                return;
            }
            match h {
                zapret::Health::Fine | zapret::Health::Offline => {
                    if matches!(h, zapret::Health::Fine) && st.zapret_broken.swap(false, Ordering::SeqCst) {
                        changed(&app);
                    }
                    strikes = 0;
                    wait = Duration::from_secs(2 * 3600);
                }
                zapret::Health::Broken => {
                    strikes += 1;
                    if strikes < 2 {
                        wait = Duration::from_secs(120); // перепроверить: вдруг сеть моргнула
                        continue;
                    }
                    log(&app, trs!("zapret: стратегия перестала пробивать YouTube/Discord — подбираю заново"));
                    st.zapret_broken.store(true, Ordering::SeqCst);
                    changed(&app);
                    auto_repick(&app, my).await;
                    // Перезапустили zapret — у нового запуска своя проверка, эта
                    // выйдет на первой же сверке номера. Не вышло — следим дальше.
                    strikes = 0;
                    wait = Duration::from_secs(2 * 3600);
                }
            }
        }
    });
}

async fn zapret_health() -> zapret::Health {
    let targets: Vec<(String, String)> = zapret::HEALTH_TARGETS.iter().map(|(n, u)| (n.to_string(), u.to_string())).collect();
    let (ctrl, (_, _, _, res)) = tokio::join!(
        zapret::check_target(zapret::CONTROL_TARGET.0, zapret::CONTROL_TARGET.1, Duration::from_secs(6)),
        zapret::check_all(&targets, Duration::from_secs(5))
    );
    zapret::health_of(ctrl.ok > 0, &res)
}

/// Подбор в фоне, без выключения VPN (в гибриде VPN работает дальше).
/// `my` — запуск zapret, который проверяли: сменился — подбор уже не нужен.
async fn auto_repick(app: &AppHandle, my: u64) {
    let st = app.state::<AppState>();
    if st.ztesting.swap(true, Ordering::SeqCst) {
        return;
    }
    let _busy = Busy(&st.ztesting);
    let Ok(_one) = st.zop.try_lock() else { return };
    st.zcancel.store(false, Ordering::SeqCst);
    let c = zapret_cfg(&st);
    let prev = c.strategy.clone();
    let hybrid = st.hybrid.lock().unwrap().clone();
    let (root, game) = (c.root.clone(), c.game);
    let Ok(Ok(scan)) = tauri::async_runtime::spawn_blocking(move || zapret::scan(&root, game)).await else { return };
    // Пока проверяли, zapret выключили или запустили заново — не трогаем.
    if st.zgen.load(Ordering::SeqCst) != my || !zapret_running(&st) {
        return;
    }
    // Какой запуск VPN несёт маршруты гибрида: переподключат — у нового их нет.
    let vpn_gen = st.gen.load(Ordering::SeqCst);
    changed(app);
    stop_zapret(&st);
    // Дальше zgen меняет «Отключить», другой режим или переподключение VPN.
    let gen0 = st.zgen.load(Ordering::SeqCst);
    let targets: Vec<(String, String)> = zapret::HEALTH_TARGETS.iter().map(|(n, u)| (n.to_string(), u.to_string())).collect();
    let launcher = Arc::new(Winws { app: app.clone(), cfg: c.clone(), engine: zengine(&st), run: zrun(&st), hybrid: hybrid.clone() });
    let a = app.clone();
    let scores = zapret::pick_best(
        launcher,
        &scan.strategies,
        &targets,
        Duration::from_secs(4),
        Duration::from_millis(500),
        st.zcancel.clone(),
        move |done, total, sc| {
            let _ = a.emit("zapret-progress", serde_json::json!({ "done": done, "total": total, "score": sc }));
        },
    )
    .await;
    // Сначала «Стоп», потом номер: «Отключить» ставит «Стоп» после смены номера,
    // так что увидели «Стоп» — увидим и новый номер.
    let stopped = st.zcancel.load(Ordering::SeqCst);
    if st.zgen.load(Ordering::SeqCst) != gen0 {
        log(app, trs!("zapret: фоновый подбор прерван"));
        if hybrid.is_some() {
            reenable_hybrid(app).await; // переподключились во время подбора
        }
        changed(app);
        return;
    }
    // «Стоп» в окне Zapret: подбор бросаем, прежнюю стратегию включаем обратно.
    let base = &scores[0];
    let open_anyway = base.ok == base.total;
    let found = if stopped || open_anyway {
        None
    } else {
        zapret::best(&scores).filter(|b| b.ok > base.ok).map(|b| b.name.clone())
    };
    let name = found.clone().unwrap_or_else(|| prev.clone());
    // Ничего лучше, та же самая или «Стоп» — сутки не подбираем заново: иначе
    // провайдер (или стратегия, что чинит только YouTube) гонял бы подбор по кругу.
    let quiet = if found.as_ref().is_some_and(|n| *n != prev) { 0 } else { 24 * 3600 };
    st.zquiet_until.store(unix_now() + quiet, Ordering::SeqCst);
    st.store.lock().unwrap().settings.zapret_strategy = name.clone();
    persist(&st);
    let a = app.clone();
    let r = tauri::async_runtime::spawn_blocking(move || {
        let st = a.state::<AppState>();
        let st = st.inner();
        // Режим за это время могли сменить — включаем, только если он тот же.
        let (zmode, hyb) = {
            let s = st.store.lock().unwrap();
            (s.settings.zapret, s.settings.zapret_hybrid)
        };
        match hybrid {
            Some(h) if is_connected(st) && hyb && !zmode && st.hybrid.lock().unwrap().is_none() => {
                if st.gen.load(Ordering::SeqCst) == vpn_gen {
                    start_hybrid_with(&a, st, h).map(|_| true).map_err(|e| drop_hybrid_routes(&a, st, e, vpn_gen))
                } else {
                    // VPN успели переподключить (без маршрутов гибрида) — поднимаем целиком.
                    start_core_ex(&a, st, true, HybridStart::FromPicker).map(|_| st.hybrid.lock().unwrap().is_some())
                }
            }
            None if zmode && !is_connected(st) && !zapret_running(st) => start_zapret(&a, st, &zapret_cfg(st)).map(|_| true),
            _ => Ok(false), // за это время выключили, переподключили или сменили режим — не трогаем
        }
    })
    .await
    .map_err(|e| e.to_string())
    .and_then(|r| r);
    let r = match r {
        Ok(false) => {
            log(app, tr!("zapret: фоновый подбор закончен, «{name}» запомнил, но не включил — VPN или режим за это время поменялись (строки выше)"));
            changed(app);
            return;
        }
        r => r.map(|_| ()),
    };
    match (&found, r) {
        (_, Err(e)) => notify(app, trs!("Zapret не включился"), e),
        _ if stopped => log(app, tr!("zapret: фоновый подбор остановлен — оставил «{prev}»")),
        _ if open_anyway => log(app, tr!("zapret: YouTube и Discord открываются и без zapret — оставил «{prev}»")),
        (Some(n), Ok(())) if *n != prev => {
            notify(app, trs!("Zapret: сменил стратегию"), tr!("«{prev}» перестала пробивать YouTube/Discord — теперь «{n}»"))
        }
        (Some(_), Ok(())) => log(app, trs!("zapret: лучшей осталась та же стратегия — следующая проверка через сутки")),
        (None, Ok(())) => notify(
            app,
            trs!("Zapret перестал пробивать"),
            trs!("YouTube/Discord не открываются ни с одной стратегией. Нажми «Обновить» в окне Zapret или включи для них VPN"),
        ),
    }
    changed(app);
}

// ---------------- трей и окно ----------------

/// Когда мини-окно спряталось от потери фокуса (мс с начала эпохи).
static MINI_HIDDEN_AT: AtomicU64 = AtomicU64::new(0);
fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Мини-окно из трея (ui/mini.html): показать над значком у часов или спрятать.
/// Создаётся при первом клике и дальше только прячется/показывается.
fn toggle_mini(app: &AppHandle, at: tauri::PhysicalPosition<f64>) {
    const W: f64 = 300.0;
    const H: f64 = 380.0;
    if let Some(w) = app.get_webview_window("mini") {
        if w.is_visible().unwrap_or(false) {
            let _ = w.hide();
            return;
        }
        // Клик по значку сначала уводит фокус — окно уже спряталось от этого же клика: не открываем снова.
        if now_ms().saturating_sub(MINI_HIDDEN_AT.load(Ordering::SeqCst)) < 350 {
            return;
        }
        place_mini(&w, at, W, H);
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let mut b = tauri::WebviewWindowBuilder::new(app, "mini", tauri::WebviewUrl::App("mini.html".into()))
        .title("rxvpn")
        .inner_size(W, H)
        .resizable(false)
        .decorations(false)
        .transparent(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .visible(false);
    // Та же папка профиля окна, что у главного: у WebView2 одна среда на процесс.
    if let Some(d) = WEBVIEW_DIR.get() {
        b = b.data_directory(d.clone());
    }
    match b.build() {
        Ok(w) => {
            place_mini(&w, at, W, H);
            let _ = w.show();
            let _ = w.set_focus();
        }
        Err(e) => {
            log(app, tr!("мини-окно не открылось: {e}"));
            show_main(app);
        }
    }
}

/// Над курсором у часов (панель задач обычно внизу), не вылезая за край экрана.
fn place_mini(w: &tauri::WebviewWindow, at: tauri::PhysicalPosition<f64>, width: f64, height: f64) {
    let scale = w.scale_factor().unwrap_or(1.0);
    let (pw, ph) = (width * scale, height * scale);
    let mut x = at.x - pw / 2.0;
    let mut y = at.y - ph - 12.0 * scale;
    if let Ok(Some(m)) = w.current_monitor().or_else(|_| w.primary_monitor()) {
        let (mx, my) = (m.position().x as f64, m.position().y as f64);
        let (mw, mh) = (m.size().width as f64, m.size().height as f64);
        x = x.clamp(mx + 8.0, mx + mw - pw - 8.0);
        if y < my + 8.0 {
            y = at.y + 12.0 * scale; // панель задач сверху — открываем вниз
        }
        y = y.clamp(my + 8.0, my + mh - ph - 8.0);
    }
    let _ = w.set_position(tauri::PhysicalPosition::new(x, y));
}

/// Мини-окно → «Открыть rxvpn»: прячем мини, показываем большое.
#[tauri::command]
fn show_main_window(app: AppHandle) {
    if let Some(w) = app.get_webview_window("mini") {
        let _ = w.hide();
    }
    show_main(&app);
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let menu = build_tray_menu(app.handle())?;
    TrayIconBuilder::with_id("main")
        .icon(Image::from_bytes(TRAY_OFF)?)
        .tooltip(trs!("rxvpn — отключено"))
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| on_tray_menu(app, ev.id().as_ref()))
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                position,
                ..
            } = ev
            {
                // Левый клик — мини-окно (кнопка и состояние); правый — меню, как раньше.
                toggle_mini(tray.app_handle(), position);
            }
        })
        .build(app)?;
    Ok(())
}

/// Сколько серверов показывать в одной группе меню (дальше — «ещё N»).
const TRAY_GROUP_MAX: usize = 40;

/// Текст пункта меню: в Windows «&» — подчёркнутая буква, удваиваем;
/// длинные имена из подписок режем, чтобы меню не уезжало за экран.
fn menu_text(s: &str) -> String {
    let mut t: String = s.chars().filter(|c| !c.is_control()).take(60).collect();
    if s.chars().count() > 60 {
        t.push('…');
    }
    if cfg!(windows) {
        t.replace('&', "&&")
    } else {
        t
    }
}

/// Меню трея целиком: собирается заново при каждом изменении (сервер,
/// режим, подключение) — так галочки всегда правдивые.
fn build_tray_menu(app: &AppHandle) -> tauri::Result<Menu<Wry>> {
    let st = app.state::<AppState>();
    let connected = is_connected(&st);
    let servers = visible_servers(&st); // как в окне: без скрытых фильтрами
    let (subs, selected, settings) = {
        let s = st.store.lock().unwrap();
        (s.subscriptions.clone(), s.selected.clone(), s.settings.clone())
    };
    let auto = st.run.lock().unwrap().as_ref().is_some_and(|r| r.auto);
    let zname = zapret_running_name(&st);
    let pause = pauseui::current(&st);
    let status = match (connected, active_node(&st)) {
        _ if pause.is_some() && !connected && zname.is_none() => pauseui::tray_status(pause.as_ref().unwrap()),
        _ if zname.is_some() && !connected => tr!("● Zapret без VPN: {}", menu_text(zname.as_deref().unwrap_or(""))),
        (true, Some((_, n))) if auto => tr!("● Подключено: Авто → {}", menu_text(&n)),
        (true, Some((_, n))) => tr!("● Подключено: {}", menu_text(&n)),
        (true, None) => trs!("● Подключено: выбираю сервер…").to_string(),
        (false, _) => trs!("○ Отключено").to_string(),
    };
    let status = MenuItem::with_id(app, "status", status, false, None::<&str>)?;
    // Идёт подбор zapret — «Отключить» останавливает и его.
    let on = connected || zname.is_some() || st.ztesting.load(Ordering::SeqCst);
    let can = !servers.is_empty() || settings.zapret;
    let toggle_text = if on { trs!("Отключить") } else if pause.is_some() { trs!("Включить сейчас") } else { trs!("Подключить") };
    let toggle = MenuItem::with_id(app, "toggle", toggle_text, can, None::<&str>)?;
    // Пауза — только пока что-то подключено.
    let pause_menu = Submenu::with_id(app, "pause", trs!("Пауза"), on && !st.ztesting.load(Ordering::SeqCst))?;
    for m in pauseui::CHOICES {
        pause_menu.append(&MenuItem::with_id(app, format!("pause:{m}"), pauseui::choice_label(m), true, None::<&str>)?)?;
    }

    // --- сервер ---
    let srv = Submenu::with_id(app, "srv", trs!("Сервер"), !servers.is_empty())?;
    if servers.len() > 1 {
        let is_auto = selected.as_deref() == Some(rxvpn_core::AUTO_ID);
        srv.append(&CheckMenuItem::with_id(app, format!("srv:{}", rxvpn_core::AUTO_ID), trs!("⚡ Авто — самый быстрый"), true, is_auto, None::<&str>)?)?;
        srv.append(&PredefinedMenuItem::separator(app)?)?;
    }
    // Как в окне: без папки, папки (в порядке появления), подписки.
    let mut groups: Vec<(String, Vec<&Node>)> = Vec::new();
    let manual: Vec<&Node> = servers.iter().filter(|n| n.sub_id.is_none() && n.group.is_none()).collect();
    if !manual.is_empty() {
        groups.push((trs!("Добавлены вручную").into(), manual));
    }
    let mut folders: Vec<&str> = Vec::new();
    for g in servers.iter().filter(|n| n.sub_id.is_none()).filter_map(|n| n.group.as_deref()) {
        if !folders.contains(&g) {
            folders.push(g);
        }
    }
    for f in folders {
        let list: Vec<&Node> = servers.iter().filter(|n| n.sub_id.is_none() && n.group.as_deref() == Some(f)).collect();
        groups.push((f.to_string(), list));
    }
    for sub in &subs {
        let list: Vec<&Node> = servers.iter().filter(|n| n.sub_id.as_deref() == Some(sub.id.as_str())).collect();
        if !list.is_empty() {
            groups.push((sub.name.clone(), list));
        }
    }
    let add_items = |menu: &Submenu<Wry>, list: &[&Node]| -> tauri::Result<()> {
        for n in list.iter().take(TRAY_GROUP_MAX) {
            let on = selected.as_deref() == Some(n.id.as_str());
            menu.append(&CheckMenuItem::with_id(app, format!("srv:{}", n.id), menu_text(&n.name), true, on, None::<&str>)?)?;
        }
        if list.len() > TRAY_GROUP_MAX {
            let more = tr!("…ещё {} — в окне rxvpn", list.len() - TRAY_GROUP_MAX);
            menu.append(&MenuItem::with_id(app, "more", more, false, None::<&str>)?)?;
        }
        Ok(())
    };
    if groups.len() == 1 {
        add_items(&srv, &groups[0].1)?;
    } else {
        for (i, (name, list)) in groups.iter().enumerate() {
            let g = Submenu::with_id(app, format!("grp:{i}"), format!("{} ({})", menu_text(name), list.len()), true)?;
            add_items(&g, list)?;
            srv.append(&g)?;
        }
    }

    // --- маршрутизация и режим ---
    let route = Submenu::with_id(app, "route", trs!("Маршрутизация"), true)?;
    for (id, label, mode) in [
        ("route:bypassru", trs!("Обход РФ"), RouteMode::BypassRu),
        ("route:blocked", trs!("Только заблокированное"), RouteMode::Blocked),
        ("route:global", trs!("Всё через VPN"), RouteMode::Global),
    ] {
        route.append(&CheckMenuItem::with_id(app, id, label, true, settings.route == mode, None::<&str>)?)?;
    }
    let mode = Submenu::with_id(app, "mode", trs!("Режим"), true)?;
    mode.append(&CheckMenuItem::with_id(app, "mode:proxy", trs!("Прокси"), true, !settings.zapret && !settings.tun, None::<&str>)?)?;
    mode.append(&CheckMenuItem::with_id(app, "mode:tun", trs!("TUN · все программы"), true, !settings.zapret && settings.tun, None::<&str>)?)?;
    mode.append(&CheckMenuItem::with_id(app, "mode:zapret", trs!("Zapret · без VPN"), true, settings.zapret, None::<&str>)?)?;
    let ads = CheckMenuItem::with_id(app, "ads", trs!("Блокировать рекламу"), true, settings.block_ads, None::<&str>)?;

    let show = MenuItem::with_id(app, "show", trs!("Открыть rxvpn"), true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", trs!("Выход"), true, None::<&str>)?;
    let (sep1, sep2) = (PredefinedMenuItem::separator(app)?, PredefinedMenuItem::separator(app)?);
    Menu::with_items(app, &[&status, &toggle, &pause_menu, &sep1, &srv, &route, &mode, &ads, &sep2, &show, &quit])
}

/// Отключить всё: VPN, kill switch, zapret, подбор и DNS (DNS — в фоне: netsh — секунды).
fn stop_everything(app: &AppHandle, st: &AppState, why: &'static str) {
    let a = app.clone();
    tauri::async_runtime::spawn(async move { dohui::doh_stop_now(&a, why).await });
    stop_core(st);
    kill_off(app, st, why);
    stop_zapret(st);
    // После остановки: подбор, увидевший «Стоп», уже видит и смену zgen
    // (значит, «Отключить», а не «Стоп» — ничего не включает обратно).
    st.zcancel.store(true, Ordering::SeqCst);
    reset_auto(st);
}

fn on_tray_menu(app: &AppHandle, id: &str) {
    match id {
        "toggle" => {
            let st = app.state::<AppState>();
            if running(&st) || st.ztesting.load(Ordering::SeqCst) {
                stop_everything(app, &st, trs!("отключено"));
                pauseui::clear(&st);
                log(app, trs!("отключено (из трея)"));
                changed(app);
            } else {
                connect_in_background(app.clone(), true, false);
            }
        }
        "show" => show_main(app),
        "quit" => app.exit(0),
        "ads" => tray_apply(app, trs!("реклама"), false, |s| {
            s.settings.block_ads = !s.settings.block_ads;
            true
        }),
        "mode:proxy" | "mode:tun" => {
            let tun = id == "mode:tun";
            tray_apply(app, if tun { trs!("режим TUN") } else { trs!("режим прокси") }, tun, move |s| {
                let was_zapret = std::mem::replace(&mut s.settings.zapret, false);
                (std::mem::replace(&mut s.settings.tun, tun) != tun) | was_zapret
            })
        }
        "mode:zapret" => tray_apply(app, trs!("режим zapret"), false, |s| !std::mem::replace(&mut s.settings.zapret, true)),
        "route:bypassru" | "route:blocked" | "route:global" => {
            let mode = match id {
                "route:blocked" => RouteMode::Blocked,
                "route:global" => RouteMode::Global,
                _ => RouteMode::BypassRu,
            };
            tray_apply(app, trs!("маршрутизация"), false, move |s| std::mem::replace(&mut s.settings.route, mode) != mode)
        }
        _ if id.starts_with("pause:") => {
            let m = id["pause:".len()..].parse::<u32>().unwrap_or(u32::MAX);
            if let Err(e) = pauseui::start(app, m) {
                log(app, e);
            }
        }
        _ => {
            if let Some(sid) = id.strip_prefix("srv:").map(str::to_string) {
                reset_auto(app.state::<AppState>().inner());
                tray_apply(app, trs!("сервер"), false, move |s| {
                    // id из меню — только тот, что мы сами туда положили; но
                    // сервер могли удалить, пока меню висело открытым.
                    let ok = sid == rxvpn_core::AUTO_ID || s.servers.iter().any(|n| n.id == sid);
                    ok && s.selected.replace(sid.clone()).as_deref() != Some(sid.as_str())
                })
            }
        }
    }
}

/// Изменение из трея: поправить, сохранить и, если подключены, переподключиться.
/// В отдельном потоке — меню не ждёт. Окно узнаёт через state-changed.
/// `want_tun` — человек сам выбрал TUN: можно просить права администратора.
fn tray_apply(app: &AppHandle, what: &'static str, want_tun: bool, f: impl FnOnce(&mut Store) -> bool + Send + 'static) {
    let app = app.clone();
    std::thread::spawn(move || {
        let st = app.state::<AppState>();
        let (route_before, zapret_before) = {
            let s = st.store.lock().unwrap();
            (s.settings.route, s.settings.zapret)
        };
        let changed_now = {
            let mut s = st.store.lock().unwrap();
            f(&mut s)
        };
        if !changed_now {
            refresh_tray(&app);
            return;
        }
        // «Только заблокированное» без списков — сначала скачать.
        let route = st.store.lock().unwrap().settings.route;
        if route == RouteMode::Blocked && !geodata::present(&st.paths.core) {
            let r = if st.lists_busy.swap(true, Ordering::SeqCst) {
                Err(trs!("они уже качаются — подожди и выбери ещё раз").to_string())
            } else {
                notify(&app, trs!("Качаю списки блокировок"), trs!("Пара минут — потом включу «Только заблокированное»"));
                let proxy = probe_proxy(&st).map(|p| format!("socks5h://127.0.0.1:{p}"));
                let r = tauri::async_runtime::block_on(geodata::update(&st.paths.core, proxy.as_deref()));
                st.lists_busy.store(false, Ordering::SeqCst);
                r.map(|_| ())
            };
            if let Err(e) = r {
                notify(&app, trs!("Списки не скачались"), &e);
                st.store.lock().unwrap().settings.route = route_before;
                changed(&app);
                return;
            }
        }
        persist(&st);
        // zapret перезапускаем, только если сменился сам режим (сервер,
        // маршрутизация и реклама ему не важны).
        let mode_changed = st.store.lock().unwrap().settings.zapret != zapret_before;
        if is_connected(&st) || (zapret_running(&st) && mode_changed) {
            let allow_tun = want_tun || st.tun_active.load(Ordering::SeqCst) || winsys::is_admin();
            match connect_any_blocking(&app, allow_tun) {
                Ok(()) => log(&app, tr!("из трея: {what}")),
                Err(e) if e == NEED_ADMIN => {
                    show_main(&app);
                    let _ = app.emit("need-admin", ());
                }
                Err(e) => notify(&app, trs!("rxvpn не переподключился"), &e),
            }
        } else {
            log(&app, tr!("из трея: {what}"));
        }
        changed(&app);
    });
}

/// Только для отладочной сборки (в релизе этого кода нет): команды меню трея
/// из файла RXVPN_TRAY_FIFO — чтобы проверить трей там, где его не кликнуть.
#[cfg(debug_assertions)]
fn debug_tray_hook(app: AppHandle) {
    use tauri::menu::MenuItemKind;
    fn dump(items: Vec<MenuItemKind<Wry>>, depth: usize) {
        for it in items {
            let pad = "  ".repeat(depth);
            match it {
                MenuItemKind::MenuItem(i) => eprintln!("[tray]{pad}{}{}", i.text().unwrap_or_default(), if i.is_enabled().unwrap_or(true) { "" } else { trs!(" (серый)") }),
                MenuItemKind::Check(c) => eprintln!("[tray]{pad}[{}] {}", if c.is_checked().unwrap_or(false) { "x" } else { " " }, c.text().unwrap_or_default()),
                MenuItemKind::Submenu(sm) => {
                    eprintln!("[tray]{pad}{} ▸", sm.text().unwrap_or_default());
                    dump(sm.items().unwrap_or_default(), depth + 1);
                }
                MenuItemKind::Predefined(_) => eprintln!("[tray]{pad}———"),
                _ => {}
            }
        }
    }
    let Some(path) = std::env::var_os("RXVPN_TRAY_FIFO") else { return };
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(200));
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        if text.trim().is_empty() {
            continue;
        }
        let _ = std::fs::write(&path, "");
        for cmd in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            eprintln!("[tray] >>> {cmd}");
            if cmd == "dump" {
                if let Ok(m) = build_tray_menu(&app) {
                    dump(m.items().unwrap_or_default(), 0);
                }
            } else {
                on_tray_menu(&app, cmd);
            }
        }
    });
}

fn refresh_tray(app: &AppHandle) {
    let st = app.state::<AppState>();
    let zname = zapret_running_name(&st);
    let connected = is_connected(&st) || zname.is_some();
    let auto = st.run.lock().unwrap().as_ref().is_some_and(|r| r.auto);
    let vpn = is_connected(&st);
    let hybrid = vpn && zname.is_some();
    let name = if vpn {
        active_node(&st).map(|(_, n)| if auto { tr!("Авто: {n}") } else { n }).map(|n| if hybrid { format!("{n} + zapret") } else { n })
    } else {
        zname.map(|n| tr!("zapret без VPN, «{n}»"))
    };
    if let Some(tray) = app.tray_by_id("main") {
        if let Ok(menu) = build_tray_menu(app) {
            let _ = tray.set_menu(Some(menu));
        }
        if let Ok(icon) = Image::from_bytes(if connected { TRAY_ON } else { TRAY_OFF }) {
            let _ = tray.set_icon(Some(icon));
        }
        let tip = match (connected, name) {
            (true, Some(n)) => tr!("rxvpn — подключено: {n}"),
            _ => trs!("rxvpn — отключено").to_string(),
        };
        let _ = tray.set_tooltip(Some(tip));
    }
}

// ---------------- защита от второго запуска ----------------

/// Уже запущенная копия есть (мьютекс): попросить её показать окно.
/// Канал — порт на 127.0.0.1; если его занял кто-то чужой, просто не покажем.
fn handoff_to_running(msg: &str) -> bool {
    let addr: SocketAddr = ([127, 0, 0, 1], LOCK_PORT).into();
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
    let mut hello = String::new();
    let _ = BufReader::new(&s).read_line(&mut hello);
    if hello.trim() != "rxvpn" {
        return false; // порт занят чужой программой
    }
    let _ = writeln!(s, "{msg}");
    true
}

fn serve_lock(app: AppHandle, listener: TcpListener) {
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let mut c = conn;
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = writeln!(c, "rxvpn");
            let mut line = String::new();
            // Любая программа на компе может сюда постучаться — читаем не больше строчки.
            let _ = BufReader::new((&c).take(64)).read_line(&mut line);
            if line.trim() == "show" {
                show_main(&app);
            }
        }
    });
}

// ---------------- команды для интерфейса ----------------

#[tauri::command]
async fn get_view(st: State<'_, AppState>) -> Res<View> {
    Ok(view(&st))
}

#[tauri::command]
fn get_log(st: State<'_, AppState>) -> Vec<String> {
    st.log_buf.lock().unwrap().iter().cloned().collect()
}

#[tauri::command]
async fn connect(app: AppHandle, st: State<'_, AppState>) -> Res<View> {
    reset_auto(&st);
    let r = connect_any(&app, true).await;
    refresh_tray(&app);
    // В лог — чтобы причину было видно и после того, как всплывашка пропала.
    if let Err(e) = &r {
        if e != NEED_ADMIN {
            log(&app, tr!("не подключился: {e}"));
        }
    }
    r?;
    Ok(view(&st))
}

/// Трафик по программам с момента включения (включается при первом вызове).
#[tauri::command]
async fn app_traffic(st: State<'_, AppState>) -> Res<Vec<rxvpn_core::apptraffic::AppUsage>> {
    let mut g = st.app_traffic.lock().unwrap();
    if g.is_none() {
        *g = Some(rxvpn_core::apptraffic::AppTraffic::start()?);
    }
    Ok(g.as_ref().map(|t| t.snapshot()).unwrap_or_default())
}

/// Окно закрыли или «Сбросить» — остановить подсчёт (следующий вызов начнёт с нуля).
#[tauri::command]
async fn app_traffic_stop(st: State<'_, AppState>) -> Res<()> {
    st.app_traffic.lock().unwrap().take();
    Ok(())
}

/// «Открыть интернет»: Xray упал, kill switch держит блокировку — снять её, не подключаясь.
#[tauri::command]
async fn kill_release(app: AppHandle, st: State<'_, AppState>) -> Res<View> {
    kill_off(&app, &st, trs!("сняли блокировку вручную"));
    refresh_tray(&app);
    Ok(view(&st))
}

#[tauri::command]
async fn disconnect(app: AppHandle, st: State<'_, AppState>) -> Res<View> {
    dohui::doh_stop_now(&app, trs!("отключено")).await;
    stop_core(&st);
    kill_off(&app, &st, trs!("отключено"));
    stop_zapret(&st);
    // И подбор, если идёт. После остановки: см. on_tray_menu.
    st.zcancel.store(true, Ordering::SeqCst);
    reset_auto(&st);
    pauseui::clear(&st);
    log(&app, trs!("отключено"));
    refresh_tray(&app);
    Ok(view(&st))
}

#[tauri::command]
async fn select_server(app: AppHandle, st: State<'_, AppState>, id: String) -> Res<View> {
    st.store.lock().unwrap().selected = Some(id);
    reset_auto(&st);
    persist(&st);
    // Как в v2rayN: выбрал другой сервер во время работы — переподключаемся.
    if is_connected(&st) {
        let tun = st.tun_active.load(Ordering::SeqCst);
        let r = start_core_blocking(&app, tun || winsys::is_admin()).await;
        refresh_tray(&app);
        r?;
    }
    Ok(view(&st))
}

#[tauri::command]
async fn delete_server(st: State<'_, AppState>, id: String) -> Res<View> {
    st.store.lock().unwrap().remove_server(&id);
    persist(&st);
    Ok(view(&st))
}

fn merge(into: &mut ImportResult, r: ImportResult) {
    into.added += r.added;
    into.updated += r.updated;
    into.errors.extend(r.errors);
}

async fn refresh_sub(app: &AppHandle, st: &AppState, sub_id: &str) -> ImportResult {
    let (url, name, socks, hwid) = {
        let s = st.store.lock().unwrap();
        let Some(sub) = s.subscriptions.iter().find(|x| x.id == sub_id) else {
            return ImportResult::default();
        };
        (sub.url.clone(), sub.name.clone(), s.settings.socks_port, sub.hwid.clone())
    };
    // Если VPN уже работает — качаем подписку через него.
    let _ = socks;
    let via = probe_proxy(st);
    match net::fetch_subscription_full(&url, via, hwid.as_deref()).await {
        Ok((body, usage)) => {
            // Панель перестала присылать остаток — убираем старый, иначе
            // «подписка закончилась» висело бы и после продления.
            if let Some(sub) = st.store.lock().unwrap().subscriptions.iter_mut().find(|x| x.id == sub_id) {
                sub.usage = usage;
            }
            // Разбираем без блокировки: большая подписка не должна вешать окно.
            let (nodes, errors) = tauri::async_runtime::spawn_blocking(move || rxvpn_core::store::parse_subscription(&body))
                .await
                .unwrap_or_default();
            let mut r = st.store.lock().unwrap().apply_parsed(sub_id, nodes, errors, now());
            persist(st);
            // Сервис с привязкой к устройствам вместо серверов прислал «сервер»-записку
            // «включите отправку HWID» — говорим человеку, где это включается.
            let wants_hwid = hwid.is_none()
                && st.store.lock().unwrap().servers.iter().any(|n| n.sub_id.as_deref() == Some(sub_id) && n.name.to_lowercase().contains("hwid"));
            if wants_hwid {
                r.errors.push(tr!("подписка «{name}»: сервис просит номер устройства (HWID) и без него серверы не отдаёт. Включается кнопкой «HWID» у подписки"));
            }
            let hid = {
                let s = st.store.lock().unwrap();
                let f = s.subscriptions.iter().find(|x| x.id == sub_id).map(|x| x.filter.clone()).unwrap_or_default();
                s.servers.iter().filter(|n| n.sub_id.as_deref() == Some(sub_id) && !f.matches(&n.name)).count()
            };
            let hid = if hid > 0 { tr!(" (фильтр подписки скрыл {hid})") } else { String::new() };
            log(app, tr!("подписка «{name}»: {} серверов{hid}", r.added));
            warn_sub_usage(app);
            r
        }
        Err(e) => ImportResult {
            errors: vec![tr!("подписка «{name}»: {e}")],
            ..Default::default()
        },
    }
}

/// Вставка: ссылки на сервера и/или ссылки на подписки (https://...).
#[tauri::command]
async fn import_text(app: AppHandle, st: State<'_, AppState>, text: String) -> Res<ImportResult> {
    let mut links = String::new();
    let mut sub_urls = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.starts_with("http://") || line.starts_with("https://") {
            sub_urls.push(line.to_string());
        } else {
            links.push_str(line);
            links.push('\n');
        }
    }

    let mut total = ImportResult::default();
    if !links.is_empty() {
        let r = st.store.lock().unwrap().import_links(&links);
        merge(&mut total, r);
        persist(&st);
    }
    for url in sub_urls {
        if url.starts_with("http://") {
            // Без шифрования провайдер может подменить список серверов.
            total.errors.push(trs!("⚠ подписка по http:// — её может подменить провайдер; если панель умеет https, лучше https").into());
        }
        let id = st.store.lock().unwrap().add_subscription("", &url);
        persist(&st);
        let r = refresh_sub(&app, &st, &id).await;
        merge(&mut total, r);
    }
    Ok(total)
}

/// Отправлять ли сервису номер устройства (HWID) при загрузке подписки; сразу обновляет её.
#[tauri::command]
async fn set_sub_hwid(app: AppHandle, st: State<'_, AppState>, id: String, on: bool) -> Res<ImportResult> {
    st.store.lock().unwrap().set_sub_hwid(&id, on)?;
    persist(&st);
    log(&app, if on { trs!("подписка: отправка HWID включена") } else { trs!("подписка: отправка HWID выключена") });
    Ok(refresh_sub(&app, &st, &id).await)
}

/// Фильтр подписки: страны и слова, как их ввёл человек.
#[tauri::command]
async fn set_sub_filter(app: AppHandle, st: State<'_, AppState>, id: String, countries: String, words: String) -> Res<View> {
    let f = filter::parse(&countries, &words)?;
    apply_filter(&app, &st, move |s| {
        let sub = s.subscriptions.iter_mut().find(|x| x.id == id).ok_or(trs!("Подписки уже нет"))?;
        sub.filter = f;
        Ok(())
    })
    .await
}

/// «Скрыть мёртвые» и «убрать дубли» (для всех серверов).
#[tauri::command]
async fn set_list_filter(app: AppHandle, st: State<'_, AppState>, hide_dead: bool, dedup: bool) -> Res<View> {
    apply_filter(&app, &st, move |s| {
        s.list_filter = filter::ListFilter { hide_dead, dedup };
        Ok(())
    })
    .await
}

/// Поменять фильтр; если в «Авто» от этого поменялся набор серверов — перезапуск.
async fn apply_filter(app: &AppHandle, st: &AppState, f: impl FnOnce(&mut Store) -> Res<()>) -> Res<View> {
    let before: Vec<String> = visible_servers(st).into_iter().map(|n| n.id).collect();
    f(&mut st.store.lock().unwrap())?;
    persist(st);
    let after: Vec<String> = visible_servers(st).into_iter().map(|n| n.id).collect();
    let auto = st.store.lock().unwrap().is_auto();
    if auto && before != after && is_connected(st) {
        log(app, tr!("фильтр: для «Авто» теперь {} серверов — переподключаюсь", after.len()));
        let r = connect_any(app, true).await;
        refresh_tray(app);
        r?;
    } else {
        refresh_tray(app);
    }
    Ok(view(st))
}

/// Страны серверов подписки (для флажков в «Фильтре»): код → сколько. "" — не понять.
#[tauri::command]
fn sub_countries(st: State<'_, AppState>, id: String) -> Vec<(String, usize)> {
    filter::sub_countries(&st.store.lock().unwrap(), &id)
}

#[tauri::command]
async fn update_subscription(app: AppHandle, st: State<'_, AppState>, id: String) -> Res<ImportResult> {
    Ok(refresh_sub(&app, &st, &id).await)
}

#[tauri::command]
async fn update_all_subscriptions(app: AppHandle, st: State<'_, AppState>) -> Res<ImportResult> {
    let ids: Vec<String> = st
        .store
        .lock()
        .unwrap()
        .subscriptions
        .iter()
        .map(|s| s.id.clone())
        .collect();
    let mut total = ImportResult::default();
    for id in ids {
        let r = refresh_sub(&app, &st, &id).await;
        merge(&mut total, r);
    }
    Ok(total)
}

#[tauri::command]
async fn delete_subscription(st: State<'_, AppState>, id: String) -> Res<View> {
    st.store.lock().unwrap().remove_subscription(&id);
    persist(&st);
    Ok(view(&st))
}

// ---------------- «Почему не открывается сайт» ----------------

/// Проверить сайт по шагам (шаги — событием diag-step по мере готовности).
#[tauri::command]
async fn diagnose(app: AppHandle, st: State<'_, AppState>, site: String) -> Res<rxvpn_core::diag::Report> {
    if is_connected(&st) && st.tun_active.load(Ordering::SeqCst) {
        return Err(trs!("В режиме «Все программы» весь трафик компа, и проверок тоже, идёт в туннель — напрямую не проверить. \
                    Переключись на «Браузер» на минуту и проверь снова")
            .into());
    }
    if st.diag_busy.swap(true, Ordering::SeqCst) {
        return Err(trs!("Проверка уже идёт").into());
    }
    let _busy = Busy(&st.diag_busy);
    let proxy = probe_proxy(&st).map(|p| format!("socks5h://127.0.0.1:{p}"));
    let a = app.clone();
    let sys_doh = dohui::doh_label_applied(&st);
    let r = rxvpn_core::diag::run(&site, proxy, sys_doh.as_deref(), move |s| {
        let _ = a.emit("diag-step", s);
    })
    .await;
    let r = r.inspect_err(|e| note_check(&st, trs!("сайт"), format!("{site}: {e}")))?;
    log(&app, tr!("проверка {}: {}", r.host, r.title));
    note_check(&st, trs!("сайт"), format!("{}: {} — {}", r.host, r.title, r.advice));
    Ok(r)
}

/// Что сделать с сайтом после проверки: «vpn» — всегда через VPN, «direct» — всегда
/// напрямую, «zapret» — в свои сайты zapret.
#[tauri::command]
async fn diag_apply(app: AppHandle, st: State<'_, AppState>, host: String, action: String) -> Res<View> {
    let host = rxvpn_core::diag::normalize(&host)?;
    let same = |l: &String| l.trim().eq_ignore_ascii_case(&host);
    let (restart_vpn, restart_zapret) = {
        let mut s = st.store.lock().unwrap();
        let mut n = s.settings.clone();
        match action.as_str() {
            "vpn" => {
                n.direct.retain(|l| !same(l));
                if !n.proxy.iter().any(same) {
                    n.proxy.push(host.clone());
                }
            }
            "direct" => {
                n.proxy.retain(|l| !same(l));
                if !n.direct.iter().any(same) {
                    n.direct.push(host.clone());
                }
            }
            "zapret" if !n.zapret => {
                // Режим VPN: сайт — в гибрид (мимо VPN через zapret), гибрид — включить.
                if !n.hybrid_sites.iter().any(same) {
                    n.hybrid_sites.push(host.clone());
                }
                if n.hybrid_services.is_none() {
                    n.hybrid_services = Some(rxvpn_core::xray::hybrid_on(&n).iter().map(|x| x.key.to_string()).collect());
                }
                n.zapret_hybrid = true;
            }
            "zapret" => {
                if !n.zapret_targets.iter().any(same) {
                    n.zapret_targets.push(host.clone());
                }
            }
            _ => return Err(trs!("не то действие").into()),
        }
        validate_settings(&n)?;
        let vpn_mode = !n.zapret;
        s.settings = n;
        (action != "zapret" || vpn_mode, action == "zapret" && !vpn_mode)
    };
    persist(&st);
    log(&app, format!("{host}: {}", match action.as_str() {
        "vpn" => trs!("теперь всегда через VPN (Свои сайты)"),
        "direct" => trs!("теперь всегда напрямую (Свои сайты)"),
        _ if restart_vpn => trs!("теперь мимо VPN через zapret (Обход → «Через zapret, мимо VPN»)"),
        _ => trs!("добавлен в свои сайты zapret"),
    }));
    if restart_vpn && is_connected(&st) {
        let tun = st.tun_active.load(Ordering::SeqCst);
        start_core_blocking(&app, tun).await?;
    }
    if restart_zapret {
        restart_zapret_if_running(&app).await?;
    }
    refresh_tray(&app);
    Ok(view(&st))
}

// ---------------- Сервисы через сервер ----------------

/// Страна выхода и что работает через сервер (ChatGPT, Gemini, YouTube Premium,
/// Netflix). Отдельный временный Xray: подключение и его правила не трогает.
#[tauri::command]
async fn check_services(app: AppHandle, st: State<'_, AppState>, id: String) -> Res<services::Report> {
    probe_bind(&st)?;
    if !runner::xray_path(&st.paths.core).exists() {
        return Err(trs!("Ядро Xray не скачано").into());
    }
    if st.svc_busy.swap(true, Ordering::SeqCst) {
        return Err(trs!("Проверка уже идёт").into());
    }
    let _busy = Busy(&st.svc_busy);
    let (node, mask, tweaks) = {
        let s = st.store.lock().unwrap();
        let node = s.servers.iter().find(|n| n.id == id).cloned().ok_or(trs!("Сервер не найден"))?;
        (node, rxvpn_core::xray::finalmask(&s.settings), s.settings.node_tweaks.clone())
    };
    let r = batch::check_services(&st.paths.core, &node, mask, &tweaks).await;
    match &r {
        Ok(rep) => {
            let list: Vec<String> = rep
                .services
                .iter()
                .map(|x| format!("{} — {}", x.name, x.detail))
                .collect();
            let land = if rep.country.is_empty() { "?" } else { rep.country.as_str() };
            log(&app, tr!("сервисы через «{}»: выход {land}; {}", node.name, list.join("; ")));
            note_check(&st, trs!("сервисы"), tr!("{} · выход {land}; {}", node.summary(), list.join("; ")));
        }
        Err(e) => {
            log(&app, tr!("сервисы через «{}»: {e}", node.name));
            note_check(&st, trs!("сервисы"), format!("{}: {e}", node.summary()));
        }
    }
    r
}

#[derive(Serialize)]
struct TweakPick {
    results: Vec<batch::VariantResult>,
    /// Что подошло и запомнено для сервера (None — ничего не прошло).
    chosen: Option<String>,
    view: View,
}

/// «Подобрать обход»: перебрать варианты анти-DPI для сервера во временном Xray
/// и запомнить первый рабочий (от самого безобидного к самому заметному).
#[tauri::command]
async fn pick_tweak(app: AppHandle, st: State<'_, AppState>, id: String) -> Res<TweakPick> {
    probe_bind(&st)?;
    if !runner::xray_path(&st.paths.core).exists() {
        return Err(trs!("Ядро Xray не скачано").into());
    }
    if st.svc_busy.swap(true, Ordering::SeqCst) {
        return Err(trs!("Проверка уже идёт").into());
    }
    let _busy = Busy(&st.svc_busy);
    let node = st.store.lock().unwrap().servers.iter().find(|n| n.id == id).cloned().ok_or(trs!("Сервер не найден"))?;
    log(&app, tr!("«{}»: подбираю обход — пробую варианты…", node.name));
    let results = batch::pick_tweak(&st.paths.core, &node).await?;
    let chosen = results.iter().find(|r| r.ms.is_some()).cloned();
    let Some(c) = chosen else {
        log(&app, tr!("«{}»: ни один вариант не прошёл — сервер лежит или закрыт по IP", node.name));
        return Ok(TweakPick { results, chosen: None, view: view(&st) });
    };
    let in_use = {
        let mut s = st.store.lock().unwrap();
        let mut n = s.settings.clone();
        n.node_tweaks.retain(|k, _| s.servers.iter().any(|x| &x.id == k));
        n.node_tweaks.insert(id.clone(), c.tweak.clone());
        validate_settings(&n)?;
        let site = n.site_servers.iter().any(|r| r.server == id || r.backup == id);
        s.settings = n;
        site || st.run.lock().unwrap().as_ref().is_some_and(|r| r.nodes.iter().any(|(_, nid, _)| nid == &id))
    };
    persist(&st);
    log(&app, tr!("«{}»: работает — {} ({} мс), запомнил для сервера", node.name, c.label, c.ms.unwrap_or(0)));
    if in_use && is_connected(&st) {
        let tun = st.tun_active.load(Ordering::SeqCst);
        start_core_blocking(&app, tun).await?;
    }
    Ok(TweakPick { results, chosen: Some(c.label), view: view(&st) })
}

#[derive(Serialize)]
struct PhoneRouting {
    link: String,
    /// QR (SVG), если ссылка не слишком длинная для камеры.
    qr: Option<String>,
}

/// Маршруты rxvpn — на телефон: профиль Happ (iPhone/Android) по QR или ссылке.
#[tauri::command]
fn phone_routing(st: State<'_, AppState>) -> PhoneRouting {
    let s = st.store.lock().unwrap().settings.clone();
    let link = rxvpn_core::export::happ_routing_link(&s, unix_now());
    let qr = qr::svg(&link).ok();
    PhoneRouting { link, qr }
}

#[tauri::command]
fn phone_routing_copy(st: State<'_, AppState>) -> Res<()> {
    let s = st.store.lock().unwrap().settings.clone();
    let link = rxvpn_core::export::happ_routing_link(&s, unix_now());
    arboard::Clipboard::new().and_then(|mut c| c.set_text(link)).map_err(|e| tr!("буфер обмена: {e}"))
}

/// Сервисы и их сайты — шаблоны для «Сайт → свой сервер».
#[derive(Serialize)]
struct ServiceInfo {
    key: &'static str,
    name: &'static str,
    sites: &'static [&'static str],
}

#[tauri::command]
fn services_list() -> Vec<ServiceInfo> {
    services::SERVICES.iter().map(|(key, name, sites)| ServiceInfo { key, name, sites }).collect()
}

/// «Сайт → свой сервер»: запомнить у каждого правила подписку его сервера —
/// сервер узнаётся по паре (id, подписка), не по одному id (его можно подделать).
fn bind_site_servers(s: &mut Settings, servers: &[Node]) {
    for r in &mut s.site_servers {
        if let Some(n) = servers.iter().find(|n| n.id == r.server) {
            r.sub = n.sub_id.clone().unwrap_or_default();
        }
        if r.backup.is_empty() {
            r.backup_sub.clear();
        } else if let Some(n) = servers.iter().find(|n| n.id == r.backup) {
            r.backup_sub = n.sub_id.clone().unwrap_or_default();
        }
    }
    // Сервер для белых списков — тоже по паре (id, подписка).
    if s.wl_server.is_empty() {
        s.wl_server_sub.clear();
    } else if let Some(n) = servers.iter().find(|n| n.id == s.wl_server) {
        s.wl_server_sub = n.sub_id.clone().unwrap_or_default();
    }
}

/// «Пускать <сервис> через этот сервер»: правило «Сайт → свой сервер» с сайтами
/// сервиса. Уже есть правило с таким названием — меняем в нём только сервер.
#[tauri::command]
async fn site_server_add(app: AppHandle, st: State<'_, AppState>, key: String, id: String) -> Res<View> {
    let (_, name, sites) = services::SERVICES.iter().find(|x| x.0 == key).ok_or(trs!("Не тот сервис"))?;
    let server_name = {
        let mut s = st.store.lock().unwrap();
        let server_name = s.servers.iter().find(|n| n.id == id).map(|n| n.name.clone()).ok_or(trs!("Сервер не найден"))?;
        let mut n = s.settings.clone();
        match n.site_servers.iter_mut().find(|r| r.name == *name) {
            Some(r) => {
                r.server = id.clone();
                r.sub = String::new(); // проставит bind_site_servers
                if r.sites.iter().all(|l| l.trim().is_empty()) {
                    r.sites = sites.iter().map(|x| x.to_string()).collect();
                }
            }
            None => n.site_servers.push(rxvpn_core::SiteServer {
                name: name.to_string(),
                sites: sites.iter().map(|x| x.to_string()).collect(),
                server: id.clone(),
                ..Default::default()
            }),
        }
        bind_site_servers(&mut n, &s.servers);
        validate_settings(&n)?;
        s.settings = n;
        server_name
    };
    persist(&st);
    log(&app, tr!("{name}: теперь через «{server_name}» (Сайт → сервер)"));
    if is_connected(&st) {
        let tun = st.tun_active.load(Ordering::SeqCst);
        start_core_blocking(&app, tun).await?;
    }
    refresh_tray(&app);
    Ok(view(&st))
}

// ---------------- Telegram без VPN ----------------

/// Запустить или остановить прокси по настройкам (перезапуск — с освобождением порта).
async fn tg_apply(app: &AppHandle) -> Res<()> {
    let st = app.state::<AppState>();
    let mut slot = st.tg.lock().await;
    if let Some(old) = slot.take() {
        old.shutdown().await;
    }
    *st.tg_info.lock().unwrap() = None;
    let s = st.store.lock().unwrap().settings.clone();
    if !s.tg_proxy {
        return Ok(());
    }
    let secret = tgproxy::secret_from_hex(&s.tg_secret).ok_or(trs!("секрет прокси испорчен"))?;
    let a = app.clone();
    let cfg = tgproxy::Config { port: s.tg_port, secret, cf_on: s.tg_cf, cf_domains: Vec::new() };
    let r = tgproxy::start(cfg, move |line| log(&a, line)).await?;
    *st.tg_info.lock().unwrap() = Some((r.stats.clone(), r.port));
    log(app, tr!("Telegram без VPN: прокси на 127.0.0.1:{}{}", r.port, if s.tg_cf { trs!(", запасной путь — Cloudflare") } else { "" }));
    *slot = Some(r);
    drop(slot);
    if s.tg_cf {
        // Свежий список доменов (Flowseal обновляет, когда старые блокируют); не вышло — встроенный.
        let proxy = probe_proxy(&st).map(|p| format!("socks5h://127.0.0.1:{p}"));
        match tgproxy::fetch_cf_list(proxy.as_deref()).await {
            Ok(list) => {
                if let Some(r) = st.tg.lock().await.as_ref() {
                    r.set_cf_domains(list);
                }
            }
            Err(e) => log(app, tr!("Telegram: свежий список Cloudflare-доменов не скачался ({e}) — беру встроенный")),
        }
    }
    Ok(())
}

/// Включить/выключить «Telegram без VPN» и запасной путь через Cloudflare.
#[tauri::command]
async fn tg_set(app: AppHandle, st: State<'_, AppState>, on: bool, cf: bool) -> Res<View> {
    {
        let mut s = st.store.lock().unwrap();
        let mut n = s.settings.clone();
        if on && tgproxy::secret_from_hex(&n.tg_secret).is_none() {
            n.tg_secret = tgproxy::secret_hex(&tgproxy::new_secret());
        }
        (n.tg_proxy, n.tg_cf) = (on, cf);
        validate_settings(&n)?;
        s.settings = n;
    }
    persist(&st);
    if let Err(e) = tg_apply(&app).await {
        st.store.lock().unwrap().settings.tg_proxy = false;
        persist(&st);
        return Err(tr!("Telegram без VPN не включился: {e}"));
    }
    if !on {
        log(&app, trs!("Telegram без VPN: выключен"));
    }
    Ok(view(&st))
}

/// Открыть ссылку прокси в Telegram Desktop: он сам предложит «Подключить».
#[tauri::command]
async fn tg_open(st: State<'_, AppState>) -> Res<()> {
    let link = tg_view(&st).link;
    if link.is_empty() {
        return Err(trs!("Сначала включи «Telegram без VPN»").into());
    }
    // Открываем сами (от администратора — через Проводник пользователя, см. open_tg_link).
    // Не вышло — ссылка в буфере обмена, окно подскажет вставить её в Telegram.
    winsys::open_tg_link(&link).inspect_err(|_| {
        let _ = arboard::Clipboard::new().and_then(|mut c| c.set_text(link.clone()));
    })
}

#[tauri::command]
async fn rename_subscription(app: AppHandle, st: State<'_, AppState>, id: String, name: String) -> Res<View> {
    st.store.lock().unwrap().rename_subscription(&id, &name)?;
    persist(&st);
    refresh_tray(&app);
    Ok(view(&st))
}

/// Сложить сервера в папку («» — вынуть из папки).
#[tauri::command]
async fn set_server_group(app: AppHandle, st: State<'_, AppState>, ids: Vec<String>, group: String) -> Res<View> {
    let g = Some(group.as_str()).filter(|g| !g.trim().is_empty());
    st.store.lock().unwrap().set_group(&ids, g)?;
    persist(&st);
    refresh_tray(&app);
    Ok(view(&st))
}

/// Переименовать папку («» — разобрать: сервера остаются, без папки).
#[tauri::command]
async fn rename_group(app: AppHandle, st: State<'_, AppState>, old: String, name: String) -> Res<View> {
    st.store.lock().unwrap().rename_group(&old, &name)?;
    persist(&st);
    refresh_tray(&app);
    Ok(view(&st))
}

/// «Проверить все»: результаты приходят событием test-result по мере готовности.
#[tauri::command]
async fn test_all(app: AppHandle, st: State<'_, AppState>) -> Res<Vec<TestResult>> {
    probe_bind(&st)?;
    if !runner::xray_path(&st.paths.core).exists() {
        return Err(trs!("Ядро Xray не скачано").into());
    }
    if st.testing.swap(true, Ordering::SeqCst) {
        return Err(trs!("Проверка уже идёт").into());
    }
    // Видимые и «мёртвые»: иначе мёртвый не воскрес бы никогда.
    let (nodes, mask, tweaks) = {
        let s = st.store.lock().unwrap();
        (filter::checkable(&s), rxvpn_core::xray::finalmask(&s.settings), s.settings.node_tweaks.clone())
    };
    let app2 = app.clone();
    let r = batch::test_all(&st.paths.core, &nodes, mask, tweaks, move |r| {
        let _ = app2.emit("test-result", r);
    })
    .await;
    st.testing.store(false, Ordering::SeqCst);
    if let Ok(list) = &r {
        let mut t = st.last_test.lock().unwrap();
        t.clear();
        t.extend(list.iter().filter_map(|x| x.ms.map(|ms| (x.id.clone(), ms))));
    }
    if let Ok(list) = &r {
        for x in list {
            stat(&st, &x.id, x.ms);
        }
        save_stats(&st);
        let ok = list.iter().filter(|x| x.ms.is_some()).count();
        log(&app, tr!("проверка всех: работают {ok} из {}", list.len()));
        let mut ms: Vec<u64> = list.iter().filter_map(|x| x.ms).collect();
        ms.sort_unstable();
        let mid = ms.get(ms.len() / 2).map(|m| tr!(", медиана {m} мс")).unwrap_or_default();
        note_check(&st, trs!("все сервера"), tr!("работают {ok} из {}{mid}", list.len()));
    }
    if let Err(e) = &r {
        note_check(&st, trs!("все сервера"), e.clone());
    }
    r
}

/// «Проверить скорость всех»: через каждый сервер — задержка и 3 МБ с Cloudflare,
/// по 3 сервера за раз. Результаты — по мере готовности (событие `speed-all-result`),
/// в стабильность (stats.json) и в «Авто».
#[tauri::command]
async fn speed_all(app: AppHandle, st: State<'_, AppState>) -> Res<Vec<batch::SpeedTestResult>> {
    probe_bind(&st)?;
    if !runner::xray_path(&st.paths.core).exists() {
        return Err(trs!("Ядро Xray не скачано").into());
    }
    if st.speed_all_busy.swap(true, Ordering::SeqCst) {
        return Err(trs!("Проверка скорости уже идёт").into());
    }
    let _busy = Busy(&st.speed_all_busy);
    st.speed_all_cancel.store(false, Ordering::SeqCst);
    let nodes = visible_servers(&st);
    let (mask, tweaks) = {
        let s = st.store.lock().unwrap();
        (rxvpn_core::xray::finalmask(&s.settings), s.settings.node_tweaks.clone())
    };
    if nodes.is_empty() {
        return Err(trs!("Серверов пока нет").into());
    }
    changed(&app);
    log(&app, tr!("скорость всех: {} серверов, по {} за раз, до 3 МБ через каждый", nodes.len(), batch::SPEED_PARALLEL));
    let a = app.clone();
    let r = batch::speed_all(&st.paths.core, &nodes, mask, &tweaks, st.speed_all_cancel.clone(), move |x| {
        let _ = a.emit("speed-all-result", x);
    })
    .await;
    let list = match r {
        Ok(l) => l,
        Err(e) => {
            note_check(&st, trs!("скорость серверов"), e.clone());
            changed(&app);
            return Err(e);
        }
    };
    let now = unix_now();
    {
        let mut stats = st.stats.lock().unwrap();
        for x in list.iter().filter(|x| !x.skipped) {
            stats.record(&x.id, now, x.ms);
            if let Some(m) = x.mbps {
                stats.record_speed(&x.id, now, m);
            }
        }
    }
    st.stats_dirty.store(true, Ordering::SeqCst);
    save_stats(&st);
    st.last_test.lock().unwrap().extend(list.iter().filter_map(|x| x.ms.map(|ms| (x.id.clone(), ms))));
    let measured: Vec<f64> = list.iter().filter_map(|x| x.mbps).collect();
    let mb = list.iter().map(|x| x.bytes).sum::<u64>() >> 20;
    let best = measured.iter().cloned().fold(0.0, f64::max);
    let skipped = list.iter().filter(|x| x.skipped).count();
    let text = tr!("измерено {} из {}{}{}, ушло {mb} МБ",
        measured.len(),
        list.len(),
        if measured.is_empty() { String::new() } else { tr!(", лучший {best} Мбит/с") },
        if skipped > 0 { tr!(", остановлено (не дошла очередь у {skipped})") } else { String::new() }
    );
    log(&app, tr!("скорость всех: {text}"));
    note_check(&st, trs!("скорость серверов"), text);
    changed(&app);
    Ok(list)
}

/// «Стоп» для «Проверить скорость всех»: начатые докачаются, новые не начнутся.
#[tauri::command]
fn speed_all_cancel(st: State<'_, AppState>) {
    st.speed_all_cancel.store(true, Ordering::SeqCst);
}

#[tauri::command]
async fn real_delay(app: AppHandle, st: State<'_, AppState>) -> Res<u64> {
    let Some(port) = probe_proxy(&st) else {
        return Err(trs!("Сначала подключись").into());
    };
    // Через служебный вход — меряем именно сервер, мимо правил маршрутизации.
    let r = net::real_delay_with_timeout(&format!("socks5h://127.0.0.1:{port}"), net::CHECK_URLS, Duration::from_secs(10)).await;
    match &r {
        Ok(ms) => {
            st.ping.store((*ms).max(1), Ordering::SeqCst);
            log(&app, tr!("проверка: {ms} мс"));
            note_check(&st, trs!("задержка"), tr!("{ms} мс"));
        }
        // Подробности — в лог, рядом со строками Xray про ту же попытку.
        Err(e) => {
            log(&app, tr!("проверка не прошла: {}", e.replace('\n', " ")));
            note_check(&st, trs!("задержка"), tr!("не прошла: {}", e.replace('\n', " ")));
        }
    }
    r
}

// ---------------- «Мой IP», DNS, скорость ----------------

/// Для проверки на стенде без интернета: RXVPN_PLAIN_HTTP=1 — сервисы по http.
/// Только в отладочной сборке: в релизе адреса всегда как есть (https).
fn svc(url: &str) -> String {
    if cfg!(debug_assertions) && std::env::var_os("RXVPN_PLAIN_HTTP").is_some() {
        url.replacen("https://", "http://", 1)
    } else {
        url.to_string()
    }
}

#[derive(Serialize)]
struct IpSide {
    info: Option<checks::IpInfo>,
    error: Option<String>,
}

#[derive(Serialize)]
struct IpReport {
    connected: bool,
    tun: bool,
    /// Через VPN (служебный вход — мимо правил).
    vpn: Option<IpSide>,
    /// Без VPN. В TUN не меряем: там и «напрямую» идёт в туннель.
    direct: Option<IpSide>,
    /// IPv6: какой адрес видят сайты при прямом запросе и что это значит.
    v6: V6Report,
}

#[derive(Serialize)]
struct V6Report {
    seen: Option<String>,
    verdict: checks::V6Verdict,
}

#[tauri::command]
async fn check_ip(st: State<'_, AppState>) -> Res<IpReport> {
    let probe = probe_proxy(&st).map(|p| format!("socks5h://127.0.0.1:{p}"));
    let tun = probe.is_some() && st.tun_active.load(Ordering::SeqCst);
    let services: Vec<String> = checks::IP_SERVICES.iter().map(|u| svc(u)).collect();
    let list: Vec<&str> = services.iter().map(String::as_str).collect();
    let side = |r: Res<checks::IpInfo>| match r {
        Ok(i) => IpSide { info: Some(i), error: None },
        Err(e) => IpSide { info: None, error: Some(e) },
    };
    let vpn = async {
        match &probe {
            Some(p) => Some(side(checks::my_ip(Some(p), &list).await)),
            None => None,
        }
    };
    let direct = async {
        if tun {
            None
        } else {
            Some(side(checks::my_ip(None, &list).await))
        }
    };
    let v6_list: Vec<String> = checks::IPV6_SERVICES.iter().map(|u| svc(u)).collect();
    let v6_refs: Vec<&str> = v6_list.iter().map(String::as_str).collect();
    let (vpn, direct, seen) = tokio::join!(vpn, direct, checks::seen_ipv6(&v6_refs));
    let local = tauri::async_runtime::spawn_blocking(|| winsys::local_ipv6(rxvpn_core::xray::TUN_NAME)).await.unwrap_or_default();
    let v6 = V6Report { seen: seen.map(|ip| ip.to_string()), verdict: checks::ipv6_verdict(seen, &local, tun) };
    let side_text = |s: &Option<IpSide>| match s {
        None => "—".to_string(),
        Some(IpSide { info: Some(i), .. }) => format!("{} {} ({}, {})", i.ip, i.country_code, i.city, i.isp),
        Some(IpSide { error: Some(e), .. }) => tr!("ошибка: {e}"),
        Some(_) => "?".into(),
    };
    note_check(
        &st,
        trs!("мой IP"),
        tr!("через VPN: {}; напрямую: {}; IPv6: {:?}{}", side_text(&vpn), side_text(&direct), v6.verdict, if tun { " (TUN)" } else { "" }),
    );
    Ok(IpReport { connected: probe.is_some(), tun, vpn, direct, v6 })
}

#[derive(Serialize)]
struct DnsReport {
    leak: checks::DnsLeak,
    verdict: checks::Verdict,
    /// Как проверяли — чтобы было понятно, что именно показано.
    how: String,
    /// Какой сервис ответил (ipleak.net / bash.ws).
    service: String,
}

#[tauri::command]
async fn check_dns(app: AppHandle, st: State<'_, AppState>) -> Res<DnsReport> {
    let probe = probe_proxy(&st).map(|p| format!("socks5h://127.0.0.1:{p}"));
    let tun = probe.is_some() && st.tun_active.load(Ordering::SeqCst);
    let (http_port, blocked) = {
        let s = st.store.lock().unwrap();
        (s.settings.http_port, s.settings.route == RouteMode::Blocked)
    };
    let (trigger, how) = match (&probe, tun) {
        (None, _) => (checks::Trigger::System, trs!("без VPN, системный DNS Windows")),
        (Some(_), true) => (checks::Trigger::System, trs!("TUN: системный DNS Windows → rxvpn")),
        (Some(_), false) => (
            checks::Trigger::Proxy(format!("http://127.0.0.1:{http_port}")),
            trs!("как браузер через прокси rxvpn"),
        ),
    };
    // ipleak.net первым, bash.ws — запасной (его API с осени 2026 отдаёт страницу).
    let plain = svc("https://x").starts_with("http://");
    let list = vec![
        checks::LeakService::Ipleak(checks::IpleakApi {
            scheme: if plain { "http" } else { "https" }.into(),
            zone: "ipleak.net".into(),
            geo: svc("https://ipleak.net"),
        }),
        checks::LeakService::BashWs(checks::LeakApi { base: svc("https://bash.ws"), domain: "bash.ws".into() }),
    ];
    let r = checks::dns_leak_any(&list, probe.as_deref(), trigger).await;
    let (leak, service) = match r {
        Ok(x) => x,
        Err(e) => {
            log(&app, tr!("проверка DNS ({how}): {e}"));
            note_check(&st, "DNS", format!("{how}: {e}"));
            return Err(e);
        }
    };
    let verdict = checks::leak_verdict(&leak, probe.is_some(), blocked);
    st.dns_leak.store(probe.is_some() && verdict.level == "warn" && !leak.servers.is_empty(), Ordering::SeqCst);
    log(&app, tr!("проверка DNS ({how}, {service}): {}", verdict.text));
    note_check(&st, "DNS", tr!("{how}, {service}: {} — {}; серверов DNS: {}", verdict.level, verdict.text, leak.servers.len()));
    changed(&app);
    Ok(DnsReport { leak, verdict, how: how.into(), service })
}

#[derive(Serialize)]
struct SpeedReport {
    result: checks::SpeedResult,
    /// Через какой сервер мерили (None — без VPN).
    server: Option<String>,
}

#[tauri::command]
async fn speed_test(app: AppHandle, st: State<'_, AppState>) -> Res<SpeedReport> {
    if st.speed_busy.swap(true, Ordering::SeqCst) {
        return Err(trs!("Проверка скорости уже идёт").into());
    }
    let probe = probe_proxy(&st).map(|p| format!("socks5h://127.0.0.1:{p}"));
    let server = probe.as_ref().map(|_| match active_node(&st) {
        Some((_, name)) if st.store.lock().unwrap().is_auto() => tr!("Авто: {name}"),
        Some((_, name)) => name,
        None => "VPN".into(),
    });
    let d = checks::SpeedUrls::default();
    let urls = checks::SpeedUrls { down: svc(&d.down), down_fallback: d.down_fallback.map(|u| svc(&u)), up: d.up.map(|u| svc(&u)) };
    let app2 = app.clone();
    let r = checks::speedtest(probe.as_deref(), &urls, checks::SpeedLimits::default(), move |p| {
        let _ = app2.emit("speed-progress", p);
    })
    .await;
    st.speed_busy.store(false, Ordering::SeqCst);
    let result = r.map_err(|e| tr!("Скорость не измерилась: {e}")).inspect_err(|e| note_check(&st, trs!("скорость"), e.clone()))?;
    note_check(
        &st,
        trs!("скорость"),
        tr!("{}: ↓ {} Мбит/с, ↑ {} Мбит/с", if server.is_some() { trs!("через VPN") } else { trs!("без VPN") }, result.down_mbps, result.up_mbps.map(|u| u.to_string()).unwrap_or_else(|| "—".into())),
    );
    let up = result.up_mbps.map(|u| format!("{u}")).unwrap_or_else(|| "—".into());
    log(
        &app,
        tr!("скорость {}: ↓ {} Мбит/с, ↑ {up} Мбит/с, ушло {} МБ",
            server.as_deref().unwrap_or(trs!("без VPN")),
            result.down_mbps,
            (result.down_bytes + result.up_bytes) >> 20
        ),
    );
    Ok(SpeedReport { result, server })
}

// ---------------- бэкап и импорт из v2rayN ----------------

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Диалог выбора файла (системный). None — человек нажал «Отмена».
async fn pick_file(app: &AppHandle, title: &'static str, filter: (&'static str, &'static [&'static str]), save_as: Option<String>) -> Res<Option<PathBuf>> {
    use tauri_plugin_dialog::DialogExt;
    let app = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut d = app.dialog().file().set_title(title).add_filter(filter.0, filter.1);
        if let Some(w) = app.get_webview_window("main") {
            d = d.set_parent(&w);
        }
        let picked = match save_as {
            Some(name) => d.set_file_name(name).blocking_save_file(),
            None => d.blocking_pick_file(),
        };
        picked.map(|p| p.into_path().map_err(|e| e.to_string())).transpose()
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn export_backup(app: AppHandle, st: State<'_, AppState>) -> Res<Option<String>> {
    let now = now_unix();
    let name = format!("rxvpn-backup-{}.json", rxvpn_core::backup::date(now));
    let Some(path) = pick_file(&app, trs!("Сохранить бэкап rxvpn"), (trs!("Бэкап rxvpn"), &["json"]), Some(name)).await? else {
        return Ok(None);
    };
    let text = rxvpn_core::backup::export(&st.store.lock().unwrap(), env!("CARGO_PKG_VERSION"), now);
    std::fs::write(&path, text).map_err(|e| tr!("не записался файл: {e}"))?;
    log(&app, tr!("бэкап сохранён: {}", path.display()));
    Ok(Some(path.display().to_string()))
}

#[derive(Serialize)]
struct RestoreResult {
    view: View,
    notes: Vec<String>,
}

#[tauri::command]
async fn import_backup(app: AppHandle, st: State<'_, AppState>) -> Res<Option<RestoreResult>> {
    use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
    let Some(path) = pick_file(&app, trs!("Восстановить из бэкапа rxvpn"), (trs!("Бэкап rxvpn"), &["json"]), None).await? else {
        return Ok(None);
    };
    let len = std::fs::metadata(&path).map_err(|e| e.to_string())?.len();
    if len > rxvpn_core::backup::MAX_BYTES {
        return Err(trs!("Файл слишком большой для бэкапа rxvpn").into());
    }
    let raw = std::fs::read(&path).map_err(|e| tr!("не прочитать файл: {e}"))?;
    // Страховочная копия из data\backups может быть зашифрована (DPAPI).
    let raw = match rxvpn_core::store::unseal(&raw) {
        Some(r) => r?,
        None => raw,
    };
    let text = String::from_utf8(raw).map_err(|_| trs!("это не бэкап rxvpn").to_string())?;
    let restored = rxvpn_core::backup::parse(&text)?;
    let (n_srv, n_sub, n_rules) = (
        restored.store.servers.len(),
        restored.store.subscriptions.len(),
        restored.store.settings.rules.len(),
    );
    // Что в бэкапе меняет, куда и через кого идут сайты, — показываем явно:
    // чужой бэкап мог подменить DNS или вывести сайты из-под VPN.
    let rs = &restored.store.settings;
    let def = Settings::default();
    let mut risky = Vec::new();
    if rs.dns_remote != def.dns_remote || rs.dns_direct != def.dns_direct {
        risky.push(tr!("• DNS: через VPN — {}, напрямую — {}", rs.dns_remote, rs.dns_direct));
    }
    let real = |v: &[String]| v.iter().filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')).count();
    if real(&rs.hosts) > 0 {
        risky.push(tr!("• свои записи DNS (домен → IP): {} — например «{}»", real(&rs.hosts), rs.hosts[0].trim()));
    }
    if real(&rs.direct) > 0 {
        risky.push(tr!("• сайтов мимо VPN: {}", real(&rs.direct)));
    }
    if real(&rs.apps_direct) > 0 && rs.apps_mode == rxvpn_core::AppsMode::Except {
        risky.push(tr!("• программ мимо VPN: {}", real(&rs.apps_direct)));
    }
    if rs.net_profiles {
        let vpn = |a: &rxvpn_core::xray::NetAction| match a.vpn {
            rxvpn_core::xray::NetVpn::On => trs!("включать VPN"),
            rxvpn_core::xray::NetVpn::Off => trs!("ВЫКЛЮЧАТЬ VPN"),
            rxvpn_core::xray::NetVpn::Keep => trs!("VPN не трогать"),
        };
        risky.push(tr!("• профили по сети: в своих сетях ({}) — {}, в остальных — {}", rs.trusted_nets.len(), vpn(&rs.home), vpn(&rs.away)));
    }
    if !rs.site_servers.is_empty() {
        let names: Vec<&str> = rs.site_servers.iter().take(5).map(|r| r.name.as_str()).collect();
        risky.push(tr!("• сайтов через отдельный сервер: правил {} ({})", rs.site_servers.len(), names.join(", ")));
    }
    if rs.zapret || !rs.zapret_dir.is_empty() {
        risky.push(tr!("• zapret{}: папка «{}»",
            if rs.zapret { trs!(" (включён вместо VPN)") } else { "" },
            rs.zapret_dir
        ));
    }
    let risky = if risky.is_empty() {
        String::new()
    } else {
        tr!("\n\nПроверь, это точно твоё:\n{}", risky.join("\n"))
    };
    let question = tr!("В бэкапе: серверов — {n_srv}, подписок — {n_sub}, правил — {n_rules}.{risky}\n\n\
         Текущие сервера и настройки заменятся. Копия текущих сохранится в папке data\\backups."
    );
    let app2 = app.clone();
    let yes = tauri::async_runtime::spawn_blocking(move || {
        app2.dialog()
            .message(question)
            .title(trs!("Восстановить из бэкапа?"))
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(trs!("Заменить").into(), trs!("Отмена").into()))
            .blocking_show()
    })
    .await
    .map_err(|e| e.to_string())?;
    if !yes {
        return Ok(None);
    }

    // Страховка: текущее состояние — в data\backups.
    let now = now_unix();
    let dir = st.paths.data.join("backups");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let safety = dir.join(format!("before-restore-{}-{now}.json", rxvpn_core::backup::date(now)));
    let (copy, sealed) = {
        let s = st.store.lock().unwrap();
        (rxvpn_core::backup::export(&s, env!("CARGO_PKG_VERSION"), now), s.settings.encrypt_state && cfg!(windows))
    };
    let copy = if sealed { rxvpn_core::store::seal(copy.as_bytes())? } else { copy.into_bytes() };
    std::fs::write(&safety, copy).map_err(|e| tr!("не сохранилась страховочная копия: {e}"))?;

    stop_core(&st);
    kill_off(&app, &st, trs!("восстановление бэкапа"));
    stop_zapret(&st);
    let autostart = (restored.store.settings.autostart, st.store.lock().unwrap().settings.run_as_admin);
    let mut restored = restored;
    {
        // «Telegram без VPN» — как на этом компе: Telegram здесь настроен на свой
        // секрет и порт, а включать Cloudflare-путь чужим бэкапом нельзя.
        let cur = st.store.lock().unwrap().settings.clone();
        let r = &mut restored.store.settings;
        (r.tg_proxy, r.tg_port, r.tg_secret, r.tg_cf) = (cur.tg_proxy, cur.tg_port, cur.tg_secret, cur.tg_cf);
        // DNS без подмены меняет DNS Windows этого компа — как здесь, не как в бэкапе.
        (r.doh_sys, r.doh_provider, r.doh_url) = (cur.doh_sys, cur.doh_provider, cur.doh_url);
        // Просить права администратора при каждом запуске — тоже решение этого компа.
        r.run_as_admin = cur.run_as_admin;
        // Шифрование — ключом учётки этого компа.
        r.encrypt_state = cur.encrypt_state;
    }
    // Порты из бэкапа могли совпасть с портом Telegram-прокси этого компа — тогда
    // выключаем прокси (его настройки те же, перезапускать иначе незачем).
    let tg_conflict = validate_settings(&restored.store.settings).is_err() && restored.store.settings.tg_proxy;
    if tg_conflict {
        restored.store.settings.tg_proxy = false;
    }
    *st.store.lock().unwrap() = restored.store;
    persist(&st);
    if tg_conflict {
        let _ = tg_apply(&app).await;
        log(&app, trs!("Telegram без VPN выключен: порт прокси совпал с портом из бэкапа — поменяй порт и включи снова"));
    }
    if let Err(e) = apply_autostart(&st, autostart.0, autostart.1) {
        log(&app, tr!("автозапуск из бэкапа не применился: {e}"));
    }
    log(&app, tr!("восстановлено из {} (старое — в {})", path.display(), safety.display()));
    for n in &restored.notes {
        log(&app, n);
    }
    changed(&app);
    Ok(Some(RestoreResult { view: view(&st), notes: restored.notes }))
}

#[tauri::command]
async fn import_v2rayn(app: AppHandle, st: State<'_, AppState>) -> Res<Option<ImportResult>> {
    let Some(path) = pick_file(&app, trs!("База v2rayN: guiConfigs\\guiNDB.db"), (trs!("База v2rayN"), &["db"]), None).await? else {
        return Ok(None);
    };
    let found = tauri::async_runtime::spawn_blocking(move || rxvpn_core::v2rayn::read_db(&path))
        .await
        .map_err(|e| e.to_string())??;
    log(
        &app,
        tr!("v2rayN: подписок {}, своих серверов {}, пропущено {}", found.subs.len(), found.links.len(), found.skipped.len()),
    );
    let mut total = ImportResult::default();
    if !found.links.is_empty() {
        let r = st.store.lock().unwrap().import_links(&found.links.join("\n"));
        merge(&mut total, r);
    }
    let ids: Vec<String> = {
        let mut s = st.store.lock().unwrap();
        found.subs.iter().map(|(name, url)| s.add_subscription(name, url)).collect()
    };
    persist(&st);
    for id in ids {
        let r = refresh_sub(&app, &st, &id).await;
        merge(&mut total, r);
    }
    total.errors.extend(found.skipped.into_iter().map(|s| tr!("пропущено: {s}")));
    changed(&app);
    Ok(Some(total))
}

/// Автозапуск. С правами администратора (только установленная в Program Files) —
/// задачей планировщика: её без прав не подменить, и окна UAC при входе нет. Иначе —
/// ключом HKCU\…\Run (без прав: подменить его — ничего не получить).
/// Без прав задачу не создать — её создаст ближайший запуск с правами.
fn apply_autostart(st: &AppState, enabled: bool, as_admin: bool) -> Res<()> {
    let line = winsys::autostart_line().ok_or(trs!("не нашёл путь к rxvpn.exe"))?;
    if !cfg!(windows) {
        return winsys::set_autostart(enabled, &line).map_err(|e| tr!("автозапуск: {e}"));
    }
    if enabled && as_admin {
        // Задача запускает защищённую копию (её создаёт копия же, с правами).
        if winsys::is_admin() && st.paths.protected {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let args = format!("--data \"{}\" --autostart --relaunched", st.paths.data.display());
            rxvpn_core::autostart::install(&exe, &args, &st.paths.app_dir)?;
        }
        // Ключ Run больше не нужен — и опасен: его перепишет кто угодно.
        return winsys::set_autostart(false, &line).map_err(|e| tr!("автозапуск: {e}"));
    }
    if rxvpn_core::autostart::present() {
        if winsys::is_admin() {
            rxvpn_core::autostart::remove()?;
        } else {
            return Err(trs!("Автозапуск с правами администратора убрать может только rxvpn с правами администратора: перезапусти его от администратора и сохрани настройки ещё раз").into());
        }
    }
    winsys::set_autostart(enabled, &line).map_err(|e| tr!("автозапуск: {e}"))
}

/// Язык: "" — как в Windows, "ru", "en". Действует сразу: трей перестраивается,
/// новые сообщения и лог — на новом языке (уже написанное не переписывается).
#[tauri::command]
async fn set_lang(app: AppHandle, st: State<'_, AppState>, lang: String) -> Res<View> {
    let lang = rxvpn_core::i18n::sanitize(&lang);
    st.store.lock().unwrap().settings.lang = lang.clone();
    persist(&st);
    rxvpn_core::i18n::set_lang(rxvpn_core::i18n::resolve(&lang));
    refresh_tray(&app);
    Ok(view(&st))
}

#[tauri::command]
async fn save_settings(app: AppHandle, st: State<'_, AppState>, settings: Settings) -> Res<View> {
    let old = st.store.lock().unwrap().settings.clone();
    // «Telegram без VPN» меняется только своей кнопкой (tg_set), не общим сохранением.
    let mut settings = settings;
    (settings.tg_proxy, settings.tg_port, settings.tg_secret, settings.tg_cf) =
        (old.tg_proxy, old.tg_port, old.tg_secret.clone(), old.tg_cf);
    // «DNS без подмены» — тоже только своей кнопкой (doh_set): она меняет DNS Windows.
    (settings.doh_sys, settings.doh_provider, settings.doh_url) = (old.doh_sys, old.doh_provider.clone(), old.doh_url.clone());
    // Язык — только своей командой (set_lang): ей не нужен перезапуск Xray.
    settings.lang = old.lang.clone();
    {
        let s = st.store.lock().unwrap();
        bind_site_servers(&mut settings, &s.servers);
    }
    validate_settings(&settings)?;
    // Новая горячая клавиша: занята или не распознана — не сохраняем, остаётся прежняя.
    if settings.hotkey != old.hotkey {
        if let Err(e) = apply_hotkey(&app, &settings.hotkey) {
            let _ = apply_hotkey(&app, &old.hotkey);
            return Err(e);
        }
    }

    if settings.autostart != old.autostart || (settings.autostart && settings.run_as_admin != old.run_as_admin) {
        apply_autostart(&st, settings.autostart, settings.run_as_admin)?;
    }
    // Что надо перезапустить: Xray — при любой его настройке, zapret — только
    // при своих (папка, стратегия, игровой фильтр) или смене режима.
    let zkey = |s: &Settings| (s.zapret, s.zapret_dir.clone(), s.zapret_strategy.clone(), s.zapret_game_filter);
    let zap_changed = zkey(&old) != zkey(&settings);
    let xray_changed = {
        let strip = |s: &Settings| {
            let mut s = s.clone();
            (s.zapret_dir, s.zapret_strategy, s.zapret_game_filter, s.zapret_targets, s.zapret_autocheck) = Default::default();
            s.run_as_admin = false;
            s.encrypt_state = false;
            (s.net_profiles, s.trusted_nets, s.home, s.away) = Default::default();
            (s.wl_server, s.wl_server_sub, s.wl_auto) = Default::default();
            (s.hotkey, s.connect_apps) = Default::default(); // не про Xray — без переподключения
            serde_json::to_value(s).ok()
        };
        strip(&old) != strip(&settings)
    };
    let mode_changed = old.zapret != settings.zapret;
    let sealing = settings.encrypt_state && !old.encrypt_state;
    if settings.encrypt_state != old.encrypt_state {
        log(&app, if settings.encrypt_state {
            trs!("state.json и страховочные копии теперь зашифрованы ключом твоей учётки Windows")
        } else {
            trs!("шифрование state.json выключено")
        });
    }
    let kill_wanted = settings.tun && settings.kill_switch;
    st.store.lock().unwrap().settings = settings;
    persist(&st);
    if !kill_wanted {
        kill_off(&app, &st, trs!("выключен в настройках"));
    }
    if sealing {
        seal_backups(&st.paths.data.join("backups"));
    }
    let restart = (running(&st) && mode_changed)
        || (is_connected(&st) && xray_changed)
        || (zapret_running(&st) && zap_changed);
    if restart {
        let r = connect_any(&app, true).await;
        refresh_tray(&app);
        r?;
    }
    Ok(view(&st))
}

/// Запущенные программы — чтобы выбрать в «Программах», а не печатать имя.
#[tauri::command]
async fn list_processes() -> Res<Vec<String>> {
    tauri::async_runtime::spawn_blocking(winsys::list_processes)
        .await
        .map_err(|e| e.to_string())
}

/// Скачать свежие списки блокировок (через VPN, если подключены).
#[tauri::command]
async fn update_lists(app: AppHandle, st: State<'_, AppState>) -> Res<View> {
    if st.lists_busy.swap(true, Ordering::SeqCst) {
        return Err(trs!("Списки уже качаются").into());
    }
    log(&app, trs!("качаю списки блокировок (runetfreedom, ~90 МБ, из них оставлю ~3 МБ)…"));
    let proxy = probe_proxy(&st).map(|p| format!("socks5h://127.0.0.1:{p}"));
    let r = geodata::update(&st.paths.core, proxy.as_deref()).await;
    st.lists_busy.store(false, Ordering::SeqCst);
    let info = r?;
    log(&app, tr!("списки обновлены: {} сайтов, {} подсетей", info.domains, info.ips));
    // Xray читает списки при запуске — переподключаемся, если они используются.
    let blocked = st.store.lock().unwrap().settings.route == RouteMode::Blocked;
    if blocked && is_connected(&st) {
        let tun = st.tun_active.load(Ordering::SeqCst);
        let r = start_core_blocking(&app, tun).await;
        refresh_tray(&app);
        r?;
    }
    Ok(view(&st))
}

/// Показать пробное уведомление (проверить, что Windows их пропускает).
#[tauri::command]
async fn test_notification() -> Res<()> {
    notify::show("rxvpn", trs!("Уведомления работают 👍"));
    Ok(())
}

/// TUN без прав администратора не поднять: перезапускаемся с UAC и сразу подключаемся.
/// То же для zapret; `then = "zapret-test"` — после перезапуска сразу подбор стратегии.
#[tauri::command]
async fn relaunch_admin(app: AppHandle, st: State<'_, AppState>, then: Option<String>) -> Res<()> {
    let args = match then.as_deref() {
        Some("zapret-test") => "--zapret-test --relaunched",
        // Просто перезапуск (включили «Запускать с правами администратора»): что было — то и будет.
        Some("restart") if !running(&st) => "--relaunched",
        _ => "--connect --relaunched",
    };
    elevate(&st.paths, args)?;
    stop_core(&st);
    stop_zapret(&st);
    app.exit(0);
    Ok(())
}

/// Окно получило ответ `get_view` и нарисовало главную. В обычном запуске — ничего.
/// В автопроверке выпуска (`--smoke`) — отметка в своей временной папке данных и выход:
/// dev/release.py ждёт её и без неё не пакует и не подписывает (0.18.0 вышла с окном,
/// которое не дождалось `get_view`).
#[tauri::command]
fn smoke_ready(st: State<'_, AppState>, keys: u32, welcome: bool) {
    if !st.smoke {
        return;
    }
    let body = format!("{{\"version\":\"{}\",\"keys\":{keys},\"welcome\":{welcome}}}", env!("CARGO_PKG_VERSION"));
    let _ = std::fs::write(st.paths.data.join("smoke.json"), body);
    std::process::exit(0);
}

#[tauri::command]
fn take_startup_action(st: State<'_, AppState>) -> Option<String> {
    st.startup_action.lock().unwrap().take()
}

#[tauri::command]
async fn download_core(app: AppHandle, st: State<'_, AppState>) -> Res<View> {
    if st.paths.protected && !winsys::is_admin() {
        // Ядро в Program Files: обновить его может только rxvpn с правами администратора.
        return Err(trs!("Ядро лежит в папке программы (Program Files) — обновить его можно только с правами администратора: перезапусти rxvpn от администратора и нажми ещё раз").into());
    }
    let connected = is_connected(&st);
    let tun = st.tun_active.load(Ordering::SeqCst);
    log(&app, tr!("качаю {} с GitHub…", net::xray_asset_name()));
    // Если VPN уже работает — качаем через него (вдруг GitHub режут).
    let zip = net::fetch_core_zip(probe_proxy(&st)).await?;
    if connected {
        // На Windows нельзя перезаписать запущенный xray.exe — сначала гасим.
        stop_core(&st);
    }
    let files = net::install_core_zip(&zip, &st.paths.core)?;
    if let Err(e) = runner::sync_assets(&st.paths.core) {
        log(&app, tr!("списки рядом с ядром не скопировались: {e}"));
    }
    log(&app, tr!("ядро обновлено: {}", files.join(", ")));
    if connected {
        let r = start_core_blocking(&app, tun).await;
        refresh_tray(&app);
        r?;
    }
    Ok(view(&st))
}

/// Скачать sing-box (только для серверов TUIC: в Xray этого протокола нет).
/// Одна проверенная версия — хеши архива и exe вшиты в rxvpn.
#[tauri::command]
async fn download_singbox(app: AppHandle, st: State<'_, AppState>) -> Res<View> {
    if st.paths.protected && !winsys::is_admin() {
        return Err(trs!("Ядро лежит в папке программы (Program Files) — обновить его можно только с правами администратора: перезапусти rxvpn от администратора и нажми ещё раз").into());
    }
    log(&app, tr!("качаю sing-box {} с GitHub (~33 МБ)…", rxvpn_core::singbox::VERSION));
    let zip = rxvpn_core::singbox::fetch_zip(probe_proxy(&st)).await?;
    // Запущенный sing-box.exe не перезаписать — если сейчас TUIC, переподключимся.
    let connected = is_connected(&st);
    let tun = st.tun_active.load(Ordering::SeqCst);
    if connected && rxvpn_core::singbox::installed(&st.paths.core) {
        stop_core(&st);
    }
    let r = rxvpn_core::singbox::install_zip(&zip, &st.paths.core);
    if connected && !is_connected(&st) {
        let rr = start_core_blocking(&app, tun).await;
        refresh_tray(&app);
        rr?;
    }
    r?;
    log(&app, tr!("sing-box {} установлен — серверы TUIC работают", rxvpn_core::singbox::VERSION));
    Ok(view(&st))
}

#[tauri::command]
async fn open_core_dir(st: State<'_, AppState>) -> Res<()> {
    let dir = &st.paths.core;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    let opener = winsys::windows_exe("explorer.exe").ok_or(trs!("не нашёл папку Windows"))?;
    #[cfg(target_os = "macos")]
    let opener = PathBuf::from("/usr/bin/open");
    #[cfg(all(not(windows), not(target_os = "macos")))]
    let opener = PathBuf::from("xdg-open");
    let mut cmd = std::process::Command::new(opener);
    cmd.arg(dir);
    cmd.spawn().map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn export_config(st: State<'_, AppState>, id: String) -> Res<String> {
    let s = st.store.lock().unwrap();
    let node = s
        .servers
        .iter()
        .find(|n| n.id == id)
        .ok_or(trs!("сервер не найден"))?;
    Ok(serde_json::to_string_pretty(&build_config(node, &s.settings)).unwrap())
}

#[tauri::command]
async fn read_clipboard() -> Res<String> {
    arboard::Clipboard::new()
        .and_then(|mut c| c.get_text())
        .map_err(|e| tr!("буфер обмена: {e}"))
}

#[tauri::command]
async fn copy_link(st: State<'_, AppState>, id: String) -> Res<()> {
    let link = st
        .store
        .lock()
        .unwrap()
        .servers
        .iter()
        .find(|n| n.id == id)
        .map(|n| n.link.clone())
        .ok_or(trs!("сервер не найден"))?;
    if rxvpn_core::warp::is_warp(&id) {
        return Err(no_warp_link().into());
    }
    arboard::Clipboard::new()
        .and_then(|mut c| c.set_text(link))
        .map_err(|e| tr!("буфер обмена: {e}"))
}

fn no_warp_link() -> &'static str {
    trs!("У WARP нет ссылки для телефона: его ключ и цепочка через сервер живут только в rxvpn")
}

/// QR сервера — отсканировать камерой в v2rayNG / v2RayTun / Happ на телефоне.
#[tauri::command]
async fn qr_server(st: State<'_, AppState>, id: String) -> Res<String> {
    let link = st
        .store
        .lock()
        .unwrap()
        .servers
        .iter()
        .find(|n| n.id == id)
        .map(|n| n.link.clone())
        .ok_or(trs!("сервер не найден"))?;
    if rxvpn_core::warp::is_warp(&id) {
        return Err(no_warp_link().into());
    }
    if link.starts_with('{') || link.starts_with('[') {
        return Err(trs!("Этот сервер пришёл из JSON-подписки — короткой ссылки у него нет. \
                    Перенеси на телефон всю подписку: кнопка QR у группы")
            .into());
    }
    qr::svg(&link)
}

/// QR ссылки на подписку — телефон сам скачает все сервера и будет их обновлять.
#[tauri::command]
async fn qr_subscription(st: State<'_, AppState>, id: String) -> Res<String> {
    let url = st
        .store
        .lock()
        .unwrap()
        .subscriptions
        .iter()
        .find(|s| s.id == id)
        .map(|s| s.url.clone())
        .ok_or(trs!("подписка не найдена"))?;
    qr::svg(&url)
}

/// Если ядро положено в установщик (папка core рядом с программой), а в
/// рабочей папке его ещё нет — копируем. Дальше «Скачать / обновить»
/// обновляет уже копию в папке данных.
fn seed_bundled_core(app: &tauri::App) {
    let st = app.state::<AppState>();
    if runner::xray_path(&st.paths.core).exists() {
        // Ядро от прошлых версий — запомнить его хеши, пока его никто не трогал.
        if !st.paths.core.join(runner::CORE_HASHES).exists() {
            let _ = runner::record_core(&st.paths.core);
        }
        return;
    }
    let Ok(res) = app.path().resource_dir() else { return };
    let src = res.join("core");
    if !runner::xray_path(&src).exists() {
        return;
    }
    if std::fs::create_dir_all(&st.paths.core).is_err() {
        return;
    }
    if let Ok(entries) = std::fs::read_dir(&src) {
        for e in entries.flatten() {
            if e.path().is_file() {
                let _ = std::fs::copy(e.path(), st.paths.core.join(e.file_name()));
            }
        }
    }
    let _ = runner::record_core(&st.paths.core);
}

/// Подписки, которые пора обновить, — раз в 10 минут проверяем, не устарели ли.
/// Подписка кончается (≤3 дней) или трафика ≤10% — уведомление, не чаще раза в сутки
/// на подписку (в рамках одного запуска).
fn warn_sub_usage(app: &AppHandle) {
    let st = app.state::<AppState>();
    let today = now() / 86400;
    let warn: Vec<(String, String, String)> = {
        let s = st.store.lock().unwrap();
        s.subscriptions
            .iter()
            .filter_map(|x| x.usage.and_then(|u| u.warning(now())).map(|w| (x.id.clone(), x.name.clone(), w)))
            .collect()
    };
    for (id, name, w) in warn {
        let fresh = st.sub_warned.lock().unwrap().insert(id, today) != Some(today);
        if fresh {
            notify(app, tr!("Подписка «{name}»"), tr!("{w} — продли, чтобы VPN не отключился"));
        }
    }
}

// ---------------- профили по сети ----------------

#[derive(Serialize)]
struct NetNow {
    /// Wi-Fi: имя и адрес точки. None — не Wi-Fi или Windows не даёт имя.
    wifi: Option<(String, String)>,
    online: bool,
    trusted: bool,
}

fn net_now_blocking(st: &AppState) -> NetNow {
    let wifi = winsys::current_wifi();
    let online = winsys::best_interface().is_some();
    let trusted = rxvpn_core::xray::net_trusted(&st.store.lock().unwrap().settings.trusted_nets, wifi.as_ref());
    NetNow { wifi, online, trusted }
}

#[tauri::command]
async fn net_now(app: AppHandle) -> Res<NetNow> {
    tauri::async_runtime::spawn_blocking(move || net_now_blocking(app.state::<AppState>().inner()))
        .await
        .map_err(|e| e.to_string())
}

/// Сменилась сеть — выполнить профиль: режим маршрутов и включить/выключить VPN.
/// Только при смене сети: что человек переключил руками, держится до следующей.
async fn apply_net_action(app: &AppHandle, act: rxvpn_core::xray::NetAction, place: &str) {
    use rxvpn_core::xray::NetVpn;
    let st = app.state::<AppState>();
    let new_route = {
        let mut s = st.store.lock().unwrap();
        match act.route {
            Some(r) if s.settings.route != r => {
                s.settings.route = r;
                Some(r)
            }
            _ => None,
        }
    };
    if let Some(r) = new_route {
        persist(&st);
        let name = match r {
            RouteMode::BypassRu => trs!("Обход РФ"),
            RouteMode::Blocked => trs!("Только блок."),
            RouteMode::Global => trs!("Всё через VPN"),
        };
        log(app, tr!("сеть: {place} — режим «{name}»"));
    }
    let r = match act.vpn {
        NetVpn::On if !running(&st) => {
            log(app, tr!("сеть: {place} — подключаю"));
            connect_any(app, true).await
        }
        NetVpn::Off if running(&st) => {
            stop_core(&st);
            kill_off(app, &st, trs!("профиль сети: VPN не нужен"));
            stop_zapret(&st);
            reset_auto(&st);
            log(app, tr!("сеть: {place} — отключил"));
            Ok(())
        }
        _ if new_route.is_some() && is_connected(&st) => {
            let tun = st.tun_active.load(Ordering::SeqCst);
            start_core_blocking(app, tun).await
        }
        _ => Ok(()),
    };
    if let Err(e) = r {
        log(app, tr!("сеть: {place} — не вышло: {e}"));
    }
    changed(app);
}

/// Раз в 5 секунд смотрим, в какой сети комп (Wi-Fi: имя и точка; иначе — «другая»).
fn spawn_net_watch(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut last: Option<String> = None;
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let (on, home, away) = {
                let st = app.state::<AppState>();
                let s = st.store.lock().unwrap();
                (s.settings.net_profiles, s.settings.home, s.settings.away)
            };
            if !on {
                last = None;
                continue;
            }
            let a = app.clone();
            let Ok(now) = tauri::async_runtime::spawn_blocking(move || net_now_blocking(a.state::<AppState>().inner())).await else {
                continue;
            };
            if !now.online {
                continue; // без сети ничего не делаем; вернулись в ту же — не повторяем
            }
            let key = match &now.wifi {
                Some((s, b)) => format!("wifi:{s}:{b}"),
                None => "other".to_string(),
            };
            if last.as_deref() == Some(key.as_str()) {
                continue;
            }
            last = Some(key);
            let place = match (&now.wifi, now.trusted) {
                (Some((s, _)), true) => tr!("своя сеть «{s}»"),
                (Some((s, _)), false) => tr!("чужая сеть «{s}»"),
                (None, _) => trs!("не Wi-Fi (кабель или телефон)").to_string(),
            };
            apply_net_action(&app, if now.trusted { home } else { away }, &place).await;
        }
    });
}

fn spawn_sub_updater(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        // Дать подключиться при старте: подписки тогда скачаются через VPN.
        tokio::time::sleep(Duration::from_secs(20)).await;
        warn_sub_usage(&app);
        loop {
            let due: Vec<String> = {
                let st = app.state::<AppState>();
                let s = st.store.lock().unwrap();
                let hours = s.settings.sub_update_hours as i64;
                if hours == 0 {
                    Vec::new()
                } else {
                    s.subscriptions
                        .iter()
                        .filter(|x| x.updated_at.is_none_or(|t| now() - t >= hours * 3600))
                        .map(|x| x.id.clone())
                        .collect()
                }
            };
            for id in due {
                let st = app.state::<AppState>();
                let r = refresh_sub(&app, st.inner(), &id).await;
                for e in &r.errors {
                    log(&app, tr!("автообновление: {e}"));
                }
                if r.added > 0 {
                    let _ = app.emit("state-changed", ());
                }
            }
            // Списки блокировок: обновляем, только если ими пользуются.
            let (blocked, days) = {
                let st = app.state::<AppState>();
                let s = st.store.lock().unwrap();
                (s.settings.route == RouteMode::Blocked, s.settings.lists_update_days)
            };
            let st = app.state::<AppState>();
            if blocked && geodata::stale(&st.paths.core, days) && !st.lists_busy.swap(true, Ordering::SeqCst) {
                let proxy = probe_proxy(&st).map(|p| format!("socks5h://127.0.0.1:{p}"));
                let r = geodata::update(&st.paths.core, proxy.as_deref()).await;
                st.lists_busy.store(false, Ordering::SeqCst);
                match r {
                    Ok(i) => {
                        log(&app, tr!("списки блокировок обновлены: {} сайтов (применятся при следующем подключении)", i.domains));
                        let _ = app.emit("state-changed", ());
                    }
                    Err(e) => log(&app, tr!("списки блокировок не обновились: {e}")),
                }
            }
            tokio::time::sleep(Duration::from_secs(600)).await;
        }
    });
}

/// Отладка запасного профиля окна: файл `test-bad-webview` рядом с exe. Только
/// без прав (с правами rxvpn полез бы обновлять защищённую копию).
fn test_bad_webview() -> bool {
    cfg!(debug_assertions)
        && !winsys::is_admin()
        && std::env::current_exe().is_ok_and(|e| e.with_file_name("test-bad-webview").exists())
}

/// Папка профиля, которую получило главное окно (мини-окно берёт ту же).
static WEBVIEW_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Профиль окна (WebView2): кэш, Code Cache, Local Storage, Preferences. Окно с правами
/// администратора не должно читать его из папки data — туда пишет любая программа без
/// прав, а подложенный профиль (кэш байткода V8, настройки) работал бы в окне, у которого
/// есть все команды rxvpn. Поэтому копия с правами держит профиль у себя в Program Files
/// (пишет туда только администратор), без прав — как раньше, в data.
fn webview_dir(paths: &Paths, admin: bool) -> PathBuf {
    if paths.protected && admin {
        paths.app_dir.join("webview")
    } else {
        paths.data.join("webview")
    }
}

/// Попросить права администратора. С правами rxvpn работает только из защищённой копии
/// в Program Files: готова — окно UAC сразу для неё (в окне виден путь Program Files);
/// нет или другая — для себя: такой запуск разложит копию (protect_and_launch).
fn elevate(paths: &Paths, args: &str) -> Res<()> {
    let with_data = format!("--data \"{}\" {args}", paths.data.display());
    if paths.protected {
        return winsys::relaunch_as_admin(&with_data);
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if let Some(pf) = rxvpn_core::protect::protected_dir() {
        if rxvpn_core::protect::state(&pf, &exe) == rxvpn_core::protect::State::Ready {
            return winsys::run_as_admin_exe(&pf.join(rxvpn_core::protect::EXE), &with_data);
        }
    }
    winsys::relaunch_as_admin(args)
}

/// Запущены с правами не из копии: разложить (обновить) копию и запустить её с теми же
/// аргументами. Копия другая (rxvpn.exe здесь новее — или подменён) — спросить.
fn protect_and_launch(exe: &Path, paths: &Paths, args: &[String]) -> Res<()> {
    use rxvpn_core::protect::{self, State};
    let pf = protect::protected_dir().ok_or(trs!("не нашёл папку Program Files"))?;
    std::fs::create_dir_all(&paths.data).map_err(|e| e.to_string())?;
    let st = protect::state(&pf, exe);
    if st == State::Different
        && !winsys::confirm_box(
            "rxvpn",
            &tr!("rxvpn.exe в этой папке не такой, как в защищённой копии ({}).\n\n\
                 Если ты сам обновил rxvpn — нажми «Да», копия обновится.\n\
                 Если не обновлял — нажми «Нет»: файл могла подменить чужая программа.", pf.display()),
        )
    {
        return Ok(());
    }
    if st != State::Ready {
        let data_core = paths.data.join("core");
        let zip = if protect::needs_core_download(&data_core, protect::KNOWN) {
            // GitHub иногда отвечает 502/504 — пробуем несколько раз.
            let mut got = Err(String::new());
            for i in 0..3 {
                if i > 0 {
                    std::thread::sleep(Duration::from_secs(3));
                }
                got = tauri::async_runtime::block_on(net::fetch_core_zip(None));
                if got.is_ok() {
                    break;
                }
            }
            Some(got.map_err(|e| tr!("защищённая копия: ядро не скачалось с GitHub — {e}"))?)
        } else {
            None
        };
        protect::deploy(exe, &paths.app_dir, &data_core, &pf, protect::KNOWN, zip.as_deref())
            .map_err(|e| tr!("защищённая копия rxvpn в {} не разложилась: {e}", pf.display()))?;
    }
    let mut cmd = std::process::Command::new(pf.join(protect::EXE));
    let mut skip = false;
    for a in args.iter().skip(1) {
        if std::mem::take(&mut skip) {
            continue;
        }
        if a == "--data" {
            skip = true;
            continue;
        }
        cmd.arg(a);
    }
    cmd.arg("--data").arg(&paths.data);
    if !args.iter().any(|a| a == "--relaunched") {
        cmd.arg("--relaunched"); // копия подождёт, пока этот процесс отпустит замок
    }
    cmd.spawn().map_err(|e| tr!("защищённая копия не запустилась: {e}"))?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    let has = |a: &str| args.iter().any(|x| x == a);
    let from_autostart = has("--autostart");
    let mut connect_now = has("--connect");
    let relaunched = has("--relaunched");
    let zapret_test_now = has("--zapret-test");
    // Автопроверка выпуска (dev/release.py): собранный exe запускается рядом с работающей
    // rxvpn на пустой папке данных, окно зовёт настоящий get_view, рисует главную и
    // сообщает об этом (`smoke_ready`) — программа пишет отметку и выходит. В этом режиме
    // rxvpn не трогает ничего за пределами своей папки: ни замок второго запуска, ни реестр,
    // ни системный прокси, ни kill switch, ни сеть. С правами администратора не работает.
    let smoke = has("--smoke");
    if smoke && winsys::is_admin() {
        return;
    }

    // От администратора окно (WebView2) не должно слушаться переменных окружения
    // пользователя: их может поменять любая программа (HKCU\Environment), а
    // WEBVIEW2_BROWSER_EXECUTABLE_FOLDER / WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS
    // запустили бы чужой «браузер» или ключи командной строки с правами админа.
    if winsys::is_admin() {
        let bad: Vec<std::ffi::OsString> = std::env::vars_os()
            .map(|(k, _)| k)
            .filter(|k| k.to_string_lossy().to_ascii_uppercase().starts_with("WEBVIEW2_"))
            .collect();
        for k in bad {
            std::env::remove_var(k); // потоков ещё нет
        }
    }

    // Вторая копия не нужна: просим первую показать окно и выходим.
    let test_alone = test_bad_webview();
    let instance = if smoke { Some(winsys::InstanceGuard::dummy()) } else { winsys::acquire_instance(relaunched).or_else(|| test_alone.then(winsys::InstanceGuard::dummy)) };
    let Some(_instance) = instance else {
        handoff_to_running(if from_autostart { "noop" } else { "show" });
        return;
    };
    // Порт — только канал «покажи окно» для следующих запусков.
    let lock = if smoke { None } else { TcpListener::bind(("127.0.0.1", LOCK_PORT)).ok() };

    // Установленная версия хранит данные в %LOCALAPPDATA%\dev.rxmv.rxvpn
    // (отдельно от программы: переустановка их не трогает).
    let installed_base = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("dev.rxmv.rxvpn");
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rxvpn.exe"));
    let app_dir = exe.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("."));
    // Защищённая копия в Program Files (см. core/src/protect.rs): данные — в папке
    // портативной, её путь приходит аргументом --data.
    let protected = rxvpn_core::protect::is_protected(&app_dir);
    let data_arg = args
        .iter()
        .position(|a| a == "--data")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .filter(|p| rxvpn_core::protect::valid_data_dir(p));
    // Копию запустили без --data (старая кнопка «Обновить», ярлык на Program Files) —
    // берём папку с прошлого запуска; она записана в Program Files, куда пишет только
    // администратор. С --data — запоминаем.
    let data_arg = if protected { rxvpn_core::protect::remember_data(&app_dir, data_arg, winsys::is_admin()) } else { data_arg };
    // Портативная: если рядом с rxvpn.exe есть папка data — всё живёт там.
    let portable_base = if protected { data_arg.clone() } else { Some(app_dir.join("data")).filter(|d| d.is_dir()) };
    let portable = portable_base.is_some();
    let base = portable_base.unwrap_or_else(|| installed_base.clone());
    // Автопроверка — только на своей пустой папке data рядом с exe: к настоящим серверам
    // и настройкам вторая копия без замка не подходит.
    if smoke && (!portable || protected || base.join("state.json").exists()) {
        return;
    }

    // Первый запуск портативной после установленной — переносим сервера и настройки.
    if portable && !protected && !smoke && !base.join("state.json").exists() {
        let old = installed_base.join("state.json");
        if old.exists() {
            let _ = std::fs::copy(&old, base.join("state.json"));
        }
    }

    let paths = Paths {
        store: base.join("state.json"),
        // Копия: исполняемое — в Program Files, списки (geo*.dat) — в data\core портативной.
        core: if protected { app_dir.join("core") } else { base.join("core") },
        zapret_bin: if protected { app_dir.join("zapret") } else { base.join("zapret") },
        data: base,
        portable,
        protected,
        app_dir,
    };
    if paths.protected {
        runner::set_asset_dir(Some(paths.data.join("core")));
    }
    // С правами администратора rxvpn работает только из защищённой копии: портативную
    // папку может переписать любая программа. Запустили с правами отсюда — кладём
    // (или обновляем) копию и запускаем её, сами выходим.
    if winsys::is_admin() && !paths.protected {
        rxvpn_core::i18n::set_lang(rxvpn_core::i18n::system_lang());
        if let Err(e) = protect_and_launch(&exe, &paths, &args) {
            winsys::message_box("rxvpn", &e);
        }
        return;
    }
    // Копия с правами: папка данных доступна на запись программам без прав. Закрываем её
    // (и папки выше, и подпапки) от подмены ссылкой до первой работы с файлами — иначе rxvpn
    // с правами администратора записал бы или удалил файл там, куда покажет ссылка
    // (core/src/protect.rs, `lock_data`). Замок держится до выхода.
    let _data_lock = if paths.protected && winsys::is_admin() {
        rxvpn_core::i18n::set_lang(rxvpn_core::i18n::system_lang());
        let _ = std::fs::create_dir_all(&paths.data);
        match rxvpn_core::protect::lock_data(&paths.data, rxvpn_core::protect::DATA_SUBDIRS) {
            Ok(l) => Some(l),
            Err(e) => {
                winsys::message_box("rxvpn", &tr!("Папка данных rxvpn не прошла проверку — с правами администратора не запускаюсь.\n\n{e}"));
                return;
            }
        }
    } else {
        // До 0.6 конфиги Xray с паролями серверов на время запуска писались в data —
        // после падения они могли остаться. Теперь конфиг идёт через stdin. (Копия с
        // правами появилась в 0.11 — у неё таких файлов не бывает, и удалять по именам
        // в папке, куда пишут без прав, ей незачем.)
        for f in ["config.json", "test.json", "check.json", "svc.json"] {
            let _ = std::fs::remove_file(paths.data.join(f));
        }
        None
    };
    // Язык: до чтения настроек — как в Windows (сообщения о битом state.json), потом — из настроек.
    rxvpn_core::i18n::set_lang(rxvpn_core::i18n::system_lang());
    let (mut store, state_locked) = Store::load_ex(&paths.store);
    rxvpn_core::i18n::set_lang(rxvpn_core::i18n::resolve(&store.settings.lang));
    // Копия с правами: настройки, действующие на весь комп, сверяем со своим снимком
    // в Program Files — state.json в data мог поменять кто угодно без прав (core/src/guard.rs).
    if paths.protected && winsys::is_admin() && !state_locked {
        // На вопрос про чужие сервера ответили «Нет» — и по --connect сами не подключаемся.
        if guard_settings(&paths, &mut store) {
            connect_now = false;
        }
    }
    let stats = rxvpn_core::stats::Stats::load(&paths.data.join("stats.json"));

    // «Запускать с правами администратора»: копия без прав сразу просит их (окно
    // UAC — и при входе в Windows) и закрывается; новая ждёт, пока эта отпустит
    // замок. Отказали в окне — работаем без прав: VPN «Браузер» и Telegram можно,
    // zapret и «Все программы» — нет.
    let mut elevate_refused: Option<String> = None;
    // При входе в Windows окна UAC не бывает: автозапуск с правами — задача планировщика
    // (её не подменить без прав). Пришли без прав из старого ключа Run — работаем без прав
    // и не просим их: окно UAC при входе человек должен считать подозрительным.
    let autostart_needs_fix = from_autostart && store.settings.run_as_admin && !winsys::is_admin();
    if cfg!(windows) && store.settings.run_as_admin && !winsys::is_admin() && !relaunched && !from_autostart && !test_alone {
        let mut a = vec!["--relaunched"];
        if connect_now {
            a.push("--connect");
        }
        match elevate(&paths, &a.join(" ")) {
            Ok(()) => return,
            Err(e) => elevate_refused = Some(e),
        }
    }
    if !smoke {
        notify::init(&paths.data, APP_ICON);
        // Прошлый запуск мог упасть и оставить системный прокси на наш порт.
        sysproxy::cleanup_stale(&format!("127.0.0.1:{}", store.settings.http_port));
    }
    // …и системный DNS на наш DoH: вернёт spawn_doh_watch (нет прав — подскажет «Всё ли в порядке»).
    let sysdns_pending_at_start = rxvpn_core::sysdns::pending(&paths.data);
    // Паника — вернуть DNS Windows до того, как процесс умрёт.
    {
        let data = paths.data.clone();
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            dohui::doh_restore_blocking(&data);
            prev(info);
        }));
    }

    let state = AppState {
        paths,
        smoke,
        store: Mutex::new(store),
        proc: Mutex::new(None),
        gen: AtomicU64::new(0),
        proxy_set: Mutex::new(None),
        run: Mutex::new(None),
        active_tag: Mutex::new(None),
        ping: AtomicU64::new(0),
        last_test: Mutex::new(HashMap::new()),
        tun_active: AtomicBool::new(false),
        testing: AtomicBool::new(false),
        speed_all_busy: AtomicBool::new(false),
        speed_all_cancel: Arc::new(AtomicBool::new(false)),
        lists_busy: AtomicBool::new(false),
        speed_busy: AtomicBool::new(false),
        auto_prefer: Mutex::new(None),
        auto_bad: Mutex::new(HashMap::new()),
        auto_down: AtomicBool::new(false),
        log_buf: Mutex::new(Default::default()),
        checks: Mutex::new(Vec::new()),
        doh: tokio::sync::Mutex::new(None),
        doh_info: Mutex::new(None),
        doh_idle_since: Mutex::new(None),
        doh_fail_until: std::sync::atomic::AtomicI64::new(0),
        doh_stuck: AtomicBool::new(sysdns_pending_at_start),
        last_report: Mutex::new(None),
        zapret: Mutex::new(None),
        zgen: AtomicU64::new(0),
        pause: Mutex::new(None),
        pause_gen: AtomicU64::new(0),
        hybrid: Mutex::new(None),
        tg: tokio::sync::Mutex::new(None),
        tg_info: Mutex::new(None),
        diag_busy: AtomicBool::new(false),
        svc_busy: AtomicBool::new(false),
        vps_busy: AtomicBool::new(false),
        tor: Mutex::new(None),
        wl_prev: Mutex::new(None),
        wl_busy: AtomicBool::new(false),
        zapret_broken: AtomicBool::new(false),
        kill: Mutex::new(None),
        fallback_tried: Mutex::new(Default::default()),
        app_traffic: Mutex::new(None),
        dns_leak: AtomicBool::new(false),
        ipv6_off: AtomicBool::new(false),
        stats: Mutex::new(stats),
        stats_dirty: AtomicBool::new(false),
        state_locked: AtomicBool::new(state_locked),
        phys_iface: Mutex::new(None),
        zop: tokio::sync::Mutex::new(()),
        ztesting: AtomicBool::new(false),
        zcancel: Arc::new(AtomicBool::new(false)),
        zresults: Mutex::new(Vec::new()),
        zquiet_until: std::sync::atomic::AtomicI64::new(0),
        core_op: Mutex::new(()),
        startup_action: Mutex::new(zapret_test_now.then(|| "zapret-test".to_string())),
        sub_warned: Mutex::new(HashMap::new()),
    };

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, _shortcut, ev| {
                    // Зарегистрирована одна клавиша — «Подключить / Отключить», как в трее.
                    if ev.state() == tauri_plugin_global_shortcut::ShortcutState::Pressed {
                        on_tray_menu(app, "toggle");
                    }
                })
                .build(),
        )
        .manage(state)
        .setup(move |app| {
            seed_bundled_core(app);
            if let Err(e) = runner::sync_assets(&app.state::<AppState>().paths.core) {
                log(app.handle(), tr!("списки рядом с ядром не скопировались: {e}"));
            }
            // Окно создаём сами (в tauri.conf.json у него "create": false):
            // в портативном режиме кэш WebView2 кладём в папку data, а при
            // автозапуске окно не показываем — программа сидит в трее.
            let cfg = app
                .config()
                .app
                .windows
                .iter()
                .find(|w| w.label == "main")
                .cloned()
                .ok_or(trs!("нет окна main в tauri.conf.json"))?;
            let (portable, protected, data, webview_dir, autostart, as_admin, auto_connect) = {
                let st = app.state::<AppState>();
                let s = st.store.lock().unwrap();
                (st.paths.portable, st.paths.protected, st.paths.data.clone(), webview_dir(&st.paths, winsys::is_admin()), s.settings.autostart, s.settings.run_as_admin, s.settings.auto_connect)
            };
            let admin_copy = protected && winsys::is_admin();
            // Метка «окно с профилем копии уже не открывалось» (у друга антивирус не пускал
            // msedgewebview2 в Program Files, хотя сам rxvpn писать туда мог). Подложить её
            // может кто угодно, но вреда нет: запасная папка не хуже основной.
            let marker = data.join("webview-fallback");
            let fallback = || if admin_copy { rxvpn_core::protect::fallback_webview_dir() } else { None };
            let mut first = None;
            if portable {
                first = if admin_copy && marker.exists() {
                    fallback()
                } else if rxvpn_core::protect::writable(&webview_dir) {
                    Some(webview_dir.clone())
                } else {
                    log(app.handle(), tr!("в {} писать нельзя (антивирус?) — профиль окна во временной папке", webview_dir.display()));
                    fallback()
                };
            }
            #[cfg(debug_assertions)]
            if test_bad_webview() {
                // Проверка запасного пути: файл вместо папки — WebView2 не создастся.
                first = std::env::current_exe().ok();
            }
            let make = |dir: Option<PathBuf>| {
                let mut b = tauri::WebviewWindowBuilder::from_config(app.handle(), &cfg)?.visible(!from_autostart);
                if let Some(d) = dir {
                    b = b.data_directory(d);
                }
                b.build()
            };
            match make(first.clone()) {
                Ok(_) => {
                    if let Some(d) = first {
                        let _ = WEBVIEW_DIR.set(d);
                    }
                }
                Err(e) if portable => {
                    log(app.handle(), tr!("окно не открылось с профилем {}: {e} — пробую запасную папку", first.as_deref().map(|p| p.display().to_string()).unwrap_or_default()));
                    let _ = std::fs::write(&marker, b"");
                    let fb = fallback();
                    make(fb.clone())?;
                    if let Some(d) = fb {
                        let _ = WEBVIEW_DIR.set(d);
                    }
                }
                Err(e) => return Err(e.into()),
            }

            #[cfg(debug_assertions)]
            debug_tray_hook(app.handle().clone());
            if smoke {
                // Автопроверка: окно есть, дальше — только то, что оно само попросит.
                // Ни трея, ни автозапуска, ни kill switch, ни фоновых задач с сетью.
                return Ok(());
            }
            if let Err(e) = setup_tray(app) {
                eprintln!("трей не создан: {e}"); // i18n-skip: только для отладки
            }
            if let Some(l) = lock {
                serve_lock(app.handle().clone(), l);
            }
            // Портативную папку могли перенести — обновляем путь в автозапуске; с правами
            // администратора — пересоздаём задачу планировщика (и убираем старый ключ Run).
            if autostart {
                if let Err(e) = apply_autostart(&app.state::<AppState>(), true, as_admin) {
                    log(app.handle(), e);
                }
            }
            if autostart_needs_fix {
                log(app.handle(), trs!("автозапуск: rxvpn запустился без прав администратора из старого ключа автозапуска — прав не прошу. \
                     Перезапусти rxvpn от администратора (Ещё → Настройки → «Сохранить»): автозапуск станет задачей планировщика, без окна UAC при входе"));
            }
            kill_adopt(app.handle());
            if connect_now || auto_connect {
                connect_in_background(app.handle().clone(), true, from_autostart);
            }
            spawn_sub_updater(app.handle().clone());
            updui::spawn_daily(app.handle().clone());
            spawn_net_watch(app.handle().clone());
            spawn_app_watch(app.handle().clone());
            let hk = app.state::<AppState>().store.lock().unwrap().settings.hotkey.clone();
            if let Err(e) = apply_hotkey(app.handle(), &hk) {
                log(app.handle(), e);
            }
            dohui::spawn_doh_watch(app.handle().clone());
            if app.state::<AppState>().state_locked.load(Ordering::SeqCst) {
                log(app.handle(), trs!("state.json зашифрован под другой учёткой Windows или на другом компе — открыть его здесь нельзя. \
                     Файл не тронут; изменения в этом запуске не сохранятся. Перенос на другой комп — через бэкап"));
                notify(app.handle(), trs!("rxvpn: сервера не открылись"), trs!("state.json зашифрован под другой учёткой Windows. Подробности — в логе"));
            }
            if let Some(why) = &elevate_refused {
                log(app.handle(), tr!("запущен без прав администратора ({why}) — zapret и «Все программы» не включатся"));
                notify(app.handle(), trs!("rxvpn без прав администратора"), trs!("Zapret и «Все программы» не включатся. VPN в режиме «Браузер» работает"));
            }
            if app.state::<AppState>().store.lock().unwrap().settings.tg_proxy {
                let a = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = tg_apply(&a).await {
                        log(&a, tr!("Telegram без VPN не включился: {e}"));
                        let _ = a.emit("error-toast", tr!("Telegram без VPN не включился: {e}"));
                    }
                    changed(&a);
                });
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Мини-окно прячется, как только кликнули мимо (как окна Wi-Fi и громкости у часов).
            if window.label() == "mini" {
                match event {
                    tauri::WindowEvent::Focused(false) => {
                        MINI_HIDDEN_AT.store(now_ms(), Ordering::SeqCst);
                        let _ = window.hide();
                    }
                    tauri::WindowEvent::CloseRequested { api, .. } => {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                    _ => {}
                }
                return;
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let to_tray = window
                    .state::<AppState>()
                    .store
                    .lock()
                    .unwrap()
                    .settings
                    .close_to_tray;
                if to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_view,
            set_lang,
            set_sub_filter,
            set_list_filter,
            sub_countries,
            get_log,
            export_backup,
            import_backup,
            import_v2rayn,
            check_ip,
            check_dns,
            speed_test,
            connect,
            disconnect,
            kill_release,
            app_traffic,
            app_traffic_stop,
            download_singbox,
            show_main_window,
            select_server,
            delete_server,
            import_text,
            update_subscription,
            set_sub_hwid,
            update_all_subscriptions,
            delete_subscription,
            rename_subscription,
            set_server_group,
            rename_group,
            tg_set,
            tg_open,
            diagnose,
            diag_apply,
            check_services,
            pick_tweak,
            net_now,
            phone_routing,
            phone_routing_copy,
            site_server_add,
            warpui::warp_add,
            reportui::problem_report,
            dohui::doh_set,
            dohui::doh_restore,
            speed_all,
            speed_all_cancel,
            reportui::problem_report_copy,
            reportui::problem_report_github,
            pauseui::pause_vpn,
            reportui::problem_report_save,
            wl_check,
            services_list,
            test_all,
            real_delay,
            save_settings,
            relaunch_admin,
            take_startup_action,
            smoke_ready,
            zapret_get,
            zapret_pick_folder,
            zapret_select,
            zapret_test,
            zapret_cancel,
            zapret_use_builtin,
            zapret_update,
            download_core,
            vpsui::vps_probe,
            updui::update_check,
            updui::update_apply,
            vpsui::vps_install,
            vpsui::vps_restart,
            vpsui::vps_update,
            vpsui::vps_uninstall,
            vpsui::vps_friend_add,
            vpsui::vps_friend_set,
            vpsui::vps_friend_limits,
            vpsui::vps_friend_reset,
            vpsui::vps_set_exit,
            vpsui::vps_qr,
            vpsui::vps_copy,
            vpsui::vps_traffic,
            vpsui::vps_export_key,
            open_core_dir,
            export_config,
            read_clipboard,
            copy_link,
            qr_server,
            qr_subscription,
            list_processes,
            update_lists,
            test_notification,
        ])
        .build(tauri::generate_context!())
        .expect("не удалось запустить rxvpn")
        .run(|app, event| {
            // Выход (из трея или закрытием окна) — гасим ядро и возвращаем
            // системный прокси как был.
            if let tauri::RunEvent::Exit = event {
                let st = app.state::<AppState>();
                // DNS Windows — первым: без rxvpn наш 127.0.0.1 никому не ответит.
                dohui::doh_restore_blocking(&st.paths.data);
                stop_core(st.inner());
                stop_zapret(st.inner());
                st.zcancel.store(true, Ordering::SeqCst);
                // Выход — не падение: блокировку снимаем сами (фильтры kill switch переживают
                // процесс, а Drop состояния при выходе может и не вызваться).
                st.kill.lock().unwrap().take();
            }
        });
}
