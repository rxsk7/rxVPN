//! «Проверить все»: реальная задержка сразу всех серверов.
//! Поднимаем ОДИН временный Xray: на каждый сервер свой локальный SOCKS-порт
//! и свой исходящий. Потом параллельно делаем HTTPS-запрос через каждый порт.
//! Работающее подключение это не трогает — у временного Xray свои порты.

use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::Semaphore;

use crate::net::{real_delay_with_timeout, CHECK_URLS};
use crate::node::Node;
use crate::runner::XrayProcess;
use crate::xray::{build_test_config, build_variant_config, mask_test_config, Tweak};

/// Подобранный обход по id сервера (Settings::node_tweaks).
pub type Tweaks = std::collections::BTreeMap<String, Tweak>;
use serde_json::Value;

/// Сколько серверов проверяем одновременно.
const PARALLEL: usize = 16;
/// Таймаут на один адрес проверки (их два: основной и запасной).
const TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    pub id: String,
    /// Задержка в мс, если прошло.
    pub ms: Option<u64>,
    /// Причина, если не прошло.
    pub error: Option<String>,
}

/// Свободные локальные порты: занимаем по одному у ОС и сразу отпускаем.
fn free_ports(n: usize) -> Result<Vec<u16>, String> {
    let listeners: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    listeners
        .iter()
        .map(|l| l.local_addr().map(|a| a.port()).map_err(|e| e.to_string()))
        .collect()
}

/// Проверить сервера. `on_result` вызывается по мере готовности — чтобы список
/// в окне заполнялся вживую, а не ждал самого медленного.
/// `mask` — анти-DPI из настроек (xray::finalmask): проверяем сервера так же,
/// как потом подключаемся, иначе с ним живые сервера показались бы мёртвыми.
pub async fn test_all(
    core_dir: &Path,
    nodes: &[Node],
    mask: Option<Value>,
    tweaks: Tweaks,
    on_result: impl Fn(&TestResult) + Send + Sync + 'static,
) -> Result<Vec<TestResult>, String> {
    let urls = CHECK_URLS.iter().map(|s| s.to_string()).collect();
    test_all_with(core_dir, nodes, mask, &tweaks, urls, TIMEOUT, on_result).await
}

fn test_config(pairs: &[(&Node, u16)], mask: Option<&Value>, tweaks: &Tweaks) -> Value {
    let mut cfg = build_test_config(pairs);
    let nodes: Vec<&Node> = pairs.iter().map(|p| p.0).collect();
    mask_test_config(&mut cfg, &nodes, tweaks, mask);
    cfg
}

/// То же со своими адресами проверки и таймаутом (для тестов без интернета).
pub async fn test_all_with(
    core_dir: &Path,
    nodes: &[Node],
    mask: Option<Value>,
    tweaks: &Tweaks,
    urls: Vec<String>,
    timeout: Duration,
    on_result: impl Fn(&TestResult) + Send + Sync + 'static,
) -> Result<Vec<TestResult>, String> {
    let urls = Arc::new(urls);
    if nodes.is_empty() {
        return Ok(Vec::new());
    }
    let ports = free_ports(nodes.len())?;
    let pairs: Vec<(&Node, u16)> = nodes.iter().zip(ports.iter().copied()).collect();
    let cfg = test_config(&pairs, mask.as_ref(), tweaks);

    // Временный Xray (конфиг — через stdin, на диск не пишется). Если какой-то
    // сервер из подписки кривой и Xray не стартует со всеми — проверяем по одному,
    // чтобы кривой не ломал проверку остальных.
    let proc = XrayProcess::start(core_dir, &serde_json::to_vec(&cfg).unwrap(), |_| {}, || {});
    let mut proc = match proc {
        Ok(p) => p,
        Err(_) if nodes.len() > 1 => {
            return test_one_by_one(core_dir, nodes, mask.as_ref(), tweaks, &urls, timeout, on_result).await
        }
        Err(e) => {
            let r = TestResult { id: nodes[0].id.clone(), ms: None, error: Some(short_core_error(&e)) };
            on_result(&r);
            return Ok(vec![r]);
        }
    };

    let on_result = Arc::new(on_result);
    let sem = Arc::new(Semaphore::new(PARALLEL));
    let mut set = tokio::task::JoinSet::new();
    for (node, port) in pairs {
        let id = node.id.clone();
        let sem = sem.clone();
        let cb = on_result.clone();
        let urls = urls.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let proxy = format!("socks5h://127.0.0.1:{port}");
            let u: Vec<&str> = urls.iter().map(String::as_str).collect();
            let r = match real_delay_with_timeout(&proxy, &u, timeout).await {
                Ok(ms) => TestResult { id, ms: Some(ms), error: None },
                Err(e) => TestResult { id, ms: None, error: Some(first_line(&e)) },
            };
            cb(&r);
            r
        });
    }
    let mut results = Vec::with_capacity(nodes.len());
    while let Some(r) = set.join_next().await {
        if let Ok(r) = r {
            results.push(r);
        }
    }
    proc.stop();
    Ok(results)
}

/// Сколько серверов качаем одновременно в «Проверить скорость всех»: больше —
/// и они делят между собой канал человека, цифры врут.
pub const SPEED_PARALLEL: usize = 3;
/// На скачивание через один сервер.
const SPEED_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Debug, Clone, Serialize)]
pub struct SpeedTestResult {
    pub id: String,
    /// Задержка перед скачиванием (не ответил — скорость не меряем).
    pub ms: Option<u64>,
    pub mbps: Option<f64>,
    /// Сколько скачано (на расход трафика).
    pub bytes: u64,
    pub error: Option<String>,
    /// Отменили до того, как дошла очередь.
    pub skipped: bool,
}

/// «Проверить скорость всех»: один временный Xray со всеми серверами, через
/// каждый — задержка, потом скачать `QUICK_BYTES` с Cloudflare. По
/// `SPEED_PARALLEL` за раз; `cancel` — бросить очередь (начатые докачаются
/// до своего таймаута, новые не начнутся).
pub async fn speed_all(
    core_dir: &Path,
    nodes: &[Node],
    mask: Option<Value>,
    tweaks: &Tweaks,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    on_result: impl Fn(&SpeedTestResult) + Send + Sync + 'static,
) -> Result<Vec<SpeedTestResult>, String> {
    let urls = CHECK_URLS.iter().map(|s| s.to_string()).collect();
    let down = crate::checks::SpeedUrls::default().down;
    speed_all_with(core_dir, nodes, mask, tweaks, urls, &down, crate::checks::QUICK_BYTES, SPEED_TIMEOUT, cancel, on_result).await
}

#[allow(clippy::too_many_arguments)]
pub async fn speed_all_with(
    core_dir: &Path,
    nodes: &[Node],
    mask: Option<Value>,
    tweaks: &Tweaks,
    check_urls: Vec<String>,
    down_url: &str,
    bytes: u64,
    timeout: Duration,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    on_result: impl Fn(&SpeedTestResult) + Send + Sync + 'static,
) -> Result<Vec<SpeedTestResult>, String> {
    use std::sync::atomic::Ordering;
    if nodes.is_empty() {
        return Ok(Vec::new());
    }
    let ports = free_ports(nodes.len())?;
    let pairs: Vec<(&Node, u16)> = nodes.iter().zip(ports.iter().copied()).collect();
    let cfg = test_config(&pairs, mask.as_ref(), tweaks);
    // Кривой сервер не даёт Xray стартовать со всеми — тогда без тех, кого Xray
    // не принял по одному (их скорость — ошибка).
    let (mut proc, pairs, mut results) = match XrayProcess::start(core_dir, &serde_json::to_vec(&cfg).unwrap(), |_| {}, || {}) {
        Ok(p) => (p, pairs, Vec::new()),
        Err(e) => {
            let mut good = Vec::new();
            let mut bad = Vec::new();
            for (n, port) in pairs {
                let one = test_config(&[(n, port)], mask.as_ref(), tweaks);
                match crate::runner::test_config(core_dir, &serde_json::to_vec(&one).unwrap()) {
                    Ok(()) => good.push((n, port)),
                    Err(err) => bad.push(SpeedTestResult { id: n.id.clone(), ms: None, mbps: None, bytes: 0, error: Some(short_core_error(&err)), skipped: false }),
                }
            }
            if good.is_empty() {
                bad.iter().for_each(&on_result);
                return if bad.is_empty() { Err(short_core_error(&e)) } else { Ok(bad) };
            }
            let cfg = test_config(&good, mask.as_ref(), tweaks);
            let p = XrayProcess::start(core_dir, &serde_json::to_vec(&cfg).unwrap(), |_| {}, || {}).map_err(|e| short_core_error(&e))?;
            bad.iter().for_each(&on_result);
            (p, good, bad)
        }
    };
    let on_result = Arc::new(on_result);
    let sem = Arc::new(Semaphore::new(SPEED_PARALLEL));
    let check_urls = Arc::new(check_urls);
    let down_url = Arc::new(down_url.to_string());
    let mut set = tokio::task::JoinSet::new();
    for (node, port) in pairs {
        let (id, sem, cb, cu, du, cancel) = (node.id.clone(), sem.clone(), on_result.clone(), check_urls.clone(), down_url.clone(), cancel.clone());
        set.spawn(async move {
            let _permit = sem.acquire_owned().await;
            let skip = SpeedTestResult { id: id.clone(), ms: None, mbps: None, bytes: 0, error: None, skipped: true };
            if cancel.load(Ordering::SeqCst) {
                cb(&skip);
                return skip;
            }
            let proxy = format!("socks5h://127.0.0.1:{port}");
            let u: Vec<&str> = cu.iter().map(String::as_str).collect();
            let r = match real_delay_with_timeout(&proxy, &u, TIMEOUT).await {
                Err(e) => SpeedTestResult { id, ms: None, mbps: None, bytes: 0, error: Some(first_line(&e)), skipped: false },
                Ok(_) if cancel.load(Ordering::SeqCst) => skip,
                Ok(ms) => match crate::checks::quick_speed(&proxy, &du, bytes, timeout).await {
                    Ok((mbps, got)) => SpeedTestResult { id, ms: Some(ms), mbps: Some(mbps), bytes: got, error: None, skipped: false },
                    Err(e) => SpeedTestResult { id, ms: Some(ms), mbps: None, bytes: 0, error: Some(first_line(&e)), skipped: false },
                },
            };
            cb(&r);
            r
        });
    }
    while let Some(r) = set.join_next().await {
        if let Ok(r) = r {
            results.push(r);
        }
    }
    proc.stop();
    Ok(results)
}

/// Какие сервисы работают через сервер (страна выхода, ChatGPT, Gemini…).
/// Отдельный временный Xray только с этим сервером: работающее подключение,
/// его правила и выбранный сервер это не трогает.
pub async fn check_services(core_dir: &Path, node: &Node, mask: Option<Value>, tweaks: &Tweaks) -> Result<crate::services::Report, String> {
    let port = free_ports(1)?[0];
    let cfg = test_config(&[(node, port)], mask.as_ref(), tweaks);
    let mut proc = XrayProcess::start(core_dir, &serde_json::to_vec(&cfg).unwrap(), |_| {}, || {})
        .map_err(|e| short_core_error(&e))?;
    let report = crate::services::probe(&format!("socks5h://127.0.0.1:{port}")).await;
    proc.stop();
    if report.ip.is_empty() && report.services.iter().all(|s| s.ok.is_none()) {
        return Err(trs!("Сервер не ответил — проверь его задержку").into());
    }
    Ok(report)
}

/// Один вариант «Подобрать обход» и его результат.
#[derive(Debug, Clone, Serialize)]
pub struct VariantResult {
    pub tweak: Tweak,
    pub label: String,
    pub ms: Option<u64>,
    pub error: Option<String>,
}

/// «Подобрать обход»: все варианты сервера разом во временном Xray (у каждого
/// свой порт), по каждому — реальная задержка. Порядок — как в `tweak_variants`.
pub async fn pick_tweak(core_dir: &Path, node: &Node) -> Result<Vec<VariantResult>, String> {
    pick_tweak_with(core_dir, node, CHECK_URLS, Duration::from_secs(8)).await
}

pub async fn pick_tweak_with(core_dir: &Path, node: &Node, urls: &[&str], timeout: Duration) -> Result<Vec<VariantResult>, String> {
    let variants = crate::xray::tweak_variants(node);
    let ports = free_ports(variants.len())?;
    let list: Vec<(Tweak, u16)> = variants.into_iter().zip(ports).collect();
    let cfg = build_variant_config(node, &list);
    let mut proc = XrayProcess::start(core_dir, &serde_json::to_vec(&cfg).unwrap(), |_| {}, || {})
        .map_err(|e| short_core_error(&e))?;
    let mut set = tokio::task::JoinSet::new();
    for (i, (t, port)) in list.iter().cloned().enumerate() {
        let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
        set.spawn(async move {
            let u: Vec<&str> = urls.iter().map(String::as_str).collect();
            let r = real_delay_with_timeout(&format!("socks5h://127.0.0.1:{port}"), &u, timeout).await;
            let label = crate::xray::tweak_label(&t);
            let v = match r {
                Ok(ms) => VariantResult { tweak: t, label, ms: Some(ms), error: None },
                Err(e) => VariantResult { tweak: t, label, ms: None, error: Some(first_line(&e)) },
            };
            (i, v)
        });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(x) = r {
            out.push(x);
        }
    }
    proc.stop();
    out.sort_by_key(|x| x.0);
    Ok(out.into_iter().map(|x| x.1).collect())
}

/// Запасной путь: каждый сервер в своём временном Xray.
async fn test_one_by_one(
    core_dir: &Path,
    nodes: &[Node],
    mask: Option<&Value>,
    tweaks: &Tweaks,
    urls: &[String],
    timeout: Duration,
    on_result: impl Fn(&TestResult) + Send + Sync + 'static,
) -> Result<Vec<TestResult>, String> {
    let u: Vec<&str> = urls.iter().map(String::as_str).collect();
    let mut results = Vec::new();
    for node in nodes {
        let port = free_ports(1)?[0];
        let cfg = test_config(&[(node, port)], mask, tweaks);
        let started = XrayProcess::start(core_dir, &serde_json::to_vec(&cfg).unwrap(), |_| {}, || {});
        let r = match started {
            Ok(mut p) => {
                let proxy = format!("socks5h://127.0.0.1:{port}");
                let r = real_delay_with_timeout(&proxy, &u, timeout).await;
                p.stop();
                match r {
                    Ok(ms) => TestResult { id: node.id.clone(), ms: Some(ms), error: None },
                    Err(e) => TestResult { id: node.id.clone(), ms: None, error: Some(first_line(&e)) },
                }
            }
            Err(e) => TestResult { id: node.id.clone(), ms: None, error: Some(short_core_error(&e)) },
        };
        on_result(&r);
        results.push(r);
    }
    Ok(results)
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or(s).to_string()
}

fn short_core_error(e: &str) -> String {
    tr!("Xray не принял этот сервер: {}", e.lines().last().unwrap_or(e))
}
