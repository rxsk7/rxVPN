//! Трафик по программам: сколько скачала и отправила каждая программа, пока открыто окно.
//!
//! Источник — сама Windows: события провайдера Microsoft-Windows-Kernel-Network (ETW).
//! О каждой отправке и приёме TCP/UDP он сообщает номер процесса и число байт — работает
//! и в режиме «Браузер» (программа → прокси rxvpn), и в «Все программы» (TUN). Нужны права
//! администратора (так устроен ETW). Сессия трассировки живёт, пока жив `AppTraffic`;
//! Drop останавливает её.
//!
//! Xray и сам rxvpn не показываем: через них идёт трафик всех программ — это двойной счёт.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Трафик одной программы с момента включения.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AppUsage {
    pub name: String,
    pub up: u64,
    pub down: u64,
}

/// Имя сессии ETW (видна в `logman query -ets`).
pub const SESSION: &str = "rxvpn-app-traffic";
/// Провайдер Microsoft-Windows-Kernel-Network.
pub const PROVIDER: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";

/// Номер события → (отправка?) для TCP/UDP, IPv4/IPv6. Остальные события (подключения,
/// повторы и т.п.) — мимо.
pub fn event_dir(id: u16) -> Option<bool> {
    match id {
        10 | 26 | 42 | 58 => Some(true),  // TCP send v4/v6, UDP send v4/v6
        11 | 27 | 43 | 59 => Some(false), // TCP recv v4/v6, UDP recv v4/v6
        _ => None,
    }
}

/// Счётчики по процессам: pid → (вверх, вниз).
type Counters = Arc<Mutex<HashMap<u32, (u64, u64)>>>;

pub struct AppTraffic {
    counters: Counters,
    names: Mutex<HashMap<u32, String>>,
    #[cfg(windows)]
    trace: Option<ferrisetw::UserTrace>,
}

impl AppTraffic {
    /// Включить подсчёт. Без прав администратора — понятная ошибка.
    pub fn start() -> Result<Self, String> {
        #[cfg(windows)]
        {
            use ferrisetw::parser::Parser;
            use ferrisetw::provider::Provider;
            use ferrisetw::trace::UserTrace;
            use ferrisetw::{EventRecord, SchemaLocator};

            if !crate::winsys::is_admin() {
                return Err(trs!("Трафик по программам считает Windows — нужны права администратора").into());
            }
            // Сессия с тем же именем могла остаться после падения — убираем, иначе старт не пройдёт.
            let _ = ferrisetw::trace::stop_trace_by_name(SESSION);
            let counters: Counters = Arc::default();
            let c = counters.clone();
            let cb = move |record: &EventRecord, locator: &SchemaLocator| {
                let Some(send) = event_dir(record.event_id()) else { return };
                let Ok(schema) = locator.event_schema(record) else { return };
                let p = Parser::create(record, &schema);
                let (Ok(pid), Ok(size)) = (p.try_parse::<u32>("PID"), p.try_parse::<u32>("size")) else { return };
                if let Ok(mut m) = c.lock() {
                    let e = m.entry(pid).or_insert((0, 0));
                    if send {
                        e.0 += size as u64;
                    } else {
                        e.1 += size as u64;
                    }
                }
            };
            // Ключевые слова IPv4 (0x10) и IPv6 (0x20).
            let provider = Provider::by_guid(PROVIDER).any(0x30).add_callback(cb).build();
            let trace = UserTrace::new()
                .named(SESSION.to_string())
                .enable(provider)
                .start_and_process()
                .map_err(|e| tr!("Трафик по программам не включился: {e:?}"))?;
            Ok(Self { counters, names: Mutex::new(HashMap::new()), trace: Some(trace) })
        }
        #[cfg(not(windows))]
        {
            Err(trs!("Трафик по программам есть только в Windows").into())
        }
    }

    /// Сводка по программам (по имени exe), больше всего трафика — сверху.
    pub fn snapshot(&self) -> Vec<AppUsage> {
        let counters = self.counters.lock().map(|m| m.clone()).unwrap_or_default();
        let mut names = self.names.lock().unwrap();
        // Имена живых процессов; у закрытых остаётся последнее известное.
        if counters.keys().any(|pid| !names.contains_key(pid)) {
            for (pid, name) in crate::winsys::process_names() {
                names.insert(pid, name);
            }
        }
        summarize(&counters, &names)
    }
}

/// pid → байты и pid → имя → по программам, без Xray/rxvpn и пустых.
pub fn summarize(counters: &HashMap<u32, (u64, u64)>, names: &HashMap<u32, String>) -> Vec<AppUsage> {
    let mut by: HashMap<String, (u64, u64)> = HashMap::new();
    for (pid, (up, down)) in counters {
        let name = match names.get(pid) {
            Some(n) => n.clone(),
            None if *pid == 4 => "System".into(),
            None => format!("PID {pid}"),
        };
        let lower = name.to_ascii_lowercase();
        if lower == "xray.exe" || lower == "rxvpn.exe" || *pid == 0 {
            continue;
        }
        let e = by.entry(name).or_insert((0, 0));
        e.0 += up;
        e.1 += down;
    }
    let mut v: Vec<AppUsage> = by.into_iter().filter(|(_, (u, d))| u + d > 0).map(|(name, (up, down))| AppUsage { name, up, down }).collect();
    v.sort_by(|a, b| (b.up + b.down).cmp(&(a.up + a.down)).then(a.name.cmp(&b.name)));
    v
}

impl Drop for AppTraffic {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(t) = self.trace.take() {
            let _ = t.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_and_summary() {
        assert_eq!(event_dir(10), Some(true));
        assert_eq!(event_dir(43), Some(false));
        assert_eq!(event_dir(12), None, "подключение — не трафик");
        let c: HashMap<u32, (u64, u64)> = [(100, (10, 1000)), (101, (5, 50)), (200, (1, 999_999)), (300, (7, 7)), (400, (0, 0))].into();
        let n: HashMap<u32, String> =
            [(100, "chrome.exe".to_string()), (101, "chrome.exe".to_string()), (200, "xray.exe".to_string()), (400, "idle.exe".to_string())].into();
        let s = summarize(&c, &n);
        assert_eq!(s[0], AppUsage { name: "chrome.exe".into(), up: 15, down: 1050 }, "процессы одной программы складываются");
        assert_eq!(s[1].name, "PID 300", "закрытый без имени — по номеру");
        assert!(s.iter().all(|a| a.name != "xray.exe" && a.name != "idle.exe"), "Xray (двойной счёт) и пустые — мимо");
    }

    /// Живой (права администратора): своя загрузка видна под именем тестового процесса.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn counts_own_download_live() {
        let t = AppTraffic::start().expect("ETW (нужны права администратора)");
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let mut s = std::net::TcpStream::connect("1.1.1.1:80").unwrap();
        use std::io::{Read, Write};
        s.write_all(b"GET / HTTP/1.0\r\nHost: one.one.one.one\r\n\r\n").unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        std::thread::sleep(std::time::Duration::from_millis(2500));
        let me = std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().to_string();
        let snap = t.snapshot();
        eprintln!("{snap:?}");
        assert!(snap.iter().any(|a| a.name.eq_ignore_ascii_case(&me) && a.down > 0 && a.up > 0), "свой трафик посчитан ({me})");
    }
}
