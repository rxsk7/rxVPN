//! Запуск и остановка процесса Xray.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub fn xray_exe_name() -> &'static str {
    if cfg!(windows) {
        "xray.exe"
    } else {
        "xray"
    }
}

pub fn xray_path(core_dir: &Path) -> PathBuf {
    core_dir.join(xray_exe_name())
}

// ---------------- целостность ядра ----------------

/// Файлы ядра, которые исполняются: xray и библиотека TUN, которую он грузит.
fn core_bins() -> &'static [&'static str] {
    if cfg!(windows) {
        &["xray.exe", "wintun.dll"]
    } else {
        &["xray"]
    }
}

/// Хеши исполняемых файлов ядра, записанные при установке.
pub const CORE_HASHES: &str = "core.sha256";
const MAX_CORE_BIN: u64 = 200 << 20;

fn sha_hex(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// Записать хеши исполняемых файлов ядра (после установки или скачивания).
pub fn record_core(dir: &Path) -> Result<(), String> {
    let mut out = String::new();
    for f in core_bins() {
        if let Ok(data) = std::fs::read(dir.join(f)) {
            out += &format!("{}  {f}\n", sha_hex(&data));
        }
    }
    std::fs::write(dir.join(CORE_HASHES), out).map_err(|e| e.to_string())
}

/// Ядро закрыто от подмены, пока это держим.
pub struct CoreLock {
    _files: Vec<std::fs::File>,
}

/// Сверить исполняемые файлы ядра с записанными при установке и открыть их так,
/// чтобы никто не мог их переписать, пока держим. Записи нет (ядро от старой
/// версии rxvpn или положено руками) — запоминаем то, что есть.
fn verify_core(dir: &Path) -> Result<CoreLock, String> {
    let rec_path = dir.join(CORE_HASHES);
    let rec = std::fs::read_to_string(&rec_path).ok();
    let mut files = Vec::new();
    let mut seen: Vec<(String, &str)> = Vec::new();
    for f in core_bins() {
        let p = dir.join(f);
        // Нет файла — его можно подложить уже после проверки (wintun.dll грузится в TUN).
        if !p.exists() {
            return Err(tr!("в папке ядра нет {f} — скачай ядро заново: Ещё → Настройки → «Скачать ядро»"));
        }
        let mut o = std::fs::OpenOptions::new();
        o.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            o.share_mode(1); // FILE_SHARE_READ: читать и запускать можно, писать и удалять — нет
        }
        let mut file = o.open(&p).map_err(|e| format!("{f}: {e}"))?;
        let mut data = Vec::new();
        (&mut file).take(MAX_CORE_BIN + 1).read_to_end(&mut data).map_err(|e| format!("{f}: {e}"))?;
        seen.push((sha_hex(&data), f));
        files.push(file);
    }
    match rec {
        Some(text) => {
            for (h, f) in &seen {
                let want = text.lines().find_map(|l| {
                    let (hh, ff) = l.split_once("  ")?;
                    (ff.trim() == *f).then(|| hh.trim().to_string())
                });
                if want.as_deref() != Some(h.as_str()) {
                    return Err(tr!("Файл ядра {f} изменился после установки — с правами администратора не запускаю. \
                         Скачай ядро заново: Ещё → Настройки → «Скачать ядро». Своё ядро положил сам — удали {}",
                        rec_path.display()
                    ));
                }
            }
        }
        None => {
            let out: String = seen.iter().map(|(h, f)| format!("{h}  {f}\n")).collect();
            let _ = std::fs::write(&rec_path, out);
        }
    }
    Ok(CoreLock { _files: files })
}

/// Проверенное и закрытое от записи ядро — на весь запуск rxvpn (не хешировать
/// 30 МБ перед каждым `xray run -test`). Снимается только для обновления ядра.
static SESSION: Mutex<Option<(PathBuf, CoreLock)>> = Mutex::new(None);

/// С правами администратора — `verify_core` (один раз за запуск): подменённый
/// xray.exe получил бы права администратора. Без прав подмена ничего не даёт
/// сверх того, что у вируса уже есть.
pub fn core_guard(dir: &Path) -> Result<(), String> {
    if !crate::winsys::is_admin() {
        return Ok(());
    }
    let mut s = SESSION.lock().unwrap_or_else(|e| e.into_inner());
    if s.as_ref().is_some_and(|(d, _)| d == dir) {
        return Ok(());
    }
    *s = Some((dir.to_path_buf(), verify_core(dir)?));
    Ok(())
}

/// Отпустить ядро (перед обновлением файлов). Следующий запуск проверит заново.
pub fn release_core() {
    *SESSION.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

// ---------------- где лежат списки ----------------

/// Папка geoip.dat / geosite.dat / *-ru.dat для Xray. По умолчанию — папка ядра.
/// У установленной версии ядро в Program Files (писать туда может только
/// администратор), а списки обновляются и без прав — они живут в данных
/// пользователя. Это только данные: Xray их читает, но ничего оттуда не запускает.
static ASSETS: Mutex<Option<PathBuf>> = Mutex::new(None);

pub fn set_asset_dir(dir: Option<PathBuf>) {
    *ASSETS.lock().unwrap_or_else(|e| e.into_inner()) = dir;
}

pub fn asset_dir(core_dir: &Path) -> PathBuf {
    ASSETS.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_else(|| core_dir.to_path_buf())
}

/// Большие geoip.dat / geosite.dat из папки ядра — в папку списков, если там их нет
/// или они другие (обновили ядро). Ядро и списки в одной папке — ничего не делает.
pub fn sync_assets(core_dir: &Path) -> Result<(), String> {
    let assets = asset_dir(core_dir);
    if assets == core_dir {
        return Ok(());
    }
    std::fs::create_dir_all(&assets).map_err(|e| e.to_string())?;
    // Большие — как в ядре; списки РФ — только если их ещё нет (обновлённые не затираем).
    for (f, refresh) in [("geoip.dat", true), ("geosite.dat", true), ("geoip-ru.dat", false), ("geosite-ru.dat", false)] {
        let src = core_dir.join(f);
        let Ok(m) = std::fs::metadata(&src) else { continue };
        let dst = assets.join(f);
        let same = std::fs::metadata(&dst).is_ok_and(|d| !refresh || (d.len() == m.len() && d.modified().ok() >= m.modified().ok()));
        if !same {
            let tmp = assets.join(format!("{f}.tmp"));
            std::fs::copy(&src, &tmp).map_err(|e| format!("{f}: {e}"))?;
            std::fs::rename(&tmp, &dst).map_err(|e| format!("{f}: {e}"))?;
        }
    }
    Ok(())
}

/// Запустить xray.exe с аргументами и дождаться ответа (без окна консоли).
/// Для `xray run -test` и `xray api ...`.
pub fn xray_cli(core_dir: &Path, args: &[&str]) -> Result<String, String> {
    xray_cli_input(core_dir, args, None)
}

/// То же, с данными на вход (конфиг через `-c stdin:`).
fn xray_cli_input(core_dir: &Path, args: &[&str], input: Option<&[u8]>) -> Result<String, String> {
    core_guard(core_dir)?;
    let mut cmd = Command::new(xray_path(core_dir));
    cmd.args(args)
        .current_dir(core_dir)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        clean_env(&mut cmd);
    }
    cmd.env("XRAY_LOCATION_ASSET", asset_dir(core_dir));
    let mut child = cmd.spawn().map_err(|e| tr!("xray не запустился: {e}"))?;
    if let (Some(data), Some(mut pipe)) = (input, child.stdin.take()) {
        // Пишем в отдельном потоке: вывод xray читает wait_with_output, никто не ждёт друг друга.
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = pipe.write_all(&data);
        });
    }
    let out = child.wait_with_output().map_err(|e| tr!("xray не запустился: {e}"))?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        Ok(text)
    } else {
        Err(text.trim().to_string())
    }
}

/// Проверить конфиг без запуска: Ok или текст ошибки Xray. Конфиг — через
/// stdin, на диск не пишется.
pub fn test_config(core_dir: &Path, config: &[u8]) -> Result<(), String> {
    xray_cli_input(core_dir, &["run", "-test", "-c", "stdin:", "-format", "json"], Some(config)).map(|_| ())
}


/// Проверяем, свободен ли порт. Если занят — скорее всего висит Happ/v2rayN.
pub fn port_free(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

type LineCb = Arc<dyn Fn(String) + Send + Sync>;
type ExitCb = Arc<dyn Fn() + Send + Sync>;
pub type LineFn = LineCb;

pub struct XrayProcess {
    child: Child,
    tail: Arc<Mutex<VecDeque<String>>>,
    /// sing-box рядом — для серверов TUIC (см. singbox.rs). Гасится вместе с Xray.
    sidecar: Option<crate::singbox::Sidecar>,
}

impl XrayProcess {
    /// Запускает `xray run -c stdin:` и отдаёт конфиг через stdin. На диск конфиг
    /// не пишется: файл в папке, куда пишет любая программа пользователя, можно
    /// подменить между записью и чтением — а xray бывает от администратора.
    /// `on_line` получает каждую строку лога, `on_exit` вызывается, когда процесс умер.
    pub fn start(
        core_dir: &Path,
        config: &[u8],
        on_line: impl Fn(String) + Send + Sync + 'static,
        on_exit: impl Fn() + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let exe = xray_path(core_dir);
        if !exe.exists() {
            return Err(tr!("нет ядра: {}", exe.display()));
        }
        // С правами администратора: ядро сверено и закрыто от подмены до конца запуска.
        core_guard(core_dir)?;
        let on_line: LineCb = Arc::new(on_line);

        // Серверы TUIC: их выходы в конфиге помечены — поднимаем sing-box и отдаём
        // Xray конфиг без меток (с портами sing-box).
        let mut sidecar = None;
        let patched;
        let config = if config.windows(crate::singbox::MARK.len()).any(|w| w == crate::singbox::MARK.as_bytes()) {
            let mut cfg: serde_json::Value = serde_json::from_slice(config).map_err(|e| e.to_string())?;
            if let Some((sb, ports)) = crate::singbox::split(&mut cfg)? {
                sidecar = Some(crate::singbox::Sidecar::start(core_dir, &sb, &ports, on_line.clone())?);
            }
            patched = serde_json::to_vec(&cfg).map_err(|e| e.to_string())?;
            &patched[..]
        } else {
            config
        };

        let mut cmd = Command::new(&exe);
        cmd.args(["run", "-c", "stdin:", "-format", "json"])
            .current_dir(core_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000; // без чёрного окна консоли
            cmd.creation_flags(CREATE_NO_WINDOW);
            // В TUN xray работает от администратора: переменные пользователя
            // (XRAY_LOCATION_CONFDIR подмешал бы чужой конфиг) — не передаём.
            clean_env(&mut cmd);
        }
        // Где лежат geoip.dat / geosite.dat
        cmd.env("XRAY_LOCATION_ASSET", asset_dir(core_dir));

        let mut child = cmd.spawn().map_err(|e| tr!("не запустился xray: {e}"))?;
        // Windows: привязываем xray к rxvpn — если rxvpn закроют как угодно
        // (крестик, диспетчер задач, падение), Windows сама добьёт и xray.
        // Иначе xray.exe остаётся висеть и держит порты.
        #[cfg(windows)]
        job::attach(&child);

        let tail = Arc::new(Mutex::new(VecDeque::with_capacity(200)));
        let on_exit: ExitCb = Arc::new(on_exit);

        if let Some(out) = child.stdout.take() {
            pipe_lines(out, tail.clone(), on_line.clone(), Some(on_exit));
        }
        if let Some(err) = child.stderr.take() {
            pipe_lines(err, tail.clone(), on_line, None);
        }
        // Вывод уже читают потоки — можно писать конфиг. stdin закрывается сразу
        // после записи: xray читает его до конца. Ошибка записи — xray умер, это
        // увидит цикл ниже.
        if let Some(mut pipe) = child.stdin.take() {
            let _ = pipe.write_all(config);
        }

        let mut p = Self { child, tail, sidecar };

        // Ждём, пока ядро либо напишет "Xray ... started" (готово принимать
        // подключения), либо упадёт (кривой конфиг) — до 5 секунд. Фиксированная
        // пауза не годится: на медленном компе старт дольше.
        for _ in 0..50 {
            if let Ok(Some(status)) = p.child.try_wait() {
                // даём потокам дочитать последние строки ошибки
                std::thread::sleep(Duration::from_millis(150));
                let last: Vec<String> = p.tail.lock().unwrap().iter().cloned().collect();
                let tail = last
                    .iter()
                    .rev()
                    .take(6)
                    .rev()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n");
                return Err(tr!("xray завершился ({status}):\n{tail}"));
            }
            let started = p
                .tail
                .lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("core: Xray") && l.contains("started"));
            if started {
                return Ok(p);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // Не дождались строки (например, при уровне лога error её нет), но процесс жив.
        Ok(p)
    }

    /// Жив Xray (и sing-box, если он нужен этому подключению).
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None)) && self.sidecar.as_mut().is_none_or(|s| s.is_running())
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(s) = self.sidecar.as_mut() {
            s.stop();
        }
    }
}

impl Drop for XrayProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Любой другой движок (winws для zapret): тот же Job Object, без окна,
/// строки вывода — в лог. Готов, если через `settle` ещё жив.
pub struct EngineProcess {
    child: Child,
}

impl EngineProcess {
    pub fn start(
        exe: &Path,
        args: &[std::ffi::OsString],
        cwd: &Path,
        settle: Duration,
        on_line: impl Fn(String) + Send + Sync + 'static,
        on_exit: impl Fn() + Send + Sync + 'static,
    ) -> Result<Self, String> {
        let mut cmd = Command::new(exe);
        cmd.args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
            clean_env(&mut cmd);
        }
        let name = exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let mut child = cmd.spawn().map_err(|e| tr!("не запустился {name}: {e}"))?;
        #[cfg(windows)]
        job::attach(&child);
        let tail = Arc::new(Mutex::new(VecDeque::with_capacity(200)));
        let on_line: LineCb = Arc::new(on_line);
        if let Some(out) = child.stdout.take() {
            pipe_lines(out, tail.clone(), on_line.clone(), Some(Arc::new(on_exit)));
        }
        if let Some(err) = child.stderr.take() {
            pipe_lines(err, tail.clone(), on_line, None);
        }
        let t0 = std::time::Instant::now();
        while t0.elapsed() < settle {
            if let Ok(Some(status)) = child.try_wait() {
                std::thread::sleep(Duration::from_millis(150));
                let last: Vec<String> = tail.lock().unwrap().iter().cloned().collect();
                let n = last.len().saturating_sub(6);
                return Err(tr!("{name} завершился ({status}):\n{}", last[n..].join("\n")));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(Self { child })
    }

    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for EngineProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

/// xray (в TUN) и winws работают от администратора, а переменные окружения пользователя может
/// поменять любая программа (HKCU\Environment): PATH с чужими DLL, CYGWIN=…
/// Оставляем только системное, путь к Windows — от самой Windows.
#[cfg(windows)]
pub(crate) fn clean_env(cmd: &mut Command) {
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    cmd.env_clear();
    if n > 0 && n < buf.len() {
        let win = String::from_utf16_lossy(&buf[..n]);
        cmd.env("SystemRoot", &win)
            .env("windir", &win)
            .env("PATH", format!("{win}\\System32;{win}"));
    }
}

/// Вывод помощника (sing-box) — в лог с пометкой, без хвоста и без on_exit.
pub(crate) fn pipe_logs(child: &mut Child, who: &'static str, on_line: LineCb) {
    let tail = Arc::new(Mutex::new(VecDeque::new()));
    let cb: LineCb = Arc::new(move |l: String| on_line(format!("[{who}] {l}")));
    if let Some(out) = child.stdout.take() {
        pipe_lines(out, tail.clone(), cb.clone(), None);
    }
    if let Some(err) = child.stderr.take() {
        pipe_lines(err, tail, cb, None);
    }
}

fn pipe_lines(
    src: impl Read + Send + 'static,
    tail: Arc<Mutex<VecDeque<String>>>,
    on_line: LineCb,
    on_exit: Option<ExitCb>,
) {
    std::thread::spawn(move || {
        for line in BufReader::new(src).lines().map_while(Result::ok) {
            {
                let mut t = tail.lock().unwrap();
                if t.len() >= 200 {
                    t.pop_front();
                }
                t.push_back(line.clone());
            }
            on_line(line);
        }
        // stdout закрылся = процесс умер
        if let Some(cb) = on_exit {
            cb();
        }
    });
}

/// Job Object с флагом KILL_ON_JOB_CLOSE: один на весь процесс rxvpn.
/// Когда процесс rxvpn умирает, Windows закрывает его дескрипторы, задача
/// закрывается — и все привязанные к ней xray.exe завершаются.
#[cfg(windows)]
pub(crate) mod job {
    use std::sync::OnceLock;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    struct Job(HANDLE);
    // Дескриптор задачи можно использовать из любого потока.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    fn create() -> Option<Job> {
        unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 {
                CloseHandle(h);
                return None;
            }
            Some(Job(h))
        }
    }

    static JOB: OnceLock<Option<Job>> = OnceLock::new();

    pub fn attach(child: &std::process::Child) {
        use std::os::windows::io::AsRawHandle;
        if let Some(job) = JOB.get_or_init(create) {
            unsafe {
                AssignProcessToJobObject(job.0, child.as_raw_handle() as HANDLE);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_hashes_catch_swaps() {
        let dir = std::env::temp_dir().join(format!("rxvpn-core-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = core_bins()[0];
        for b in core_bins() {
            std::fs::write(dir.join(b), b"official").unwrap();
        }
        // Записи нет — запоминаем как есть.
        drop(verify_core(&dir).unwrap());
        assert!(std::fs::read_to_string(dir.join(CORE_HASHES)).unwrap().contains(bin));
        drop(verify_core(&dir).unwrap());
        // Подменили — не запускаем.
        std::fs::write(dir.join(bin), b"evil").unwrap();
        assert!(verify_core(&dir).err().unwrap().contains("изменился"));
        // Переустановили (record_core) — снова можно.
        record_core(&dir).unwrap();
        drop(verify_core(&dir).unwrap());
        // Нет одного из файлов (wintun.dll подложили бы после проверки) — нет.
        if core_bins().len() > 1 {
            std::fs::remove_file(dir.join(core_bins()[1])).unwrap();
            assert!(verify_core(&dir).err().unwrap().contains("нет"));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
