//! Защищённая копия портативного rxvpn для работы с правами администратора.
//!
//! Портативную папку может переписать любая программа пользователя. Если бы
//! rxvpn.exe, WebView2Loader.dll, xray.exe или winws запускались от
//! администратора прямо оттуда, вирус подменил бы их и получил права вместе с
//! rxvpn. Поэтому при первом запросе прав rxvpn (уже с правами) кладёт копию
//! исполняемых файлов в `%ProgramFiles%\rxvpn` — туда пишет только
//! администратор — и всё, что от администратора, запускает только оттуда.
//! Сервера, настройки и списки остаются в папке `data` портативной (это только
//! данные: из неё с правами ничего не запускается).
//!
//! Что копируется:
//!   * rxvpn.exe — сам себя (это первый запуск с правами: доверие «с первого раза»;
//!     дальше копия обновляется, только если человек подтвердил, что обновлял rxvpn);
//!   * WebView2Loader.dll, xray.exe, wintun.dll — только если хеш совпал с
//!     официальным (`KNOWN`); иначе ядро качается с GitHub со сверкой .dgst;
//!   * движок zapret ставится в копию сам (у него свои официальные хеши, zapret.rs).

use std::path::{Path, PathBuf};

/// Папка копии внутри Program Files.
pub const DIR_NAME: &str = "rxvpn";
pub const EXE: &str = "rxvpn.exe";
pub const LOADER: &str = "WebView2Loader.dll";

/// Официальные файлы, которые идут в портативной сборке: Xray v26.10.21
/// (Xray-windows-64.zip, сверено с .dgst), wintun.dll из того же архива,
/// WebView2Loader.dll x64 от Microsoft (webview2-com-sys 0.39.1).
pub const KNOWN: &[(&str, &str)] = &[
    ("xray.exe", "c77a00eb84fb93ae044c2d771a1cabcc033b81e487253fbc35b12df6879c1e15"),
    ("wintun.dll", "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"),
    (LOADER, "86545b66cdb0603bc26b626fb9ad610cb6e71f28d468f5ea66df23b03dda96d5"),
];

/// Где лежит копия: `%ProgramFiles%\rxvpn` (путь — от самой Windows).
pub fn protected_dir() -> Option<PathBuf> {
    crate::winsys::program_files().map(|p| p.join(DIR_NAME))
}

/// Это и есть папка копии (сравнение после разрешения ссылок).
pub fn is_protected(app_dir: &Path) -> bool {
    match (protected_dir().and_then(|p| std::fs::canonicalize(p).ok()), std::fs::canonicalize(app_dir)) {
        (Some(a), Ok(b)) => a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase(),
        _ => false,
    }
}

/// Можно ли писать в папку: создаём её и пробный файл. WebView2 сам об этом не
/// скажет — покажет своё окно «не удалось создать каталог данных» и закроется.
pub fn writable(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".rxvpn-write-test");
    let ok = std::fs::write(&probe, b"ok").is_ok();
    let _ = std::fs::remove_file(&probe);
    let ebw = dir.join("EBWebView");
    ok && (!ebw.exists() || {
        let p = ebw.join(".rxvpn-write-test");
        let ok = std::fs::write(&p, b"ok").is_ok();
        let _ = std::fs::remove_file(&p);
        ok
    })
}

const FALLBACK_PREFIX: &str = "rxvpn-webview-";

/// Запасной профиль окна для копии с правами, когда в её папку в Program Files писать
/// нельзя (так бывает: антивирус не пускает туда msedgewebview2). Папка — в
/// C:\Windows\Temp: обычные программы там могут создать своё, но не видят список
/// и не читают чужое, а имя у папки случайное — заранее её не подложить и не найти.
/// Профиль одноразовый: старые такие папки удаляем при следующем запуске.
pub fn fallback_webview_dir() -> Option<PathBuf> {
    let tmp = crate::winsys::windows_dir()?.join("Temp");
    if let Ok(rd) = std::fs::read_dir(&tmp) {
        for e in rd.flatten() {
            if e.file_name().to_string_lossy().starts_with(FALLBACK_PREFIX) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).ok()?;
    let name: String = b.iter().map(|x| format!("{x:02x}")).collect();
    let d = tmp.join(format!("{FALLBACK_PREFIX}{name}"));
    // create_dir, а не create_dir_all: если такая уже есть — это не наша.
    std::fs::create_dir(&d).ok()?;
    writable(&d).then_some(d)
}

fn sha_file(p: &Path) -> Option<String> {
    let m = std::fs::symlink_metadata(p).ok()?;
    if !m.is_file() || m.len() > 200 << 20 {
        return None;
    }
    std::fs::read(p).ok().map(|d| crate::net::sha256_hex(&d))
}

fn known(name: &str, data: &[u8], table: &[(&str, &str)]) -> bool {
    let h = crate::net::sha256_hex(data);
    table.iter().any(|(n, s)| n.eq_ignore_ascii_case(name) && *s == h)
}

/// Что с копией относительно текущего rxvpn.exe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Есть и та же версия — можно запускать с правами её.
    Ready,
    /// Ещё нет.
    Missing,
    /// Есть, но rxvpn.exe другой (обновили портативную — или его подменили).
    Different,
}

pub fn state(pf: &Path, exe: &Path) -> State {
    let have = sha_file(&pf.join(EXE));
    let core = pf.join("core").join(crate::runner::xray_exe_name()).is_file();
    match have {
        None => State::Missing,
        Some(h) if core && Some(h.as_str()) == sha_file(exe).as_deref() => State::Ready,
        Some(_) => State::Different,
    }
}

/// Нужен ли архив ядра с GitHub: локальное ядро портативной — не официальное
/// (человек сам обновил его кнопкой «Скачать ядро» или его подменили).
pub fn needs_core_download(data_core: &Path, table: &[(&str, &str)]) -> bool {
    let x = crate::runner::xray_exe_name();
    !std::fs::read(data_core.join(x)).is_ok_and(|d| known(x, &d, table))
}

fn write_atomic(dst: &Path, data: &[u8]) -> Result<(), String> {
    let tmp = dst.with_extension("new");
    std::fs::write(&tmp, data).map_err(|e| format!("{}: {e}", tmp.display()))?;
    if dst.exists() {
        // Запущенный exe Windows удалить не даёт, а переименовать — да.
        let old = dst.with_extension("old");
        let _ = std::fs::remove_file(&old);
        if std::fs::rename(dst, &old).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(tr!("{} занят — закрой rxvpn и попробуй ещё раз", dst.display()));
        }
    }
    std::fs::rename(&tmp, dst).map_err(|e| format!("{}: {e}", dst.display()))
}

/// Разложить копию в `pf`. `exe` — текущий rxvpn.exe, `exe_dir` — его папка (там
/// WebView2Loader.dll), `data_core` — ядро портативной. `core_zip` — архив Xray,
/// уже сверенный с GitHub (`net::fetch_core_zip`), если локальное ядро не официальное.
pub fn deploy(exe: &Path, exe_dir: &Path, data_core: &Path, pf: &Path, table: &[(&str, &str)], core_zip: Option<&[u8]>) -> Result<(), String> {
    let core = pf.join("core");
    std::fs::create_dir_all(&core).map_err(|e| tr!("не создать {}: {e}", core.display()))?;
    // Сначала всё проверяем, потом пишем: подсунутое не ляжет даже частично.
    let mut files: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    let exe_bytes = std::fs::read(exe).map_err(|e| format!("{EXE}: {e}"))?;
    if !exe_bytes.starts_with(b"MZ") && cfg!(windows) {
        return Err(trs!("rxvpn.exe не похож на программу Windows").into());
    }
    files.push((pf.join(EXE), exe_bytes));
    let loader = exe_dir.join(LOADER);
    if loader.exists() || cfg!(windows) {
        let d = std::fs::read(&loader).map_err(|e| format!("{LOADER}: {e}"))?;
        if !known(LOADER, &d, table) {
            return Err(tr!("{LOADER} рядом с rxvpn.exe не совпадает с официальным от Microsoft — возможно, подменён. Скачай портативную rxvpn заново"));
        }
        files.push((pf.join(LOADER), d));
    }
    let x = crate::runner::xray_exe_name();
    let wintun = cfg!(windows).then_some("wintun.dll");
    match core_zip {
        None => {
            for f in std::iter::once(x).chain(wintun) {
                let d = std::fs::read(data_core.join(f)).map_err(|e| format!("{f}: {e}"))?;
                if !known(f, &d, table) {
                    return Err(tr!("{f} в папке ядра не совпадает с официальным — скачаю ядро с GitHub"));
                }
                files.push((core.join(f), d));
            }
        }
        Some(_) => {
            if let Some(f) = wintun {
                let d = std::fs::read(data_core.join(f)).map_err(|e| format!("{f}: {e}"))?;
                if !known(f, &d, table) {
                    return Err(tr!("{f} в папке ядра не совпадает с официальным — скачай портативную rxvpn заново"));
                }
                files.push((core.join(f), d));
            }
        }
    }
    for f in ["LICENSE", "LICENSE-Wintun"] {
        if let Ok(d) = std::fs::read(data_core.join(f)) {
            if d.len() < 1 << 20 {
                files.push((core.join(f), d));
            }
        }
    }
    for (p, d) in &files {
        write_atomic(p, d)?;
    }
    if let Some(z) = core_zip {
        crate::net::install_core_zip(z, &core)?;
    }
    crate::runner::record_core(&core)?;
    Ok(())
}

/// Папку данных для копии передают аргументом: только своя, на этом компе.
pub fn valid_data_dir(p: &Path) -> bool {
    let s = p.to_string_lossy();
    p.is_absolute() && p.is_dir() && !s.starts_with(r"\\") && !s.contains('"') && !crate::winsys::is_remote_drive(&s)
}

/// Папки данных, закрытые от подмены, пока это держим (см. `lock_data`).
pub struct DataLock {
    _dirs: Vec<std::fs::File>,
}

/// Подпапки data, в которые копия с правами пишет сама: списки рядом с ядром, страховочные
/// копии, zapret (стратегии — внутри), состояние Tor.
pub const DATA_SUBDIRS: &[&str] = &["core", "backups", "zapret", "tor"];

/// Открыть папку так, чтобы её нельзя было переименовать, удалить или заменить ссылкой,
/// пока дескриптор открыт, и убедиться, что это настоящая папка, а не ссылка
/// (junction, symlink): ссылку Windows открывает как саму ссылку, а не как её цель.
fn lock_dir(p: &Path) -> Result<std::fs::File, String> {
    let bad = || tr!("{} — не обычная папка (ссылка?). С правами администратора rxvpn с такой папкой данных не работает: положи rxvpn в обычную папку", p.display());
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_READ_ATTRIBUTES: u32 = 0x80;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        const FILE_SHARE_READ_WRITE: u32 = 1 | 2; // без FILE_SHARE_DELETE: папку не убрать и не переименовать
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000; // иначе папку не открыть
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000; // ссылку — как ссылку
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        let f = std::fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            .share_mode(FILE_SHARE_READ_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(p)
            .map_err(|e| format!("{}: {e}", p.display()))?;
        // Атрибуты и вид «точки повторного разбора» — у открытого дескриптора, не по пути.
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{FileAttributeTagInfo, GetFileInformationByHandleEx, FILE_ATTRIBUTE_TAG_INFO};
        let mut info = FILE_ATTRIBUTE_TAG_INFO { FileAttributes: 0, ReparseTag: 0 };
        let ok = unsafe {
            GetFileInformationByHandleEx(f.as_raw_handle() as _, FileAttributeTagInfo, &mut info as *mut _ as *mut _, std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32)
        };
        if ok == 0 {
            return Err(format!("{}: {}", p.display(), std::io::Error::last_os_error()));
        }
        // Ссылка — это точка с признаком «имя-заменитель» (junction, symlink): она уводит
        // путь в другое место. Папки OneDrive («файлы по запросу») — тоже точки повторного
        // разбора, но никуда не ведут: рабочий стол в OneDrive — обычное дело, их пускаем.
        const NAME_SURROGATE: u32 = 0x2000_0000;
        let link = info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 && info.ReparseTag & NAME_SURROGATE != 0;
        if link || info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(bad());
        }
        Ok(f)
    }
    #[cfg(not(windows))]
    {
        let m = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
        if !m.is_dir() {
            return Err(bad());
        }
        std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))
    }
}

/// Копия с правами администратора пишет и удаляет файлы в папке данных, а туда пишет любая
/// программа без прав. Сделай она саму папку (или папку выше, или подпапку) ссылкой —
/// rxvpn с правами записал бы или удалил файл там, куда покажет ссылка. Поэтому до первой
/// работы с файлами: вся цепочка папок от диска до data и подпапки из `subdirs` — настоящие
/// папки, и открыты так, что до выхода rxvpn их не подменить. Подпапки, которых ещё нет,
/// создаём сами (в уже закрытой data): подложенная заранее ссылка проверку не пройдёт.
pub fn lock_data(data: &Path, subdirs: &[&str]) -> Result<DataLock, String> {
    if !data.is_absolute() {
        return Err(tr!("{} — нужен полный путь к папке данных", data.display()));
    }
    let mut dirs = Vec::new();
    // От корня диска вниз: сначала закрыта папка, потом проверяется то, что в ней.
    let mut chain: Vec<&Path> = data.ancestors().filter(|p| !p.as_os_str().is_empty()).collect();
    chain.reverse();
    for p in chain {
        dirs.push(lock_dir(p)?);
    }
    for s in subdirs {
        let p = data.join(s);
        match std::fs::create_dir(&p) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(format!("{}: {e}", p.display())),
        }
        dirs.push(lock_dir(&p)?);
    }
    Ok(DataLock { _dirs: dirs })
}

/// Файл в папке копии с путём к папке data портативной.
const DATA_PATH_FILE: &str = "data-path.txt";

/// Папка данных для копии: пришла аргументом — запомнить (если есть права писать в
/// копию); не пришла — взять запомненную. Запомненная тоже проверяется.
pub fn remember_data(app_dir: &Path, arg: Option<PathBuf>, admin: bool) -> Option<PathBuf> {
    let file = app_dir.join(DATA_PATH_FILE);
    match arg {
        Some(p) => {
            if admin && std::fs::read_to_string(&file).ok().as_deref() != Some(&*p.to_string_lossy()) {
                let _ = std::fs::write(&file, p.to_string_lossy().as_bytes());
            }
            Some(p)
        }
        None => std::fs::read_to_string(&file).ok().map(|s| PathBuf::from(s.trim())).filter(|p| valid_data_dir(p)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_path_is_remembered() {
        let root = tmp("rd");
        let (pf, data) = (root.join("pf"), root.join("portable/data"));
        std::fs::create_dir_all(&pf).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        assert_eq!(remember_data(&pf, None, true), None);
        // без прав не пишем
        assert_eq!(remember_data(&pf, Some(data.clone()), false), Some(data.clone()));
        assert_eq!(remember_data(&pf, None, true), None);
        assert_eq!(remember_data(&pf, Some(data.clone()), true), Some(data.clone()));
        assert_eq!(remember_data(&pf, None, false), Some(data.clone()));
        // папки больше нет — не берём
        std::fs::remove_dir_all(&data).unwrap();
        assert_eq!(remember_data(&pf, None, true), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn tmp(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rxvpn-protect-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn deploy_checks_hashes_and_tracks_versions() {
        let root = tmp("d");
        let (src, data_core, pf) = (root.join("portable"), root.join("portable/data/core"), root.join("pf"));
        std::fs::create_dir_all(&data_core).unwrap();
        let exe = src.join(EXE);
        std::fs::write(&exe, b"MZ v1").unwrap();
        let x = crate::runner::xray_exe_name();
        std::fs::write(data_core.join(x), b"official xray").unwrap();
        std::fs::write(data_core.join("wintun.dll"), b"official wintun").unwrap();
        std::fs::write(src.join(LOADER), b"official loader").unwrap();
        let h = |b: &[u8]| crate::net::sha256_hex(b);
        let (hx, hw, hl) = (h(b"official xray"), h(b"official wintun"), h(b"official loader"));
        let table = [(x, hx.as_str()), ("wintun.dll", hw.as_str()), (LOADER, hl.as_str())];

        assert_eq!(state(&pf, &exe), State::Missing);
        assert!(!needs_core_download(&data_core, &table));
        deploy(&exe, &src, &data_core, &pf, &table, None).unwrap();
        assert_eq!(state(&pf, &exe), State::Ready);
        assert_eq!(std::fs::read(pf.join("core").join(x)).unwrap(), b"official xray");
        assert!(pf.join("core").join(crate::runner::CORE_HASHES).exists());

        // Обновили (или подменили) rxvpn.exe в портативной — копия «другая».
        std::fs::write(&exe, b"MZ v2").unwrap();
        assert_eq!(state(&pf, &exe), State::Different);
        deploy(&exe, &src, &data_core, &pf, &table, None).unwrap();
        assert_eq!(state(&pf, &exe), State::Ready);

        // Подменённая DLL рядом с exe — не копируем ничего.
        std::fs::write(src.join(LOADER), b"evil loader").unwrap();
        std::fs::write(&exe, b"MZ v3").unwrap();
        assert!(deploy(&exe, &src, &data_core, &pf, &table, None).unwrap_err().contains(LOADER));
        assert_eq!(state(&pf, &exe), State::Different, "rxvpn.exe не заменён частично");
        std::fs::write(src.join(LOADER), b"official loader").unwrap();

        // Ядро не официальное — без архива с GitHub не ставим.
        std::fs::write(data_core.join(x), b"evil xray").unwrap();
        assert!(needs_core_download(&data_core, &table));
        assert!(deploy(&exe, &src, &data_core, &pf, &table, None).is_err());
        assert_eq!(std::fs::read(pf.join("core").join(x)).unwrap(), b"official xray", "старое ядро на месте");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Ссылка на папку без прав администратора: junction в Windows, symlink в остальных.
    fn link_dir(link: &Path, target: &Path) {
        #[cfg(windows)]
        {
            let ok = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(link).arg(target).output().unwrap().status.success();
            assert!(ok, "mklink /J не сработал");
        }
        #[cfg(not(windows))]
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    #[test]
    fn data_lock_refuses_links() {
        let root = std::fs::canonicalize(tmp("lock")).unwrap();
        // canonicalize в Windows даёт \\?\C:\… — обычный вид пути.
        let root = PathBuf::from(root.to_string_lossy().trim_start_matches(r"\\?\").to_string());
        let (data, outside) = (root.join("portable").join("data"), root.join("outside"));
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        // Обычная папка: подпапки создаются, замок берётся.
        let lock = lock_data(&data, DATA_SUBDIRS).unwrap();
        assert!(DATA_SUBDIRS.iter().all(|s| data.join(s).is_dir()));
        // Пока замок держим, папку данных не убрать и не переименовать (в Windows).
        #[cfg(windows)]
        assert!(std::fs::rename(&data, root.join("portable").join("data2")).is_err(), "data переименовалась под замком");
        // А файлы внутри — пишутся и удаляются.
        std::fs::write(data.join("state.json"), b"{}").unwrap();
        std::fs::remove_file(data.join("state.json")).unwrap();
        drop(lock);

        // Подпапка — ссылка наружу: отказ, и наружу ничего не записано.
        std::fs::remove_dir(data.join("core")).unwrap();
        link_dir(&data.join("core"), &outside);
        assert!(lock_data(&data, DATA_SUBDIRS).is_err());
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        std::fs::remove_dir(data.join("core")).or_else(|_| std::fs::remove_file(data.join("core"))).unwrap();

        // Сама data — ссылка: отказ.
        let real = root.join("portable").join("real");
        std::fs::rename(&data, &real).unwrap();
        link_dir(&data, &real);
        assert!(lock_data(&data, &[]).is_err());
        // Папка выше — ссылка: отказ.
        let via = root.join("via");
        link_dir(&via, &root.join("portable"));
        assert!(lock_data(&via.join("real"), &[]).is_err());
        assert!(lock_data(&real, &[]).is_ok());
        assert!(lock_data(Path::new("relative/data"), &[]).is_err());

        let _ = std::fs::remove_dir(&via).or_else(|_| std::fs::remove_file(&via));
        let _ = std::fs::remove_dir(&data).or_else(|_| std::fs::remove_file(&data));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Живьём на настоящей папке данных: `RXVPN_LOCK_TEST=C:\…\data cargo test … -- --ignored data_lock_live`.
    /// Подпапок не создаёт. Проверяет, что вся цепочка папок (рабочий стол, OneDrive…) проходит.
    #[test]
    #[ignore]
    fn data_lock_live() {
        let p = PathBuf::from(std::env::var("RXVPN_LOCK_TEST").expect("RXVPN_LOCK_TEST — путь к папке data"));
        lock_data(&p, &[]).unwrap_or_else(|e| panic!("{e}"));
        let have: Vec<&str> = DATA_SUBDIRS.iter().copied().filter(|s| p.join(s).exists()).collect();
        // Те подпапки, что уже есть, — тоже настоящие (create_dir для них ничего не создаёт).
        lock_data(&p, &have).unwrap_or_else(|e| panic!("{e}"));
    }

    #[test]
    fn data_dir_rules() {
        let d = tmp("v");
        assert!(valid_data_dir(&d));
        assert!(!valid_data_dir(Path::new("relative/data")));
        assert!(!valid_data_dir(&d.join("missing")));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Запасной профиль окна (нужны права администратора: пишет в C:\Windows\Temp).
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn fallback_dir_live() {
        let a = fallback_webview_dir().expect("папка не создалась");
        assert!(a.starts_with(crate::winsys::windows_dir().unwrap().join("Temp")));
        assert!(writable(&a));
        let b = fallback_webview_dir().expect("вторая не создалась");
        assert_ne!(a, b);
        assert!(!a.exists(), "старая запасная папка должна удаляться");
        std::fs::remove_dir_all(&b).unwrap();
    }
}
