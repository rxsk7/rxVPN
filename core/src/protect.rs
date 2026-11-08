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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn data_dir_rules() {
        let d = tmp("v");
        assert!(valid_data_dir(&d));
        assert!(!valid_data_dir(Path::new("relative/data")));
        assert!(!valid_data_dir(&d.join("missing")));
        let _ = std::fs::remove_dir_all(&d);
    }
}
