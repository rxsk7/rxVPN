//! Zapret внутри rxvpn: обход DPI без VPN (winws от bol-van + WinDivert).
//!
//! Человек указывает папку zapret (например, zapret-discord-youtube от Flowseal
//! или zapret-win-bundle). Из неё мы берём ТОЛЬКО текст и данные:
//! аргументы стратегий из .bat/.cmd, списки сайтов, .bin-заготовки пакетов.
//! Ни .bat, ни exe из папки не запускаются:
//!   * winws.exe и драйвер — только официальные (SHA-256 из релизов
//!     bol-van/zapret зашиты ниже). Совпали файлы в папке — берём их, нет —
//!     качаем официальный релиз (тоже со сверкой хеша);
//!   * аргументы — только известные опции winws; опции, которые пишут файлы
//!     (debug, pidfile, wf-save, hostlist-auto-debug), вырезаются; пути —
//!     только внутри папки zapret;
//!   * нужные файлы копируются в рабочую папку rxvpn, winws (он работает от
//!     администратора) читает только эти копии.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::net::sha256_hex;

// ---------------- движок: официальные бинарники ----------------

/// Файлы движка (рядом друг с другом, как в релизе).
pub const ENGINE_FILES: [&str; 4] = ["winws.exe", "cygwin1.dll", "WinDivert.dll", "WinDivert64.sys"];

/// SHA-256 официальных файлов: bol-van/zapret, binaries/windows-x86_64.
/// winws меняется от версии к версии, драйвер и DLL — одни и те же.
const KNOWN: &[(&str, &str, &str)] = &[
    ("winws.exe", "affb4f69d2ea302a7abccd5325d81826e140ddae014f1e070bc4a6c0dd555188", "v72.9"),
    ("winws.exe", "b4b1967288ba11d586e52dfa6428c8ce65940ca790b97982fff9705b386c789c", "v72.10"),
    ("winws.exe", "2da71e80878dc270ac83f5893ecbb841f9752a57f1da8ff9325636b4346bc632", "v72.12"),
    ("winws.exe", "a14bff1df6234ea555d2e0c61b589f0707c0b12d6c9b7eeccda76012154996e8", "v72.13"),
    ("cygwin1.dll", "103104a52e5293ce418944725df19e2bf81ad9269b9a120d71d39028e821499b", ""),
    ("WinDivert.dll", "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2", ""),
    // та же DLL из официального bol-van/zapret-win-bundle (другая сборка)
    ("WinDivert.dll", "16abd6a029e65557c6a309bea7b13bf81fff4e193567582e1cddbf6719f323e0", ""),
    ("WinDivert64.sys", "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2", ""),
];

/// Официальный релиз, если в папке человека бинарники не те (или их нет).
pub const OFFICIAL_URL: &str = "https://github.com/bol-van/zapret/releases/download/v72.13/zapret-v72.13.zip";
pub const OFFICIAL_ZIP_SHA256: &str = "c493e33a0dc4eba23a8686efdaba55f59755ad6ade3564aebd9d13f4c65e2e0c";
const ZIP_DIR: &str = "zapret-v72.13/binaries/windows-x86_64/";

/// Файл движка: обычный файл (не ссылка — через неё чтение ушло бы куда угодно,
/// вплоть до сетевой папки) и не больше 8 МБ (иначе подсунутый «winws.exe» на
/// несколько ГБ читался бы целиком при каждом открытии окна).
fn read_small(p: &Path) -> Result<Vec<u8>, String> {
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let m = std::fs::symlink_metadata(p).map_err(|_| tr!("нет {name}"))?;
    if m.file_type().is_symlink() || !m.is_file() {
        return Err(tr!("{name} — не обычный файл"));
    }
    if m.len() > 8 << 20 {
        return Err(tr!("{name} подозрительно большой"));
    }
    let mut data = Vec::new();
    std::fs::File::open(p)
        .and_then(|f| f.take((8 << 20) + 1).read_to_end(&mut data))
        .map_err(|e| format!("{name}: {e}"))?;
    Ok(data)
}

/// Хеш файла есть среди официальных → версия winws ("" для DLL/драйвера).
fn known(file: &str, data: &[u8]) -> Option<&'static str> {
    let h = sha256_hex(data);
    KNOWN.iter().find(|(f, sha, _)| *f == file && *sha == h).map(|(_, _, v)| *v)
}

/// Все файлы движка на месте и официальные. Ok — версия winws.
/// Проверяем перед каждым запуском: папка rxvpn доступна для записи.
pub fn engine_check(dir: &Path) -> Result<String, String> {
    let mut ver = String::new();
    for f in ENGINE_FILES {
        let data = read_small(&dir.join(f))?;
        match known(f, &data) {
            Some(v) => {
                if f == "winws.exe" {
                    ver = v.to_string();
                }
            }
            None => return Err(tr!("{f} не совпадает с официальным")),
        }
    }
    Ok(ver)
}

/// Взять движок из папки человека — только если все файлы официальные.
/// Сначала читаем и сверяем, потом пишем к себе ровно то, что сверили.
pub fn engine_from_folder(bin: &Path, engine: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    for f in ENGINE_FILES {
        let data = read_small(&bin.join(f)).map_err(|e| tr!("в папке: {e}"))?;
        if known(f, &data).is_none() {
            return Err(tr!("{f} в папке не совпадает ни с одной официальной сборкой zapret — возможно, подделка"));
        }
        files.push((f, data));
    }
    write_engine(engine, &files)
}

fn write_engine(engine: &Path, files: &[(&str, Vec<u8>)]) -> Result<String, String> {
    std::fs::create_dir_all(engine).map_err(|e| e.to_string())?;
    for (f, data) in files {
        let tmp = engine.join(format!("{f}.tmp"));
        let r = std::fs::write(&tmp, data)
            .map_err(|e| format!("{f}: {e}"))
            .and_then(|_| std::fs::rename(&tmp, engine.join(f)).map_err(|e| tr!("{f}: {e} (winws ещё запущен?)")));
        if r.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        r?;
    }
    engine_check(engine)
}

/// Файлы движка, открытые на всё время работы winws. На Windows — без права
/// записи и удаления для остальных: между сверкой хеша и запуском (и пока
/// winws работает) их не подменить, папку с ними не переименовать.
pub struct EngineLock {
    _files: Vec<std::fs::File>,
}

/// Сверка движка прямо перед запуском + блокировка файлов. Ok — версия winws.
/// В папке движка не должно быть ничего лишнего: чужая DLL рядом с winws.exe
/// загрузилась бы в процесс с правами администратора.
pub fn engine_lock(dir: &Path) -> Result<(String, EngineLock), String> {
    let rd = std::fs::read_dir(dir).map_err(|_| trs!("движок zapret не установлен").to_string())?;
    for e in rd.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if !ENGINE_FILES.iter().any(|f| f.eq_ignore_ascii_case(&n)) {
            return Err(tr!("в папке движка zapret лишний файл «{n}» — удали его: {}", dir.display()));
        }
    }
    let mut ver = String::new();
    let mut files = Vec::new();
    for f in ENGINE_FILES {
        let mut o = std::fs::OpenOptions::new();
        o.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_SHARE_READ: u32 = 1;
            o.share_mode(FILE_SHARE_READ);
        }
        let mut file = o.open(dir.join(f)).map_err(|e| format!("{f}: {e}"))?;
        let mut data = Vec::new();
        (&mut file).take((8 << 20) + 1).read_to_end(&mut data).map_err(|e| format!("{f}: {e}"))?;
        match known(f, &data) {
            Some(v) => {
                if f == "winws.exe" {
                    ver = v.to_string();
                }
            }
            None => return Err(tr!("{f} не совпадает с официальным — не запускаю")),
        }
        files.push(file);
    }
    // Служба WinDivert, оставленная другой программой, указывает на свой драйвер —
    // WinDivert.dll загрузит его, а не наш. Пускаем, только если это тот же
    // официальный файл, и держим его так же закрытым от подмены.
    if let Some(image) = crate::winsys::windivert_service_image() {
        let path = image.trim().trim_start_matches(r"\??\").trim_start_matches(r"\\?\").to_string();
        let fix = trs!("удали её (от администратора): sc stop WinDivert, затем sc delete WinDivert");
        // Сначала — что путь локальный: даже canonicalize сетевого пути уже стучится на сервер.
        if !crate::xray::local_dir(&path) {
            return Err(tr!("служба WinDivert указывает на «{image}» — {fix}"));
        }
        let ours = dir.join("WinDivert64.sys");
        let same = std::fs::canonicalize(&path).ok().zip(std::fs::canonicalize(&ours).ok()).is_some_and(|(a, b)| a == b);
        if !same {
            let mut o = std::fs::OpenOptions::new();
            o.read(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                o.share_mode(1); // FILE_SHARE_READ
            }
            let mut file = o.open(&path).map_err(|e| tr!("служба WinDivert указывает на «{path}» ({e}) — {fix}"))?;
            let mut data = Vec::new();
            (&mut file).take((8 << 20) + 1).read_to_end(&mut data).map_err(|e| e.to_string())?;
            if known("WinDivert64.sys", &data).is_none() {
                return Err(tr!("служба WinDivert зарегистрирована на чужой драйвер «{path}» — {fix}"));
            }
            files.push(file);
        }
    }
    Ok((ver, EngineLock { _files: files }))
}

/// Официальный архив → 4 файла движка (после сверки хеша архива и каждого файла).
pub fn engine_from_zip(zip_bytes: &[u8], engine: &Path) -> Result<String, String> {
    if sha256_hex(zip_bytes) != OFFICIAL_ZIP_SHA256 {
        return Err(trs!("архив zapret не совпал с официальным (хеш) — не ставлю").into());
    }
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).map_err(|e| e.to_string())?;
    let mut files = Vec::new();
    for f in ENGINE_FILES {
        let mut e = zip.by_name(&format!("{ZIP_DIR}{f}")).map_err(|_| tr!("в архиве нет {f}"))?;
        let mut data = Vec::new();
        std::io::Read::read_to_end(&mut (&mut e).take(8 << 20), &mut data).map_err(|e| e.to_string())?;
        if known(f, &data).is_none() {
            return Err(tr!("{f} в архиве не тот"));
        }
        files.push((f, data));
    }
    write_engine(engine, &files)
}

use std::io::Read as _;

/// Скачать официальный zapret (≈8 МБ). `proxy` — через VPN, если нужно.
pub async fn engine_download(engine: &Path, proxy: Option<&str>) -> Result<String, String> {
    let mut b = reqwest::Client::builder().timeout(Duration::from_secs(180)).https_only(true);
    if let Some(p) = proxy {
        b = b.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?);
    }
    let r = b
        .build()
        .map_err(|e| e.to_string())?
        .get(OFFICIAL_URL)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| tr!("GitHub недоступен: {e}"))?;
    let bytes = crate::net::read_capped(r, 64 << 20).await?;
    engine_from_zip(&bytes, engine)
}

// ---------------- встроенные стратегии Flowseal ----------------

/// Стратегии и списки zapret-discord-youtube от Flowseal (лицензия MIT) — прямо
/// в rxvpn: .bat, lists/*.txt, bin/*.bin и лицензия. Программ и драйверов внутри
/// нет: WinDivert антивирусы считают «хак-тулом» и снесли бы весь архив rxvpn.
const BUILTIN_ZIP: &[u8] = include_bytes!("../assets/zapret-flowseal.zip");
pub const BUILTIN_VERSION: &str = "1.10.4";
pub const FLOWSEAL_REPO: &str = "https://github.com/Flowseal/zapret-discord-youtube";
const SOURCE_FILE: &str = ".rxvpn-source";

/// Что лежит в папке стратегий rxvpn.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Source {
    pub version: String,
    /// true — скачано с GitHub Flowseal, false — встроенное.
    pub from_github: bool,
    /// Когда разложено (unix-время).
    pub installed_at: i64,
}

pub fn source_of(dir: &Path) -> Option<Source> {
    let t = std::fs::read_to_string(dir.join(SOURCE_FILE)).ok()?;
    let mut l = t.lines();
    let version = l.next()?.trim().to_string();
    let from_github = l.next()? == "github";
    let installed_at = l.next().and_then(|x| x.trim().parse().ok()).unwrap_or(0);
    clean_version(&version).map(|version| Source { version, from_github, installed_at })
}

fn clean_version(v: &str) -> Option<String> {
    let v = v.trim();
    let fine = v.len() <= 24
        && v.starts_with(|c: char| c.is_ascii_alphanumeric())
        && v.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c));
    fine.then(|| v.to_string())
}

/// «1.10.4» < «1.10.10»: по числам.
pub fn version_less(a: &str, b: &str) -> bool {
    let n = |v: &str| v.split(|c: char| !c.is_ascii_digit()).filter(|x| !x.is_empty()).map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    n(a) < n(b)
}

/// Папка встроенных стратегий готова: разложить, если её нет, она испорчена
/// или в rxvpn встроена версия новее той, что лежит.
/// Раскладка стратегий — по одной за раз на весь процесс: окно, автоподключение
/// и «Обновить» могут попросить одновременно.
static INSTALL: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn ensure_builtin(dir: &Path, now: i64) -> Result<Source, String> {
    let _one = INSTALL.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(s) = source_of(dir) {
        let fine = !version_less(&s.version, BUILTIN_VERSION) && scan(dir, false).is_ok_and(|x| !x.strategies.is_empty());
        if fine {
            return Ok(s);
        }
    }
    install_locked(BUILTIN_ZIP, dir, Some(BUILTIN_VERSION), false, now)
}

/// Имя файла, которое можно спокойно создать в Windows: без запрещённых символов,
/// не имя устройства (COM1.bat ушёл бы в порт), без точки/пробела в конце.
fn creatable_name(n: &str) -> bool {
    // Только то, что встречается в именах стратегий Flowseal: латиница, цифры,
    // пробел, скобки и немного знаков. Без «невидимых» символов Юникода (U+202E
    // переворачивает текст — имя в окне выглядело бы иначе, чем есть).
    !n.is_empty()
        && n.len() <= 200
        && n.chars().all(|c| c.is_ascii_alphanumeric() || " ()[]._-+,!".contains(c))
        && !reserved_name(n)
        && !n.ends_with('.')
        && !n.ends_with(' ')
}

/// Разложить архив Flowseal (встроенный или скачанный) в `dir`. Берём только
/// стратегии *.bat из корня, lists/*.txt, bin/*.bin, лицензию и официальный
/// движок из bin/ (по хешам). Остальное (service.bat, утилиты, скрипты) — мимо.
/// Новая папка собирается рядом и подменяет старую целиком; нет в ней ни одной
/// годной стратегии — старая остаётся.
pub fn install_strategies(zip_bytes: &[u8], dir: &Path, version_hint: Option<&str>, from_github: bool, now: i64) -> Result<Source, String> {
    let _one = INSTALL.lock().unwrap_or_else(|e| e.into_inner());
    install_locked(zip_bytes, dir, version_hint, from_github, now)
}

/// Уникальное имя рядом с папкой стратегий (для сборки новой и убирания старой).
fn sibling(dir: &Path, name: &str, what: &str) -> PathBuf {
    use std::sync::atomic::AtomicU64;
    static N: AtomicU64 = AtomicU64::new(0);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    dir.with_file_name(format!("{name}.{what}-{}-{t:x}-{n}", std::process::id()))
}

fn install_locked(zip_bytes: &[u8], dir: &Path, version_hint: Option<&str>, from_github: bool, now: i64) -> Result<Source, String> {
    const MAX_TOTAL: u64 = 64 << 20;
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).map_err(|e| tr!("архив стратегий: {e}"))?;
    if zip.len() > 2000 {
        return Err(trs!("в архиве стратегий слишком много файлов").into());
    }
    // Общая папка сверху (zapret-discord-youtube-1.10.5/) — снимаем.
    let names: Vec<Option<String>> = (0..zip.len())
        .map(|i| zip.by_index_raw(i).ok().and_then(|f| f.enclosed_name()).map(|p| p.to_string_lossy().replace('\\', "/")))
        .collect();
    // (enclosed_name отдаёт папку без «/» на конце: «zapret-discord-youtube-1.10.5».)
    let top = names.iter().flatten().next().map(|n| format!("{}/", n.split('/').next().unwrap_or("")));
    let prefix = top
        .filter(|t| {
            let all = names.iter().flatten();
            all.clone().all(|n| n.starts_with(t.as_str()) || format!("{n}/") == *t) && all.clone().any(|n| n.starts_with(t.as_str()))
        })
        .unwrap_or_default();

    let name = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "strategies".into());
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        // Хвосты прошлых раскладок (rxvpn закрыли посреди) — убрать. remove_dir_all
        // по ссылке (junction) не идёт: удаляет саму ссылку, не то, куда она ведёт.
        for e in std::fs::read_dir(parent).into_iter().flatten().flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with(&format!("{name}.new-")) || n.starts_with(&format!("{name}.old-")) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    // Новая папка — с уникальным именем и только что созданная нами (create_dir
    // падает, если имя уже занято), а не «удалить и создать заново».
    let tmp = sibling(dir, &name, "new");
    std::fs::create_dir(&tmp).map_err(|e| tr!("стратегии: {e}"))?;
    for sub in ["lists", "bin"] {
        std::fs::create_dir(tmp.join(sub)).map_err(|e| e.to_string())?;
    }
    let mut total = 0u64;
    let mut version = version_hint.and_then(clean_version);
    let mut engine_skipped = Vec::new();
    let mut unpack = |version: &mut Option<String>, engine_skipped: &mut Vec<String>| -> Result<(), String> {
        for (i, full) in names.iter().enumerate() {
            let Some(rel) = full.as_deref().and_then(|n| n.strip_prefix(prefix.as_str())) else { continue };
            let parts: Vec<&str> = rel.split('/').collect();
            #[derive(PartialEq)]
            enum K {
                Bat,
                Service,
                Data,
                Engine,
            }
            let kind = match parts.as_slice() {
                [n] if n.eq_ignore_ascii_case("service.bat") => K::Service,
                [n] if n.to_ascii_lowercase().ends_with(".bat") && creatable_name(n) => K::Bat,
                [n] if *n == "LICENSE.txt" => K::Data,
                ["lists", n] if n.ends_with(".txt") && safe_file_name(n) => K::Data,
                ["bin", n] if n.ends_with(".bin") && safe_file_name(n) => K::Data,
                ["bin", n] if ENGINE_FILES.contains(n) => K::Engine,
                _ => continue,
            };
            let mut f = zip.by_index(i).map_err(|e| e.to_string())?;
            if f.is_dir() {
                continue;
            }
            let cap: u64 = match kind {
                K::Bat | K::Service => 1 << 20,
                K::Engine => 8 << 20,
                // заготовки пакетов — килобайты; списки сайтов бывают большими
                K::Data if parts[0] == "bin" => 64 << 10,
                K::Data => 16 << 20,
            };
            let mut data = Vec::new();
            (&mut f).take(cap + 1).read_to_end(&mut data).map_err(|e| format!("{rel}: {e}"))?;
            if data.len() as u64 > cap {
                return Err(tr!("{rel}: слишком большой"));
            }
            total += data.len() as u64;
            if total > MAX_TOTAL {
                return Err(trs!("архив стратегий слишком большой").into());
            }
            match kind {
                K::Service => {
                    // set "LOCAL_VERSION=1.10.5" — версия сборки Flowseal. Только если
                    // версию не знаем сами: тег релиза с GitHub надёжнее надписи в архиве.
                    let t = String::from_utf8_lossy(&data);
                    if version.is_none() {
                        *version = t
                            .split("LOCAL_VERSION=")
                            .nth(1)
                            .map(|r| r.chars().take_while(|c| c.is_ascii_alphanumeric() || ".-_".contains(*c)).collect::<String>())
                            .and_then(|v| clean_version(&v));
                    }
                    continue;
                }
                K::Engine if known(parts[1], &data).is_none() => {
                    engine_skipped.push(parts[1].to_string());
                    continue;
                }
                _ => {}
            }
            std::fs::write(tmp.join(rel), &data).map_err(|e| format!("{rel}: {e}"))?;
        }
        Ok(())
    };
    let r = unpack(&mut version, &mut engine_skipped);
    let done = r.and_then(|_| {
        let n = scan(&tmp, false)?.strategies.len();
        if n == 0 {
            return Err(trs!("в архиве нет ни одной годной стратегии").into());
        }
        let src = Source { version: version.clone().unwrap_or_else(|| "?".into()), from_github, installed_at: now };
        let kind = if from_github { "github" } else { "builtin" };
        std::fs::write(tmp.join(SOURCE_FILE), format!("{}\n{kind}\n{now}\n", src.version)).map_err(|e| e.to_string())?;
        Ok(src)
    });
    let src = match done {
        Ok(s) => s,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(e);
        }
    };
    // Подмена целиком: старое — в сторону, новое — на его место.
    let old = sibling(dir, &name, "old");
    if dir.exists() {
        std::fs::rename(dir, &old).map_err(|e| tr!("старые стратегии заняты: {e}"))?;
    }
    if let Err(e) = std::fs::rename(&tmp, dir) {
        let _ = std::fs::rename(&old, dir);
        return Err(tr!("стратегии не разложились: {e}"));
    }
    let _ = std::fs::remove_dir_all(&old);
    let _ = engine_skipped; // неофициальный движок в архиве просто не берём
    Ok(src)
}

/// Тег последнего релиза из редиректа /releases/latest → …/releases/tag/<тег>.
pub fn parse_release_tag(location: &str) -> Result<String, String> {
    let tag = location
        .strip_prefix(&format!("{FLOWSEAL_REPO}/releases/tag/"))
        .ok_or_else(|| tr!("GitHub ответил непонятно: {}", location.chars().take(120).collect::<String>()))?;
    clean_version(tag).ok_or_else(|| trs!("странный номер релиза").to_string())
}

/// Скачать последний релиз Flowseal. Тег — из редиректа страницы /releases/latest,
/// без API GitHub: у API лимит 60 запросов в час на IP, а за NAT провайдера IP общий.
pub async fn fetch_flowseal(proxy: Option<&str>) -> Result<(String, Vec<u8>), String> {
    let client = |redirect: reqwest::redirect::Policy| -> Result<reqwest::Client, String> {
        let mut b = reqwest::Client::builder()
            .https_only(true)
            .timeout(Duration::from_secs(120))
            .connect_timeout(Duration::from_secs(15))
            .redirect(redirect)
            .user_agent("rxvpn");
        if let Some(p) = proxy {
            b = b.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?);
        }
        b.build().map_err(|e| e.to_string())
    };
    let r = client(reqwest::redirect::Policy::none())?
        .get(format!("{FLOWSEAL_REPO}/releases/latest"))
        .send()
        .await
        .map_err(|e| tr!("GitHub недоступен: {e}"))?;
    let loc = r
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| tr!("GitHub не сказал, какой релиз последний (код {})", r.status()))?
        .to_string();
    let tag = parse_release_tag(&loc)?;
    let url = format!("{FLOWSEAL_REPO}/releases/download/{tag}/zapret-discord-youtube-{tag}.zip");
    let resp = client(reqwest::redirect::Policy::limited(5))?
        .get(&url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| tr!("архив Flowseal {tag} не скачался: {e}"))?;
    let bytes = crate::net::read_capped(resp, 64 << 20).await?;
    Ok((tag, bytes))
}

// ---------------- стратегии ----------------

/// Опции winws (v72.13), которые пропускаем. Остальные — отказ.
const ALLOWED: &[&str] = &[
    "wsize", "wssize", "wssize-cutoff", "wssize-forced-cutoff", "synack-split",
    "ctrack-timeouts", "ctrack-disable", "ipcache-lifetime", "ipcache-hostname", "hostcase",
    "hostspell", "hostnospace", "domcase", "methodeol", "ip-id", "dpi-desync", "dup", "dup-ttl",
    "dup-ttl6", "dup-autottl", "dup-autottl6", "dup-tcp-flags-set", "dup-tcp-flags-unset",
    "dup-fooling", "dup-ts-increment", "dup-badseq-increment", "dup-badack-increment",
    "dup-replace", "dup-ip-id", "dup-start", "dup-cutoff", "orig-ttl", "orig-ttl6",
    "orig-autottl", "orig-autottl6", "orig-tcp-flags-set", "orig-tcp-flags-unset",
    "orig-mod-start", "orig-mod-cutoff", "dpi-desync-ttl", "dpi-desync-ttl6",
    "dpi-desync-autottl", "dpi-desync-autottl6", "dpi-desync-tcp-flags-set",
    "dpi-desync-tcp-flags-unset", "dpi-desync-fooling", "dpi-desync-repeats",
    "dpi-desync-skip-nosni", "dpi-desync-split-pos", "dpi-desync-split-http-req",
    "dpi-desync-split-tls", "dpi-desync-split-seqovl", "dpi-desync-split-seqovl-pattern",
    "dpi-desync-fakedsplit-pattern", "dpi-desync-fakedsplit-mod", "dpi-desync-hostfakesplit-midhost",
    "dpi-desync-hostfakesplit-mod", "dpi-desync-ipfrag-pos-tcp", "dpi-desync-ipfrag-pos-udp",
    "dpi-desync-ts-increment", "dpi-desync-badseq-increment", "dpi-desync-badack-increment",
    "dpi-desync-any-protocol", "dpi-desync-fake-tcp-mod", "dpi-desync-fake-http",
    "dpi-desync-fake-tls", "dpi-desync-fake-tls-mod", "dpi-desync-fake-unknown",
    "dpi-desync-fake-syndata", "dpi-desync-fake-quic", "dpi-desync-fake-wireguard",
    "dpi-desync-fake-dht", "dpi-desync-fake-discord", "dpi-desync-fake-stun",
    "dpi-desync-fake-unknown-udp", "dpi-desync-udplen-increment", "dpi-desync-udplen-pattern",
    "dpi-desync-cutoff", "dpi-desync-start", "hostlist", "hostlist-domains", "hostlist-exclude",
    "hostlist-exclude-domains", "hostlist-auto", "hostlist-auto-fail-threshold",
    "hostlist-auto-fail-time", "hostlist-auto-retrans-threshold", "new", "skip", "filter-l3",
    "filter-tcp", "filter-udp", "filter-l7", "filter-ssid", "ipset", "ipset-ip", "ipset-exclude",
    "ipset-exclude-ip", "bind-fix4", "bind-fix6", "wf-iface", "wf-l3", "wf-tcp", "wf-udp",
    "wf-raw-part", "ssid-filter", "nlm-filter", "nlm-list",
];

/// Пишут файлы или ломают запуск — вырезаем молча (с заметкой).
const DROPPED: &[&str] = &[
    "debug", "pidfile", "wf-save", "hostlist-auto-debug", "dry-run", "version", "daemon", "user", "uid", "comment",
    "qnum", "port", "dpi-desync-fwmark", "dpi-desync-sockarg",
    // Локальную сеть (роутер, NAS, сам комп) winws не трогает никогда — как по умолчанию.
    "wf-filter-lan",
];

/// Опции winws без значения и со значением по желанию (из исходников v72.13).
/// Остальным значение обязательно: без «=…» getopt съел бы следующий аргумент.
const NO_ARG: &[&str] = &[
    "bind-fix4", "bind-fix6", "daemon", "domcase", "dry-run", "hostcase", "hostnospace", "methodeol", "new", "skip",
    "version",
];
const OPT_ARG: &[&str] = &[
    "comment", "ctrack-disable", "debug", "dpi-desync-any-protocol", "dpi-desync-autottl", "dpi-desync-autottl6",
    "dpi-desync-skip-nosni", "dpi-desync-tcp-flags-set", "dpi-desync-tcp-flags-unset", "dup-autottl", "dup-autottl6",
    "dup-replace", "dup-tcp-flags-set", "dup-tcp-flags-unset", "ipcache-hostname", "nlm-list", "orig-autottl",
    "orig-autottl6", "orig-tcp-flags-set", "orig-tcp-flags-unset", "synack-split",
];

/// Значение — имя файла (читается winws). Можно и встроенное: "0x…" или "!".
const FILE_OPTS: &[&str] = &[
    "hostlist", "hostlist-exclude", "hostlist-auto", "ipset", "ipset-exclude",
    "dpi-desync-fake-http", "dpi-desync-fake-tls", "dpi-desync-fake-unknown",
    "dpi-desync-fake-syndata", "dpi-desync-fake-quic", "dpi-desync-fake-wireguard",
    "dpi-desync-fake-dht", "dpi-desync-fake-discord", "dpi-desync-fake-stun",
    "dpi-desync-fake-unknown-udp", "dpi-desync-split-seqovl-pattern",
    "dpi-desync-fakedsplit-pattern", "dpi-desync-udplen-pattern",
];

/// Значение опции после разбора.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub enum Val {
    #[default]
    None,
    Text(String),
    /// Файл внутри папки zapret (путь от её корня, через «/»).
    File(String),
    /// --wf-raw-part=@файл: кусок фильтра WinDivert (проверяется при запуске).
    /// Полный --wf-raw не берём: с ним winws не исключает локальную сеть.
    AtFile(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Arg {
    pub name: String,
    pub val: Val,
}

#[derive(Debug, Clone, Serialize)]
pub struct Strategy {
    /// «general (ALT2)» — имя файла без расширения.
    pub name: String,
    /// Путь файла стратегии от корня папки.
    pub file: String,
    pub args: Vec<Arg>,
    /// Что вырезали.
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Scan {
    pub strategies: Vec<Strategy>,
    /// Файлы, которые не похожи на стратегию или не прошли проверку: «файл — причина».
    pub skipped: Vec<String>,
    /// Версия официального движка в папке (bin/ или рядом), если он там есть и настоящий.
    pub engine_version: Option<String>,
    /// Почему движок из папки не годится (тогда скачаем официальный).
    pub engine_problem: Option<String>,
}

const SENT: char = '\u{1}';

/// Склеить строки с «^» в конце (так cmd переносит длинную команду).
fn join_carets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        if let Some(head) = line.strip_suffix('^') {
            cur.push_str(head);
            cur.push(' ');
        } else {
            cur.push_str(line);
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Разделить по пробелам вне кавычек; кавычки убрать, «^x» вне кавычек → «x»
/// (как делает cmd: «^!» в стратегиях Flowseal — просто «!»).
fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut q = false;
    let mut any = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            '^' if !q => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '"' => {
                q = !q;
                any = true;
            }
            ' ' | '\t' if !q => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                    any = false;
                }
            }
            _ => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Подставить %ПЕРЕМЕННЫЕ%. %~dp0 — папка самого .bat (у нас — метка SENT).
fn expand(s: &str, vars: &HashMap<String, String>) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        if let Some(tail) = after.strip_prefix("~dp0") {
            out.push(SENT);
            rest = tail;
            continue;
        }
        let Some(j) = after.find('%') else {
            return Err(trs!("непарный %").into());
        };
        let name = after[..j].to_ascii_uppercase();
        match vars.get(&name) {
            Some(v) => out.push_str(v),
            None => return Err(tr!("неизвестная переменная %{}%", &after[..j])),
        }
        rest = &after[j + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Путь после метки папки .bat → путь от корня папки zapret. Без выхода наружу.
fn rel_path(bat_dir: &Path, tail: &str) -> Result<String, String> {
    let tail = tail.replace('\\', "/");
    if tail.contains(':') || tail.starts_with('/') {
        return Err(tr!("путь «{tail}» — не внутри папки"));
    }
    let mut parts: Vec<String> = bat_dir
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    for seg in tail.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(tr!("путь «{tail}» выходит за папку zapret"));
                }
            }
            s => parts.push(s.to_string()),
        }
    }
    if parts.is_empty() {
        return Err(trs!("пустой путь").into());
    }
    // Имена — только простые: путь уходит в командную строку winws, а cygwin
    // разбирает её по-своему (кавычки ' и ", маски *?[ ).
    if let Some(bad) = parts.iter().find(|p| !p.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))) {
        return Err(tr!("файл «{bad}»: в имени необычные символы"));
    }
    // Имена устройств Windows: «COM1.txt» — это порт, а не файл (и NUL, CON…).
    if let Some(bad) = parts.iter().find(|p| reserved_name(p) || p.ends_with('.')) {
        return Err(tr!("«{bad}» — имя устройства Windows, не файл"));
    }
    Ok(parts.join("/"))
}

/// Простое имя файла (для lists/ и bin/): те же правила, что у путей в стратегиях.
fn safe_file_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 200 && n.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) && !reserved_name(n) && !n.ends_with('.')
}

fn reserved_name(part: &str) -> bool {
    // «COM1 .txt», «com¹.bat», «CONIN$» — Windows всё это считает устройствами.
    let stem = part.split('.').next().unwrap_or("").trim_end_matches([' ', '.']).to_uppercase();
    let dev = |p: &str| {
        stem.strip_prefix(p).is_some_and(|d| {
            let mut c = d.chars();
            matches!((c.next(), c.next()), (Some('0'..='9' | '¹' | '²' | '³'), None))
        })
    };
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$") || dev("COM") || dev("LPT")
}

/// Значение опции winws: числа, слова, списки, IP, hex. Ничего, что cygwin
/// понял бы как кавычки, маску или ответ-файл.
fn safe_text(v: &str) -> bool {
    !v.is_empty() && v.len() <= 4096 && v.chars().all(|c| c.is_ascii_alphanumeric() || "._,:+=/-!~".contains(c))
}

/// Разобрать одну стратегию. `bat_dir` — папка файла от корня ("" для корня).
pub fn parse_bat(text: &str, bat_dir: &Path, game_filter: bool) -> Result<(Vec<Arg>, Vec<String>), String> {
    let mut vars: HashMap<String, String> = HashMap::new();
    let game = if game_filter { "1024-65535" } else { "12" };
    for v in ["GAMEFILTER", "GAMEFILTERTCP", "GAMEFILTERUDP"] {
        vars.insert(v.into(), game.into());
    }
    let mut cmdline = None;
    for line in join_carets(text) {
        let t = line.trim();
        let low = t.to_ascii_lowercase();
        if low.starts_with("::") || low.starts_with("rem ") || low.starts_with('@') && !low.contains("winws") {
            continue;
        }
        // set "BIN=%~dp0bin\"  /  set LISTS=%~dp0lists\
        if let Some(rest) = low.strip_prefix("set ").map(|_| t[4..].trim()) {
            let rest = rest.trim_matches('"');
            if let Some((k, v)) = rest.split_once('=') {
                // Не разобрали значение — переменную просто не знаем; ошибка будет,
                // только если стратегия её использует.
                if let (false, false, Ok(val)) = (k.trim().is_empty(), k.contains(' '), expand(v, &vars)) {
                    vars.insert(k.trim().to_ascii_uppercase(), val);
                }
            }
            continue;
        }
        // Стратегия — это запуск winws.exe, сразу за которым идут его опции.
        // (В service.bat winws.exe тоже встречается — в tasklist и т.п.)
        if let Some(i) = low.find("winws.exe") {
            let rest = t[i + "winws.exe".len()..].trim_start_matches('"').trim_start();
            if rest.starts_with("--") {
                cmdline = Some(rest.to_string());
                break;
            }
        }
    }
    let cmd = cmdline.ok_or(trs!("нет запуска winws.exe — не стратегия"))?;
    let cmd = expand(&cmd, &vars)?;

    let mut args = Vec::new();
    let mut notes = Vec::new();
    for tok in tokenize(&cmd) {
        let Some(opt) = tok.strip_prefix("--") else {
            return Err(tr!("«{tok}» — не опция winws"));
        };
        let (name, value) = match opt.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (opt.to_string(), None),
        };
        if DROPPED.contains(&name.as_str()) {
            notes.push(tr!("убрал --{name}"));
            continue;
        }
        if !ALLOWED.contains(&name.as_str()) {
            return Err(tr!("незнакомая опция --{name}"));
        }
        match (&value, NO_ARG.contains(&name.as_str()), OPT_ARG.contains(&name.as_str())) {
            (None, false, false) => return Err(tr!("--{name}: нужно значение")),
            (Some(_), true, _) => return Err(tr!("--{name} не принимает значения")),
            _ => {}
        }
        let val = match value {
            None => Val::None,
            Some(v) if v.contains(SENT) => {
                let (at, path) = match v.strip_prefix('@') {
                    Some(p) => (true, p),
                    None => (false, v.as_str()),
                };
                let Some(tail) = path.strip_prefix(SENT) else {
                    return Err(tr!("--{name}: путь в середине значения"));
                };
                if tail.contains(SENT) {
                    return Err(tr!("--{name}: странный путь"));
                }
                let rel = rel_path(bat_dir, tail)?;
                match (at, name.as_str()) {
                    (true, "wf-raw-part") => Val::AtFile(rel),
                    (false, n) if FILE_OPTS.contains(&n) => Val::File(rel),
                    _ => return Err(tr!("--{name} не принимает файл")),
                }
            }
            Some(v) => {
                // Без меток — значит, не путь в папке. Пути наружу не пускаем.
                let looks_path = v.contains('\\') || v.contains(":/") || v.contains("..") || v.starts_with('@');
                if looks_path {
                    return Err(tr!("--{name}={v}: путь вне папки zapret"));
                }
                if FILE_OPTS.contains(&name.as_str()) && !(v.starts_with("0x") || v.starts_with('!')) {
                    return Err(tr!("--{name}={v}: ждали файл из папки"));
                }
                if !safe_text(&v) {
                    return Err(tr!("--{name}: в значении необычные символы"));
                }
                Val::Text(v)
            }
        };
        args.push(Arg { name, val });
    }
    if args.is_empty() {
        return Err(trs!("пустая стратегия").into());
    }
    Ok((args, notes))
}

/// Имя стратегии сохраняется в настройках — те же ограничения, что там.
fn strategy_name_ok(f: &Path) -> bool {
    let n = f.file_stem().unwrap_or_default().to_string_lossy();
    // Управляющие и «невидимые» символы (U+200B…U+200F, U+202A…U+202E, U+2066…U+2069, BOM)
    // путают имя в окне — такие файлы не показываем.
    let invisible = |c: char| c.is_control() || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{00AD}');
    !n.is_empty() && n.chars().count() <= 200 && !n.chars().any(invisible)
}

/// Найти стратегии в папке (и на уровень глубже — так устроен zapret-win-bundle).
pub fn scan(root: &Path, game_filter: bool) -> Result<Scan, String> {
    let rd = std::fs::read_dir(root).map_err(|e| tr!("не открыть папку: {e}"))?;
    let mut dirs = vec![PathBuf::new()];
    for e in rd.flatten() {
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            dirs.push(PathBuf::from(e.file_name()));
        }
    }
    let mut out = Scan::default();
    for d in &dirs {
        let Ok(rd) = std::fs::read_dir(root.join(d)) else { continue };
        let mut files: Vec<PathBuf> = rd
            .flatten()
            // Ссылки (symlink/junction) пропускаем: чтение через них может уйти
            // куда угодно, вплоть до сетевой папки (а Windows отдаст ей хеш пароля).
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| e.path())
            .filter(|p| {
                p.extension().is_some_and(|x| x.eq_ignore_ascii_case("bat") || x.eq_ignore_ascii_case("cmd"))
            })
            .collect();
        files.sort_by_key(|p| natural_key(&p.file_stem().unwrap_or_default().to_string_lossy()));
        for f in files {
            let rel = d.join(f.file_name().unwrap_or_default());
            let shown = rel.to_string_lossy().replace('\\', "/");
            let Ok(meta) = std::fs::metadata(&f) else { continue };
            if meta.len() > 1 << 20 {
                out.skipped.push(tr!("{shown} — слишком большой для стратегии"));
                continue;
            }
            let text = String::from_utf8_lossy(&std::fs::read(&f).unwrap_or_default()).into_owned();
            if !text.to_ascii_lowercase().contains("winws.exe") {
                continue; // service.bat и прочее — не стратегии, молча
            }
            match parse_bat(&text, d, game_filter) {
                Err(e) if e.starts_with(trs!("нет запуска winws.exe — не стратегия")) => {} // не стратегия — молча
                Ok(_) if !strategy_name_ok(&f) => out.skipped.push(tr!("{shown} — слишком длинное или странное имя файла")),
                Ok((args, notes)) => out.strategies.push(Strategy {
                    name: f.file_stem().unwrap_or_default().to_string_lossy().into_owned(),
                    file: shown,
                    args,
                    notes,
                }),
                Err(e) => out.skipped.push(format!("{shown} — {e}")),
            }
        }
    }
    // Движок в папке: bin/ (Flowseal) или рядом со стратегиями (bundle).
    let engine = engine_dir_in(root)
        .map(|d| check_folder_engine(&d))
        .unwrap_or_else(|| Err(trs!("в папке нет winws.exe").into()));
    match engine {
        Ok(v) => out.engine_version = Some(v),
        Err(e) => out.engine_problem = Some(e),
    }
    if out.strategies.is_empty() && out.skipped.is_empty() {
        return Err(trs!("в папке нет стратегий zapret (.bat/.cmd с winws.exe)").into());
    }
    Ok(out)
}

/// Где в папке лежит winws.exe: bin/ (Flowseal) или рядом со стратегиями (bundle).
pub fn engine_dir_in(root: &Path) -> Option<PathBuf> {
    let plain = |p: &Path, dir: bool| {
        std::fs::symlink_metadata(p).is_ok_and(|m| !m.file_type().is_symlink() && if dir { m.is_dir() } else { m.is_file() })
    };
    let mut cands = vec![root.to_path_buf()];
    if let Ok(rd) = std::fs::read_dir(root) {
        let mut subs: Vec<PathBuf> = rd.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.path()).collect();
        // bin/ (Flowseal) — первым.
        subs.sort_by_key(|p| !p.file_name().is_some_and(|n| n.eq_ignore_ascii_case("bin")));
        cands.splice(0..0, subs);
    }
    cands.into_iter().find(|d| plain(d, true) && plain(&d.join("winws.exe"), false))
}

/// Путь внутри папки без ссылок (symlink/junction) по дороге: через ссылку
/// чтение ушло бы куда угодно, вплоть до сетевой папки.
fn no_links(root: &Path, rel: &str) -> Result<(), String> {
    let mut p = root.to_path_buf();
    for part in rel.split('/') {
        p.push(part);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_symlink() => return Err(tr!("{rel}: это ссылка (symlink) — по ссылкам не хожу")),
            Ok(_) => {}
            Err(_) => return Ok(()), // файла нет — дальше разберутся
        }
    }
    Ok(())
}

fn check_folder_engine(dir: &Path) -> Result<String, String> {
    let mut ver = String::new();
    for f in ENGINE_FILES {
        let data = read_small(&dir.join(f))?;
        match known(f, &data) {
            Some(v) if f == "winws.exe" => ver = v.to_string(),
            Some(_) => {}
            None => return Err(tr!("{f} не совпадает ни с одной официальной сборкой — возможно, подделка")),
        }
    }
    Ok(ver)
}

/// «general (ALT10)» после «general (ALT9)», а «general (ALT)» — перед ALT2.
/// Ключ: текст без цифр + число из цифр (у Flowseal номер один на имя).
fn natural_key(s: &str) -> (String, u64, String) {
    let low = s.to_lowercase();
    let text: String = low.chars().filter(|c| !c.is_ascii_digit()).collect();
    let num: String = low.chars().filter(|c| c.is_ascii_digit()).collect();
    (text, num.parse().unwrap_or(0), low)
}

/// Кусок фильтра WinDivert winws вставляет в скобки, а после них добавляет
/// «и не локальная сеть». Лишняя «)» в куске закрыла бы скобку раньше — и
/// фильтр захватил бы трафик к роутеру и к самому компу. Поэтому: только текст
/// и скобки в балансе.
fn check_wf_part(rel: &str, p: &Path) -> Result<(), String> {
    let data = std::fs::read(p).map_err(|e| format!("{rel}: {e}"))?;
    if data.len() > 16 * 1024 || !data.iter().all(|&b| b.is_ascii_graphic() || b" \t\r\n".contains(&b)) {
        return Err(tr!("{rel}: не похоже на фильтр WinDivert"));
    }
    let mut depth = 0i32;
    for &b in &data {
        depth += match b {
            b'(' => 1,
            b')' => -1,
            _ => 0,
        };
        if depth < 0 {
            return Err(tr!("{rel}: скобки фильтра не в балансе — он вышел бы за свои рамки"));
        }
    }
    if depth != 0 {
        return Err(tr!("{rel}: скобки фильтра не в балансе"));
    }
    Ok(())
}

/// Подготовить запуск: скопировать файлы стратегии в рабочую папку `run` и собрать
/// аргументы. Пути в аргументах — относительные («files/lists/x.txt»): winws
/// запускается с текущей папкой `run`, и в командную строку не попадают пробелы,
/// кириллица и прочее из пути, куда человек положил rxvpn.
/// Пропавший *-user.txt создаём, как это делает Flowseal.
pub fn prepare(root: &Path, s: &Strategy, run: &Path) -> Result<Vec<OsString>, String> {
    let files = run.join("files");
    if files.exists() {
        // Не стёрлось — значит, файлы ещё держит прошлый winws: старые списки не берём.
        std::fs::remove_dir_all(&files).map_err(|e| tr!("рабочая папка zapret занята ({e}) — winws ещё работает?"))?;
    }
    std::fs::create_dir_all(&files).map_err(|e| e.to_string())?;
    let root_c = std::fs::canonicalize(root).map_err(|e| tr!("папка zapret: {e}"))?;
    let place = |rel: &str| -> Result<PathBuf, String> {
        let dst = files.join(rel);
        if let Some(p) = dst.parent() {
            std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        if dst.exists() {
            return Ok(dst);
        }
        no_links(root, rel)?;
        let src = root.join(rel);
        match std::fs::canonicalize(&src) {
            Ok(c) => {
                // Ярлык/ссылка, уводящая из папки, — нет.
                if !c.starts_with(&root_c) || !c.is_file() {
                    return Err(tr!("{rel}: ведёт за пределы папки zapret"));
                }
                if std::fs::metadata(&c).map(|m| m.len()).unwrap_or(0) > 64 << 20 {
                    return Err(tr!("{rel}: слишком большой"));
                }
                std::fs::copy(&c, &dst).map_err(|e| format!("{rel}: {e}"))?;
            }
            Err(_) => {
                let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
                // Так их создаёт service.bat Flowseal (пустыми оставлять нельзя).
                let stub = if name.starts_with("ipset") && name.ends_with("-user.txt") {
                    "203.0.113.113/32\n"
                } else if name.ends_with("-user.txt") {
                    "domain.example.abc\n"
                } else {
                    return Err(tr!("в папке нет файла {rel}"));
                };
                std::fs::write(&dst, stub).map_err(|e| e.to_string())?;
            }
        }
        Ok(dst)
    };
    let mut out = Vec::new();
    for a in &s.args {
        let mut o = OsString::from(format!("--{}", a.name));
        match &a.val {
            Val::None => {}
            Val::Text(t) => o.push(format!("={t}")),
            Val::File(rel) => {
                place(rel)?;
                o.push(format!("=files/{rel}"));
            }
            Val::AtFile(rel) => {
                check_wf_part(rel, &place(rel)?)?;
                o.push(format!("=@files/{rel}"));
            }
        }
        out.push(o);
    }
    Ok(out)
}

/// Свои сайты — в список, который стратегии Flowseal и так берут
/// (lists/list-general-user.txt в рабочей папке): winws будет обходить
/// блокировку и для них. Списки исключений не трогаем. Сколько дописали.
pub fn add_user_hosts(run: &Path, hosts: &[String]) -> usize {
    // «https://site.com/page» из сайтов для проверки — в списке нужно только имя.
    let hosts: Vec<String> = hosts
        .iter()
        .map(|h| h.trim())
        .filter_map(|h| match url::Url::parse(h) {
            Ok(u) if h.contains("://") => u.host_str().map(str::to_string),
            _ => Some(h.to_ascii_lowercase()),
        })
        .filter(|h| h.len() <= 253 && h.contains('.') && h.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        .take(1000)
        .collect();
    if hosts.is_empty() {
        return 0;
    }
    let mut done = 0;
    let mut stack = vec![(run.join("files"), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let Ok(t) = e.file_type() else { continue };
            if t.is_dir() && depth < 3 {
                stack.push((p, depth + 1));
            } else if t.is_file() && e.file_name().to_string_lossy().eq_ignore_ascii_case("list-general-user.txt") {
                let mut text = std::fs::read_to_string(&p).unwrap_or_default();
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                for h in &hosts {
                    text.push_str(h);
                    text.push('\n');
                }
                if std::fs::write(&p, text).is_ok() {
                    done += 1;
                }
            }
        }
    }
    done
}

// ---------------- гибрид: zapret рядом с VPN ----------------

/// Как winws работать рядом с VPN: только на настоящей сетевой карте (в TUN
/// иначе он портил бы пакеты, которые программы отдают в туннель) и не трогая
/// соединения с самими VPN-серверами.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Hybrid {
    /// Номер сетевой карты (Windows ifIndex), None — все (режим «Прокси»).
    pub iface: Option<u32>,
    /// IP VPN-серверов — их соединения winws пропускает как есть.
    pub exclude: Vec<std::net::IpAddr>,
}

/// Файл с адресами VPN-серверов (в рабочей папке, рядом со списками).
const HYBRID_EXCLUDE: &str = "rxvpn-vpn-servers.txt";

/// Подготовить запуск стратегии для гибрида: как `prepare`, плюс список
/// исключённых адресов в каждом профиле winws (профили разделяет --new) и
/// --wf-iface, если нужен.
pub fn prepare_hybrid(root: &Path, s: &Strategy, run: &Path, h: &Hybrid) -> Result<Vec<OsString>, String> {
    let args = prepare(root, s, run)?;
    let mut list: String = h.exclude.iter().map(|ip| format!("{ip}\n")).collect();
    if list.is_empty() {
        list = "203.0.113.113/32\n".into(); // пустой список winws не принимает
    }
    std::fs::write(run.join("files").join(HYBRID_EXCLUDE), list).map_err(|e| e.to_string())?;
    let ex = OsString::from(format!("--ipset-exclude=files/{HYBRID_EXCLUDE}"));
    let mut out = Vec::new();
    if let Some(i) = h.iface {
        out.push(OsString::from(format!("--wf-iface={i}")));
    }
    for a in args {
        if a == "--new" {
            out.push(ex.clone());
        }
        out.push(a);
    }
    out.push(ex);
    Ok(out)
}

/// Что проверяем в фоне: работает ли ещё стратегия (YouTube и Discord) и есть
/// ли вообще интернет (ya.ru не блокируют — не открылся, значит, сеть упала).
pub const HEALTH_TARGETS: &[(&str, &str)] = &[
    ("YouTube", "https://www.youtube.com"),
    ("YouTube video", "https://redirector.googlevideo.com"),
    ("YouTube images", "https://i.ytimg.com"),
    ("Discord", "https://discord.com"),
    ("Discord Gateway", "https://gateway.discord.gg"),
];
pub const CONTROL_TARGET: (&str, &str) = ("Yandex", "https://ya.ru");

/// Итог фоновой проверки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Fine,
    /// Пробивать перестало: YouTube или Discord не открываются совсем.
    Broken,
    /// Интернета нет вовсе — стратегия ни при чём.
    Offline,
}

pub fn health_of(control_ok: bool, targets: &[TargetResult]) -> Health {
    if !control_ok {
        return Health::Offline;
    }
    // Как браузер: TLS 1.3 и страница целиком. Ответ по TLS 1.2 при обрыве
    // на 16–20 КБ — это и есть «замедлялка», а не «работает».
    let dead = |name: &str| targets.iter().find(|t| t.name == name).is_some_and(|t| !t.full);
    if dead("YouTube") || dead("YouTube video") || dead("Discord") {
        Health::Broken
    } else {
        Health::Fine
    }
}

// ---------------- проверка: какая стратегия открывает сайты ----------------

/// Что проверяем по умолчанию (как в test zapret.ps1 от Flowseal).
pub const DEFAULT_TARGETS: &[(&str, &str)] = &[
    ("Discord", "https://discord.com"),
    ("Discord Gateway", "https://gateway.discord.gg"),
    ("Discord CDN", "https://cdn.discordapp.com"),
    ("Discord Updates", "https://updates.discord.com"),
    ("YouTube", "https://www.youtube.com"),
    ("youtu.be", "https://youtu.be"),
    ("YouTube images", "https://i.ytimg.com"),
    ("YouTube video", "https://redirector.googlevideo.com"),
    ("Google", "https://www.google.com"),
    ("Cloudflare", "https://www.cloudflare.com"),
];

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TargetResult {
    pub name: String,
    pub url: String,
    /// Прошло проверок из 2 (TLS 1.3 с чтением ответа, TLS 1.2).
    pub ok: u8,
    /// Прошла главная — TLS 1.3 и ответ целиком (так ходит браузер).
    pub full: bool,
    /// Обрыв после первых килобайт — типичная «заморозка на 16–20 КБ».
    pub stalled: bool,
    pub ms: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Score {
    /// Имя стратегии; "" — без zapret.
    pub name: String,
    pub ok: u32,
    pub total: u32,
    /// Суммарное время удачных проверок.
    pub ms: u64,
    pub targets: Vec<TargetResult>,
    pub error: Option<String>,
}

impl Score {
    /// Лучше: больше прошло, при равенстве — быстрее.
    fn better(&self, o: &Score) -> bool {
        self.ok > o.ok || (self.ok == o.ok && self.ms < o.ms)
    }
}

const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";

fn client(tls: Option<reqwest::tls::Version>, timeout: Duration) -> Option<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        // Обычный браузерный: своё имя в каждой проверке выдавало бы rxvpn.
        .user_agent(BROWSER_UA);
    if let Some(v) = tls {
        b = b.min_tls_version(v).max_tls_version(v);
    }
    b.build().ok()
}

/// Одна цель: TLS 1.3 (и дочитать до 64 КБ — ловит обрыв на 16–20 КБ) и
/// TLS 1.2. Успех — любой ответ сервера. Обычный HTTP не проверяем: браузер
/// туда не ходит, а открытым текстом провайдер видел бы каждую проверку.
pub async fn check_target(name: &str, url: &str, timeout: Duration) -> TargetResult {
    use reqwest::tls::Version;
    let t0 = Instant::now();
    let mut ok = 0u8;
    let mut stalled = false;
    let mut full = false;
    let mut ms = 0u64;
    // TLS 1.3 + тело
    if let Some(c) = client(Some(Version::TLS_1_3), timeout) {
        let t = Instant::now();
        if let Ok(mut r) = c.get(url).send().await {
            let mut got = 0usize;
            let mut fine = true;
            loop {
                match r.chunk().await {
                    Ok(Some(ch)) => {
                        got += ch.len();
                        if got >= 64 * 1024 {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        fine = false;
                        break;
                    }
                }
            }
            if fine {
                ok += 1;
                full = true;
                ms += t.elapsed().as_millis() as u64;
            } else if got > 0 {
                stalled = true;
            }
        }
    }
    if let Some(c) = client(Some(Version::TLS_1_2), timeout) {
        let t = Instant::now();
        if c.get(url).send().await.is_ok() {
            ok += 1;
            ms += t.elapsed().as_millis() as u64;
        }
    }
    let _ = t0;
    TargetResult { name: name.into(), url: url.into(), ok, full, stalled, ms }
}

/// Проверок на одну цель.
const CHECKS: u32 = 2;

/// Проверить все цели параллельно.
pub async fn check_all(targets: &[(String, String)], timeout: Duration) -> (u32, u32, u64, Vec<TargetResult>) {
    let mut set = tokio::task::JoinSet::new();
    for (i, (n, u)) in targets.iter().cloned().enumerate() {
        set.spawn(async move { (i, check_target(&n, &u, timeout).await) });
    }
    let mut res: Vec<(usize, TargetResult)> = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(x) = r {
            res.push(x);
        }
    }
    res.sort_by_key(|x| x.0);
    let list: Vec<TargetResult> = res.into_iter().map(|x| x.1).collect();
    let ok = list.iter().map(|t| t.ok as u32).sum();
    let ms = list.iter().map(|t| t.ms).sum();
    (ok, targets.len() as u32 * CHECKS, ms, list)
}

/// Кто запускает стратегию (в приложении — winws, в тестах — заглушка).
/// Возвращает «ручку»: пока живёт — стратегия работает.
pub trait Launcher: Send + Sync {
    fn start(&self, s: &Strategy) -> Result<Box<dyn Send>, String>;
}

/// Прогнать все стратегии и выбрать лучшую. Первая строка — «без zapret».
/// `progress(готово, всего, последний результат)`.
pub async fn pick_best(
    launcher: Arc<dyn Launcher>,
    strategies: &[Strategy],
    targets: &[(String, String)],
    timeout: Duration,
    warmup: Duration,
    cancel: Arc<AtomicBool>,
    progress: impl Fn(usize, usize, &Score) + Send + Sync,
) -> Vec<Score> {
    let total = strategies.len() + 1;
    let (ok, all, ms, t) = check_all(targets, timeout).await;
    let base = Score { name: String::new(), ok, total: all, ms, targets: t, error: None };
    progress(1, total, &base);
    let mut out = vec![base];
    for (i, s) in strategies.iter().enumerate() {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        let l = launcher.clone();
        let st = s.clone();
        let started = tokio::task::spawn_blocking(move || l.start(&st)).await.map_err(|e| e.to_string()).and_then(|r| r);
        let score = match started {
            Ok(guard) => {
                tokio::time::sleep(warmup).await;
                let (ok, all, ms, t) = check_all(targets, timeout).await;
                drop(guard);
                Score { name: s.name.clone(), ok, total: all, ms, targets: t, error: None }
            }
            Err(e) => Score { name: s.name.clone(), ok: 0, total: targets.len() as u32 * CHECKS, ms: 0, targets: vec![], error: Some(e) },
        };
        progress(i + 2, total, &score);
        out.push(score);
    }
    out
}

/// Лучшая из проверенных (не «без zapret»).
pub fn best(scores: &[Score]) -> Option<&Score> {
    scores
        .iter()
        .skip(1)
        .filter(|s| s.error.is_none() && s.ok > 0)
        .fold(None, |b: Option<&Score>, s| match b {
            Some(b) if !s.better(b) => Some(b),
            _ => Some(s),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOWSEAL_LINE: &str = r#"@echo off
chcp 65001 > nul
:: 65001 - UTF-8
cd /d "%~dp0"
call service.bat status_zapret
set "BIN=%~dp0bin\"
set "LISTS=%~dp0lists\"
cd /d %BIN%

start "zapret: %~n0" /min "%BIN%winws.exe" --wf-tcp=80,443,%GameFilterTCP% --wf-udp=443,%GameFilterUDP% ^
--filter-udp=443 --hostlist="%LISTS%list-general.txt" --hostlist="%LISTS%list-general-user.txt" --dpi-desync=fake --dpi-desync-repeats=6 --dpi-desync-fake-quic="%BIN%quic_initial_www_google_com.bin" --new ^
--filter-tcp=443 --hostlist-domains=discord.media --dpi-desync=multisplit --dpi-desync-split-seqovl-pattern="%BIN%tls_clienthello_www_google_com.bin" --dpi-desync-fakedsplit-pattern=0x00
"#;

    #[test]
    fn parses_flowseal_style() {
        let (args, notes) = parse_bat(FLOWSEAL_LINE, Path::new(""), false).unwrap();
        assert!(notes.is_empty());
        assert_eq!(args[0], Arg { name: "wf-tcp".into(), val: Val::Text("80,443,12".into()) });
        assert_eq!(args[2].val, Val::Text("443".into()));
        assert_eq!(args[3].val, Val::File("lists/list-general.txt".into()));
        assert!(args.iter().any(|a| a.val == Val::File("bin/quic_initial_www_google_com.bin".into())));
        assert!(args.iter().any(|a| a.name == "new" && a.val == Val::None));
        assert!(args.iter().any(|a| a.name == "dpi-desync-fakedsplit-pattern" && a.val == Val::Text("0x00".into())));
        let (g, _) = parse_bat(FLOWSEAL_LINE, Path::new(""), true).unwrap();
        assert_eq!(g[0].val, Val::Text("80,443,1024-65535".into()), "игровой фильтр");
    }

    #[test]
    fn rejects_hostile_strategies() {
        let mk = |extra: &str| format!("set \"BIN=%~dp0bin\\\"\nstart \"z\" /min \"%BIN%winws.exe\" --wf-tcp=443 {extra}\n");
        for (bad, why) in [
            ("--hostlist=C:\\Windows\\System32\\x.txt", "путь наружу"),
            ("--hostlist=\\\\evil\\share\\l.txt", "UNC"),
            ("--hostlist=\"%~dp0..\\..\\x.txt\"", "выход вверх"),
            ("--wf-raw=@C:\\x.txt", "@ наружу"),
            ("--frobnicate=1", "неизвестная опция"),
            ("--hostlist=list.txt", "файл без папки"),
            ("--dpi-desync=fake & calc.exe", "лишнее после опций"),
            ("--wf-tcp=%PATH%", "переменная окружения"),
            ("--dpi-desync=\"%BIN%x\"", "файл там, где не ждут"),
            // cygwin сам разбирает командную строку: кавычки, маски, ответ-файлы.
            ("--dpi-desync=\"fake ^\" --debug=@C:\\x\"", "кавычка внутри значения"),
            ("--dpi-desync=fake'x", "одинарная кавычка"),
            ("--hostlist-domains=*.ru", "маска"),
            ("--dpi-desync=\"fake split\"", "пробел в значении"),
            ("--hostlist=\"%~dp0lists\\it's.txt\"", "кавычка в имени файла"),
            ("--hostlist=\"%~dp0my lists\\a.txt\"", "пробел в имени папки"),
            // Значение обязательно: иначе getopt съест следующий аргумент как значение.
            ("--hostlist-auto --new", "опция без значения"),
            ("--new=1", "значение там, где его не бывает"),
            // Полный сырой фильтр WinDivert обходит защиту локальной сети.
            ("--wf-raw=@%~dp0bin\\f.txt", "wf-raw"),
            ("--wf-raw-part=%~dp0bin\\f.txt", "кусок фильтра без @"),
            // Имена устройств Windows — не файлы.
            ("--hostlist=\"%~dp0lists\\COM1.-user.txt\"", "COM1"),
            ("--hostlist=\"%~dp0lists\\nul\"", "NUL"),
            ("--hostlist=\"%~dp0lists\\x.txt.\"", "точка в конце"),
        ] {
            assert!(parse_bat(&mk(bad), Path::new(""), false).is_err(), "{why}: {bad}");
        }
        // «^!» у Flowseal — экранированный «!» (встроенная заготовка winws).
        let (a, _) = parse_bat(&mk("--dpi-desync-fake-tls=^! --dpi-desync-fake-tls-mod=rnd,dupsid,sni=www.google.com"), Path::new(""), false).unwrap();
        assert_eq!(a[1].val, Val::Text("!".into()));
        assert_eq!(a[2].val, Val::Text("rnd,dupsid,sni=www.google.com".into()));
        // service.bat: winws.exe есть, но не запуск стратегии.
        assert!(parse_bat("tasklist /FI \"IMAGENAME eq winws.exe\" | find /I \"winws.exe\" > nul\n", Path::new(""), false)
            .unwrap_err()
            .starts_with("нет запуска"));
        // Необязательное значение — можно и так, и так.
        assert!(parse_bat(&mk("--dpi-desync-autottl --dpi-desync-any-protocol=1 --new --wf-filter-lan=0"), Path::new(""), false)
            .is_ok_and(|(a, n)| a.iter().all(|x| x.name != "wf-filter-lan") && n.len() == 1));
        // Пишущие файлы опции вырезаются, стратегия остаётся.
        let (args, notes) = parse_bat(&mk("--debug=@C:\\Windows\\log.txt --pidfile=C:\\x --wf-save=C:\\y --dpi-desync=fake"), Path::new(""), false).unwrap();
        assert!(args.iter().all(|a| !["debug", "pidfile", "wf-save"].contains(&a.name.as_str())));
        assert_eq!(notes.len(), 3);
        // Вверх из подпапки — можно, пока внутри корня (zapret-win-bundle).
        let bundle = "start \"z\" /min \"%~dp0winws.exe\" --wf-tcp=443 --hostlist=\"%~dp0..\\files\\list.txt\"\n";
        let (a, _) = parse_bat(bundle, Path::new("zapret-winws"), false).unwrap();
        assert_eq!(a[1].val, Val::File("files/list.txt".into()));
        assert!(parse_bat("echo hi\n", Path::new(""), false).is_err());
    }

    #[test]
    fn natural_order() {
        let mut v = vec!["general (ALT10)", "general (ALT2)", "general", "general (ALT)", "general (ALT9)"];
        v.sort_by_key(|s| natural_key(s));
        assert_eq!(v, ["general", "general (ALT)", "general (ALT2)", "general (ALT9)", "general (ALT10)"]);
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rxvpn-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn mkzip(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (n, d) in files {
            w.start_file(*n, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(d).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn builtin_strategies_ready() {
        let root = tmpdir("zbuiltin");
        let dir = root.join("strategies");
        let s = ensure_builtin(&dir, 100).unwrap();
        assert_eq!((s.version.as_str(), s.from_github), (BUILTIN_VERSION, false));
        let sc = scan(&dir, false).unwrap();
        assert_eq!(sc.strategies.len(), 22, "{:?}", sc.skipped);
        assert!(sc.skipped.is_empty(), "{:?}", sc.skipped);
        assert!(sc.engine_version.is_none(), "движка во встроенном нет — его качаем");
        for st in &sc.strategies {
            prepare(&dir, st, &root.join("run")).unwrap_or_else(|e| panic!("{}: {e}", st.name));
        }
        assert!(dir.join("LICENSE.txt").exists(), "лицензия MIT — с собой");
        // Второй раз — не перекладываем.
        assert_eq!(ensure_builtin(&dir, 200).unwrap().installed_at, 100);
        // Испортили (стратегий нет) — разложим заново.
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            if e.path().extension().is_some_and(|x| x == "bat") {
                std::fs::remove_file(e.path()).unwrap();
            }
        }
        assert_eq!(ensure_builtin(&dir, 300).unwrap().installed_at, 300);
        // В папке старая версия с GitHub (rxvpn обновили) — встроенная новее, берём её.
        std::fs::write(dir.join(SOURCE_FILE), "1.9.0\ngithub\n5\n").unwrap();
        assert_eq!(ensure_builtin(&dir, 400).unwrap().version, BUILTIN_VERSION);
        // А свежее встроенной — оставляем.
        std::fs::write(dir.join(SOURCE_FILE), "1.11.0\ngithub\n5\n").unwrap();
        assert!(ensure_builtin(&dir, 500).unwrap().from_github);
        assert!(version_less("1.10.4", "1.10.10") && !version_less("1.10.4", "1.10.4") && version_less("1.9", "1.10"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn downloaded_strategies_are_filtered() {
        let root = tmpdir("zinstall");
        let dir = root.join("strategies");
        let bat = FLOWSEAL_LINE.as_bytes();
        let z = mkzip(&[
            ("zapret-discord-youtube-9.9/", b""),
            ("zapret-discord-youtube-9.9/general.bat", bat),
            ("zapret-discord-youtube-9.9/general (ALT).bat", bat),
            ("zapret-discord-youtube-9.9/service.bat", b"set \"LOCAL_VERSION=9.9.1\"\r\necho"),
            ("zapret-discord-youtube-9.9/COM1.bat", bat),
            ("zapret-discord-youtube-9.9/sub/deep.bat", bat),
            ("zapret-discord-youtube-9.9/lists/list-general.txt", b"youtube.com\n"),
            ("zapret-discord-youtube-9.9/lists/my list.txt", b"x"),
            ("zapret-discord-youtube-9.9/bin/quic_initial_www_google_com.bin", b"q"),
            ("zapret-discord-youtube-9.9/bin/tls_clienthello_www_google_com.bin", b"t"),
            ("zapret-discord-youtube-9.9/bin/winws.exe", b"MZ not official"),
            ("zapret-discord-youtube-9.9/bin/evil.dll", b"MZ"),
            ("zapret-discord-youtube-9.9/utils/test zapret.ps1", b"rm -rf"),
            ("zapret-discord-youtube-9.9/../../escape.bat", bat),
        ]);
        let s = install_strategies(&z, &dir, Some("9.9"), true, 7).unwrap();
        assert_eq!((s.version.as_str(), s.from_github), ("9.9", true), "версия — тег релиза, а не надпись в архиве");
        let mut got: Vec<String> = Vec::new();
        for d in ["", "lists", "bin"] {
            for e in std::fs::read_dir(dir.join(d)).unwrap().flatten() {
                if e.file_type().unwrap().is_file() {
                    got.push(format!("{d}/{}", e.file_name().to_string_lossy()));
                }
            }
        }
        got.sort();
        assert_eq!(got, ["/.rxvpn-source", "/general (ALT).bat", "/general.bat", "bin/quic_initial_www_google_com.bin", "bin/tls_clienthello_www_google_com.bin", "lists/list-general.txt"]);
        assert!(!root.join("escape.bat").exists() && !dir.join("sub").exists() && !dir.join("utils").exists());
        assert_eq!(source_of(&dir).unwrap(), s);
        // Архив без годных стратегий — старое остаётся как было.
        let bad = mkzip(&[("x/general.bat", b"echo hi"), ("x/lists/a.txt", b"1")]);
        assert!(install_strategies(&bad, &dir, None, true, 8).is_err());
        assert_eq!(source_of(&dir).unwrap().installed_at, 7);
        assert!(dir.join("general.bat").exists());
        assert!(install_strategies(b"not a zip", &dir, None, true, 9).is_err());
        // Огромный файл в архиве — отказ.
        let big = vec![b'a'; (16 << 20) + 10];
        let z = mkzip(&[("general.bat", bat), ("lists/list-general.txt", &big)]);
        assert!(install_strategies(&z, &dir, None, true, 10).unwrap_err().contains("большой"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn installs_do_not_mix_and_names_are_plain() {
        // Две раскладки одновременно (окно + автоподключение / «Обновить») — каждая целиком.
        let root = tmpdir("zrace");
        let dir = root.join("strategies");
        let bat = FLOWSEAL_LINE.as_bytes();
        let gh = mkzip(&[("x/general (GH).bat", bat), ("x/lists/list-general.txt", b"a.com\n")]);
        for i in 0..20 {
            std::thread::scope(|sc| {
                sc.spawn(|| install_strategies(&gh, &dir, Some("9.9"), true, i));
                sc.spawn(|| install_strategies(BUILTIN_ZIP, &dir, Some(BUILTIN_VERSION), false, i));
            });
            let src = source_of(&dir).expect("метка на месте");
            let n = scan(&dir, false).unwrap().strategies.len();
            assert_eq!(n, if src.from_github { 1 } else { 22 }, "набор целиком, не смесь");
        }
        let left: Vec<_> = std::fs::read_dir(&root).unwrap().flatten().map(|e| e.file_name()).collect();
        assert_eq!(left.len(), 1, "временных папок не осталось: {left:?}");
        // Имена устройств и «невидимые» символы — мимо.
        for bad in ["COM1.bat", "com¹.bat", "CONIN$.bat", "COM1 .bat", "nul.bat", "gen\u{202E}tab.bat", "a<b.bat"] {
            assert!(!creatable_name(bad), "{bad}");
        }
        assert!(creatable_name("general (FAKE TLS AUTO ALT2).bat"));
        for bad in [".", "..", "-", "_1"] {
            assert!(clean_version(bad).is_none(), "{bad}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn user_hosts_go_to_general_user_list() {
        let run = tmpdir("zuser");
        std::fs::create_dir_all(run.join("files/lists")).unwrap();
        std::fs::write(run.join("files/lists/list-general-user.txt"), "domain.example.abc").unwrap();
        std::fs::write(run.join("files/lists/list-exclude-user.txt"), "keep.example\n").unwrap();
        let n = add_user_hosts(&run, &["site.ru".into(), "bad host".into(), "x.example".into(), "https://Video.Example.com/w?v=1".into(), "mailto:a.b".into()]);
        assert_eq!(n, 1);
        assert_eq!(
            std::fs::read_to_string(run.join("files/lists/list-general-user.txt")).unwrap(),
            "domain.example.abc\nsite.ru\nx.example\nvideo.example.com\n"
        );
        assert_eq!(std::fs::read_to_string(run.join("files/lists/list-exclude-user.txt")).unwrap(), "keep.example\n", "исключения не трогаем");
        let _ = std::fs::remove_dir_all(&run);
    }

    #[test]
    fn hybrid_args_and_health() {
        let root = tmpdir("zhybrid");
        std::fs::create_dir_all(root.join("lists")).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("lists/list-general.txt"), "youtube.com\n").unwrap();
        std::fs::write(root.join("bin/quic_initial_www_google_com.bin"), [1u8]).unwrap();
        std::fs::write(root.join("bin/tls_clienthello_www_google_com.bin"), [2u8]).unwrap();
        let (args, _) = parse_bat(FLOWSEAL_LINE, Path::new(""), false).unwrap();
        let s = Strategy { name: "g".into(), file: "g.bat".into(), args, notes: vec![] };
        let run = root.join("run");
        let h = Hybrid { iface: Some(17), exclude: vec!["203.0.113.7".parse().unwrap(), "2001:db8::1".parse().unwrap()] };
        let a: Vec<String> = prepare_hybrid(&root, &s, &run, &h).unwrap().into_iter().map(|x| x.into_string().unwrap()).collect();
        assert_eq!(a[0], "--wf-iface=17");
        let ex = "--ipset-exclude=files/rxvpn-vpn-servers.txt";
        // В каждом профиле (до каждого --new и в последнем) — исключение VPN-серверов.
        let profiles = a.iter().filter(|x| *x == "--new").count() + 1;
        assert_eq!(a.iter().filter(|x| *x == ex).count(), profiles);
        for (i, x) in a.iter().enumerate() {
            if x == "--new" {
                assert_eq!(a[i - 1], ex);
            }
        }
        assert_eq!(a.last().unwrap(), ex);
        assert_eq!(std::fs::read_to_string(run.join("files/rxvpn-vpn-servers.txt")).unwrap(), "203.0.113.7\n2001:db8::1\n");
        // Без TUN — без --wf-iface; без адресов — заглушка (пустой список winws не принимает).
        let a = prepare_hybrid(&root, &s, &run, &Hybrid::default()).unwrap();
        assert!(!a.iter().any(|x| x.to_string_lossy().starts_with("--wf-iface")));
        assert_eq!(std::fs::read_to_string(run.join("files/rxvpn-vpn-servers.txt")).unwrap(), "203.0.113.113/32\n");
        // Здоровье: сеть есть, YouTube мёртв — сломалось; сети нет — не трогаем.
        let t = |name: &str, ok: u8| TargetResult { name: name.into(), url: String::new(), ok, full: ok == 2, stalled: false, ms: 0 };
        let fine = vec![t("YouTube", 2), t("YouTube video", 2), t("Discord", 2)];
        assert_eq!(health_of(true, &fine), Health::Fine);
        assert_eq!(health_of(true, &[t("YouTube", 0), t("YouTube video", 2), t("Discord", 2)]), Health::Broken);
        // Отвечает только по TLS 1.2, а страница обрывается — «замедлялка», не «работает».
        let stall = TargetResult { stalled: true, ..t("YouTube video", 1) };
        assert!(!stall.full);
        assert_eq!(health_of(true, &[t("YouTube", 2), stall, t("Discord", 2)]), Health::Broken);
        assert_eq!(health_of(false, &[t("YouTube", 0)]), Health::Offline);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn release_tag_from_redirect() {
        assert_eq!(parse_release_tag("https://github.com/Flowseal/zapret-discord-youtube/releases/tag/1.10.5").unwrap(), "1.10.5");
        for bad in [
            "https://evil.com/Flowseal/zapret-discord-youtube/releases/tag/1.0",
            "https://github.com/Flowseal/zapret-discord-youtube/releases/tag/../../x",
            "https://github.com/Flowseal/zapret-discord-youtube/releases/tag/1.0?x=1",
            "/releases/tag/1.0",
        ] {
            assert!(parse_release_tag(bad).is_err(), "{bad}");
        }
    }

    /// FLOWSEAL_ZIP=настоящий архив релиза: раскладывается, движок из него — официальный.
    #[test]
    #[ignore]
    fn real_flowseal_release_zip() {
        let Some(z) = std::env::var_os("FLOWSEAL_ZIP") else { return };
        let root = tmpdir("zrelease");
        let dir = root.join("strategies");
        let s = install_strategies(&std::fs::read(z).unwrap(), &dir, None, true, 1).unwrap();
        let sc = scan(&dir, false).unwrap();
        eprintln!("{s:?}: стратегий {}, движок {:?} {:?}", sc.strategies.len(), sc.engine_version, sc.engine_problem);
        assert!(sc.strategies.len() >= 20 && sc.engine_version.is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn huge_or_linked_engine_files_are_not_read() {
        let dir = std::env::temp_dir().join(format!("rxvpn-zbig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // «winws.exe» на 9 ГБ (дыра в файле — места на диске не занимает)
        let f = std::fs::File::create(dir.join("winws.exe")).unwrap();
        f.set_len(9 << 30).unwrap();
        let t = Instant::now();
        assert!(engine_check(&dir).unwrap_err().contains("большой"));
        assert!(engine_from_folder(&dir, &dir.join("e")).unwrap_err().contains("большой"));
        assert!(t.elapsed() < Duration::from_secs(1), "не читали целиком");
        #[cfg(unix)]
        {
            std::fs::remove_file(dir.join("winws.exe")).unwrap();
            std::fs::write(dir.join("real"), b"x").unwrap();
            std::os::unix::fs::symlink(dir.join("real"), dir.join("winws.exe")).unwrap();
            assert!(engine_check(&dir).unwrap_err().contains("не обычный файл"));
        }
        // Длинное имя стратегии в настройках не сохранится — такую не показываем.
        let long = format!("{}.bat", "a".repeat(201));
        std::fs::write(dir.join(&long), FLOWSEAL_LINE).unwrap();
        std::fs::write(dir.join("ok.bat"), FLOWSEAL_LINE).unwrap();
        let sc = scan(&dir, false).unwrap();
        assert_eq!(sc.strategies.len(), 1);
        assert!(sc.skipped.iter().any(|x| x.contains("имя")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn engine_hash_checks() {
        let dir = std::env::temp_dir().join(format!("rxvpn-zengine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for f in ENGINE_FILES {
            std::fs::write(dir.join(f), b"fake").unwrap();
        }
        let e = engine_from_folder(&dir, &dir.join("engine")).unwrap_err();
        assert!(e.contains("подделка"), "{e}");
        assert!(engine_from_zip(b"not a zip", &dir.join("engine")).unwrap_err().contains("хеш"));
        assert!(engine_check(&dir).is_err());
        assert!(engine_lock(&dir).err().unwrap().contains("не совпадает"));
        assert!(engine_lock(&dir.join("нет")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prepare_copies_and_stubs() {
        let root = std::env::temp_dir().join(format!("rxvpn-zprep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lists")).unwrap();
        std::fs::create_dir_all(root.join("bin")).unwrap();
        std::fs::write(root.join("lists/list-general.txt"), "youtube.com\n").unwrap();
        std::fs::write(root.join("bin/quic_initial_www_google_com.bin"), [1u8, 2, 3]).unwrap();
        std::fs::write(root.join("bin/tls_clienthello_www_google_com.bin"), [4u8]).unwrap();
        let (args, _) = parse_bat(FLOWSEAL_LINE, Path::new(""), false).unwrap();
        let s = Strategy { name: "general".into(), file: "general.bat".into(), args, notes: vec![] };
        let run = root.join("_run");
        let a = prepare(&root, &s, &run).unwrap();
        let joined: Vec<String> = a.iter().map(|x| x.to_string_lossy().into_owned()).collect();
        assert!(joined[0] == "--wf-tcp=80,443,12");
        let user = joined.iter().find(|x| x.contains("list-general-user.txt")).unwrap();
        let p = user.split_once('=').unwrap().1;
        assert!(p.starts_with("files/"), "относительно рабочей папки: {p}");
        assert_eq!(std::fs::read_to_string(run.join(p)).unwrap(), "domain.example.abc\n");
        assert!(!root.join("lists/list-general-user.txt").exists(), "папку человека не трогаем");
        // Список — ссылка наружу (могла бы вести и на сетевую папку): не идём.
        #[cfg(unix)]
        {
            let outside = root.with_extension("outside");
            std::fs::create_dir_all(&outside).unwrap();
            std::fs::write(outside.join("secret.txt"), "x").unwrap();
            std::fs::remove_file(root.join("lists/list-general.txt")).unwrap();
            std::os::unix::fs::symlink(outside.join("secret.txt"), root.join("lists/list-general.txt")).unwrap();
            assert!(prepare(&root, &s, &run).unwrap_err().contains("ссылка"));
            std::fs::remove_file(root.join("lists/list-general.txt")).unwrap();
            std::os::unix::fs::symlink(&outside, root.join("lists2")).unwrap();
            assert!(no_links(&root, "lists2/secret.txt").unwrap_err().contains("ссылка"));
            // .bat-ссылка в папке — не стратегия, молча мимо.
            std::fs::write(outside.join("evil.bat"), FLOWSEAL_LINE).unwrap();
            std::os::unix::fs::symlink(outside.join("evil.bat"), root.join("evil.bat")).unwrap();
            std::fs::write(root.join("good.bat"), FLOWSEAL_LINE).unwrap();
            let sc = scan(&root, false).unwrap();
            assert_eq!(sc.strategies.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["good"]);
            let _ = std::fs::remove_dir_all(&outside);
            std::fs::write(root.join("lists/list-general.txt"), "youtube.com\n").unwrap();
        }
        // Кусок фильтра WinDivert: скобки в балансе — можно, лишняя «)» — нет
        // (иначе кусок вырвался бы из-под «и не локальная сеть»).
        let part = "start \"z\" /min \"%~dp0winws.exe\" --wf-tcp=443 --wf-raw-part=@\"%~dp0f\\part.txt\"\n";
        let (args, _) = parse_bat(part, Path::new(""), false).unwrap();
        assert_eq!(args[1].val, Val::AtFile("f/part.txt".into()));
        let ps = Strategy { name: "p".into(), file: "p.bat".into(), args, notes: vec![] };
        std::fs::create_dir_all(root.join("f")).unwrap();
        std::fs::write(root.join("f/part.txt"), "outbound and udp and\n (udp.DstPort>=50000 and udp.DstPort<=50099)\n").unwrap();
        assert!(prepare(&root, &ps, &run).unwrap().iter().any(|a| a.to_string_lossy() == "--wf-raw-part=@files/f/part.txt"));
        for evil in ["false)) or ((true", "true) or (true", "(((", "udp\u{0}"] {
            std::fs::write(root.join("f/part.txt"), evil).unwrap();
            assert!(prepare(&root, &ps, &run).is_err(), "{evil}");
        }
        // Нет обязательного файла — ошибка.
        std::fs::remove_file(root.join("bin/quic_initial_www_google_com.bin")).unwrap();
        assert!(prepare(&root, &s, &run).unwrap_err().contains("нет файла"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Подбор: «провайдер» рвёт соединения, пока не включена нужная стратегия.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn picks_the_working_strategy() {
        use std::io::{Read, Write};
        use std::sync::atomic::AtomicUsize;
        const NONE: usize = usize::MAX;
        let active = Arc::new(AtomicUsize::new(NONE));
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let a2 = active.clone();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let a = a2.clone();
                std::thread::spawn(move || {
                    let mut s = s;
                    let mut b = [0u8; 2048];
                    let _ = s.read(&mut b);
                    let cur = a.load(Ordering::SeqCst);
                    // стратегия 1 — «хорошая», 2 — открывает только половину
                    let pass = cur == 1 || (cur == 2 && b.starts_with(b"GET / HTTP/1.1"));
                    if pass {
                        let body = vec![b'x'; 70_000];
                        let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                        let _ = s.write_all(&body);
                    }
                    // иначе — молча рвём, как ТСПУ
                });
            }
        });
        struct Fake(Arc<AtomicUsize>);
        struct Guard(Arc<AtomicUsize>);
        impl Drop for Guard {
            fn drop(&mut self) {
                self.0.store(NONE, Ordering::SeqCst);
            }
        }
        impl Launcher for Fake {
            fn start(&self, s: &Strategy) -> Result<Box<dyn Send>, String> {
                let i: usize = s.name.trim_start_matches('s').parse().unwrap();
                if i == 3 {
                    return Err("winws завершился: error opening filter".into());
                }
                self.0.store(i, Ordering::SeqCst);
                Ok(Box::new(Guard(self.0.clone())))
            }
        }
        let st = |n: &str| Strategy { name: n.into(), file: format!("{n}.bat"), args: vec![], notes: vec![] };
        let strategies = vec![st("s0"), st("s1"), st("s2"), st("s3")];
        let targets = vec![("A".to_string(), format!("http://127.0.0.1:{port}/")), ("B".to_string(), format!("http://127.0.0.1:{port}/b"))];
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let scores = pick_best(
            Arc::new(Fake(active.clone())),
            &strategies,
            &targets,
            Duration::from_secs(2),
            Duration::from_millis(50),
            Arc::new(AtomicBool::new(false)),
            move |done, total, sc| seen2.lock().unwrap().push((done, total, sc.name.clone())),
        )
        .await;
        assert_eq!(scores.len(), 5, "без zapret + 4 стратегии");
        assert_eq!(scores[0].ok, 0, "без zapret ничего не открывается");
        assert_eq!(scores[2].ok, 4, "s1 открывает всё: 2 цели × 2 проверки");
        assert!(scores[2].targets.iter().all(|t| t.full));
        assert!(scores[3].ok > 0 && scores[3].ok < 4, "s2 — частично: {}", scores[3].ok);
        assert!(scores[4].error.as_deref().unwrap().contains("error opening filter"));
        assert_eq!(best(&scores).unwrap().name, "s1");
        assert_eq!(seen.lock().unwrap().len(), 5);
        assert_eq!(active.load(Ordering::SeqCst), NONE, "после подбора ничего не оставили запущенным");

        // Отмена — останавливаемся сразу.
        let stop = Arc::new(AtomicBool::new(true));
        let s2 = pick_best(Arc::new(Fake(active.clone())), &strategies, &targets, Duration::from_secs(2), Duration::ZERO, stop, |_, _, _| {}).await;
        assert_eq!(s2.len(), 1);
    }

    /// ZAPRET_ZIP=официальный zapret-v72.13.zip: движок ставится, подделка — нет.
    #[test]
    #[ignore]
    fn real_official_zip() {
        let Some(z) = std::env::var_os("ZAPRET_ZIP") else { return };
        let bytes = std::fs::read(z).unwrap();
        let dir = std::env::temp_dir().join(format!("rxvpn-zzip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(engine_from_zip(&bytes, &dir).unwrap(), "v72.13");
        assert_eq!(engine_check(&dir).unwrap(), "v72.13");
        assert_eq!(engine_lock(&dir).unwrap().0, "v72.13");
        // Подсунули DLL рядом с winws.exe — не запускаем.
        std::fs::write(dir.join("version.dll"), b"x").unwrap();
        assert!(engine_lock(&dir).err().unwrap().contains("version.dll"));
        std::fs::remove_file(dir.join("version.dll")).unwrap();
        // Подменили один файл после установки — проверка перед запуском это видит.
        std::fs::write(dir.join("winws.exe"), b"evil").unwrap();
        assert!(engine_check(&dir).unwrap_err().contains("winws.exe"));
        // Испорченный архив — не ставим.
        let mut bad = bytes.clone();
        let n = bad.len() / 2;
        bad[n] ^= 1;
        assert!(engine_from_zip(&bad, &dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ZAPRET_DIR=настоящая папка Flowseal: все стратегии разбираются.
    #[test]
    #[ignore]
    fn real_flowseal_folder() {
        let Some(dir) = std::env::var_os("ZAPRET_DIR").map(PathBuf::from) else { return };
        let s = scan(&dir, false).unwrap();
        eprintln!("стратегий {}, пропущено {:?}, движок {:?} {:?}", s.strategies.len(), s.skipped, s.engine_version, s.engine_problem);
        assert!(!s.strategies.is_empty());
        assert!(s.skipped.is_empty(), "{:?}", s.skipped);
        assert!(s.engine_version.is_some(), "официальный движок узнали");
        let run = std::env::temp_dir().join("rxvpn-zreal-run");
        for st in &s.strategies {
            prepare(&dir, st, &run).unwrap_or_else(|e| panic!("{}: {e}", st.name));
        }
        let _ = std::fs::remove_dir_all(&run);
    }
}
