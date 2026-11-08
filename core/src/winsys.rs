//! Мелочи Windows: автозапуск и права администратора (нужны для TUN).
//! На других ОС — заглушки, чтобы всё собиралось и тестировалось.

/// Имя записи в автозапуске.
pub const RUN_NAME: &str = "rxvpn";

#[cfg(windows)]
mod imp {
    use super::RUN_NAME;
    use std::io;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

    /// Включить/выключить запуск вместе с Windows (текущий пользователь, без админа).
    /// `command` — полная строка запуска, например `"C:\rxvpn\rxvpn.exe" --autostart`.
    pub fn set_autostart(enabled: bool, command: &str) -> io::Result<()> {
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_WRITE)?;
        if enabled {
            key.set_value(RUN_NAME, &command.to_string())
        } else {
            match key.delete_value(RUN_NAME) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                r => r,
            }
        }
    }

    pub fn autostart_command() -> Option<String> {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(RUN_KEY, KEY_READ)
            .ok()?
            .get_value(RUN_NAME)
            .ok()
    }

    pub fn is_admin() -> bool {
        unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
    }

    /// Перезапустить себя с правами администратора (появится окно UAC).
    /// Ok — новый процесс запущен, текущий надо закрыть.
    pub fn relaunch_as_admin(args: &str) -> Result<(), String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        run_as_admin_exe(&exe, args)
    }

    /// Запустить `exe` с правами администратора (окно UAC).
    pub fn run_as_admin_exe(exe: &std::path::Path, args: &str) -> Result<(), String> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        let wide = |s: &std::ffi::OsStr| s.encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let verb = wide("runas".as_ref());
        let file = wide(exe.as_os_str());
        let params = wide(args.as_ref());
        let r = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        // По документации успех — значение больше 32. Отказ в окне UAC даёт 5.
        if (r as isize) > 32 {
            Ok(())
        } else if r as isize == 5 {
            Err(trs!("отменено в окне контроля учётных записей").into())
        } else {
            Err(tr!("не удалось перезапустить (код {})", r as isize))
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::io;
    pub fn set_autostart(_enabled: bool, _command: &str) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, trs!("автозапуск пока только для Windows")))
    }
    pub fn autostart_command() -> Option<String> {
        None
    }
    pub fn is_admin() -> bool {
        // На Linux TUN тоже требует root, но клиент пока для Windows.
        false
    }
    pub fn relaunch_as_admin(_args: &str) -> Result<(), String> {
        Err(trs!("перезапуск от администратора есть только в Windows").into())
    }
    pub fn run_as_admin_exe(_exe: &std::path::Path, _args: &str) -> Result<(), String> {
        Err(trs!("перезапуск от администратора есть только в Windows").into())
    }
}

pub use imp::{autostart_command, is_admin, relaunch_as_admin, run_as_admin_exe, set_autostart};

/// Окно с сообщением (до того, как есть окно программы). Вне Windows — в stderr.
pub fn message_box(title: &str, text: &str) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING, MB_OK};
        let w = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (t, b) = (w(title), w(text));
        unsafe { MessageBoxW(std::ptr::null_mut(), b.as_ptr(), t.as_ptr(), MB_OK | MB_ICONWARNING) };
    }
    #[cfg(not(windows))]
    eprintln!("{title}: {text}"); // i18n-skip: только для отладки
}

/// Вопрос «Да/Нет» до того, как есть окно программы. Вне Windows — «нет».
pub fn confirm_box(title: &str, text: &str) -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_YESNO};
        let w = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (t, b) = (w(title), w(text));
        unsafe { MessageBoxW(std::ptr::null_mut(), b.as_ptr(), t.as_ptr(), MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES }
    }
    #[cfg(not(windows))]
    {
        eprintln!("{title}: {text}"); // i18n-skip: только для отладки
        false
    }
}

/// Открыть ссылку tg:// в Telegram Desktop (кто зарегистрирован в системе).
/// Только наши ссылки на локальный прокси — ничего чужого так не откроем.
/// Кто держит рабочий стол: None — не Проводник из папки Windows (или его нет);
/// Some(false) — Проводник без прав администратора; Some(true) — Проводник сам с правами
/// (UAC выключен или так настроено: тогда любая программа пользователя и так от администратора).
#[cfg(windows)]
fn shell_elevated() -> Option<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};
    unsafe {
        let hwnd = GetShellWindow();
        if hwnd.is_null() {
            return None;
        }
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, &mut pid);
        if pid == 0 {
            return None;
        }
        let proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if proc.is_null() {
            return None;
        }
        // Это действительно Проводник из папки Windows, а не чужая оболочка.
        let mut buf = [0u16; 520];
        let mut len = buf.len() as u32;
        let image_ok = QueryFullProcessImageNameW(proc, 0, buf.as_mut_ptr(), &mut len) != 0
            && windows_exe("explorer.exe").is_some_and(|e| {
                String::from_utf16_lossy(&buf[..len as usize]).eq_ignore_ascii_case(&e.to_string_lossy())
            });
        let mut token: HANDLE = std::ptr::null_mut();
        let mut out = None;
        if image_ok && OpenProcessToken(proc, TOKEN_QUERY, &mut token) != 0 {
            let mut el = TOKEN_ELEVATION { TokenIsElevated: 1 };
            let mut ret = 0u32;
            if GetTokenInformation(token, TokenElevation, &mut el as *mut _ as *mut _, std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut ret) != 0 {
                out = Some(el.TokenIsElevated != 0);
            }
            CloseHandle(token);
        }
        CloseHandle(proc);
        out
    }
}

pub fn open_tg_link(url: &str) -> Result<(), String> {
    // Только наша ссылка на локальный прокси и только простые символы: Проводник ниже получает
    // её аргументом — ни кавычек, ни пробелов, ни запятых (у explorer.exe это разделители ключей).
    if !url.starts_with("tg://proxy?server=127.0.0.1&port=")
        || !url.bytes().all(|b| b.is_ascii_alphanumeric() || b"/:?=&.%_-".contains(&b))
    {
        return Err(trs!("не та ссылка").into());
    }
    // От администратора сами не открываем: обработчик tg:// Windows берёт и из HKCU\Software\Classes,
    // куда пишет любая программа пользователя, — она запустилась бы с правами администратора.
    // Отдаём ссылку Проводнику: новый explorer.exe передаёт её уже запущенному Проводнику
    // пользователя и закрывается — Telegram открывается без прав администратора, как от клика.
    if is_admin() {
        #[cfg(windows)]
        {
            match shell_elevated() {
                // Нет Проводника (другая оболочка, упал) — новый explorer.exe открыл бы ссылку
                // с нашими правами. Не открываем.
                None => {
                    return Err(trs!("Проводник Windows не запущен — ссылку не открываю (она открылась бы с правами администратора). Ссылка скопирована: вставь её в Telegram").into());
                }
                // Проводник без прав: отдаём ему — Telegram откроется без прав администратора.
                Some(false) => {
                    let explorer = windows_exe("explorer.exe").ok_or(trs!("не нашёл папку Windows"))?;
                    let mut c = std::process::Command::new(explorer);
                    c.arg(url);
                    crate::runner::clean_env(&mut c);
                    return c.spawn().map(|_| ()).map_err(|e| tr!("не открылось: {e}"));
                }
                // Проводник сам с правами администратора: у пользователя всё и так от админа —
                // открыть напрямую ничего не повышает (ниже, как без прав).
                Some(true) => {}
            }
        }
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
        let (verb, file) = (wide("open"), wide(url));
        let r = unsafe { ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL) };
        // Больше 32 — открылось; 31 (SE_ERR_NOASSOC) — никто не умеет tg://.
        if (r as isize) > 32 {
            Ok(())
        } else if r as isize == 31 {
            Err(trs!("Telegram Desktop не установлен (никто не открывает ссылки tg://)").into())
        } else {
            Err(tr!("не открылось (код {})", r as isize))
        }
    }
    #[cfg(not(windows))]
    {
        std::process::Command::new("xdg-open").arg(url).spawn().map(|_| ()).map_err(|e| e.to_string())
    }
}

/// Буква диска — сетевая (подключённый сетевой диск «Z:»). Такую папку
/// не читаем: Windows отдаёт чужому серверу хеш пароля при первом же обращении.
/// Полный путь к программе из папки Windows (explorer.exe) — от самой Windows,
/// не поиском: `Command::new("explorer")` сначала смотрит в папку rxvpn.exe
/// (её может переписать любая программа пользователя) и в PATH из HKCU\Environment,
/// а rxvpn бывает запущен от администратора.
#[cfg(windows)]
pub fn windows_exe(name: &str) -> Option<std::path::PathBuf> {
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut buf = [0u16; 260];
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    (n > 0 && n < buf.len()).then(|| std::path::PathBuf::from(String::from_utf16_lossy(&buf[..n])).join(name))
}

/// Папка Program Files (64-бит) — от самой Windows (KnownFolder), не из переменных окружения.
#[cfg(windows)]
pub fn program_files() -> Option<std::path::PathBuf> {
    known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramFiles)
}

/// Папка Windows (C:\Windows) — тоже от самой Windows, не из %SystemRoot%.
#[cfg(windows)]
pub fn windows_dir() -> Option<std::path::PathBuf> {
    known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_Windows)
}

#[cfg(windows)]
fn known_folder(id: &windows_sys::core::GUID) -> Option<std::path::PathBuf> {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;
    unsafe {
        let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
        if SHGetKnownFolderPath(id, 0, std::ptr::null_mut(), &mut p) != 0 || p.is_null() {
            if !p.is_null() {
                CoTaskMemFree(p as _);
            }
            return None;
        }
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
        CoTaskMemFree(p as _);
        Some(std::path::PathBuf::from(s))
    }
}

#[cfg(not(windows))]
pub fn program_files() -> Option<std::path::PathBuf> {
    None
}

#[cfg(not(windows))]
pub fn windows_dir() -> Option<std::path::PathBuf> {
    None
}

/// Папка программы лежит внутри Program Files (после разрешения ссылок)?
/// Туда по умолчанию пишет только администратор — значит, rxvpn.exe, ядро и
/// движок zapret в ней не подменит программа без прав.
pub fn inside_program_files(dir: &std::path::Path) -> bool {
    let (Some(pf), Ok(d)) = (program_files(), std::fs::canonicalize(dir)) else { return false };
    let Ok(pf) = std::fs::canonicalize(pf) else { return false };
    path_inside(&d, &pf)
}

/// `d` — строго внутри `root` (без учёта регистра, по целым компонентам).
pub fn path_inside(d: &std::path::Path, root: &std::path::Path) -> bool {
    let low = |p: &std::path::Path| p.components().map(|c| c.as_os_str().to_string_lossy().to_lowercase()).collect::<Vec<_>>();
    let (d, r) = (low(d), low(root));
    d.len() > r.len() && d.starts_with(&r)
}

#[cfg(windows)]
pub fn is_remote_drive(path: &str) -> bool {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    const DRIVE_REMOTE: u32 = 4;
    let b = path.as_bytes();
    if b.len() < 2 || b[1] != b':' {
        return false;
    }
    let root: Vec<u16> = format!("{}:\\", b[0] as char).encode_utf16().chain(std::iter::once(0)).collect();
    unsafe { GetDriveTypeW(root.as_ptr()) == DRIVE_REMOTE }
}

#[cfg(not(windows))]
pub fn is_remote_drive(_path: &str) -> bool {
    false
}

/// Номер настоящей сетевой карты, через которую идёт интернет (маршрут к 1.1.1.1).
/// Спрашивать до запуска TUN: после него «лучший» путь — сам туннель.
#[cfg(windows)]
pub fn best_interface() -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterface;
    let dest = u32::from_ne_bytes([1, 1, 1, 1]); // адрес в сетевом порядке байт
    let mut idx = 0u32;
    let r = unsafe { GetBestInterface(dest, &mut idx) };
    (r == 0 && idx != 0).then_some(idx)
}

#[cfg(not(windows))]
pub fn best_interface() -> Option<u32> {
    None
}

/// Имя сетевого подключения по номеру («Ethernet», «Wi-Fi», «rxvpn» у нашего TUN).
#[cfg(windows)]
pub fn iface_alias(idx: u32) -> Option<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias};
    use windows_sys::Win32::NetworkManagement::Ndis::{IF_MAX_STRING_SIZE, NET_LUID_LH};
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    if unsafe { ConvertInterfaceIndexToLuid(idx, &mut luid) } != 0 {
        return None;
    }
    let mut buf = [0u16; IF_MAX_STRING_SIZE as usize + 1];
    if unsafe { ConvertInterfaceLuidToAlias(&luid, buf.as_mut_ptr(), buf.len()) } != 0 {
        return None;
    }
    let n = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..n]))
}

#[cfg(not(windows))]
pub fn iface_alias(_idx: u32) -> Option<String> {
    None
}

/// Зашифровать данные ключом текущей учётки Windows (DPAPI): расшифровать
/// их можно только под этой учёткой на этом компе. `entropy` — своя «соль»
/// rxvpn, чтобы чужая программа не расшифровала файл одним общим вызовом.
#[cfg(windows)]
pub fn dpapi(data: &[u8], entropy: &[u8], seal: bool) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let ent = CRYPT_INTEGER_BLOB { cbData: entropy.len() as u32, pbData: entropy.as_ptr() as *mut u8 };
    let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    let ok = unsafe {
        if seal {
            CryptProtectData(&input, std::ptr::null(), &ent, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        } else {
            CryptUnprotectData(&input, std::ptr::null_mut(), &ent, std::ptr::null(), std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut out)
        }
    };
    if ok == 0 || out.pbData.is_null() {
        return Err(if seal { trs!("не зашифровалось") } else { trs!("не расшифровать: файл зашифрован на другом компе или под другой учёткой Windows") }.into());
    }
    let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
    // Расшифрованное (пароли серверов, ключ SSH) не оставляем в освобождённой куче Windows.
    {
        use zeroize::Zeroize;
        unsafe { std::slice::from_raw_parts_mut(out.pbData, out.cbData as usize) }.zeroize();
    }
    unsafe { LocalFree(out.pbData as _) };
    Ok(v)
}

#[cfg(not(windows))]
pub fn dpapi(_data: &[u8], _entropy: &[u8], _seal: bool) -> Result<Vec<u8>, String> {
    Err(trs!("шифрование есть только в Windows").into())
}

/// Wi-Fi, к которому подключён комп: (имя сети, адрес точки «aa:bb:cc:dd:ee:ff»).
/// None — не Wi-Fi или Windows не даёт имя (Windows 11 24H2+: нужен доступ к
/// местоположению для классических приложений).
#[cfg(windows)]
pub fn current_wifi() -> Option<(String, String)> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WiFi::{
        wlan_interface_state_connected, wlan_intf_opcode_current_connection, WlanCloseHandle, WlanEnumInterfaces,
        WlanFreeMemory, WlanOpenHandle, WlanQueryInterface, WLAN_CONNECTION_ATTRIBUTES, WLAN_INTERFACE_INFO_LIST,
    };
    let mut ver = 0u32;
    let mut h: HANDLE = std::ptr::null_mut();
    if unsafe { WlanOpenHandle(2, std::ptr::null(), &mut ver, &mut h) } != 0 {
        return None;
    }
    let mut found = None;
    unsafe {
        let mut list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        if WlanEnumInterfaces(h, std::ptr::null(), &mut list) == 0 && !list.is_null() {
            let n = (*list).dwNumberOfItems as usize;
            let items = std::slice::from_raw_parts((*list).InterfaceInfo.as_ptr(), n);
            for it in items.iter().filter(|i| i.isState == wlan_interface_state_connected) {
                let mut size = 0u32;
                let mut data: *mut std::ffi::c_void = std::ptr::null_mut();
                let r = WlanQueryInterface(
                    h,
                    &it.InterfaceGuid,
                    wlan_intf_opcode_current_connection,
                    std::ptr::null(),
                    &mut size,
                    &mut data,
                    std::ptr::null_mut(),
                );
                if r == 0 && !data.is_null() && size as usize >= std::mem::size_of::<WLAN_CONNECTION_ATTRIBUTES>() {
                    let a = &*(data as *const WLAN_CONNECTION_ATTRIBUTES);
                    let s = &a.wlanAssociationAttributes.dot11Ssid;
                    let len = (s.uSSIDLength as usize).min(32);
                    let ssid = String::from_utf8_lossy(&s.ucSSID[..len]).into_owned();
                    let b = a.wlanAssociationAttributes.dot11Bssid;
                    let bssid = b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":");
                    if !ssid.is_empty() {
                        found = Some((ssid, bssid));
                    }
                }
                if !data.is_null() {
                    WlanFreeMemory(data);
                }
                if found.is_some() {
                    break;
                }
            }
            WlanFreeMemory(list as *const _);
        }
        WlanCloseHandle(h, std::ptr::null());
    }
    found
}

#[cfg(not(windows))]
pub fn current_wifi() -> Option<(String, String)> {
    None
}

/// Глобальные IPv6-адреса сетевых карт (кроме туннеля `tun`) — чтобы понять,
/// не видят ли сайты твой настоящий IPv6 в обход TUN.
#[cfg(windows)]
pub fn local_ipv6(tun: &str) -> Vec<std::net::Ipv6Addr> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{FreeMibTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_TABLE};
    use windows_sys::Win32::Networking::WinSock::AF_INET6;
    let mut out = Vec::new();
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    if unsafe { GetUnicastIpAddressTable(AF_INET6, &mut table) } != 0 || table.is_null() {
        return out;
    }
    unsafe {
        let n = (*table).NumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), n);
        for r in rows {
            let ip = std::net::Ipv6Addr::from(r.Address.Ipv6.sin6_addr.u.Byte);
            // 2000::/3 — адреса в интернете (не fe80::, не fd00::)
            if ip.segments()[0] & 0xe000 == 0x2000
                && !iface_alias(r.InterfaceIndex).is_some_and(|a| a.eq_ignore_ascii_case(tun))
            {
                out.push(ip);
            }
        }
        FreeMibTable(table as *const _);
    }
    out
}

#[cfg(not(windows))]
pub fn local_ipv6(_tun: &str) -> Vec<std::net::Ipv6Addr> {
    Vec::new()
}

/// Как `best_interface`, но не туннель `tun` (его имя): после смены Wi-Fi на
/// кабель номер карты другой, а при работающем TUN «лучший» путь — он сам.
pub fn physical_interface(tun: &str) -> Option<u32> {
    let i = best_interface()?;
    match iface_alias(i) {
        Some(a) if a.eq_ignore_ascii_case(tun) => None,
        Some(_) => Some(i),
        // Имя узнать не вышло — не рискуем: это может быть и туннель.
        None => None,
    }
}

/// Файл драйвера, на который указывает уже зарегистрированная служба WinDivert
/// (её мог оставить другой zapret/GoodbyeDPI). Тогда WinDivert.dll возьмёт драйвер
/// оттуда, а не наш сверенный. None — службы нет.
#[cfg(windows)]
pub fn windivert_service_image() -> Option<String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    let key = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Services\WinDivert", KEY_READ)
        .ok()?;
    // Служба есть, а пути нет — тоже странно: вернём пустую строку, проверка откажет.
    Some(key.get_value::<String, _>("ImagePath").unwrap_or_default())
}

#[cfg(not(windows))]
pub fn windivert_service_image() -> Option<String> {
    None
}

/// Имена запущенных программ (без повторов, по алфавиту) — для выбора в
/// «Правилах по программам». Системные процессы без файла не попадают.
pub fn list_processes() -> Vec<String> {
    let mut names = imp_list_processes();
    names.retain(|n| !n.is_empty() && n != "System" && n != "[System Process]" && n != "Idle");
    names.sort_by_key(|n| n.to_lowercase());
    names.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    names
}

#[cfg(windows)]
fn imp_list_processes() -> Vec<String> {
    process_names().into_values().collect()
}

/// Запущенные процессы: номер → имя exe (снимок Toolhelp).
#[cfg(windows)]
pub fn process_names() -> std::collections::HashMap<u32, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut out = std::collections::HashMap::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut e) != 0;
        while ok {
            let len = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            out.insert(e.th32ProcessID, String::from_utf16_lossy(&e.szExeFile[..len]));
            ok = Process32NextW(snap, &mut e) != 0;
        }
        CloseHandle(snap);
    }
    out
}

#[cfg(not(windows))]
pub fn process_names() -> std::collections::HashMap<u32, String> {
    Default::default()
}

#[cfg(not(windows))]
fn imp_list_processes() -> Vec<String> {
    let Ok(dir) = std::fs::read_dir("/proc") else { return Vec::new() };
    dir.flatten()
        .filter(|e| e.file_name().to_string_lossy().chars().all(|c| c.is_ascii_digit()))
        .filter_map(|e| std::fs::read_to_string(e.path().join("comm")).ok())
        .map(|s| s.trim().to_string())
        .collect()
}

/// «Уже запущен?» — именованный мьютекс в пространстве текущего сеанса
/// (Local\\). Раньше замком был TCP-порт, а его может занять любой
/// пользователь компа, и rxvpn молча не запустился бы. Мьютекс в чужом
/// сеансе на наш не влияет. Держи guard, пока программа работает.
pub struct InstanceGuard {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl Drop for InstanceGuard {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

// HANDLE — просто число для ОС; guard живёт в одном потоке, но Tauri хочет Send.
#[cfg(windows)]
unsafe impl Send for InstanceGuard {}

/// None — уже запущена другая копия (в этом сеансе). `wait` — подождать до 8 с:
/// так копия, перезапущенная от администратора, ждёт, пока закроется старая.
pub fn acquire_instance(wait: bool) -> Option<InstanceGuard> {
    #[cfg(windows)]
    {
        let tries = if wait { 80 } else { 1 };
        for i in 0..tries {
            if i > 0 {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            unsafe {
                use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};
                use windows_sys::Win32::System::Threading::CreateMutexW;
                let name: Vec<u16> = "Local\\dev.rxmv.rxvpn.instance".encode_utf16().chain(Some(0)).collect();
                let h = CreateMutexW(std::ptr::null(), 0, name.as_ptr());
                let err = GetLastError();
                // Нет handle (например, ACCESS_DENIED — мьютекс держит копия от
                // администратора) или он уже был — значит, rxvpn уже работает.
                if !h.is_null() && err != ERROR_ALREADY_EXISTS {
                    return Some(InstanceGuard { handle: h });
                }
                if !h.is_null() {
                    CloseHandle(h);
                }
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        // Для разработки на Linux замок не нужен.
        let _ = wait;
        Some(InstanceGuard {})
    }
}

/// Строка автозапуска для текущего exe.
pub fn autostart_line() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    Some(format!("\"{}\" --autostart", exe.display()))
}

/// Версия Windows для отчёта: «Windows 11 Pro 24H2 (сборка 26100.4061)».
#[cfg(windows)]
pub fn windows_version() -> String {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    let Ok(k) = winreg::RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", KEY_READ) else {
        return trs!("Windows (версия не прочиталась)").into();
    };
    let get = |n: &str| k.get_value::<String, _>(n).unwrap_or_default();
    let build = get("CurrentBuild");
    let ubr: u32 = k.get_value("UBR").unwrap_or(0);
    let mut name = get("ProductName");
    // В реестре Windows 11 до сих пор пишет «Windows 10» — отличаем по сборке.
    if build.parse::<u32>().is_ok_and(|b| b >= 22000) {
        name = name.replacen("Windows 10", "Windows 11", 1);
    }
    let disp = get("DisplayVersion");
    tr!("{name}{}{} (сборка {build}.{ubr}, {})", if disp.is_empty() { "" } else { " " }, disp, std::env::consts::ARCH)
}

#[cfg(not(windows))]
pub fn windows_version() -> String {
    tr!("не Windows ({} {})", std::env::consts::OS, std::env::consts::ARCH)
}

#[cfg(test)]
mod path_tests {
    /// Живой (Windows с рабочим столом): обычный Проводник — без прав администратора.
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn shell_found_live() {
        assert!(super::shell_elevated().is_some(), "рабочий стол держит Проводник из папки Windows");
    }

    #[test]
    fn tg_link_rules() {
        // Чужое и опасное для Проводника — отказ ещё до запуска чего-либо.
        for bad in ["https://evil.example", "tg://proxy?server=1.2.3.4&port=1", "tg://proxy?server=127.0.0.1&port=1,/select", "tg://proxy?server=127.0.0.1&port=1 x", "tg://proxy?server=127.0.0.1&port=1\"&x"] {
            assert!(super::open_tg_link(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn inside() {
        use std::path::Path;
        assert!(super::path_inside(Path::new("/pf/rxvpn"), Path::new("/PF")));
        assert!(!super::path_inside(Path::new("/pf"), Path::new("/pf")));
        assert!(!super::path_inside(Path::new("/pfx/rxvpn"), Path::new("/pf")));
        assert!(!super::path_inside(Path::new("/home/u/rxvpn"), Path::new("/pf")));
    }
}

