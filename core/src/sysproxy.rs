//! Системный прокси Windows: реестр Internet Settings + уведомление WinINet,
//! чтобы браузеры подхватили изменения сразу.
//! На других ОС — заглушки (там будет TUN).

/// Адреса, которые идут мимо прокси: localhost и домашние сети.
pub const BYPASS: &str = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

#[cfg(windows)]
mod imp {
    use super::BYPASS;
    use std::io;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    const PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    fn key(write: bool) -> io::Result<RegKey> {
        let flags = if write { KEY_READ | KEY_WRITE } else { KEY_READ };
        RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(PATH, flags)
    }

    pub fn enable(http_addr: &str) -> io::Result<()> {
        let k = key(true)?;
        k.set_value("ProxyEnable", &1u32)?;
        k.set_value("ProxyServer", &http_addr.to_string())?;
        k.set_value("ProxyOverride", &BYPASS.to_string())?;
        refresh();
        Ok(())
    }

    pub fn disable() -> io::Result<()> {
        let k = key(true)?;
        k.set_value("ProxyEnable", &0u32)?;
        refresh();
        Ok(())
    }

    /// Текущий прокси, если включён.
    pub fn current() -> Option<String> {
        let k = key(false).ok()?;
        let on: u32 = k.get_value("ProxyEnable").ok()?;
        if on == 0 {
            return None;
        }
        k.get_value::<String, _>("ProxyServer").ok()
    }

    fn refresh() {
        use windows_sys::Win32::Networking::WinInet::{
            InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
        };
        unsafe {
            InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
            InternetSetOptionW(std::ptr::null(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::io;
    pub fn enable(_http_addr: &str) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            trs!("системный прокси пока только для Windows"),
        ))
    }
    pub fn disable() -> io::Result<()> {
        Ok(())
    }
    pub fn current() -> Option<String> {
        None
    }
}

pub use imp::{current, disable, enable};

/// Если прошлый запуск упал и оставил прокси на наш порт — интернет у человека
/// не работает. При старте убираем такой "хвост".
pub fn cleanup_stale(our_addr: &str) {
    if current().as_deref() == Some(our_addr) {
        let _ = disable();
    }
}
