//! Всплывающие уведомления Windows.
//!
//! Windows показывает уведомление только от «зарегистрированного» приложения
//! (AppUserModelID). Установщики делают это ярлыком в «Пуске», а портативной
//! версии ярлыка нет. Поэтому регистрируем ID сами — ключом в реестре
//! HKCU\Software\Classes\AppUserModelId\<ID> с именем и значком (так Microsoft
//! советует делать для приложений без установщика). Не получилось —
//! показываем от имени PowerShell: некрасиво, но видно.

use std::path::Path;

#[cfg(windows)]
mod imp {
    use std::path::Path;
    use std::sync::OnceLock;
    use tauri_winrt_notification::{Duration, Toast};

    const AUMID: &str = "dev.rxmv.rxvpn";
    static APP_ID: OnceLock<String> = OnceLock::new();

    fn register(data_dir: &Path, icon_png: &[u8]) -> std::io::Result<()> {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        let icon = data_dir.join("rxvpn-icon.png");
        if !icon.exists() {
            std::fs::create_dir_all(data_dir)?;
            std::fs::write(&icon, icon_png)?;
        }
        let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(format!(r"Software\Classes\AppUserModelId\{AUMID}"))?;
        key.set_value("DisplayName", &"rxvpn")?;
        key.set_value("IconUri", &icon.display().to_string())?;
        Ok(())
    }

    pub fn init(data_dir: &Path, icon_png: &[u8]) {
        let id = match register(data_dir, icon_png) {
            Ok(()) => AUMID.to_string(),
            Err(_) => Toast::POWERSHELL_APP_ID.to_string(),
        };
        let _ = APP_ID.set(id);
    }

    pub fn show(title: &str, body: &str) {
        let id = APP_ID.get().cloned().unwrap_or_else(|| Toast::POWERSHELL_APP_ID.to_string());
        let (title, body) = (title.to_string(), body.to_string());
        // WinRT-вызов может занять время — не держим вызывающий поток.
        std::thread::spawn(move || {
            let _ = Toast::new(&id)
                .title(&title)
                .text1(&body)
                .sound(None)
                .duration(Duration::Short)
                .show();
        });
    }
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;
    pub fn init(_data_dir: &Path, _icon_png: &[u8]) {}
    pub fn show(title: &str, body: &str) {
        eprintln!("[уведомление] {title}: {body}"); // i18n-skip: только для отладки
    }
}

pub fn init(data_dir: &Path, icon_png: &[u8]) {
    imp::init(data_dir, icon_png)
}

pub fn show(title: &str, body: &str) {
    imp::show(title, body)
}
