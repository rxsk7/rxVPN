//! Автозапуск с правами администратора — задачей планировщика Windows, а не
//! ключом HKCU\…\Run.
//!
//! Почему: ключ Run может переписать любая программа пользователя. Если rxvpn
//! при входе в Windows просит права через окно UAC, вирус подменяет путь в Run
//! на свой exe с тем же именем — и человек сам даёт ему права администратора
//! (окно выглядит как обычно: «неизвестный издатель», «rxvpn.exe»).
//! Задачу «с наивысшими правами» создать и изменить может только администратор,
//! а запускает она exe из Program Files (туда пишет тоже только администратор).
//! Окна UAC при входе больше нет — значит, любое такое окно подозрительно.

/// Папка и имя задачи в планировщике.
pub const TASK_NAME: &str = r"rxvpn\Autostart";

/// Безопасно для XML: & < > " '.
fn xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}

/// SID вида S-1-5-21-…: только цифры, «S» и дефисы.
pub fn valid_sid(sid: &str) -> bool {
    sid.starts_with("S-1-") && sid.len() <= 184 && sid[2..].bytes().all(|b| b.is_ascii_digit() || b == b'-')
}

/// XML задачи: при входе этого пользователя — rxvpn.exe --autostart с наивысшими
/// правами, только пока он в системе (без пароля), без ограничений по времени и батарее.
pub fn task_xml(exe: &str, args: &str, user_sid: &str) -> Result<String, String> {
    if !valid_sid(user_sid) {
        return Err(trs!("автозапуск: странный SID учётки").into());
    }
    if exe.is_empty() || exe.contains('"') || exe.chars().any(char::is_control) {
        return Err(trs!("автозапуск: странный путь к rxvpn.exe").into());
    }
    if args.chars().any(char::is_control) {
        return Err(trs!("автозапуск: странный путь к rxvpn.exe").into());
    }
    let (exe, sid, args) = (xml(exe), xml(user_sid), xml(args));
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>rxvpn</Author><Description>rxvpn: autostart with administrator rights</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{sid}</UserId><Delay>PT5S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{sid}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>"{exe}"</Command><Arguments>{args}</Arguments></Exec></Actions>
</Task>
"#
    ))
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::path::Path;
    use std::process::Command;

    fn schtasks() -> Result<Command, String> {
        use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
        let mut buf = [0u16; 260];
        let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 || n >= buf.len() {
            return Err(trs!("не нашёл папку System32").into());
        }
        let mut c = Command::new(std::path::PathBuf::from(String::from_utf16_lossy(&buf[..n])).join("schtasks.exe"));
        c.creation_flags(0x0800_0000);
        crate::runner::clean_env(&mut c);
        Ok(c)
    }

    /// SID текущей учётки (у токена администратора — тот же человек).
    pub fn user_sid() -> Option<String> {
        use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut tok: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
                return None;
            }
            let mut buf = vec![0u64; 64]; // 512 байт, выровнено
            let mut len = 0u32;
            let ok = GetTokenInformation(tok, TokenUser, buf.as_mut_ptr().cast(), 512, &mut len);
            CloseHandle(tok);
            if ok == 0 {
                return None;
            }
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut w: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(tu.User.Sid, &mut w) == 0 || w.is_null() {
                return None;
            }
            let mut n = 0;
            while *w.add(n) != 0 {
                n += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(w, n));
            LocalFree(w as _);
            valid_sid(&s).then_some(s)
        }
    }

    /// Создать (или пересоздать) задачу. XML пишется во временный файл в папке
    /// программы `admin_dir` — туда может писать только администратор, так что
    /// подменить его между записью и чтением планировщиком некому.
    pub fn install(exe: &Path, args: &str, admin_dir: &Path) -> Result<(), String> {
        let sid = user_sid().ok_or(trs!("автозапуск: не узнать учётку Windows"))?;
        let text = task_xml(&exe.display().to_string(), args, &sid)?;
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        let file = admin_dir.join("rxvpn-autostart.xml");
        std::fs::write(&file, bytes).map_err(|e| tr!("автозапуск: {e}"))?;
        let out = schtasks()?.args(["/Create", "/TN", TASK_NAME, "/XML"]).arg(&file).arg("/F").output();
        let _ = std::fs::remove_file(&file);
        let out = out.map_err(|e| tr!("автозапуск: schtasks не запустился: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(tr!("автозапуск: планировщик не принял задачу (код {})", out.status.code().unwrap_or(-1)))
        }
    }

    /// Убрать задачу. Её нет — тоже успех.
    pub fn remove() -> Result<(), String> {
        if !present() {
            return Ok(());
        }
        let out = schtasks()?.args(["/Delete", "/TN", TASK_NAME, "/F"]).output().map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(tr!("автозапуск: задачу не удалить (код {}) — нужны права администратора", out.status.code().unwrap_or(-1)))
        }
    }

    pub fn present() -> bool {
        schtasks().ok().and_then(|mut c| c.args(["/Query", "/TN", TASK_NAME]).output().ok()).is_some_and(|o| o.status.success())
    }
}

#[cfg(not(windows))]
mod imp {
    use std::path::Path;
    pub fn user_sid() -> Option<String> {
        None
    }
    pub fn install(_exe: &Path, _args: &str, _admin_dir: &Path) -> Result<(), String> {
        Err(trs!("автозапуск пока только для Windows").into())
    }
    pub fn remove() -> Result<(), String> {
        Ok(())
    }
    pub fn present() -> bool {
        false
    }
}

pub use imp::{install, present, remove, user_sid};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_xml_is_safe() {
        let x = task_xml(r"C:\Program Files\rxvpn & co\rxvpn.exe", r#"--data "C:\Users\Я\rx<1>\data" --autostart"#, "S-1-5-21-1-2-3-1001").unwrap();
        assert!(x.contains(r#"<Arguments>--data &quot;C:\Users\Я\rx&lt;1&gt;\data&quot; --autostart</Arguments>"#), "{x}");
        assert!(x.contains(r#"<Command>"C:\Program Files\rxvpn &amp; co\rxvpn.exe"</Command>"#), "{x}");
        assert!(x.contains("<RunLevel>HighestAvailable</RunLevel>") && x.contains("<LogonType>InteractiveToken</LogonType>"));
        assert_eq!(x.matches("S-1-5-21-1-2-3-1001").count(), 2, "триггер и запуск — только этой учётки");
        assert!(task_xml(r"C:\x.exe", "", "S-1-5-21-1</UserId><x>").is_err());
        assert!(task_xml(r#"C:\x.exe" --evil"#, "", "S-1-5-21-1").is_err());
        assert!(task_xml("C:\\x\n.exe", "", "S-1-5-21-1").is_err());
        assert!(task_xml(r"C:\x.exe", "a\nb", "S-1-5-21-1").is_err());
        assert!(valid_sid("S-1-5-18") && !valid_sid("S-1-5-x") && !valid_sid("1-5-18"));
    }
}
