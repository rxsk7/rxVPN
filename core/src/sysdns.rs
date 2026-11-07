//! Системный DNS Windows на время «DNS без подмены» (doh.rs): у сетевых карт с
//! интернетом первым ставим 127.0.0.1 (и ::1), запасными — их прежние DNS.
//!
//! Порядок — чтобы никогда не остаться без интернета:
//! 1. Что было (статические DNS из реестра, DHCP — пометкой) — сначала в запись
//!    возврата, и только потом меняем. В Windows она лежит в `HKLM\SOFTWARE\rxvpn`
//!    (`DnsRestore`): писать туда может только администратор. Файл в `data\`
//!    подменила бы любая программа без прав — и rxvpn с правами админа поставил бы
//!    её DNS всей системе. В других ОС (тесты) — файл `data/dns-restore.json`.
//! 2. Возврат — по этой записи: при выключении, отключении, выходе, панике и
//!    при следующем запуске rxvpn, если прошлый упал. Вернули — запись удаляем.
//! 3. Прежние DNS остаются запасными: если rxvpn не запущен (упал, комп
//!    перезагрузили), Windows сама перейдёт на них — интернет не пропадёт.
//!
//! Меняем через `netsh` по номеру карты (не по имени — оно бывает на любом
//! языке), аргументы — отдельными строками, без оболочки; адреса проверены.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Сетевая карта и её DNS до нас.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Iface {
    pub index: u32,
    pub guid: String,
    pub alias: String,
    /// Статические DNS (пусто — брались от DHCP/роутера).
    pub v4_static: Vec<String>,
    pub v6_static: Vec<String>,
    /// Прежние рабочие DNS (статические или от DHCP) — станут запасными.
    pub v4_fallback: Vec<String>,
    pub v6_fallback: Vec<String>,
    /// IPv6 тоже меняли (слушаем на ::1).
    pub v6: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Saved {
    pub ifaces: Vec<Iface>,
}

pub fn restore_file(data: &Path) -> PathBuf {
    data.join("dns-restore.json")
}

/// Осталась запись возврата — значит, DNS сейчас наш (или прошлый запуск упал).
pub fn pending(data: &Path) -> bool {
    imp::store_read(data).is_some()
}

/// Список DNS из реестра («1.1.1.1,8.8.8.8» или через пробел): только настоящие
/// адреса, без наших 127.0.0.1/::1 (их мог оставить упавший запуск), не больше 4.
pub fn parse_servers(s: &str, v6: bool) -> Vec<String> {
    s.split([',', ' ', ';'])
        .filter_map(|x| x.trim().parse::<IpAddr>().ok())
        .filter(|ip| ip.is_ipv6() == v6 && !ip.is_loopback() && !ip.is_unspecified())
        .map(|ip| ip.to_string())
        .take(4)
        .collect()
}

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Команды netsh: поставить наш DNS (и прежние запасными).
pub fn apply_cmds(i: &Iface) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut fam = |proto: &str, ours: &str, fallback: &[String]| {
        let name = format!("name={}", i.index);
        let addr = format!("address={ours}");
        out.push(args(&["interface", proto, "set", "dnsservers", &name, "source=static", &addr, "register=none", "validate=no"]));
        for (n, fb) in fallback.iter().enumerate() {
            let (a, idx) = (format!("address={fb}"), format!("index={}", n + 2));
            out.push(args(&["interface", proto, "add", "dnsservers", &name, &a, &idx, "validate=no"]));
        }
    };
    fam("ipv4", "127.0.0.1", &i.v4_fallback);
    if i.v6 {
        fam("ipv6", "::1", &i.v6_fallback);
    }
    out
}

/// Команды netsh: вернуть как было.
pub fn restore_cmds(i: &Iface) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut fam = |proto: &str, stat: &[String]| {
        let name = format!("name={}", i.index);
        match stat.split_first() {
            None => out.push(args(&["interface", proto, "set", "dnsservers", &name, "source=dhcp"])),
            Some((first, rest)) => {
                let a = format!("address={first}");
                out.push(args(&["interface", proto, "set", "dnsservers", &name, "source=static", &a, "register=primary", "validate=no"]));
                for (n, x) in rest.iter().enumerate() {
                    let (a, idx) = (format!("address={x}"), format!("index={}", n + 2));
                    out.push(args(&["interface", proto, "add", "dnsservers", &name, &a, &idx, "validate=no"]));
                }
            }
        }
    };
    fam("ipv4", &i.v4_static);
    if i.v6 {
        fam("ipv6", &i.v6_static);
    }
    out
}

fn save(data: &Path, s: &Saved) -> Result<(), String> {
    imp::store_write(data, &serde_json::to_string(s).unwrap())
}

fn load(data: &Path) -> Option<Saved> {
    parse_saved(&imp::store_read(data)?)
}

/// Разобрать и проверить запись возврата.
fn parse_saved(b: &str) -> Option<Saved> {
    if b.len() > 64 * 1024 {
        return None;
    }
    let s: Saved = serde_json::from_str(b).ok()?;
    // Файл мог кто-то подменить: в netsh пойдут только номера и проверенные адреса.
    let ok = s.ifaces.len() <= 32
        && s.ifaces.iter().all(|i| {
            [&i.v4_static, &i.v4_fallback].iter().all(|v| v.iter().all(|a| a.parse::<std::net::Ipv4Addr>().is_ok()))
                && [&i.v6_static, &i.v6_fallback].iter().all(|v| v.iter().all(|a| a.parse::<std::net::Ipv6Addr>().is_ok()))
        });
    ok.then_some(s)
}

/// Поставить наш DNS на карты `ifaces` (их прежние DNS — уже внутри).
/// Сначала файл возврата, потом netsh; не вышло на какой-то карте — всё назад.
pub fn apply(data: &Path, ifaces: Vec<Iface>) -> Result<Saved, String> {
    // Прошлый раз не вернули (упал) — сначала вернуть, иначе «прежним» запишем свой 127.0.0.1.
    if pending(data) {
        restore(data)?;
    }
    if ifaces.is_empty() {
        return Err(trs!("DoH: не нашёл сетевую карту с интернетом").into());
    }
    let saved = Saved { ifaces };
    save(data, &saved)?;
    let mut done: Vec<&Iface> = Vec::new();
    for i in &saved.ifaces {
        if let Err(e) = imp::run_all(&apply_cmds(i)) {
            for d in done.iter().chain([&i]) {
                let _ = imp::run_all(&restore_cmds(d));
            }
            imp::store_clear(data);
            imp::flush();
            return Err(tr!("DoH: DNS у «{}» не поменялся ({e}) — вернул как было", i.alias));
        }
        done.push(i);
    }
    imp::flush();
    Ok(saved)
}

/// Добавить карту, появившуюся после включения (переключился с Wi-Fi на кабель).
pub fn add(data: &Path, i: Iface) -> Result<(), String> {
    let mut s = load(data).ok_or(trs!("DoH: запись возврата DNS пропала"))?;
    if s.ifaces.iter().any(|x| x.index == i.index) {
        return Ok(());
    }
    s.ifaces.push(i.clone());
    save(data, &s)?;
    if let Err(e) = imp::run_all(&apply_cmds(&i)) {
        let _ = imp::run_all(&restore_cmds(&i));
        s.ifaces.retain(|x| x.index != i.index);
        let _ = save(data, &s);
        return Err(e);
    }
    imp::flush();
    Ok(())
}

/// Вернуть DNS как было (по файлу). Нет файла — нечего возвращать.
/// Ошибка у одной карты (её вынули) не мешает остальным; файл удаляем, когда вернули всё.
pub fn restore(data: &Path) -> Result<(), String> {
    if !pending(data) {
        return Ok(());
    }
    let Some(s) = load(data) else {
        // Испорченная запись: возвращаем DHCP на всех картах с нашим 127.0.0.1 — это безопаснее всего.
        let r = imp::reset_ours();
        if r.is_ok() {
            imp::store_clear(data);
        }
        return r;
    };
    let mut errs = Vec::new();
    for i in &s.ifaces {
        if let Err(e) = imp::run_all(&restore_cmds(i)) {
            // Карты больше нет — и возвращать нечего.
            if imp::iface_exists(i.index) {
                errs.push(format!("«{}»: {e}", i.alias));
            }
        }
    }
    imp::flush();
    if errs.is_empty() {
        imp::store_clear(data);
        Ok(())
    } else {
        Err(tr!("DNS Windows вернулся не везде: {}", errs.join("; ")))
    }
}

/// Карты с интернетом (кроме туннеля `tun`) и их DNS сейчас.
pub fn targets(tun: &str, v6: bool) -> Vec<Iface> {
    imp::targets(tun, v6)
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::Command;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    /// Путь к System32 — от самой Windows, не из переменных окружения: их меняет
    /// любая программа (HKCU\Environment), а netsh мы запускаем с правами админа.
    fn system32(exe: &str) -> Result<PathBuf, String> {
        use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
        let mut buf = [0u16; 260];
        let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
        if n == 0 || n >= buf.len() {
            return Err(trs!("не нашёл папку System32").into());
        }
        Ok(PathBuf::from(String::from_utf16_lossy(&buf[..n])).join(exe))
    }

    fn command(exe: &str) -> Result<Command, String> {
        let mut c = Command::new(system32(exe)?);
        c.creation_flags(0x0800_0000);
        crate::runner::clean_env(&mut c);
        Ok(c)
    }

    fn run(a: &[String]) -> Result<(), String> {
        let out = command("netsh.exe")?.args(a).output().map_err(|e| tr!("netsh не запустился: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(tr!("netsh {} — код {}", a[..4.min(a.len())].join(" "), out.status.code().unwrap_or(-1)))
        }
    }

    pub fn run_all(cmds: &[Vec<String>]) -> Result<(), String> {
        cmds.iter().try_for_each(|c| run(c))
    }

    pub fn flush() {
        if let Ok(mut c) = command("ipconfig.exe") {
            let _ = c.arg("/flushdns").output();
        }
    }

    const KEY: &str = r"SOFTWARE\rxvpn";
    const VALUE: &str = "DnsRestore";

    pub fn store_read(_data: &Path) -> Option<String> {
        RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(KEY, KEY_READ).ok()?.get_value::<String, _>(VALUE).ok()
    }

    pub fn store_write(_data: &Path, v: &str) -> Result<(), String> {
        use winreg::enums::KEY_WRITE;
        let (k, _) = RegKey::predef(HKEY_LOCAL_MACHINE)
            .create_subkey_with_flags(KEY, KEY_READ | KEY_WRITE)
            .map_err(|e| tr!("DoH: не записалось в реестр ({e}) — нужны права администратора"))?;
        k.set_value(VALUE, &v.to_string()).map_err(|e| tr!("DoH: не записалось в реестр: {e}"))
    }

    pub fn store_clear(_data: &Path) {
        use winreg::enums::KEY_WRITE;
        if let Ok(k) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(KEY, KEY_READ | KEY_WRITE) {
            let _ = k.delete_value(VALUE);
        }
        let _ = RegKey::predef(HKEY_LOCAL_MACHINE).delete_subkey(KEY); // пустой ключ — убрать
    }

    fn reg(v6: bool, guid: &str, name: &str) -> String {
        let p = format!(r"SYSTEM\CurrentControlSet\Services\{}\Parameters\Interfaces\{guid}", if v6 { "Tcpip6" } else { "Tcpip" });
        RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(p, KEY_READ).and_then(|k| k.get_value::<String, _>(name)).unwrap_or_default()
    }

    struct Raw {
        index: u32,
        guid: String,
        alias: String,
    }

    /// Карты: работает, не loopback, есть шлюз.
    fn adapters(with_gateway: bool) -> Vec<Raw> {
        use windows_sys::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES_LH};
        use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;
        let mut len: u32 = 32 * 1024;
        let mut buf: Vec<u64> = Vec::new();
        let mut r = 0;
        for _ in 0..3 {
            buf = vec![0u64; (len as usize).div_ceil(8)];
            r = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, GAA_FLAG_INCLUDE_GATEWAYS, std::ptr::null(), buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH, &mut len) };
            if r != 111 {
                break; // не ERROR_BUFFER_OVERFLOW
            }
        }
        let mut out = Vec::new();
        if r != 0 {
            return out;
        }
        let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !p.is_null() {
            let a = unsafe { &*p };
            p = a.Next;
            // 1 — IfOperStatusUp; 24 — loopback.
            if a.OperStatus != 1 || a.IfType == 24 || (with_gateway && a.FirstGatewayAddress.is_null()) {
                continue;
            }
            let index = unsafe { a.Anonymous1.Anonymous.IfIndex };
            let guid = unsafe { std::ffi::CStr::from_ptr(a.AdapterName as *const std::ffi::c_char) }.to_string_lossy().to_string();
            let alias = if a.FriendlyName.is_null() {
                String::new()
            } else {
                let mut n = 0;
                while unsafe { *a.FriendlyName.add(n) } != 0 && n < 256 {
                    n += 1;
                }
                String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(a.FriendlyName, n) })
            };
            if index != 0 && guid.starts_with('{') {
                out.push(Raw { index, guid, alias });
            }
        }
        out
    }

    pub fn targets(tun: &str, v6: bool) -> Vec<Iface> {
        adapters(true)
            .into_iter()
            .filter(|r| !r.alias.eq_ignore_ascii_case(tun))
            .take(16)
            .map(|r| {
                let v4_static = parse_servers(&reg(false, &r.guid, "NameServer"), false);
                let v6_static = parse_servers(&reg(true, &r.guid, "NameServer"), true);
                let v4_fallback = if v4_static.is_empty() { parse_servers(&reg(false, &r.guid, "DhcpNameServer"), false) } else { v4_static.clone() };
                let v6_fallback = if v6_static.is_empty() { parse_servers(&reg(true, &r.guid, "DhcpNameServer"), true) } else { v6_static.clone() };
                Iface { index: r.index, guid: r.guid, alias: r.alias, v4_static, v6_static, v4_fallback, v6_fallback, v6 }
            })
            .collect()
    }

    pub fn iface_exists(index: u32) -> bool {
        adapters(false).iter().any(|r| r.index == index)
    }

    /// Файла нет или испорчен: у карт, где первым стоит наш 127.0.0.1, — DHCP.
    pub fn reset_ours() -> Result<(), String> {
        let mut errs = Vec::new();
        for r in adapters(false) {
            for v6 in [false, true] {
                let ns = reg(v6, &r.guid, "NameServer");
                let ours = if v6 { "::1" } else { "127.0.0.1" };
                if ns.split([',', ' ']).next().is_some_and(|f| f.trim() == ours) {
                    let name = format!("name={}", r.index);
                    if let Err(e) = run(&args(&["interface", if v6 { "ipv6" } else { "ipv4" }, "set", "dnsservers", &name, "source=dhcp"])) {
                        errs.push(e);
                    }
                }
            }
        }
        flush();
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.join("; "))
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    pub fn store_read(data: &Path) -> Option<String> {
        std::fs::read_to_string(restore_file(data)).ok()
    }
    pub fn store_write(data: &Path, v: &str) -> Result<(), String> {
        let p = restore_file(data);
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, v).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &p).map_err(|e| e.to_string())
    }
    pub fn store_clear(data: &Path) {
        let _ = std::fs::remove_file(restore_file(data));
    }
    pub fn run_all(_cmds: &[Vec<String>]) -> Result<(), String> {
        Err(trs!("системный DNS меняется только в Windows").into())
    }
    pub fn flush() {}
    pub fn targets(_tun: &str, _v6: bool) -> Vec<Iface> {
        Vec::new()
    }
    pub fn iface_exists(_index: u32) -> bool {
        false
    }
    pub fn reset_ours() -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wifi() -> Iface {
        Iface {
            index: 12,
            guid: "{A}".into(),
            alias: "Wi-Fi".into(),
            v4_static: vec![],
            v6_static: vec![],
            v4_fallback: vec!["192.168.1.1".into()],
            v6_fallback: vec!["fe80::1".into()],
            v6: true,
        }
    }

    #[test]
    fn servers_from_registry() {
        assert_eq!(parse_servers("1.1.1.1,8.8.8.8", false), vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(parse_servers("192.168.1.1 127.0.0.1 x;  2001:db8::1", false), vec!["192.168.1.1"]);
        assert_eq!(parse_servers("::1 2001:db8::1 1.1.1.1", true), vec!["2001:db8::1"]);
        assert!(parse_servers("", false).is_empty());
        assert_eq!(parse_servers("1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9", false).len(), 4);
    }

    #[test]
    fn netsh_plans() {
        let a = apply_cmds(&wifi());
        assert_eq!(a[0].join(" "), "interface ipv4 set dnsservers name=12 source=static address=127.0.0.1 register=none validate=no");
        assert_eq!(a[1].join(" "), "interface ipv4 add dnsservers name=12 address=192.168.1.1 index=2 validate=no");
        assert_eq!(a[2].join(" "), "interface ipv6 set dnsservers name=12 source=static address=::1 register=none validate=no");
        assert_eq!(a.len(), 4);
        // Было от DHCP — возвращаем DHCP.
        let r = restore_cmds(&wifi());
        assert_eq!(r[0].join(" "), "interface ipv4 set dnsservers name=12 source=dhcp");
        assert_eq!(r[1].join(" "), "interface ipv6 set dnsservers name=12 source=dhcp");
        // Были свои — возвращаем их в том же порядке.
        let mut s = wifi();
        s.v4_static = vec!["1.1.1.1".into(), "8.8.8.8".into()];
        s.v6 = false;
        let r = restore_cmds(&s);
        assert_eq!(r.len(), 2);
        assert!(r[0].join(" ").contains("source=static address=1.1.1.1 register=primary"));
        assert!(r[1].join(" ").contains("address=8.8.8.8 index=2"));
    }

    #[test]
    fn restore_record_is_checked() {
        let good = serde_json::to_string(&Saved { ifaces: vec![wifi()] }).unwrap();
        assert_eq!(parse_saved(&good).unwrap().ifaces[0], wifi());
        // Подмена: «адрес» с лишним аргументом для netsh — запись не принимаем.
        let mut bad = wifi();
        bad.v4_static = vec!["1.1.1.1 & calc".into()];
        assert!(parse_saved(&serde_json::to_string(&Saved { ifaces: vec![bad] }).unwrap()).is_none());
        let mut v6_in_v4 = wifi();
        v6_in_v4.v4_fallback = vec!["::1".into()];
        assert!(parse_saved(&serde_json::to_string(&Saved { ifaces: vec![v6_in_v4] }).unwrap()).is_none());
        assert!(parse_saved("{not json").is_none());
        assert!(parse_saved(&"x".repeat(70_000)).is_none());
    }

    /// Только не в Windows: там это настоящий реестр и netsh (тест не должен трогать сеть).
    #[cfg(not(windows))]
    #[test]
    fn apply_without_netsh_leaves_nothing() {
        let dir = std::env::temp_dir().join(format!("rxvpn-sysdns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        save(&dir, &Saved { ifaces: vec![wifi()] }).unwrap();
        assert!(pending(&dir));
        imp::store_clear(&dir);
        assert!(apply(&dir, vec![wifi()]).is_err());
        assert!(!pending(&dir), "не поменяли — записи возврата нет");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
