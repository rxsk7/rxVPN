//! Проверки Windows-частей (реестр, автозапуск, Job Object). Запускаются только
//! в Windows (или под Wine):
//!   cargo test -p rxvpn-core --test windows -- --include-ignored
#![cfg(windows)]

use std::time::Duration;

#[test]
fn autostart_roundtrip() {
    let line = r#""C:\rxvpn test\rxvpn.exe" --autostart"#;
    rxvpn_core::winsys::set_autostart(true, line).unwrap();
    assert_eq!(rxvpn_core::winsys::autostart_command().as_deref(), Some(line));
    rxvpn_core::winsys::set_autostart(false, line).unwrap();
    assert_eq!(rxvpn_core::winsys::autostart_command(), None);
    // повторное выключение — не ошибка
    rxvpn_core::winsys::set_autostart(false, line).unwrap();
}

#[test]
fn system_proxy_roundtrip() {
    use rxvpn_core::sysproxy;
    sysproxy::enable("127.0.0.1:10901").unwrap();
    assert_eq!(sysproxy::current().as_deref(), Some("127.0.0.1:10901"));
    sysproxy::cleanup_stale("127.0.0.1:10901");
    assert_eq!(sysproxy::current(), None);
}

#[test]
fn is_admin_does_not_crash() {
    let _ = rxvpn_core::winsys::is_admin();
}

/// Сетевая карта для гибрида: номер и имя подключения (не наш TUN).
#[test]
fn physical_interface_named() {
    use rxvpn_core::winsys;
    let Some(i) = winsys::best_interface() else { return }; // нет сети — нечего проверять
    let alias = winsys::iface_alias(i);
    println!("карта #{i}: {alias:?}");
    assert!(alias.as_deref().is_some_and(|a| !a.is_empty()), "имя подключения");
    assert_eq!(winsys::physical_interface(rxvpn_core::xray::TUN_NAME), Some(i));
    assert_eq!(winsys::physical_interface(alias.as_deref().unwrap()), None, "совпало с именем туннеля — не берём");
    assert_eq!(winsys::iface_alias(0x7fff_fff0), None);
}

/// Дочерний процесс должен умереть вместе с родителем, даже если родителя
/// убили (а не закрыли нормально). Запускаем сами себя как «родителя»:
/// он стартует xray и висит; мы его убиваем и смотрим, жив ли xray.
#[test]
#[ignore]
fn xray_dies_with_parent() {
    let Some(dir) = std::env::var_os("XRAY_DIR").map(std::path::PathBuf::from) else { return };
    if std::env::var_os("RXVPN_CHILD_MODE").is_some() {
        let cfg = std::env::temp_dir().join("rxvpn-job.json");
        std::fs::write(
            &cfg,
            r#"{"inbounds":[{"listen":"127.0.0.1","port":24711,"protocol":"socks"}],"outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        let p = rxvpn_core::runner::XrayProcess::start(&dir, &std::fs::read(&cfg).unwrap(), |_| {}, || {}).unwrap();
        std::mem::forget(p); // не даём Drop убить xray — пусть это сделает Windows
        std::thread::sleep(Duration::from_secs(60));
        return;
    }
    let me = std::env::current_exe().unwrap();
    let mut parent = std::process::Command::new(me)
        .args(["xray_dies_with_parent", "--include-ignored", "--exact", "--nocapture"])
        .env("RXVPN_CHILD_MODE", "1")
        .spawn()
        .unwrap();
    // ждём, пока xray займёт порт
    let mut up = false;
    for _ in 0..80 {
        if std::net::TcpStream::connect(("127.0.0.1", 24711)).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(up, "xray не поднялся");
    parent.kill().unwrap(); // как «Снять задачу» в диспетчере
    let _ = parent.wait();
    let mut dead = false;
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", 24711)).is_err() {
            dead = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(dead, "xray пережил rxvpn и держит порт");
}

/// Контрольный опыт: тот же сценарий, но xray запущен напрямую, без Job Object.
/// Он ДОЛЖЕН пережить родителя — иначе тест выше ничего не доказывает.
#[test]
#[ignore]
// Процесс специально бросаем без wait(): проверяем, что без Job он переживёт родителя.
#[allow(clippy::zombie_processes)]
fn control_without_job_xray_survives() {
    let Some(dir) = std::env::var_os("XRAY_DIR").map(std::path::PathBuf::from) else { return };
    if std::env::var_os("RXVPN_CHILD_MODE2").is_some() {
        let cfg = std::env::temp_dir().join("rxvpn-nojob.json");
        std::fs::write(
            &cfg,
            r#"{"inbounds":[{"listen":"127.0.0.1","port":24712,"protocol":"socks"}],"outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        let _c = std::process::Command::new(dir.join("xray.exe"))
            .args(["run", "-c"])
            .arg(&cfg)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_secs(60));
        return;
    }
    let me = std::env::current_exe().unwrap();
    let mut parent = std::process::Command::new(me)
        .args(["control_without_job_xray_survives", "--include-ignored", "--exact"])
        .env("RXVPN_CHILD_MODE2", "1")
        .spawn()
        .unwrap();
    let mut up = false;
    for _ in 0..80 {
        if std::net::TcpStream::connect(("127.0.0.1", 24712)).is_ok() {
            up = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(up, "xray не поднялся");
    parent.kill().unwrap();
    let _ = parent.wait();
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        std::net::TcpStream::connect(("127.0.0.1", 24712)).is_ok(),
        "без Job Object xray тоже умер — значит, тест с Job Object ничего не доказывает"
    );
}

/// Вторая копия видит первую; после выхода первой — запускается.
#[cfg(windows)]
#[test]
fn single_instance_mutex() {
    let first = rxvpn_core::winsys::acquire_instance(false).expect("первая копия");
    assert!(rxvpn_core::winsys::acquire_instance(false).is_none(), "вторая — нет");
    drop(first);
    assert!(rxvpn_core::winsys::acquire_instance(false).is_some(), "после закрытия первой — можно");
}

/// Движок zapret: берём официальный из папки Flowseal (ZAPRET_DIR), файлы
/// блокируются от подмены, winws запускается с чистым окружением.
/// Под Wine драйвер WinDivert не грузится — тогда ждём внятную ошибку winws.
#[test]
#[ignore]
fn zapret_engine_locked_and_launched() {
    use rxvpn_core::{runner::EngineProcess, zapret};
    use std::sync::{Arc, Mutex};
    let Some(dir) = std::env::var_os("ZAPRET_DIR").map(std::path::PathBuf::from) else { return };
    // Папка rxvpn с пробелом, кириллицей и апострофом — в аргументы winws это не попадает.
    let work = std::env::temp_dir().join(format!("rxvpn zw Ром's {}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    let (engine, run) = (work.join("engine"), work.join("run"));

    let scan = zapret::scan(&dir, false).unwrap();
    assert!(!scan.strategies.is_empty());
    // ZAPRET_ENGINE_ZIP — официальный архив bol-van: движок из него, а не из папки
    // (так работает встроенный zapret: стратегии свои, движок скачан с GitHub).
    let v = match std::env::var_os("ZAPRET_ENGINE_ZIP") {
        Some(z) => zapret::engine_from_zip(&std::fs::read(z).unwrap(), &engine).unwrap(),
        None => zapret::engine_from_folder(&zapret::engine_dir_in(&dir).expect("bin с winws.exe"), &engine).unwrap(),
    };
    eprintln!("движок {v}");

    let (_, lock) = zapret::engine_lock(&engine).unwrap();
    // Пока файлы открыты нами — ни записать, ни переименовать, ни удалить.
    assert!(std::fs::OpenOptions::new().write(true).open(engine.join("winws.exe")).is_err(), "запись должна быть запрещена");
    assert!(std::fs::rename(engine.join("WinDivert64.sys"), engine.join("x.sys")).is_err(), "переименование тоже");
    assert!(std::fs::remove_file(engine.join("cygwin1.dll")).is_err(), "и удаление");
    // Вторая проверка (следующая стратегия при подборе) открывается рядом с первой.
    let (_, lock2) = zapret::engine_lock(&engine).unwrap();
    drop(lock2);

    // Служба WinDivert от другой программы: чужой драйвер — отказ, тот же официальный — можно.
    {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
        let (key, _) = hklm.create_subkey(r"SYSTEM\CurrentControlSet\Services\WinDivert").unwrap();
        let fake = work.join("other.sys");
        std::fs::write(&fake, b"not a driver").unwrap();
        key.set_value("ImagePath", &format!(r"\??\{}", fake.display())).unwrap();
        let e = zapret::engine_lock(&engine).err().expect("чужой драйвер");
        assert!(e.contains("чужой драйвер"), "{e}");
        key.set_value("ImagePath", &r"\\attacker\share\WinDivert64.sys".to_string()).unwrap();
        assert!(zapret::engine_lock(&engine).is_err(), "сетевой путь");
        let copy = work.join("WinDivert64.sys");
        std::fs::copy(engine.join("WinDivert64.sys"), &copy).unwrap();
        key.set_value("ImagePath", &format!(r"\??\{}", copy.display())).unwrap();
        let (_, l3) = zapret::engine_lock(&engine).expect("официальный драйвер в другой папке");
        assert!(std::fs::OpenOptions::new().write(true).open(&copy).is_err(), "его тоже не подменить");
        drop(l3);
        hklm.delete_subkey_all(r"SYSTEM\CurrentControlSet\Services\WinDivert").unwrap();
    }

    // Окружение у движка — только системное.
    std::env::set_var("RXVPN_LEAK_TEST", "1");
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let s2 = seen.clone();
    let cmd = std::path::PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32").join("cmd.exe");
    let args: Vec<std::ffi::OsString> = ["/c", "set"].iter().map(Into::into).collect();
    let _ = EngineProcess::start(&cmd, &args, &engine, Duration::from_secs(3), move |l| s2.lock().unwrap().push(l), || {});
    std::thread::sleep(Duration::from_millis(300));
    let env = seen.lock().unwrap().join("\n").to_uppercase();
    eprintln!("окружение движка:\n{env}");
    assert!(env.contains("SYSTEMROOT="), "{env}");
    assert!(!env.contains("RXVPN_LEAK_TEST") && !env.contains("USERPROFILE="), "лишнее из окружения: {env}");

    // Сам winws со стратегией (пути с пробелами, файлы — в рабочей папке).
    let s = &scan.strategies[0];
    let args = zapret::prepare(&dir, s, &run).unwrap();
    let out = Arc::new(Mutex::new(Vec::<String>::new()));
    let o2 = out.clone();
    let r = EngineProcess::start(&engine.join("winws.exe"), &args, &run, Duration::from_millis(1500), move |l| o2.lock().unwrap().push(l), || {});
    eprintln!("winws «{}»: {}", s.name, match &r { Ok(_) => "работает".to_string(), Err(e) => e.clone() });
    eprintln!("вывод winws:\n{}", out.lock().unwrap().join("\n"));
    if let Err(e) = &r {
        assert!(e.contains("winws.exe завершился"), "{e}");
    }
    drop(r);
    drop(lock);

    // Все стратегии папки: winws сам проверяет разобранные нами аргументы
    // (--dry-run: разобрать опции, прочитать файлы и выйти с кодом 0).
    let mut bad = Vec::new();
    for s in &scan.strategies {
        let mut args = zapret::prepare(&dir, s, &run).unwrap();
        args.push("--dry-run".into());
        let o = std::process::Command::new(engine.join("winws.exe")).args(&args).current_dir(&run).output().unwrap();
        if !o.status.success() {
            bad.push(format!("{}: {}\n{}", s.name, o.status, String::from_utf8_lossy(&o.stdout).lines().chain(String::from_utf8_lossy(&o.stderr).lines()).collect::<Vec<_>>().join("\n")));
        }
    }
    // Гибрид: тот же winws, но с --wf-iface и исключением адресов VPN-серверов в каждом профиле.
    let h = zapret::Hybrid { iface: Some(1), exclude: vec!["203.0.113.7".parse().unwrap(), "2001:db8::1".parse().unwrap()] };
    for s in scan.strategies.iter().take(2) {
        let mut args = zapret::prepare_hybrid(&dir, s, &run, &h).unwrap();
        args.push("--dry-run".into());
        let o = std::process::Command::new(engine.join("winws.exe")).args(&args).current_dir(&run).output().unwrap();
        if !o.status.success() {
            bad.push(format!("гибрид {}: {}\n{}", s.name, o.status, String::from_utf8_lossy(&o.stdout)));
        }
    }
    eprintln!("dry-run: {} стратегий, не приняты: {}", scan.strategies.len(), bad.len());
    assert!(bad.is_empty(), "{}", bad.join("\n---\n"));
    let _ = std::fs::remove_dir_all(&work);
}

/// DPAPI: state.json с «Шифровать пароли» — на диске без паролей, читается обратно;
/// испорченный — «закрыт», файл не трогаем.
#[test]
fn state_sealed_roundtrip() {
    use rxvpn_core::{parse_link, Store};
    let dir = std::env::temp_dir().join(format!("rxvpn-seal-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("state.json");
    let mut s = Store::default();
    s.servers.push(parse_link("trojan://SECRETPASS@a.example:443#t").unwrap());
    s.settings.encrypt_state = true;
    s.save(&p).unwrap();
    let raw = std::fs::read(&p).unwrap();
    assert!(raw.starts_with(rxvpn_core::store::SEALED));
    assert!(!String::from_utf8_lossy(&raw).contains("SECRETPASS"), "пароль не виден");
    let (back, locked) = Store::load_ex(&p);
    assert!(!locked);
    assert_eq!(back.servers[0].password.as_deref(), Some("SECRETPASS"));
    // Чужой ключ / испорчен — «закрыт», файл как был.
    let mut bad = rxvpn_core::store::SEALED.to_vec();
    bad.extend_from_slice(b"AAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    std::fs::write(&p, &bad).unwrap();
    let (empty, locked) = Store::load_ex(&p);
    assert!(locked && empty.servers.is_empty());
    assert_eq!(std::fs::read(&p).unwrap(), bad);
    let _ = std::fs::remove_dir_all(&dir);
}
