//! sing-box — помощник Xray для протоколов, которых в Xray нет (TUIC v5).
//!
//! Главное ядро остаётся Xray: маршруты, «Обход РФ», TUN, kill switch, проверки — всё
//! работает как с любым сервером. Для сервера tuic:// Xray получает обычный SOCKS-выход на
//! 127.0.0.1, а за ним стоит sing-box, который и говорит с сервером по TUIC.
//!
//! Безопасность:
//! - качаем одну проверенную версию: SHA-256 архива и самого sing-box.exe вшиты в rxvpn;
//! - перед каждым запуском sing-box.exe сверяется с вшитым хешем и держится открытым
//!   «только для чтения» — подменить его, пока он работает, нельзя;
//! - конфиг — через stdin, на диск не пишется; SOCKS-входы только на 127.0.0.1;
//! - метку `rxvpnSingbox` в конфиге Xray ставит только сам rxvpn (из своего разбора tuic://):
//!   из JSON-подписок она вычищается, а здесь принимается только TUIC с известными полями.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};

use crate::link::Tuic;

pub const VERSION: &str = "1.14.4";
pub const ZIP_NAME: &str = "sing-box-1.14.4-windows-amd64.zip";
pub const ZIP_URL: &str = "https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-windows-amd64.zip";
/// SHA-256 архива (совпадает с digest, который публикует GitHub).
pub const ZIP_SHA256: &str = "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df";
/// SHA-256 sing-box.exe внутри архива.
pub const EXE_SHA256: &str = "8f30682ee198855440d2a7fe070d5d3653793b2d01bb8c85eea88f93bbe7c8b9";
const ZIP_ENTRY: &str = "sing-box-1.14.4-windows-amd64/sing-box.exe";
const MAX_ZIP: usize = 80 << 20;
const MAX_EXE: u64 = 200 << 20;

/// Метка на SOCKS-выходе Xray: «за этим выходом — sing-box с таким выходом».
pub const MARK: &str = "rxvpnSingbox";

pub fn exe_path(core_dir: &Path) -> PathBuf {
    core_dir.join("sing-box.exe")
}

pub fn installed(core_dir: &Path) -> bool {
    exe_path(core_dir).exists()
}

/// Сервер везёт sing-box (а не Xray).
pub fn is_sidecar_link(link: &str) -> bool {
    link.trim_start().get(..7).is_some_and(|s| s.eq_ignore_ascii_case("tuic://"))
}

/// Скачать архив sing-box (через `socks_port`, если VPN уже работает) и сверить хеш.
pub async fn fetch_zip(socks_port: Option<u16>) -> Result<Vec<u8>, String> {
    let mut b = reqwest::Client::builder().timeout(Duration::from_secs(300)).https_only(true);
    if let Some(p) = socks_port {
        b = b.proxy(reqwest::Proxy::all(format!("socks5h://127.0.0.1:{p}")).map_err(|e| e.to_string())?);
    }
    let client = b.build().map_err(|e| e.to_string())?;
    let r = client.get(ZIP_URL).send().await.and_then(|r| r.error_for_status()).map_err(|e| tr!("GitHub недоступен: {e}"))?;
    let zip = crate::net::read_capped(r, MAX_ZIP).await?;
    let got = crate::net::sha256_hex(&zip);
    if got != ZIP_SHA256 {
        return Err(tr!("архив sing-box не сошёлся с хешем (ждали {ZIP_SHA256}, пришло {got}) — не ставлю"));
    }
    Ok(zip)
}

/// Достать sing-box.exe из архива, сверить и положить в папку ядра.
pub fn install_zip(zip: &[u8], core_dir: &Path) -> Result<(), String> {
    if crate::net::sha256_hex(zip) != ZIP_SHA256 {
        return Err(trs!("архив sing-box не тот — не ставлю").into());
    }
    let mut a = zip::ZipArchive::new(std::io::Cursor::new(zip)).map_err(|e| tr!("архив sing-box: {e}"))?;
    let mut f = a.by_name(ZIP_ENTRY).map_err(|_| trs!("в архиве нет sing-box.exe").to_string())?;
    let mut exe = Vec::new();
    (&mut f).take(MAX_EXE).read_to_end(&mut exe).map_err(|e| e.to_string())?;
    if crate::net::sha256_hex(&exe) != EXE_SHA256 {
        return Err(trs!("sing-box.exe в архиве не тот — не ставлю").into());
    }
    std::fs::create_dir_all(core_dir).map_err(|e| e.to_string())?;
    let tmp = core_dir.join("sing-box.exe.part");
    std::fs::write(&tmp, &exe).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, exe_path(core_dir)).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        tr!("sing-box.exe не записался (он сейчас запущен?): {e}")
    })
}

/// Выход sing-box для TUIC. `server` — адрес, к которому подключаться (уже IP, если
/// имя разрешили заранее), SNI остаётся по имени из ссылки.
pub fn tuic_outbound(t: &Tuic, server: &str, tag: &str) -> Value {
    let mut tls = json!({"enabled": true, "alpn": t.alpn});
    if let Some(s) = &t.sni {
        tls["server_name"] = json!(s);
    }
    json!({
        "type": "tuic", "tag": tag, "server": server, "server_port": t.port,
        "uuid": t.uuid, "password": t.password,
        "congestion_control": t.congestion, "udp_relay_mode": t.udp_relay,
        "heartbeat": "10s", "tls": tls,
    })
}

/// Выход Xray для такого сервера: SOCKS на 127.0.0.1 (порт подставит `split`) с меткой.
pub fn xray_outbound(link: &str) -> Option<Value> {
    let (_, t) = crate::link::parse_tuic(link).ok()?;
    Some(json!({
        "tag": "proxy", "protocol": "socks",
        "settings": {"servers": [{"address": "127.0.0.1", "port": 1}]},
        MARK: tuic_outbound(&t, &t.host, "out"),
    }))
}

/// Метку из чужого JSON (подписки) — убрать: её ставит только rxvpn.
pub fn strip_marks(outbounds: &mut [Value]) {
    for o in outbounds {
        if let Some(m) = o.as_object_mut() {
            m.remove(MARK);
        }
    }
}

/// Принимаем только TUIC с известными полями и безопасными значениями.
fn check(ob: &Value) -> Result<(), String> {
    const KEYS: &[&str] = &["type", "tag", "server", "server_port", "uuid", "password", "congestion_control", "udp_relay_mode", "heartbeat", "tls"];
    const TLS: &[&str] = &["enabled", "alpn", "server_name", "certificate"];
    let m = ob.as_object().ok_or(trs!("sing-box: странный выход в конфиге — не запускаю"))?;
    let ok = ob["type"] == "tuic"
        && m.keys().all(|k| KEYS.contains(&k.as_str()))
        && ob["tls"].as_object().is_some_and(|t| t.keys().all(|k| TLS.contains(&k.as_str())) && t.get("enabled") == Some(&json!(true)))
        && ob["server"].as_str().is_some_and(|s| !s.is_empty() && s.len() <= 253)
        && ob["server_port"].as_u64().is_some_and(|p| (1..=65535).contains(&p));
    if ok {
        Ok(())
    } else {
        Err(trs!("sing-box: странный выход в конфиге — не запускаю").into())
    }
}

/// Сервер по имени → IP заранее: тогда sing-box не ходит в DNS, а в TUN Xray знает,
/// какой адрес выпускать мимо туннеля.
fn resolve(host: &str, port: u16) -> Vec<String> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return vec![host.to_string()];
    }
    use std::net::ToSocketAddrs;
    let mut v: Vec<String> = (host, port).to_socket_addrs().map(|a| a.map(|x| x.ip().to_string()).collect()).unwrap_or_default();
    v.dedup();
    v
}

/// Найти в конфиге Xray выходы с меткой: каждому — свой SOCKS-вход sing-box на
/// свободном порту 127.0.0.1. Возвращает конфиг sing-box (None — меток нет) и порты.
pub fn split(cfg: &mut Value) -> Result<Option<(Value, Vec<u16>)>, String> {
    let Some(outs) = cfg["outbounds"].as_array_mut() else { return Ok(None) };
    let (mut ins, mut sb_outs, mut rules, mut ports, mut direct_ips) = (vec![], vec![], vec![], vec![], vec![]);
    for o in outs.iter_mut() {
        let Some(mut ob) = o.as_object_mut().and_then(|m| m.remove(MARK)) else { continue };
        check(&ob)?;
        let port = std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map_err(|e| e.to_string())?.port();
        let i = ports.len();
        let host = ob["server"].as_str().unwrap_or_default().to_string();
        let ips = resolve(&host, ob["server_port"].as_u64().unwrap_or(443) as u16);
        let ip = ips.first().ok_or_else(|| tr!("sing-box: адрес «{host}» не нашёлся"))?;
        ob["server"] = json!(ip);
        ob["tag"] = json!(format!("o{i}"));
        direct_ips.extend(ips.iter().cloned());
        o["settings"]["servers"][0]["port"] = json!(port);
        ins.push(json!({"type": "socks", "tag": format!("i{i}"), "listen": "127.0.0.1", "listen_port": port}));
        rules.push(json!({"inbound": [format!("i{i}")], "outbound": format!("o{i}")}));
        sb_outs.push(ob);
        ports.push(port);
    }
    if ports.is_empty() {
        return Ok(None);
    }
    // В TUN пакеты sing-box к серверу тоже попадают в туннель — Xray выпускает их
    // напрямую (его выходы и так привязаны к настоящему адаптеру), иначе петля.
    let tun = cfg["inbounds"].as_array().is_some_and(|a| a.iter().any(|i| i["protocol"] == "tun"));
    if tun {
        direct_ips.sort();
        direct_ips.dedup();
        let has_direct = cfg["outbounds"].as_array().is_some_and(|a| a.iter().any(|o| o["tag"] == "direct"));
        if !has_direct {
            cfg["outbounds"].as_array_mut().unwrap().push(json!({"tag": "direct", "protocol": "freedom"}));
        }
        let rule = json!({"inboundTag": ["tun"], "ip": direct_ips, "outboundTag": "direct"});
        match cfg["routing"]["rules"].as_array_mut() {
            Some(r) => r.insert(0, rule),
            None => cfg["routing"]["rules"] = json!([rule]),
        }
    }
    let sb = json!({
        "log": {"level": "warn", "timestamp": false},
        "inbounds": ins,
        "outbounds": sb_outs,
        "route": {"rules": rules, "final": "o0"},
    });
    Ok(Some((sb, ports)))
}

/// Запущенный sing-box: процесс + открытый на чтение exe (не подменить, пока работает).
pub struct Sidecar {
    child: Child,
    _lock: std::fs::File,
}

impl Sidecar {
    /// Сверить sing-box.exe, запустить с конфигом через stdin и дождаться, пока
    /// откроются его порты (до 5 секунд).
    pub fn start(core_dir: &Path, cfg: &Value, ports: &[u16], on_line: crate::runner::LineFn) -> Result<Self, String> {
        let exe = exe_path(core_dir);
        if !exe.exists() {
            return Err(trs!("для TUIC нужен sing-box: Ещё → Настройки → «Скачать sing-box»").into());
        }
        let mut o = std::fs::OpenOptions::new();
        o.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            o.share_mode(1); // FILE_SHARE_READ: запускать можно, менять и удалять — нет
        }
        let mut lock = o.open(&exe).map_err(|e| format!("sing-box.exe: {e}"))?;
        let mut data = Vec::new();
        (&mut lock).take(MAX_EXE + 1).read_to_end(&mut data).map_err(|e| format!("sing-box.exe: {e}"))?;
        if crate::net::sha256_hex(&data) != EXE_SHA256 {
            return Err(trs!("sing-box.exe не тот, что качал rxvpn (подменён?) — не запускаю. Скачай заново: Ещё → Настройки").into());
        }
        drop(data);

        let mut cmd = Command::new(&exe);
        cmd.args(["run", "-c", "stdin", "--disable-color"])
            .current_dir(core_dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // без окна
            crate::runner::clean_env(&mut cmd);
        }
        let mut child = cmd.spawn().map_err(|e| tr!("не запустился sing-box: {e}"))?;
        #[cfg(windows)]
        crate::runner::job::attach(&child);
        crate::runner::pipe_logs(&mut child, "sing-box", on_line);
        if let Some(mut p) = child.stdin.take() {
            let _ = p.write_all(cfg.to_string().as_bytes());
        }
        let mut s = Self { child, _lock: lock };
        for _ in 0..50 {
            if let Ok(Some(st)) = s.child.try_wait() {
                return Err(tr!("sing-box завершился ({st}) — подробности в логе"));
            }
            let up = ports.iter().all(|p| std::net::TcpStream::connect_timeout(&([127, 0, 0, 1], *p).into(), Duration::from_millis(100)).is_ok());
            if up {
                return Ok(s);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        s.stop();
        Err(trs!("sing-box не открыл порты за 5 секунд").into())
    }

    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: &str = "tuic://2dd61d93-75d8-4da4-ac0e-6aece7eac365:p%40ss@tuic.example.com:8443?sni=cdn.example.com&alpn=h3&congestion_control=cubic#Мой%20TUIC";

    #[test]
    fn tuic_links() {
        let (n, t) = crate::link::parse_tuic(LINK).unwrap();
        assert_eq!(n.name, "Мой TUIC");
        assert_eq!((t.host.as_str(), t.port, t.password.as_str()), ("tuic.example.com", 8443, "p@ss"));
        assert_eq!(t.sni.as_deref(), Some("cdn.example.com"));
        assert_eq!(t.congestion, "cubic");
        assert!(crate::parse_link(LINK).is_ok());
        for bad in [
            "tuic://not-a-uuid:p@h.com:443",
            "tuic://2dd61d93-75d8-4da4-ac0e-6aece7eac365:p@h.com:443?allow_insecure=1",
            "tuic://2dd61d93-75d8-4da4-ac0e-6aece7eac365:p@h.com:0",
            "tuic://2dd61d93-75d8-4da4-ac0e-6aece7eac365:p@h.com:443?congestion_control=evil",
            "tuic://2dd61d93-75d8-4da4-ac0e-6aece7eac365:p@bad host:443",
        ] {
            assert!(crate::parse_link(bad).is_err(), "{bad}");
        }
        assert!(is_sidecar_link(LINK) && !is_sidecar_link("vless://x"));
    }

    #[test]
    fn split_marks_and_tun() {
        let mut ob = xray_outbound("tuic://2dd61d93-75d8-4da4-ac0e-6aece7eac365:p@203.0.113.9:443?sni=a.com").unwrap();
        ob["tag"] = json!("proxy-3");
        let mut cfg = json!({
            "inbounds": [{"tag": "tun", "protocol": "tun"}],
            "outbounds": [ob, {"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [{"outboundTag": "block", "ip": ["10.0.0.0/8"]}]},
        });
        let (sb, ports) = split(&mut cfg).unwrap().unwrap();
        assert_eq!(ports.len(), 1);
        assert!(cfg["outbounds"][0].get(MARK).is_none(), "метка не уходит в Xray");
        assert_eq!(cfg["outbounds"][0]["settings"]["servers"][0]["port"], ports[0]);
        assert_eq!(sb["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(sb["outbounds"][0]["server"], "203.0.113.9");
        assert_eq!(cfg["routing"]["rules"][0]["ip"][0], "203.0.113.9", "в TUN сервер sing-box — мимо туннеля");
        assert_eq!(cfg["routing"]["rules"][0]["outboundTag"], "direct");

        // Без меток — ничего не трогаем.
        let mut plain = json!({"outbounds": [{"tag": "proxy", "protocol": "vless"}]});
        assert!(split(&mut plain).unwrap().is_none());

        // Чужая метка (не TUIC / лишние поля) — отказ.
        for evil in [json!({"type": "direct", "tag": "x"}), json!({"type": "tuic", "server": "a", "server_port": 1, "tls": {"enabled": true}, "detour": "x"})] {
            let mut c = json!({"outbounds": [{"tag": "proxy", "protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": 1}]}, MARK: evil}]});
            assert!(split(&mut c).is_err());
        }
        let mut outs = vec![json!({"tag": "p", MARK: {"type": "tuic"}})];
        strip_marks(&mut outs);
        assert!(outs[0].get(MARK).is_none());
    }
}
