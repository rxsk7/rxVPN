//! Проба: что Windows делает с пакетами, которые WinDivert (winws гибрида) отправил заново,
//! если на ALE_AUTH_CONNECT стоит блок с разрешением «по программе» (так устроен kill switch).
//!   cargo run -p rxvpn-core --example ks_probe -- <отчёт.txt> <локальный IP карты> <имя карты>
//! Права администратора. Трогает один адрес (TARGET): сессия WFP динамическая — умерла
//! проба, фильтры сняла Windows. Kill switch и работающий rxvpn не затрагиваются.
// i18n-skip-begin: инструмент автора, не для пользователя.
#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    win::main()
}

#[cfg(windows)]
mod win {
    use std::io::Write;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    const TARGET: Ipv4Addr = Ipv4Addr::new(104, 16, 132, 229);
    const SUBLAYER: GUID = GUID::from_u128(0x7a1f_3c9e_52b4_4d0a_9e61_8c2b_5f40_e001);
    /// SNI: два из списков гибрида (winws их обрабатывает) и один посторонний.
    const NAMES: &[&str] = &["www.youtube.com", "discord.com", "example.com"];

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    struct Wfp {
        h: HANDLE,
    }

    enum C {
        Remote,
        App(*mut FWP_BYTE_BLOB),
        Iface(u64),
        Tcp443,
    }

    impl Wfp {
        fn open() -> Result<Self, String> {
            let mut name = wide("rxvpn ks_probe");
            let mut s: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
            s.displayData.name = name.as_mut_ptr();
            s.flags = FWPM_SESSION_FLAG_DYNAMIC;
            let mut h: HANDLE = std::ptr::null_mut();
            let c = unsafe { FwpmEngineOpen0(std::ptr::null(), 10, std::ptr::null(), &s, &mut h) };
            if c != 0 {
                return Err(format!("FwpmEngineOpen0 0x{c:08x}"));
            }
            let mut sname = wide("rxvpn ks_probe");
            let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
            sub.subLayerKey = SUBLAYER;
            sub.displayData.name = sname.as_mut_ptr();
            sub.weight = 0xFFFF;
            let c = unsafe { FwpmSubLayerAdd0(h, &sub, std::ptr::null_mut()) };
            if c != 0 {
                return Err(format!("FwpmSubLayerAdd0 0x{c:08x}"));
            }
            Ok(Wfp { h })
        }

        /// Фильтр на TARGET (условие Remote добавляется всегда). Возвращает id.
        fn add(&self, weight: u8, permit: bool, conds: &[C]) -> Result<u64, String> {
            let mut addr = FWP_V4_ADDR_AND_MASK { addr: u32::from(TARGET), mask: 0xFFFF_FFFF };
            let mut luids: Vec<Box<u64>> = Vec::new();
            let mut raw: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
            for c in std::iter::once(&C::Remote).chain(conds) {
                let mut v: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
                let field = match c {
                    C::Remote => {
                        v.r#type = FWP_V4_ADDR_MASK;
                        v.Anonymous.v4AddrMask = &mut addr;
                        FWPM_CONDITION_IP_REMOTE_ADDRESS
                    }
                    C::App(b) => {
                        v.r#type = FWP_BYTE_BLOB_TYPE;
                        v.Anonymous.byteBlob = *b;
                        FWPM_CONDITION_ALE_APP_ID
                    }
                    C::Iface(l) => {
                        luids.push(Box::new(*l));
                        v.r#type = FWP_UINT64;
                        v.Anonymous.uint64 = &mut **luids.last_mut().unwrap();
                        FWPM_CONDITION_IP_LOCAL_INTERFACE
                    }
                    C::Tcp443 => {
                        v.r#type = FWP_UINT8;
                        v.Anonymous.uint8 = 6;
                        raw.push(FWPM_FILTER_CONDITION0 { fieldKey: FWPM_CONDITION_IP_PROTOCOL, matchType: FWP_MATCH_EQUAL, conditionValue: v });
                        v = unsafe { std::mem::zeroed() };
                        v.r#type = FWP_UINT16;
                        v.Anonymous.uint16 = 443;
                        FWPM_CONDITION_IP_REMOTE_PORT
                    }
                };
                raw.push(FWPM_FILTER_CONDITION0 { fieldKey: field, matchType: FWP_MATCH_EQUAL, conditionValue: v });
            }
            let mut name = wide("rxvpn ks_probe");
            let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
            f.displayData.name = name.as_mut_ptr();
            f.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            f.subLayerKey = SUBLAYER;
            f.weight.r#type = FWP_UINT8;
            f.weight.Anonymous.uint8 = weight;
            f.numFilterConditions = raw.len() as u32;
            f.filterCondition = raw.as_mut_ptr();
            f.action.r#type = if permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK };
            let mut id = 0u64;
            let c = unsafe { FwpmFilterAdd0(self.h, &f, std::ptr::null_mut(), &mut id) };
            if c != 0 {
                return Err(format!("FwpmFilterAdd0 0x{c:08x}"));
            }
            Ok(id)
        }

        fn del(&self, id: u64) {
            unsafe { FwpmFilterDeleteById0(self.h, id) };
        }
    }

    impl Drop for Wfp {
        fn drop(&mut self) {
            unsafe { FwpmEngineClose0(self.h) }; // динамическая сессия: фильтры и полка уходят сами
        }
    }

    async fn attempt(local: Ipv4Addr, sni: &str) -> String {
        let sock = match tokio::net::TcpSocket::new_v4() {
            Ok(s) => s,
            Err(e) => return format!("сокет: {e}"),
        };
        if let Err(e) = sock.bind(SocketAddr::from((local, 0))) {
            return format!("bind: {e}");
        }
        let tcp = match tokio::time::timeout(Duration::from_secs(6), sock.connect(SocketAddr::from((TARGET, 443)))).await {
            Err(_) => return "connect: ТАЙМАУТ".into(),
            Ok(Err(e)) => return format!("connect: ОШИБКА {e} (os {:?})", e.raw_os_error()),
            Ok(Ok(s)) => s,
        };
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(sni.to_string()).unwrap();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp);
        match tokio::time::timeout(Duration::from_secs(6), tls).await {
            Err(_) => "connect ok; ClientHello: ОТВЕТА НЕТ (таймаут)".into(),
            Ok(Ok(_)) => "connect ok; ClientHello: ответ есть (TLS установлен)".into(),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData => format!("connect ok; ClientHello: ответ есть ({e})"),
            Ok(Err(e)) => format!("connect ok; ClientHello: обрыв {:?} {e}", e.kind()),
        }
    }

    fn netevents(path: &str) {
        let sys = std::env::var_os("SystemRoot").map(std::path::PathBuf::from).unwrap_or_else(|| r"C:\Windows".into());
        let _ = std::process::Command::new(sys.join("System32").join("netsh.exe"))
            .args(["wfp", "show", "netevents", &format!("file={path}")])
            .stdout(std::process::Stdio::null())
            .status();
    }

    pub fn main() {
        let a: Vec<String> = std::env::args().skip(1).collect();
        let mut out = std::fs::File::create(&a[0]).expect("отчёт");
        let local: Ipv4Addr = a[1].parse().expect("локальный IP");
        let luid = rxvpn_core::killswitch::interface_luid(&a[2]);
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let mut say = |s: String| {
            let _ = writeln!(out, "{s}");
            let _ = out.flush();
        };
        say(format!("цель {TARGET}:443, с адреса {local}, карта «{}» LUID {luid:?}", a[2]));
        let round = |say: &mut dyn FnMut(String), title: &str| {
            say(format!("== {title}"));
            for n in NAMES {
                let r = rt.block_on(attempt(local, n));
                say(format!("   {n}: {r}"));
            }
        };
        round(&mut say, "A. без фильтров");
        let w = match Wfp::open() {
            Ok(w) => w,
            Err(e) => return say(format!("WFP не открылся: {e}")),
        };
        let me = wide(&std::env::current_exe().unwrap().to_string_lossy());
        let mut my_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        let c = unsafe { FwpmGetAppIdFromFileName0(me.as_ptr(), &mut my_id) };
        if c != 0 {
            return say(format!("id программы: 0x{c:08x}"));
        }
        let res = (|| -> Result<(), String> {
            w.add(0, false, &[])?;
            round(&mut say, "B. только блок (ожидается отказ connect)");
            w.add(15, true, &[C::App(my_id)])?;
            round(&mut say, "C. блок + разрешение пробе по программе (как Xray в kill switch)");
            netevents(&format!("{}.C.xml", a[0]));
            for sysname in ["System", "system"] {
                let mut s = wide(sysname);
                let mut blob = FWP_BYTE_BLOB { size: (s.len() * 2) as u32, data: s.as_mut_ptr() as *mut u8 };
                let id = w.add(12, true, &[C::App(&mut blob)])?;
                round(&mut say, &format!("D. C + разрешение программе «{sysname}»"));
                w.del(id);
            }
            if let Some(l) = luid {
                let id = w.add(12, true, &[C::Iface(l), C::Tcp443])?;
                round(&mut say, "E. C + разрешение «эта карта, TCP 443» без программы");
                w.del(id);
            }
            if let Some(l) = luid {
                let mut s = wide("System");
                let mut blob = FWP_BYTE_BLOB { size: (s.len() * 2) as u32, data: s.as_mut_ptr() as *mut u8 };
                let id = w.add(12, true, &[C::App(&mut blob), C::Iface(l), C::Tcp443])?;
                round(&mut say, "H. C + узкое: «System» И эта карта И TCP 443 (как в kill switch)");
                w.del(id);
                if let Some(other) = rxvpn_core::killswitch::interface_luid("rxvpn") {
                    let id = w.add(12, true, &[C::App(&mut blob), C::Iface(other), C::Tcp443])?;
                    round(&mut say, "I. C + узкое, но карта другая — туннель (ожидается таймаут)");
                    w.del(id);
                }
            }
            round(&mut say, "F. снова C (контроль)");
            netevents(&format!("{}.end.xml", a[0]));
            Ok(())
        })();
        if let Err(e) = res {
            say(format!("ОШИБКА: {e}"));
        }
        unsafe { FwpmFreeMemory0(&mut my_id as *mut *mut FWP_BYTE_BLOB as *mut *mut core::ffi::c_void) };
        drop(w);
        round(&mut say, "G. фильтры сняты");
        say("готово".into());
    }
}
// i18n-skip-end
