//! Kill switch для режима «Весь комп» (TUN): пока он включён, в интернет выходят только
//! туннель rxvpn, сам Xray (он и несёт туннель к серверу) и rxvpn.exe; плюс локальная сеть,
//! loopback и DHCP. Упал Xray, пропал адаптер — программы не уйдут в интернет мимо VPN.
//!
//! Устроено на Windows Filtering Platform (как у Mullvad и WireGuard):
//! * своя подуровень-«полка» фильтров на слоях ALE_AUTH_CONNECT v4/v6 (исходящие соединения
//!   и первый UDP-пакет каждого потока);
//! * на ней «заблокировать всё» с весом 0 и разрешения с большим весом;
//! * разрешение для туннеля — по LUID адаптера, ставится заново после каждого запуска Xray
//!   (`allow_interface`): адаптер пересоздаётся.
//!
//! Фильтры «статические» (сессия не динамическая, флага PERSISTENT нет): они переживают
//! смерть rxvpn — упал, сняли в диспетчере задач, — и интернет остаётся закрытым, а не
//! открывается мимо VPN. Снимаются: обычным выключением (Drop), следующим запуском rxvpn
//! (`leftover` → `enable` или `clear`) и перезагрузкой — её статические фильтры не
//! переживают, так что навсегда без интернета не остаться. У каждого фильтра свой заранее
//! известный ключ (`filter_key`): чужой процесс rxvpn находит и убирает их без списка id.
//! Нужны права администратора (как и TUN).
//!
//! Гибрид «Через zapret, мимо VPN». Сайты гибрида Xray отправляет напрямую — он разрешён по
//! программе. Но winws (драйвер WinDivert) перехватывает эти пакеты на сетевой карте и
//! отправляет заново из ядра, и Windows проверяет их на ALE_AUTH_CONNECT ещё раз — уже как
//! программу «System» (проверено пробой `examples/ks_probe.rs`: без разрешения не проходит даже
//! SYN). Для них — отдельное узкое разрешение `allow_reinject`: программа «System» **и** та
//! самая сетевая карта **и** только порты, которые перехватывает стратегия winws. Обычная
//! программа под него не попадает: её соединение отсекается по её же имени раньше, чем
//! появится пакет, который WinDivert мог бы перехватить.

use std::path::{Path, PathBuf};

/// Локальные сети, которые kill switch не трогает: принтеры, NAS, роутер, mDNS, мультикаст.
pub const LAN_V4: &[(u32, u32)] = &[
    (0x0A00_0000, 0xFF00_0000), // 10.0.0.0/8
    (0xAC10_0000, 0xFFF0_0000), // 172.16.0.0/12
    (0xC0A8_0000, 0xFFFF_0000), // 192.168.0.0/16
    (0xA9FE_0000, 0xFFFF_0000), // 169.254.0.0/16
    (0xE000_0000, 0xF000_0000), // 224.0.0.0/4 мультикаст
    (0xFFFF_FFFF, 0xFFFF_FFFF), // 255.255.255.255 broadcast
];
/// IPv6: link-local, unique-local, мультикаст.
pub const LAN_V6: &[([u8; 16], u8)] = &[
    ([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
    ([0xfc, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
    ([0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8),
];

/// Веса фильтров на «полке» rxvpn: больше — главнее. Порядок важен:
/// loopback и свои программы (Xray, rxvpn) > туннель > блок DNS > локальная сеть и DHCP > блок всего.
/// Блок DNS стоит между туннелем и локальной сетью: DNS через туннель и от самого Xray
/// проходит, а запрос к роутеру (192.168.x.x:53) — нет.
pub const W_APP: u8 = 15;
pub const W_TUN: u8 = 14;
pub const W_DNS_BLOCK: u8 = 13;
pub const W_LAN: u8 = 12;

/// Сколько ключей фильтров отведено: 0..KEY_REINJECT — постоянные, дальше четыре —
/// пакеты zapret (TCP/UDP × v4/v6), KEY_TUN и KEY_TUN+1 — туннель.
pub const KEYS: u32 = 64;
pub const KEY_REINJECT: u32 = 48;
pub const KEY_TUN: u32 = 56;
/// Больше диапазонов портов в одном разрешении не берём (у стратегий Flowseal их до десятка).
pub const PORT_RANGES_MAX: usize = 32;

/// Что пропускать для гибрида: пакеты, которые winws перехватил и отправил заново.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reinject {
    /// LUID настоящей сетевой карты (той же, что в `--wf-iface` у winws).
    pub luid: u64,
    /// Диапазоны удалённых портов из `--wf-tcp` / `--wf-udp` стратегии.
    pub tcp: Vec<(u16, u16)>,
    pub udp: Vec<(u16, u16)>,
}

impl Reinject {
    fn check(&self) -> Result<(), String> {
        for list in [&self.tcp, &self.udp] {
            if list.len() > PORT_RANGES_MAX || list.iter().any(|(lo, hi)| *lo == 0 || lo > hi) {
                return Err(trs!("kill switch: порты стратегии zapret не разобраны").into());
            }
        }
        Ok(())
    }
}

/// Осталась ли блокировка от прошлого rxvpn (он умер, не сняв kill switch).
/// Не вышло спросить Windows — считаем, что нет.
pub fn leftover() -> bool {
    #[cfg(windows)]
    {
        imp::leftover()
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Снять блокировку, оставшуюся от прошлого rxvpn. Нечего снимать — тоже Ok.
pub fn clear() -> Result<(), String> {
    #[cfg(windows)]
    {
        imp::clear()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}

/// Включённый kill switch. Drop — фильтры снимаются. Процесс умер без Drop — остаются
/// до следующего запуска rxvpn или перезагрузки.
pub struct KillSwitch {
    #[cfg(windows)]
    inner: imp::Engine,
    apps: Vec<PathBuf>,
}

impl std::fmt::Debug for KillSwitch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KillSwitch").field("apps", &self.apps).finish()
    }
}

impl KillSwitch {
    /// Включить: блок всего, кроме `apps` (полные пути к exe), локальной сети, loopback и DHCP.
    /// Осталась блокировка прошлого rxvpn — заменяется одной транзакцией, без окна «открыто».
    pub fn enable(apps: &[&Path]) -> Result<Self, String> {
        for a in apps {
            if !a.is_absolute() || !a.is_file() {
                return Err(tr!("kill switch: нет файла {}", a.display()));
            }
        }
        #[cfg(windows)]
        {
            let inner = imp::Engine::open(apps)?;
            Ok(Self { inner, apps: apps.iter().map(|p| p.to_path_buf()).collect() })
        }
        #[cfg(not(windows))]
        {
            Err(trs!("kill switch есть только в Windows").into())
        }
    }

    /// Пустить трафик через адаптер туннеля (LUID). Прошлое разрешение для туннеля снимается.
    pub fn allow_interface(&mut self, luid: u64) -> Result<(), String> {
        #[cfg(windows)]
        {
            self.inner.allow_interface(luid)
        }
        #[cfg(not(windows))]
        {
            let _ = luid;
            Err(trs!("kill switch есть только в Windows").into())
        }
    }

    /// Пропустить (Some) или перестать пропускать (None) пакеты, которые winws гибрида
    /// отправил заново. Прошлое такое разрешение снимается той же транзакцией.
    /// Ошибка — разрешения нет вовсе: сайты гибрида закрыты, мимо ничего не идёт.
    pub fn allow_reinject(&mut self, r: Option<&Reinject>) -> Result<(), String> {
        if let Some(r) = r {
            r.check()?;
        }
        #[cfg(windows)]
        {
            self.inner.allow_reinject(r)
        }
        #[cfg(not(windows))]
        {
            Err(trs!("kill switch есть только в Windows").into())
        }
    }

    pub fn apps(&self) -> &[PathBuf] {
        &self.apps
    }
}

/// LUID сетевого адаптера по имени подключения («rxvpn» у нашего TUN). None — такого нет.
pub fn interface_luid(alias: &str) -> Option<u64> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
        use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
        let w: Vec<u16> = alias.encode_utf16().chain(Some(0)).collect();
        let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
        if unsafe { ConvertInterfaceAliasToLuid(w.as_ptr(), &mut luid) } != 0 {
            return None;
        }
        Some(unsafe { luid.Value })
    }
    #[cfg(not(windows))]
    {
        let _ = alias;
        None
    }
}

#[cfg(windows)]
mod imp {
    use std::path::Path;

    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    /// Своя «полка» фильтров rxvpn (постоянный GUID — видно в `netsh wfp show filters`).
    const SUBLAYER: GUID = GUID::from_u128(0x7a1f_3c9e_52b4_4d0a_9e61_8c2b_5f40_d713);
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

    /// Ключ фильтра номер `i`: по нему фильтр находит и убирает любой процесс rxvpn.
    fn filter_key(i: u32) -> GUID {
        GUID::from_u128(0x7a1f_3c9e_52b4_4d0a_9e61_8c2b_5f40_d800 + i as u128)
    }

    fn open_engine() -> Result<HANDLE, String> {
        let mut name = wide("rxvpn kill switch");
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        // Без FWPM_SESSION_FLAG_DYNAMIC: фильтры остаются, если процесс умер.
        session.displayData.name = name.as_mut_ptr();
        let mut h: HANDLE = std::ptr::null_mut();
        check(trs!("движок WFP не открылся"), unsafe {
            FwpmEngineOpen0(std::ptr::null(), RPC_C_AUTHN_WINNT, std::ptr::null(), &session, &mut h)
        })?;
        Ok(h)
    }

    /// Убрать все наши фильтры и полку. Чего нет — пропускаем. Внутри транзакции.
    fn wipe(h: HANDLE) {
        for i in 0..super::KEYS {
            unsafe { FwpmFilterDeleteByKey0(h, &filter_key(i)) };
        }
        unsafe { FwpmSubLayerDeleteByKey0(h, &SUBLAYER) };
    }

    fn wipe_committed(h: HANDLE) -> Result<(), String> {
        check(trs!("транзакция"), unsafe { FwpmTransactionBegin0(h, 0) })?;
        wipe(h);
        check(trs!("применение фильтров"), unsafe { FwpmTransactionCommit0(h) })
    }

    fn sublayer_exists(h: HANDLE) -> bool {
        let mut sub: *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
        if unsafe { FwpmSubLayerGetByKey0(h, &SUBLAYER, &mut sub) } != 0 {
            return false;
        }
        unsafe { FwpmFreeMemory0(&mut sub as *mut *mut FWPM_SUBLAYER0 as *mut *mut core::ffi::c_void) };
        true
    }

    pub(super) fn leftover() -> bool {
        let Ok(h) = open_engine() else { return false };
        let found = sublayer_exists(h);
        unsafe { FwpmEngineClose0(h) };
        found
    }

    pub(super) fn clear() -> Result<(), String> {
        let h = open_engine()?;
        let r = wipe_committed(h).and_then(|()| {
            if sublayer_exists(h) {
                Err(trs!("kill switch: блокировка не снялась — перезагрузи компьютер").into())
            } else {
                Ok(())
            }
        });
        unsafe { FwpmEngineClose0(h) };
        r
    }

    // Веса фильтров (больше — главнее; «заблокировать всё» — 0).
    use super::{W_APP, W_DNS_BLOCK, W_LAN, W_TUN};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn check(what: &str, code: u32) -> Result<(), String> {
        if code == 0 {
            Ok(())
        } else {
            Err(tr!("kill switch: {what} — ошибка WFP 0x{code:08x}"))
        }
    }

    /// Условие фильтра. Значения держит сам `Cond` (указатели внутрь живут, пока он жив).
    enum Val {
        U8(u8),
        U16(u16),
        U32(u32),
        U64(Box<u64>),
        V4(Box<FWP_V4_ADDR_AND_MASK>),
        V6(Box<FWP_V6_ADDR_AND_MASK>),
        Blob(*mut FWP_BYTE_BLOB),
        /// Диапазон портов (условия с одним полем WFP складывает через «или»).
        Ports(Box<FWP_RANGE0>),
    }

    fn ports(lo: u16, hi: u16) -> Val {
        let mut r: FWP_RANGE0 = unsafe { std::mem::zeroed() };
        r.valueLow.r#type = FWP_UINT16;
        r.valueLow.Anonymous.uint16 = lo;
        r.valueHigh.r#type = FWP_UINT16;
        r.valueHigh.Anonymous.uint16 = hi;
        Val::Ports(Box::new(r))
    }

    struct Cond {
        field: GUID,
        mt: FWP_MATCH_TYPE,
        val: Val,
    }

    impl Cond {
        fn raw(&mut self) -> FWPM_FILTER_CONDITION0 {
            let mut v: FWP_CONDITION_VALUE0 = unsafe { std::mem::zeroed() };
            match &mut self.val {
                Val::U8(x) => {
                    v.r#type = FWP_UINT8;
                    v.Anonymous.uint8 = *x;
                }
                Val::U16(x) => {
                    v.r#type = FWP_UINT16;
                    v.Anonymous.uint16 = *x;
                }
                Val::U32(x) => {
                    v.r#type = FWP_UINT32;
                    v.Anonymous.uint32 = *x;
                }
                Val::U64(x) => {
                    v.r#type = FWP_UINT64;
                    v.Anonymous.uint64 = &mut **x;
                }
                Val::V4(x) => {
                    v.r#type = FWP_V4_ADDR_MASK;
                    v.Anonymous.v4AddrMask = &mut **x;
                }
                Val::V6(x) => {
                    v.r#type = FWP_V6_ADDR_MASK;
                    v.Anonymous.v6AddrMask = &mut **x;
                }
                Val::Blob(b) => {
                    v.r#type = FWP_BYTE_BLOB_TYPE;
                    v.Anonymous.byteBlob = *b;
                }
                Val::Ports(r) => {
                    v.r#type = FWP_RANGE_TYPE;
                    v.Anonymous.rangeValue = &mut **r;
                }
            }
            FWPM_FILTER_CONDITION0 { fieldKey: self.field, matchType: self.mt, conditionValue: v }
        }
    }

    pub(super) struct Engine {
        h: HANDLE,
        /// Следующий свободный ключ постоянных фильтров.
        next: u32,
    }

    // Дескриптор движка WFP можно использовать из любого потока (обращения — под Mutex в AppState).
    unsafe impl Send for Engine {}

    impl Engine {
        pub(super) fn open(apps: &[&Path]) -> Result<Self, String> {
            let h = open_engine()?;
            // Старое (в том числе от умершего rxvpn) и новое — одной транзакцией: между ними
            // нет мгновения без блокировки. Ошибка посередине — откат, всё как было.
            if let Err(err) = check(trs!("транзакция"), unsafe { FwpmTransactionBegin0(h, 0) }) {
                unsafe { FwpmEngineClose0(h) };
                return Err(err);
            }
            wipe(h);
            let mut e = Engine { h, next: 0 };
            let r = e.install(apps).and_then(|()| check(trs!("применение фильтров"), unsafe { FwpmTransactionCommit0(h) }));
            if let Err(err) = r {
                unsafe { FwpmTransactionAbort0(h) };
                unsafe { FwpmEngineClose0(h) };
                std::mem::forget(e); // Drop снял бы блокировку прошлого rxvpn — её решает вызывающий
                return Err(err);
            }
            Ok(e)
        }

        fn key(&mut self) -> Result<u32, String> {
            if self.next >= super::KEY_REINJECT {
                return Err(trs!("kill switch: слишком много фильтров").into());
            }
            self.next += 1;
            Ok(self.next - 1)
        }

        fn install(&mut self, apps: &[&Path]) -> Result<(), String> {
            let mut sname = wide("rxvpn");
            let mut sub: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
            sub.subLayerKey = SUBLAYER;
            sub.displayData.name = sname.as_mut_ptr();
            sub.weight = 0xFFFF;
            let code = unsafe { FwpmSubLayerAdd0(self.h, &sub, std::ptr::null_mut()) };
            if code != FWP_E_ALREADY_EXISTS {
                check(trs!("своя полка фильтров"), code)?;
            }

            // id приложений: FwpmGetAppIdFromFileName0 выделяет память — освобождаем в конце.
            let mut ids: Vec<*mut FWP_BYTE_BLOB> = Vec::new();
            let res = (|| {
                for a in apps {
                    let w = wide(&a.to_string_lossy());
                    let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
                    check(trs!("id программы"), unsafe { FwpmGetAppIdFromFileName0(w.as_ptr(), &mut blob) })?;
                    ids.push(blob);
                }
                for (layer, v6) in [(FWPM_LAYER_ALE_AUTH_CONNECT_V4, false), (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true)] {
                    // 1. Всё остальное — в блок.
                    let k = self.key()?;
                    self.add(k, layer, 0, FWP_ACTION_BLOCK, &mut [])?;
                    // 2. loopback (127.0.0.1, ::1 — локальные прокси rxvpn и всё, что слушает localhost).
                    let k = self.key()?;
                    self.add(k, layer, W_APP, FWP_ACTION_PERMIT, &mut [Cond {
                        field: FWPM_CONDITION_FLAGS,
                        mt: FWP_MATCH_FLAGS_ALL_SET,
                        val: Val::U32(FWP_CONDITION_FLAG_IS_LOOPBACK),
                    }])?;
                    // 3. Xray и rxvpn.exe: туннель к серверу и служебные проверки.
                    for b in &ids {
                        let k = self.key()?;
                        self.add(k, layer, W_APP, FWP_ACTION_PERMIT, &mut [Cond { field: FWPM_CONDITION_ALE_APP_ID, mt: FWP_MATCH_EQUAL, val: Val::Blob(*b) }])?;
                    }
                    // 4. Локальная сеть (условия с одним полем WFP складывает через «или»).
                    let mut lan: Vec<Cond> = if v6 {
                        super::LAN_V6
                            .iter()
                            .map(|(addr, p)| Cond {
                                field: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                mt: FWP_MATCH_EQUAL,
                                val: Val::V6(Box::new(FWP_V6_ADDR_AND_MASK { addr: *addr, prefixLength: *p })),
                            })
                            .collect()
                    } else {
                        super::LAN_V4
                            .iter()
                            .map(|(addr, mask)| Cond {
                                field: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                mt: FWP_MATCH_EQUAL,
                                val: Val::V4(Box::new(FWP_V4_ADDR_AND_MASK { addr: *addr, mask: *mask })),
                            })
                            .collect()
                    };
                    let k = self.key()?;
                    self.add(k, layer, W_LAN, FWP_ACTION_PERMIT, &mut lan)?;
                    // 4½. DNS мимо туннеля — в блок, даже в локальную сеть: иначе, пока Xray лежит,
                    //     Windows спросит роутер, тот — провайдера, и провайдер увидит имена сайтов.
                    //     (Пока Xray жив, это делает он сам — autoSystemWfpBlockLeak; тут — на случай
                    //     его падения.) Туннель и сам Xray весят больше и DNS не теряют.
                    for proto in [17u8, 6] {
                        let k = self.key()?;
                        self.add(k, layer, W_DNS_BLOCK, FWP_ACTION_BLOCK, &mut [
                            Cond { field: FWPM_CONDITION_IP_PROTOCOL, mt: FWP_MATCH_EQUAL, val: Val::U8(proto) },
                            Cond { field: FWPM_CONDITION_IP_REMOTE_PORT, mt: FWP_MATCH_EQUAL, val: Val::U16(53) },
                        ])?;
                    }
                    // 5. DHCP — иначе адрес от роутера не продлится и сеть отвалится вовсе.
                    let k = self.key()?;
                    self.add(k, layer, W_LAN, FWP_ACTION_PERMIT, &mut [
                        Cond { field: FWPM_CONDITION_IP_PROTOCOL, mt: FWP_MATCH_EQUAL, val: Val::U8(17) },
                        Cond { field: FWPM_CONDITION_IP_REMOTE_PORT, mt: FWP_MATCH_EQUAL, val: Val::U16(if v6 { 547 } else { 67 }) },
                    ])?;
                }
                Ok(())
            })();
            for mut b in ids {
                unsafe { FwpmFreeMemory0(&mut b as *mut *mut FWP_BYTE_BLOB as *mut *mut core::ffi::c_void) };
            }
            res
        }

        fn add(&mut self, key: u32, layer: GUID, weight: u8, action: FWP_ACTION_TYPE, conds: &mut [Cond]) -> Result<u64, String> {
            let mut raw: Vec<FWPM_FILTER_CONDITION0> = conds.iter_mut().map(Cond::raw).collect();
            let mut name = wide("rxvpn kill switch");
            let mut f: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
            f.displayData.name = name.as_mut_ptr();
            f.filterKey = filter_key(key);
            f.layerKey = layer;
            f.subLayerKey = SUBLAYER;
            f.weight.r#type = FWP_UINT8;
            f.weight.Anonymous.uint8 = weight;
            f.numFilterConditions = raw.len() as u32;
            f.filterCondition = if raw.is_empty() { std::ptr::null_mut() } else { raw.as_mut_ptr() };
            f.action.r#type = action;
            let mut id = 0u64;
            check(trs!("фильтр"), unsafe { FwpmFilterAdd0(self.h, &f, std::ptr::null_mut(), &mut id) })?;
            Ok(id)
        }

        pub(super) fn allow_interface(&mut self, luid: u64) -> Result<(), String> {
            check(trs!("транзакция"), unsafe { FwpmTransactionBegin0(self.h, 0) })?;
            let r = (|| {
                for (i, layer) in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6].into_iter().enumerate() {
                    let key = super::KEY_TUN + i as u32;
                    // Разрешения для прошлого адаптера может и не быть — не ошибка.
                    unsafe { FwpmFilterDeleteByKey0(self.h, &filter_key(key)) };
                    self.add(key, layer, W_TUN, FWP_ACTION_PERMIT, &mut [Cond {
                        field: FWPM_CONDITION_IP_LOCAL_INTERFACE,
                        mt: FWP_MATCH_EQUAL,
                        val: Val::U64(Box::new(luid)),
                    }])?;
                }
                Ok(())
            })();
            match r {
                Ok(()) => check(trs!("применение фильтров"), unsafe { FwpmTransactionCommit0(self.h) }),
                Err(e) => {
                    unsafe { FwpmTransactionAbort0(self.h) };
                    Err(e)
                }
            }
        }
    }

    impl Engine {
        pub(super) fn allow_reinject(&mut self, r: Option<&super::Reinject>) -> Result<(), String> {
            check(trs!("транзакция"), unsafe { FwpmTransactionBegin0(self.h, 0) })?;
            // Так Windows называет ядро в ALE_APP_ID: строка «System» с нулём на конце.
            let mut sys = wide("System");
            let mut blob = FWP_BYTE_BLOB { size: (sys.len() * 2) as u32, data: sys.as_mut_ptr() as *mut u8 };
            let res = (|| {
                for i in 0..4 {
                    unsafe { FwpmFilterDeleteByKey0(self.h, &filter_key(super::KEY_REINJECT + i)) };
                }
                let Some(r) = r else { return Ok(()) };
                let mut key = super::KEY_REINJECT;
                for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6] {
                    for (proto, list) in [(6u8, &r.tcp), (17, &r.udp)] {
                        key += 1;
                        if list.is_empty() {
                            continue;
                        }
                        let mut conds = vec![
                            Cond { field: FWPM_CONDITION_ALE_APP_ID, mt: FWP_MATCH_EQUAL, val: Val::Blob(&mut blob) },
                            Cond { field: FWPM_CONDITION_IP_LOCAL_INTERFACE, mt: FWP_MATCH_EQUAL, val: Val::U64(Box::new(r.luid)) },
                            Cond { field: FWPM_CONDITION_IP_PROTOCOL, mt: FWP_MATCH_EQUAL, val: Val::U8(proto) },
                        ];
                        conds.extend(list.iter().map(|(lo, hi)| Cond { field: FWPM_CONDITION_IP_REMOTE_PORT, mt: FWP_MATCH_RANGE, val: ports(*lo, *hi) }));
                        // Вес как у локальной сети — ниже блока DNS: порт 53 не пройдёт и тут.
                        self.add(key - 1, layer, W_LAN, FWP_ACTION_PERMIT, &mut conds)?;
                    }
                }
                Ok(())
            })();
            match res {
                Ok(()) => check(trs!("применение фильтров"), unsafe { FwpmTransactionCommit0(self.h) }),
                Err(e) => {
                    unsafe { FwpmTransactionAbort0(self.h) };
                    Err(e)
                }
            }
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            // Фильтры статические — сами не уйдут: снимаем явно. Не снялись (быть не должно) —
            // их уберёт следующий запуск rxvpn или перезагрузка.
            let _ = wipe_committed(self.h);
            unsafe { FwpmEngineClose0(self.h) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_ranges_are_networks() {
        for (addr, mask) in LAN_V4 {
            assert_eq!(addr & mask, *addr, "адрес {addr:08x} — начало своей сети");
            assert_eq!(mask.leading_ones() + mask.trailing_zeros(), 32, "маска {mask:08x} без дыр");
        }
        for (addr, p) in LAN_V6 {
            assert!(*p <= 128);
            let full = u128::from_be_bytes(*addr);
            let m = if *p == 0 { 0 } else { u128::MAX << (128 - *p) };
            assert_eq!(full & m, full);
        }
        // Публичные адреса VPN-серверов в «локальную сеть» не попадают.
        let inside = |ip: u32| LAN_V4.iter().any(|(a, m)| ip & m == *a);
        assert!(!inside(0x0808_0808)); // 8.8.8.8
        assert!(!inside(0xC633_6407)); // 198.51.100.7
        assert!(inside(0xC0A8_0101)); // 192.168.1.1
    }

    #[test]
    fn dns_block_sits_between_tunnel_and_lan() {
        assert!(W_APP > W_DNS_BLOCK, "Xray сам узнаёт адрес сервера — его DNS не режем");
        assert!(W_TUN > W_DNS_BLOCK, "DNS через туннель проходит");
        assert!(W_DNS_BLOCK > W_LAN, "DNS к роутеру — в блок, хотя локальная сеть разрешена");
        assert!(W_LAN > 0 && W_APP <= 15, "вес — FWP_UINT8 от 0 до 15");
    }

    #[test]
    fn filter_keys_fit() {
        // Постоянных фильтров — по 7 + число программ на слой; программ две (Xray, rxvpn).
        assert!(2 * (7 + 2) <= KEY_REINJECT, "постоянные фильтры не залезают на ключи zapret");
        assert!(KEY_REINJECT + 4 <= KEY_TUN, "четыре ключа zapret не залезают на ключи туннеля");
        assert!(KEY_TUN + 2 <= KEYS, "оба ключа туннеля попадают под уборку");
    }

    #[test]
    fn reinject_is_narrow() {
        assert!(W_DNS_BLOCK > W_LAN, "разрешение для пакетов zapret (вес W_LAN) не открывает DNS");
        let ok = Reinject { luid: 1, tcp: vec![(80, 80), (443, 443)], udp: vec![(50000, 50100)] };
        assert!(ok.check().is_ok());
        assert!(Reinject { tcp: vec![(0, 80)], ..ok.clone() }.check().is_err(), "порт 0");
        assert!(Reinject { udp: vec![(500, 400)], ..ok.clone() }.check().is_err(), "перевёрнутый диапазон");
        assert!(Reinject { tcp: vec![(1, 1); PORT_RANGES_MAX + 1], ..ok }.check().is_err(), "слишком много");
    }

    #[test]
    fn needs_real_files() {
        assert!(KillSwitch::enable(&[Path::new("relative.exe")]).is_err());
        assert!(KillSwitch::enable(&[Path::new(r"C:\definitely\missing\xray.exe")]).is_err());
    }

    /// Живой тест (нужны права администратора): включить и выключить, сеть после Drop работает.
    #[test]
    #[ignore]
    fn enable_and_drop_live() {
        let exe = std::env::current_exe().unwrap();
        let mut ks = KillSwitch::enable(&[exe.as_path()]).expect("kill switch");
        if let Some(l) = interface_luid("Ethernet").or_else(|| interface_luid("Wi-Fi")) {
            ks.allow_interface(l).expect("разрешение для адаптера");
            ks.allow_interface(l).expect("повторно — старое снимается");
        }
        assert!(leftover(), "пока включён — блокировка видна");
        drop(ks);
        assert!(!leftover(), "после Drop ничего не осталось");
    }
}
