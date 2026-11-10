//! Генерация config.json для Xray из `Node` + настроек.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::node::{Node, Protocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    /// Всё через VPN, кроме российских сайтов и локальной сети.
    BypassRu,
    /// Вообще всё через VPN (кроме локальной сети).
    Global,
    /// Через VPN только то, что заблокировано в РФ (списки runetfreedom),
    /// остальное напрямую.
    Blocked,
}

/// Списки «Только заблокированное» (вырезаны из runetfreedom, см. geodata.rs).
pub const GEOSITE_RU: &str = "geosite-ru.dat";
pub const GEOIP_RU: &str = "geoip-ru.dat";

/// Что делать с трафиком, подошедшим под правило.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Proxy,
    Direct,
    Block,
}

/// Правило из редактора. Все заполненные условия должны совпасть одновременно
/// (сайт И программа И порт...). Внутри «сайтов» — любой из списка.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rule {
    pub enabled: bool,
    pub name: String,
    /// Сайты, IP, подсети, geosite:/geoip:/ext: — как в «Своих сайтах».
    pub sites: Vec<String>,
    /// Программы: Telegram.exe, путь или папка.
    pub apps: Vec<String>,
    /// Порты: "443", "80,443", "1000-2000".
    pub ports: String,
    /// "", "tcp" или "udp".
    pub network: String,
    /// Распознанный протокол: bittorrent, quic, tls, http.
    pub protocols: Vec<String>,
    pub action: Action,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            enabled: true,
            name: String::new(),
            sites: Vec::new(),
            apps: Vec::new(),
            ports: String::new(),
            network: String::new(),
            protocols: Vec::new(),
            action: Action::Proxy,
        }
    }
}

// serde(default) на всей структуре: если в старом state.json нет новых полей,
// они берутся из Default, а не ломают загрузку (и не стирают сервера).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// SOCKS5 порт. По умолчанию не 10808, чтобы не драться с Happ/v2rayN.
    pub socks_port: u16,
    /// HTTP порт (его ставим в системный прокси Windows).
    pub http_port: u16,
    pub route: RouteMode,
    pub system_proxy: bool,
    /// Пускать в локальные порты всю домашнюю сеть (для телефона через ПК).
    pub allow_lan: bool,
    pub log_level: String,
    /// Свои правила: эти сайты/IP идут напрямую, мимо VPN.
    pub direct: Vec<String>,
    /// Свои правила: эти сайты/IP всегда через VPN (даже .ru в режиме «Обход РФ»).
    pub proxy: Vec<String>,
    /// TUN: весь трафик компа (игры, любые программы) через VPN. Нужны права админа.
    pub tun: bool,
    /// Kill switch в TUN: упал Xray — интернет закрыт, пока VPN не вернётся или не нажмут
    /// «Отключить» (core/src/killswitch.rs). Только с правами администратора.
    pub kill_switch: bool,
    /// Горячая клавиша «Подключить / Отключить» (как в трее), например "Ctrl+Alt+V". Пусто — выключена.
    pub hotkey: String,
    /// Запустилась одна из этих программ (имя exe) — подключиться самому.
    pub connect_apps: Vec<String>,
    /// Запускаться вместе с Windows (свёрнутым в трей).
    pub autostart: bool,
    /// Подключаться к выбранному серверу сразу при запуске программы.
    pub auto_connect: bool,
    /// Крестик окна сворачивает в трей, а не закрывает программу.
    pub close_to_tray: bool,
    /// Обновлять подписки раз в N часов (0 — не обновлять сами).
    pub sub_update_hours: u32,
    /// Резать рекламу и трекеры (geosite:category-ads-all) для всех программ.
    pub block_ads: bool,
    /// Всплывающие уведомления Windows (переключение сервера, отвал и т.п.).
    pub notifications: bool,
    /// Правила по программам: «всё через VPN, кроме…» или «только эти через VPN».
    pub apps_mode: AppsMode,
    /// Программы мимо VPN (режим Except).
    pub apps_direct: Vec<String>,
    /// Программы через VPN (режим Only).
    pub apps_proxy: Vec<String>,
    /// Правила из редактора — проверяются раньше программ и «Своих сайтов».
    pub rules: Vec<Rule>,
    /// DNS через VPN (для заблокированного и всего остального в режиме «Всё»).
    pub dns_remote: String,
    /// DNS напрямую (для .ru, адресов серверов, всего в «Только заблокированное»).
    pub dns_direct: String,
    /// Отдавать программам и IPv6-адреса (иначе только IPv4).
    pub dns_ipv6: bool,
    /// Свои записи DNS: "домен IP" по строке.
    pub hosts: Vec<String>,
    /// Стратегия маршрутизации: auto / AsIs / IPIfNonMatch / IPOnDemand.
    pub domain_strategy: String,
    /// Обновлять списки блокировок раз в N дней (0 — только вручную).
    pub lists_update_days: u32,
    /// Анти-DPI: резать первый TLS-пакет (ClientHello с именем сайта) на куски.
    pub fragment: bool,
    /// Размер кусков в байтах: "100-200" (случайно из диапазона) или "150".
    pub fragment_length: String,
    /// Пауза между кусками в мс: "10-20".
    pub fragment_delay: String,
    /// Анти-DPI: мусорные пакеты перед UDP-подключением (KCP, QUIC, Hysteria).
    pub udp_noise: bool,
    /// Режим «Zapret · без VPN»: подключение запускает zapret, а не Xray.
    pub zapret: bool,
    /// Папка zapret (Flowseal / zapret-win-bundle): оттуда стратегии и списки.
    pub zapret_dir: String,
    /// Выбранная стратегия (имя файла без расширения).
    pub zapret_strategy: String,
    /// «Игровой фильтр» Flowseal: обрабатывать порты 1024–65535 (для игр).
    pub zapret_game_filter: bool,
    /// Свои сайты для проверки стратегий (к YouTube/Discord по умолчанию).
    pub zapret_targets: Vec<String>,
    /// Гибрид: в режимах VPN YouTube и Discord идут мимо VPN через zapret.
    pub zapret_hybrid: bool,
    /// Какие сервисы гибрида включены (ключи из HYBRID_SERVICES). None — старый
    /// state.json, где гибрид был только для YouTube и Discord: они и включены.
    pub hybrid_services: Option<Vec<String>>,
    /// Свои сайты гибрида: мимо VPN через zapret.
    pub hybrid_sites: Vec<String>,
    /// Раз в 2 часа проверять, что стратегия ещё пробивает, и подбирать заново.
    pub zapret_autocheck: bool,
    /// «Telegram без VPN»: локальный MTProto-прокси через веб-вход Telegram (tgproxy).
    pub tg_proxy: bool,
    pub tg_port: u16,
    /// Секрет прокси (32 hex). Пусто — создаётся при первом включении.
    pub tg_secret: String,
    /// Запасной путь через Cloudflare-домены сообщества tg-ws-proxy.
    pub tg_cf: bool,
    /// «DNS без подмены» в режиме «Без VPN»: системный DNS Windows — на локальный
    /// DoH rxvpn (doh.rs, sysdns.rs). Провайдер: cloudflare / google / custom.
    pub doh_sys: bool,
    pub doh_provider: String,
    /// Свой DoH (https://…), если doh_provider = custom.
    pub doh_url: String,
    /// Язык окна, трея и сообщений: "" — как в Windows, "ru", "en" (меняет только set_lang).
    pub lang: String,
    /// Запускаться с правами администратора: копия без прав сразу просит их (UAC).
    pub run_as_admin: bool,
    /// «Сайт → свой сервер»: ChatGPT через один сервер, YouTube через другой.
    pub site_servers: Vec<SiteServer>,
    /// Шифровать state.json и страховочные копии ключом учётки Windows (DPAPI).
    pub encrypt_state: bool,
    /// Обход DPI, подобранный для отдельных серверов (id → что помогло).
    pub node_tweaks: std::collections::BTreeMap<String, Tweak>,
    /// Профили по сети: что делать дома (в своих Wi-Fi) и в остальных сетях.
    pub net_profiles: bool,
    pub trusted_nets: Vec<TrustedNet>,
    pub home: NetAction,
    pub away: NetAction,
    /// Tor на Arti: что пускать через Tor.
    pub tor_mode: TorMode,
    /// «Сайт → Tor»: эти сайты (и .onion) — через Tor.
    pub tor_sites: Vec<String>,
    /// Изоляция по сайтам: у каждого сайта своя цепочка Tor.
    pub tor_isolate: bool,
    /// Белые списки: сервер, на который переключаться (id + подписка; пусто — не задан).
    pub wl_server: String,
    pub wl_server_sub: String,
    /// Замечать режим белых списков и переключаться самому.
    pub wl_auto: bool,
}

/// Что идёт через Tor.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TorMode {
    #[default]
    Off,
    /// Только адреса .onion.
    Onion,
    /// .onion и сайты из `tor_sites`.
    Sites,
    /// Весь TCP через Tor, UDP — в блок.
    All,
}

/// Своя (доверенная) сеть Wi-Fi: имя и адрес точки доступа. Имя может взять
/// любой (поддельная точка «как дома»), адрес точки подделать сложнее —
/// совпасть должны оба. Mesh/несколько точек — несколько записей.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct TrustedNet {
    pub ssid: String,
    pub bssid: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetVpn {
    /// Не трогать.
    #[default]
    Keep,
    /// Подключить.
    On,
    /// Отключить.
    Off,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct NetAction {
    /// Режим маршрутов (None — не менять).
    pub route: Option<RouteMode>,
    pub vpn: NetVpn,
}

pub const TRUSTED_NETS_MAX: usize = 32;

fn valid_bssid(b: &str) -> bool {
    b.len() == 17 && b.split(':').count() == 6 && b.split(':').all(|x| x.len() == 2 && x.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
}

/// Своя ли сейчас сеть: Wi-Fi (имя, адрес точки), None — не Wi-Fi.
pub fn net_trusted(list: &[TrustedNet], wifi: Option<&(String, String)>) -> bool {
    let Some((ssid, bssid)) = wifi else { return false };
    !ssid.is_empty() && list.iter().any(|t| &t.ssid == ssid && &t.bssid == bssid)
}

/// Обход DPI для одного сервера («Подобрать обход»). Пустой — «без обхода»:
/// общий анти-DPI из настроек к этому серверу не применяется.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct Tweak {
    /// Нарезка ClientHello: размер кусков, «100-200». Пусто — без нарезки.
    pub fragment: String,
    /// Пауза между кусками в мс: «10-20».
    pub delay: String,
    /// Отпечаток TLS-клиента (uTLS). Пусто — как у сервера.
    pub fp: String,
    /// Шум перед UDP-подключением (Hysteria2, KCP).
    pub noise: bool,
}

pub const TWEAK_FPS: &[&str] = &["chrome", "firefox", "safari", "ios", "edge", "randomized"];
pub const NODE_TWEAKS_MAX: usize = 5000;

pub fn validate_tweak(t: &Tweak) -> Result<(), String> {
    if t.fragment.is_empty() != t.delay.is_empty() {
        return Err(trs!("обход: нарезка без паузы").into());
    }
    if !t.fragment.is_empty() {
        check_range(&t.fragment, 1, 16_384)?;
        check_range(&t.delay, 0, 1_000)?;
    }
    if !t.fp.is_empty() && !TWEAK_FPS.contains(&t.fp.as_str()) {
        return Err(tr!("обход: непонятный отпечаток «{}»", t.fp));
    }
    Ok(())
}

/// По-человечески: «нарезка 100-200 байт + отпечаток firefox».
pub fn tweak_label(t: &Tweak) -> String {
    let mut p = Vec::new();
    if !t.fragment.is_empty() {
        p.push(tr!("нарезка {} байт", t.fragment));
    }
    if !t.fp.is_empty() {
        p.push(tr!("отпечаток {}", t.fp));
    }
    if t.noise {
        p.push(trs!("шум UDP").to_string());
    }
    if p.is_empty() {
        trs!("без обхода").into()
    } else {
        p.join(" + ")
    }
}

fn tweak_mask(t: &Tweak) -> Option<Value> {
    let mut m = Map::new();
    if !t.fragment.is_empty() {
        m.insert(
            "tcp".into(),
            json!([{ "type": "fragment", "settings": { "packets": "tlshello", "lengths": [t.fragment.trim()], "delays": [t.delay.trim()] } }]),
        );
    }
    if t.noise {
        m.insert("udp".into(), json!([{ "type": "noise", "settings": { "noise": [{ "rand": "10-20", "delay": "10-16" }] } }]));
    }
    (!m.is_empty()).then_some(Value::Object(m))
}

/// Что пробовать при «Подобрать обход»: от самого безобидного к самому заметному.
pub fn tweak_variants(node: &Node) -> Vec<Tweak> {
    let outs = node_outbounds(node);
    let str_of = |o: &Value, p: &str| o.pointer(p).and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
    let udp = outs.iter().any(|o| {
        matches!(str_of(o, "/protocol").as_str(), "hysteria" | "wireguard")
            || matches!(str_of(o, "/streamSettings/network").as_str(), "kcp" | "mkcp" | "hysteria" | "quic")
    });
    let tls = outs.iter().any(|o| matches!(str_of(o, "/streamSettings/security").as_str(), "tls" | "reality"));
    let frag = |a: &str, b: &str| Tweak { fragment: a.into(), delay: b.into(), ..Default::default() };
    let fp = |f: &str| Tweak { fp: f.into(), ..Default::default() };
    let mut v = vec![Tweak::default()];
    if udp {
        v.push(Tweak { noise: true, ..Default::default() });
        return v;
    }
    v.extend([frag("100-200", "10-20"), frag("10-30", "5-10"), frag("1-5", "1-3")]);
    if tls {
        v.extend([fp("firefox"), fp("safari"), fp("randomized")]);
        v.push(Tweak { fp: "firefox".into(), ..frag("100-200", "10-20") });
    }
    v
}

/// Анти-DPI одного исходящего: подобранный для его сервера или общий из настроек.
pub(crate) fn mask_outbound(o: &mut Value, tweak: Option<&Tweak>, global: Option<&Value>) {
    match tweak {
        Some(t) => {
            if !t.fp.is_empty() {
                for k in ["tlsSettings", "realitySettings"] {
                    if let Some(x) = o.pointer_mut(&format!("/streamSettings/{k}")).and_then(Value::as_object_mut) {
                        x.insert("fingerprint".into(), json!(t.fp));
                    }
                }
            }
            if let Some(m) = tweak_mask(t) {
                mask_one(o, &m);
            }
        }
        None => {
            if let Some(m) = global {
                mask_one(o, m);
            }
        }
    }
}

/// Эти сайты всегда идут через свой сервер (`server` — id из списка серверов),
/// а не через тот, к которому подключён. Остальное — как обычно.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct SiteServer {
    pub name: String,
    pub sites: Vec<String>,
    pub server: String,
    /// Подписка сервера ("" — добавлен вручную). id сервера — некриптографический
    /// хеш ссылки: чужая подписка могла бы подобрать такой же и, когда настоящий
    /// сервер пропадёт, перехватить правило. Совпасть должны оба. Заполняет rxvpn.
    pub sub: String,
    /// Запасной сервер (пусто — нет): основной не отвечает — сайты идут через него
    /// (balancer Xray с fallbackTag). Оба не отвечают — сайты закрыты.
    pub backup: String,
    pub backup_sub: String,
}

/// Правило «сайт → сервер», уже найденное в списке серверов. `node: None` —
/// сервера нет (удалён) или он не запустился: эти сайты закрыты, а не идут
/// мимо выбранного сервера (например, напрямую с настоящим IP).
#[derive(Debug, Clone, Copy)]
pub struct SiteRoute<'a> {
    pub sites: &'a [String],
    pub node: Option<&'a Node>,
    /// Запасной (только вместе с `node`; другой сервер).
    pub backup: Option<&'a Node>,
}

/// Сколько правил «сайт → сервер» можно: каждое — ещё один сервер в Xray.
pub const SITE_SERVERS_MAX: usize = 16;

pub fn validate_site_server(r: &SiteServer) -> Result<(), String> {
    let name = crate::store::clean_name(&r.name, 60).map_err(|e| tr!("Сайт → сервер: {e}"))?;
    let label = if name.is_empty() { trs!("без названия") } else { name.as_str() };
    let ctx = |e: String| tr!("Сайт → сервер «{label}»: {e}");
    if real_lines(&r.sites).next().is_none() {
        return Err(ctx(trs!("нет ни одного сайта").into()));
    }
    if r.sites.len() > 500 {
        return Err(ctx(trs!("больше 500 строк").into()));
    }
    validate_rules(&r.sites).map_err(ctx)?;
    let plain = |x: &str| x.len() <= 128 && x.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if r.server.is_empty() || r.server == crate::store::AUTO_ID || !plain(&r.server) || !plain(&r.sub) {
        return Err(ctx(trs!("не выбран сервер").into()));
    }
    if r.backup == crate::store::AUTO_ID || !plain(&r.backup) || !plain(&r.backup_sub) || (r.backup.is_empty() && !r.backup_sub.is_empty()) {
        return Err(ctx(trs!("запасной сервер — не тот").into()));
    }
    if r.backup == r.server && r.backup_sub == r.sub {
        return Err(ctx(trs!("запасной сервер совпадает с основным").into()));
    }
    Ok(())
}

/// Правила, которые действуют: проверенные, не больше SITE_SERVERS_MAX
/// (state.json при загрузке целиком не проверяется).
fn site_rules(s: &Settings) -> impl Iterator<Item = &SiteServer> {
    s.site_servers.iter().take(SITE_SERVERS_MAX).filter(|r| validate_site_server(r).is_ok())
}

/// Тот ли это сервер: тот же id и та же подписка.
pub fn site_server_is(r: &SiteServer, n: &Node) -> bool {
    n.id == r.server && n.sub_id.as_deref().unwrap_or("") == r.sub
}

/// Тот ли это запасной сервер правила.
pub fn site_backup_is(r: &SiteServer, n: &Node) -> bool {
    !r.backup.is_empty() && n.id == r.backup && n.sub_id.as_deref().unwrap_or("") == r.backup_sub
}

/// Сопоставить правила с серверами. Сервер удалили (или подписка его убрала) —
/// `node: None`: эти сайты закрыты, пока не выберешь другой.
pub fn site_routes<'a>(s: &'a Settings, nodes: &'a [Node]) -> Vec<SiteRoute<'a>> {
    site_rules(s)
        .map(|r| {
            let main = nodes.iter().find(|n| site_server_is(r, n));
            let backup = nodes.iter().find(|n| site_backup_is(r, n));
            match main {
                // Основного нет — сайты через запасной, как через основной.
                None => SiteRoute { sites: &r.sites, node: backup, backup: None },
                Some(m) => SiteRoute { sites: &r.sites, node: Some(m), backup: backup.filter(|b| b.id != m.id) },
            }
        })
        .collect()
}

/// Куда идут сайты правила и какие исходящие ради этого нужны.
struct SitePlan<'a> {
    /// По правилу: тег и балансировщик ли это.
    to: Vec<(String, bool)>,
    /// Новые исходящие: сервер, главный тег, префикс помощников.
    outs: Vec<(&'a Node, String, String)>,
    balancers: Vec<Value>,
}

/// Тег исходящего для каждого правила по порядку. Без запасного: сервер
/// подключения — его же тег ("proxy" или "node-N" в «Авто»), другие — "site-K"
/// (один сервер в нескольких правилах — одно подключение). С запасным — свои
/// копии "sp-NN" (основной) и "sb-NN" (запасной), помощники — "sh-NN-…": селектор
/// балансировщика — префикс, и "sp-01" не должен совпасть ни с чем, кроме себя.
fn site_plan<'a>(up: &Upstream, routes: &[SiteRoute<'a>]) -> SitePlan<'a> {
    let mut extra: Vec<&str> = Vec::new();
    let mut p = SitePlan { to: Vec::with_capacity(routes.len()), outs: Vec::new(), balancers: Vec::new() };
    for (i, r) in routes.iter().enumerate() {
        let Some(node) = r.node else {
            p.to.push(("block".to_string(), false));
            continue;
        };
        if let Some(b) = r.backup {
            let (sp, sb) = (format!("sp-{i:02}"), format!("sb-{i:02}"));
            p.outs.push((node, sp.clone(), format!("sh-{i:02}-p-")));
            p.outs.push((b, sb.clone(), format!("sh-{i:02}-b-")));
            // leastPing по одному кандидату: жив по замерам — он, нет — fallbackTag.
            p.balancers.push(json!({ "tag": format!("bal-{i:02}"), "selector": [sp], "fallbackTag": sb, "strategy": { "type": "leastPing" } }));
            p.to.push((format!("bal-{i:02}"), true));
            continue;
        }
        let id = node.id.as_str();
        let own = match up {
            Upstream::Single(n) => (n.id == id).then(|| "proxy".to_string()),
            Upstream::Auto { nodes, .. } => nodes.iter().position(|n| n.id == id).map(auto_tag),
        };
        let tag = own.unwrap_or_else(|| {
            let k = extra.iter().position(|x| *x == id).unwrap_or_else(|| {
                extra.push(id);
                p.outs.push((node, format!("site-{}", extra.len() - 1), format!("site-{}-", extra.len() - 1)));
                extra.len() - 1
            });
            format!("site-{k}")
        });
        p.to.push((tag, false));
    }
    p
}

/// Исходящие, через которые идут сайты «Сайт → сервер» (для счётчиков трафика):
/// теги серверов, без "block" и балансировщиков.
pub fn site_tags(up: &Upstream, routes: &[SiteRoute]) -> Vec<String> {
    let p = site_plan(up, routes);
    let mut out: Vec<String> = p.to.iter().filter(|(t, bal)| !bal && t != "block").map(|(t, _)| t.clone()).collect();
    out.extend(p.outs.iter().map(|(_, t, _)| t.clone()));
    let mut seen = std::collections::HashSet::new();
    out.retain(|t| seen.insert(t.clone()));
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AppsMode {
    /// Все программы через VPN, кроме списка apps_direct.
    #[default]
    Except,
    /// Через VPN только программы из apps_proxy, остальные напрямую.
    Only,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            socks_port: 10900,
            http_port: 10901,
            route: RouteMode::BypassRu,
            system_proxy: true,
            allow_lan: false,
            log_level: "warning".into(),
            direct: Vec::new(),
            proxy: Vec::new(),
            tun: false,
            kill_switch: false,
            hotkey: "Ctrl+Alt+V".into(),
            connect_apps: Vec::new(),
            autostart: false,
            auto_connect: false,
            close_to_tray: true,
            sub_update_hours: 12,
            block_ads: false,
            notifications: true,
            apps_mode: AppsMode::Except,
            apps_direct: Vec::new(),
            apps_proxy: Vec::new(),
            rules: Vec::new(),
            dns_remote: "1.1.1.1".into(),
            dns_direct: DIRECT_DNS.into(),
            dns_ipv6: false,
            hosts: Vec::new(),
            domain_strategy: "auto".into(),
            lists_update_days: 3,
            fragment: false,
            fragment_length: "100-200".into(),
            fragment_delay: "10-20".into(),
            udp_noise: false,
            zapret: false,
            zapret_dir: String::new(),
            zapret_strategy: String::new(),
            zapret_game_filter: false,
            zapret_targets: Vec::new(),
            zapret_hybrid: false,
            hybrid_services: None,
            hybrid_sites: Vec::new(),
            zapret_autocheck: true,
            tg_proxy: false,
            tg_port: crate::tgproxy::DEFAULT_PORT,
            tg_secret: String::new(),
            tg_cf: false,
            doh_sys: false,
            doh_provider: "cloudflare".into(),
            doh_url: String::new(),
            lang: String::new(),
            run_as_admin: false,
            site_servers: Vec::new(),
            encrypt_state: false,
            node_tweaks: Default::default(),
            net_profiles: false,
            trusted_nets: Vec::new(),
            home: NetAction::default(),
            away: NetAction { route: Some(RouteMode::Global), vpn: NetVpn::On },
            tor_mode: TorMode::Off,
            tor_sites: Vec::new(),
            tor_isolate: true,
            wl_server: String::new(),
            wl_server_sub: String::new(),
            wl_auto: true,
        }
    }
}

/// Что DNS отвечает на имена .onion при включённом Tor (TEST-NET-2): запрос не
/// уходит ни провайдеру, ни DNS VPN, а соединение на этот адрес — в блок.
/// .onion открывается по имени — через системный прокси (режим «Браузер»).
pub const ONION_STUB: &str = "198.51.100.254";

/// Адрес и сетка TUN-адаптера. 172.19.0.0/30 — как у sing-box, почти никогда
/// не пересекается с домашними сетями.
/// Имя адаптера TUN в Windows (по нему гибрид отличает туннель от сетевой карты).
pub const TUN_NAME: &str = "rxvpn";
const TUN_GATEWAY_V4: &str = "172.19.0.1/30";
const TUN_GATEWAY_V6: &str = "fdfe:dcba:9876::1/126";
/// DNS, который Windows получит на TUN-адаптере. Сами запросы до них не доходят:
/// всё на порт 53 из TUN перехватывается и отвечается встроенным DNS Xray.
const TUN_DNS: [&str; 2] = ["1.1.1.1", "8.8.8.8"];
/// Яндекс DNS — напрямую, для .ru/.рф (в режиме «Обход РФ») и для адреса самого
/// сервера (иначе, чтобы узнать IP сервера, надо сходить через этот же сервер).
const DIRECT_DNS: &str = "77.88.8.8";

/// Во что превратилась строка из списка сайтов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleTarget {
    /// Для поля "domain" в Xray: "domain:example.com", "geosite:...", "full:..."
    Domain(String),
    /// Для поля "ip": "1.2.3.4", "10.0.0.0/8", "geoip:..."
    Ip(String),
}

/// Разобрать то, что человек написал в список: домен, ссылку, IP, подсеть,
/// или готовое правило Xray (geosite:, geoip:, domain:, full:, regexp:, keyword:).
///   "https://www.youtube.com/watch?v=1" -> domain:youtube.com (с поддоменами)
///   "*.example.com"                     -> domain:example.com
///   "госуслуги.рф"                      -> domain:xn--c1aapkosapc.xn--p1ai
///   "192.168.0.0/16"                    -> ip
pub fn parse_rule(line: &str) -> Result<RuleTarget, String> {
    use std::net::IpAddr;

    let s = line.trim();
    let lower = s.to_lowercase();
    for p in ["geosite:", "domain:", "full:", "regexp:", "keyword:"] {
        if lower.starts_with(p) {
            return Ok(RuleTarget::Domain(s.to_string()));
        }
    }
    if lower.starts_with("geoip:") {
        return Ok(RuleTarget::Ip(lower));
    }
    // ext:файл.dat:категория — свои списки. По имени файла понятно, IP это или домены.
    if lower.starts_with("ext:") {
        if lower.matches(':').count() < 2 {
            return Err(tr!("не понял: «{s}» — формат ext:файл.dat:категория"));
        }
        // Только имя файла рядом с xray.exe: никаких путей (../, C:\, \\шара).
        let file = s[4..].rsplit_once(':').map(|(f, _)| f).unwrap_or("");
        let plain = !file.is_empty()
            && file.ends_with(".dat")
            && file.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            && !file.starts_with('.');
        if !plain {
            return Err(tr!("«{s}»: в ext: нужно просто имя файла .dat из папки ядра, без пути"));
        }
        return Ok(if lower.contains("geoip") {
            RuleTarget::Ip(s.to_string())
        } else {
            RuleTarget::Domain(s.to_string())
        });
    }
    if s.parse::<IpAddr>().is_ok() {
        return Ok(RuleTarget::Ip(s.to_string()));
    }
    if let Some((ip, bits)) = s.split_once('/') {
        if ip.parse::<IpAddr>().is_ok() && bits.parse::<u8>().is_ok() {
            return Ok(RuleTarget::Ip(s.to_string()));
        }
    }

    // Всё остальное считаем сайтом. Отрезаем схему, путь, порт, "*." и "www.".
    let no_scheme = lower.split_once("://").map(|(_, r)| r).unwrap_or(&lower);
    let host = no_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .trim_start_matches("*.")
        .trim_start_matches('.');
    // url сам приводит кириллицу к punycode (сайт.рф -> xn--80aswg.xn--p1ai)
    // и отсекает мусор с пробелами и запрещёнными символами.
    let parsed = url::Url::parse(&format!("http://{host}"))
        .map_err(|_| tr!("не понял: «{s}»"))?;
    let host = parsed.host_str().ok_or_else(|| tr!("не понял: «{s}»"))?;
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.parse::<IpAddr>().is_ok() {
        return Ok(RuleTarget::Ip(host.to_string()));
    }
    let host = host.strip_prefix("www.").unwrap_or(host);
    if !host.contains('.') {
        return Err(tr!("не понял: «{s}» — нужен домен вида site.com"));
    }
    Ok(RuleTarget::Domain(format!("domain:{host}")))
}

/// Проверить список целиком: вернуть ошибку с первой непонятной строкой.
pub fn validate_rules(lines: &[String]) -> Result<(), String> {
    for l in lines.iter().filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')) {
        parse_rule(l)?;
    }
    Ok(())
}

/// Лёгкий адрес для фоновых проверок: обычный HTTP, ответ 204 без тела.
/// Внутри туннеля всё равно шифруется, а байтов в разы меньше, чем у HTTPS.
pub const PROBE_URLS_HTTP: &[&str] = &[
    "http://www.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204",
];

/// Тег главного исходящего i-го сервера в режиме «Авто».
pub fn auto_tag(i: usize) -> String {
    format!("node-{i}")
}

/// Как часто «Авто» проверяет все сервера. Каждая проверка — новое
/// TLS-рукопожатие (~5 КБ), поэтому чем больше серверов, тем реже:
/// 10 серверов — раз в минуту, 30 — раз в 2 минуты, 75+ — раз в 5 минут.
pub fn observe_interval_secs(n: usize) -> u64 {
    (n as u64 * 4).clamp(60, 300)
}

/// Через что выпускать трафик: один сервер или «Авто» по нескольким.
pub enum Upstream<'a> {
    Single(&'a Node),
    /// Все сервера в одном Xray, трафик — через `prefer` (node-N), остальных
    /// observatory только проверяет. Переключение — перезапуск с другим prefer.
    Auto { nodes: &'a [Node], prefer: usize },
}

/// Служебные порты запуска (все на 127.0.0.1).
#[derive(Debug, Default, Clone, Copy)]
pub struct RunOpts<'a> {
    /// Счётчики трафика и результаты проверок: http://127.0.0.1:port/debug/vars
    pub metrics_port: Option<u16>,
    /// Служебный SOCKS-вход: всё, что через него, всегда идёт через VPN
    /// (проверка задержки, подписки), какие бы правила ни стояли.
    pub probe_port: Option<u16>,
    /// «Сайт → свой сервер» (см. `site_routes`).
    pub sites: &'a [SiteRoute<'a>],
    /// Tor: (порт SOCKS Arti, порт входа `tor-up`, через который Arti ходит в
    /// сеть Tor — всегда через VPN). None при `tor_mode` ≠ Off — Arti не
    /// запустилась: то, что шло бы через Tor, закрыто.
    pub tor: Option<(u16, u16)>,
    /// Служебный SOCKS-вход прямо в интернет, мимо VPN, TUN и Tor (проверка белых
    /// списков): порт и пароль на этот запуск (логин "rxvpn") — чтобы чужие
    /// программы на компе не ходили через него мимо туннеля.
    pub direct: Option<(u16, &'a str)>,
}

/// Куда отправить совпавший трафик.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum To {
    Direct,
    Proxy,
    Block,
    DnsOut,
}

/// Дописать в правило, куда идёт трафик. `px` — тег исходящего «через VPN»:
/// "proxy" для одного сервера, "node-N" (выбранный) в «Авто».
fn put(mut rule: Value, to: To, px: &str) -> Value {
    let v = match to {
        To::Direct => "direct",
        To::Block => "block",
        To::DnsOut => "dns-out",
        To::Proxy => px,
    };
    rule["type"] = json!("field");
    rule["outboundTag"] = json!(v);
    rule
}

fn real_lines(lines: &[String]) -> impl Iterator<Item = &str> {
    lines
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// Список строк -> 0, 1 или 2 правила Xray (домены и IP отдельно: в Xray поля
/// внутри одного правила работают как И, а нам нужно ИЛИ).
fn rules_for(lines: &[String], to: To, px: &str) -> Vec<Value> {
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    for l in real_lines(lines) {
        match parse_rule(l) {
            Ok(RuleTarget::Domain(d)) => domains.push(d),
            Ok(RuleTarget::Ip(i)) => ips.push(i),
            Err(_) => {} // кривые строки отсекаются ещё при сохранении настроек
        }
    }
    let mut out = Vec::new();
    if !domains.is_empty() {
        out.push(put(json!({ "domain": domains }), to, px));
    }
    if !ips.is_empty() {
        out.push(put(json!({ "ip": ips }), to, px));
    }
    out
}

/// Строки списка программ -> имена для правила Xray "process".
/// Xray сравнивает имя без .exe С УЧЁТОМ регистра, а люди пишут как придётся
/// ("telegram.exe" при файле "Telegram.exe"), поэтому добавляем варианты.
/// Пути (C:\Games\cs2.exe) и папки (D:\Games\) Xray понимает сам.
pub fn app_names(lines: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |v: String| {
        if !v.is_empty() && !out.contains(&v) {
            out.push(v);
        }
    };
    for l in real_lines(lines) {
        let l = l.trim_matches('"');
        if l.contains('/') || l.contains('\\') {
            add(l.replace('\\', "/"));
            continue;
        }
        let base = if l.to_lowercase().ends_with(".exe") { &l[..l.len() - 4] } else { l };
        let lower = base.to_lowercase();
        let mut cap = lower.clone();
        if let Some(f) = cap.get_mut(0..1) {
            f.make_ascii_uppercase();
        }
        add(base.to_string());
        add(lower.clone());
        add(cap);
        add(base.to_uppercase());
    }
    out
}

/// Проверить список программ: не пусто внутри и без символов, которых не бывает в именах.
pub fn validate_apps(lines: &[String]) -> Result<(), String> {
    for l in real_lines(lines) {
        let t = l.trim_matches('"');
        if t.is_empty() || t.contains(['*', '?', '<', '>', '|']) {
            return Err(tr!("не понял: «{l}» — нужно имя программы, например Telegram.exe"));
        }
    }
    Ok(())
}

const PROTOCOLS: &[&str] = &["bittorrent", "quic", "tls", "http"];

/// Проверить правило из редактора; текст ошибки — для человека.
pub fn validate_rule(r: &Rule) -> Result<(), String> {
    let name = if r.name.trim().is_empty() { trs!("без названия").to_string() } else { r.name.trim().to_string() };
    let ctx = |e: String| tr!("Правило «{name}»: {e}");
    validate_rules(&r.sites).map_err(ctx)?;
    validate_apps(&r.apps).map_err(ctx)?;
    parse_ports(&r.ports).map_err(ctx)?;
    if !["", "tcp", "udp"].contains(&r.network.as_str()) {
        return Err(ctx(tr!("непонятная сеть «{}»", r.network)));
    }
    if let Some(p) = r.protocols.iter().find(|p| !PROTOCOLS.contains(&p.as_str())) {
        return Err(ctx(tr!("непонятный протокол «{p}»")));
    }
    let empty = real_lines(&r.sites).next().is_none()
        && real_lines(&r.apps).next().is_none()
        && r.ports.trim().is_empty()
        && r.network.is_empty()
        && r.protocols.is_empty();
    if empty {
        return Err(ctx(trs!("нет ни одного условия — правило подошло бы ко всему").into()));
    }
    Ok(())
}

/// "80, 443,1000-2000" -> "80,443,1000-2000" (формат Xray). Пусто — Ok("").
fn parse_ports(s: &str) -> Result<String, String> {
    let mut out = Vec::new();
    for part in s.split([',', ' ', ';']).map(str::trim).filter(|p| !p.is_empty()) {
        let ok = |x: &str| x.parse::<u16>().ok().filter(|&p| p > 0);
        match part.split_once('-') {
            Some((a, b)) => match (ok(a.trim()), ok(b.trim())) {
                (Some(a), Some(b)) if a <= b => out.push(format!("{a}-{b}")),
                _ => return Err(tr!("непонятный диапазон портов «{part}»")),
            },
            None => match ok(part) {
                Some(p) => out.push(p.to_string()),
                None => return Err(tr!("непонятный порт «{part}»")),
            },
        }
    }
    Ok(out.join(","))
}

/// Правило редактора -> правила Xray. Домены и IP — отдельными правилами
/// (в Xray поля одного правила работают как И), остальные условия — в каждое.
fn build_rule(r: &Rule, px: &str) -> Vec<Value> {
    let mut base = serde_json::Map::new();
    let apps = app_names(&r.apps);
    if !apps.is_empty() {
        base.insert("process".into(), json!(apps));
    }
    if let Ok(p) = parse_ports(&r.ports) {
        if !p.is_empty() {
            base.insert("port".into(), json!(p));
        }
    }
    if !r.network.is_empty() {
        base.insert("network".into(), json!(r.network));
    }
    if !r.protocols.is_empty() {
        base.insert("protocol".into(), json!(r.protocols));
    }
    let to = match r.action {
        Action::Proxy => To::Proxy,
        Action::Direct => To::Direct,
        Action::Block => To::Block,
    };
    let mut domains = Vec::new();
    let mut ips = Vec::new();
    for l in real_lines(&r.sites) {
        match parse_rule(l) {
            Ok(RuleTarget::Domain(d)) => domains.push(d),
            Ok(RuleTarget::Ip(i)) => ips.push(i),
            Err(_) => {}
        }
    }
    let with = |k: &str, v: &Vec<String>| {
        let mut m = base.clone();
        m.insert(k.into(), json!(v));
        put(Value::Object(m), to, px)
    };
    let mut out = Vec::new();
    if !domains.is_empty() {
        out.push(with("domain", &domains));
    }
    if !ips.is_empty() {
        out.push(with("ip", &ips));
    }
    if domains.is_empty() && ips.is_empty() && !base.is_empty() {
        out.push(put(Value::Object(base), to, px));
    }
    out
}

/// Строки «Свои записи DNS» -> {домен: IP}. Понимает и порядок hosts-файла (IP домен).
pub fn parse_hosts(lines: &[String]) -> Result<serde_json::Map<String, Value>, String> {
    use std::net::IpAddr;
    let mut m = serde_json::Map::new();
    for l in real_lines(lines) {
        let parts: Vec<&str> = l.split_whitespace().collect();
        let [a, b] = parts.as_slice() else {
            return Err(tr!("не понял запись DNS «{l}» — нужно «домен IP»"));
        };
        let (domain, value) = if a.parse::<IpAddr>().is_ok() { (*b, *a) } else { (*a, *b) };
        if !domain.contains('.') && domain != "localhost" {
            return Err(tr!("не понял запись DNS «{l}» — нужно «домен IP»"));
        }
        m.insert(domain.to_lowercase(), json!(value));
    }
    Ok(m)
}

/// Проверить настройки DNS и маршрутизации, которые человек мог ввести руками.
pub fn validate_settings(s: &Settings) -> Result<(), String> {
    if crate::i18n::sanitize(&s.lang) != s.lang {
        return Err(trs!("Язык: неизвестное значение").into());
    }
    if s.hotkey.len() > 40 || !s.hotkey.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b' ') {
        return Err(trs!("Горячая клавиша: например Ctrl+Alt+V").into());
    }
    if s.connect_apps.len() > 50 {
        return Err(trs!("Автоподключение: не больше 50 программ").into());
    }
    for a in &s.connect_apps {
        let ok = a.len() <= 64
            && a.to_ascii_lowercase().ends_with(".exe")
            && a.chars().all(|c| c.is_alphanumeric() || " ._-()".contains(c));
        if !ok {
            return Err(tr!("Автоподключение: «{a}» — нужно имя программы, например Discord.exe"));
        }
    }
    if s.tg_proxy && (s.tg_port < 1024 || s.tg_port == s.socks_port || s.tg_port == s.http_port) {
        return Err(trs!("Порт Telegram: от 1024 и не такой, как SOCKS/HTTP").into());
    }
    if !matches!(s.doh_provider.as_str(), "cloudflare" | "google" | "custom") {
        return Err(trs!("DoH: неизвестный сервер").into());
    }
    if s.doh_provider == "custom" || !s.doh_url.is_empty() {
        crate::doh::validate_url(&s.doh_url)?;
    }
    if !s.tg_secret.is_empty() && crate::tgproxy::secret_from_hex(&s.tg_secret).is_none() {
        return Err(trs!("Секрет Telegram-прокси испорчен").into());
    }
    if s.socks_port == s.http_port {
        return Err(trs!("SOCKS и HTTP порты должны отличаться").into());
    }
    if s.socks_port < 1024 || s.http_port < 1024 {
        return Err(trs!("Порты бери от 1024 и выше").into());
    }
    // Уходит в конфиг Xray как есть — только из списка.
    if !["debug", "info", "warning", "error", "none"].contains(&s.log_level.as_str()) {
        return Err(tr!("непонятный уровень лога «{}»", s.log_level));
    }
    if s.sub_update_hours > 24 * 30 || s.lists_update_days > 365 {
        return Err(trs!("слишком большой интервал обновления").into());
    }
    validate_rules(&s.direct).map_err(|e| tr!("«Напрямую»: {e}"))?;
    validate_rules(&s.proxy).map_err(|e| tr!("«Через VPN»: {e}"))?;
    validate_apps(&s.apps_direct).map_err(|e| tr!("Программы: {e}"))?;
    validate_apps(&s.apps_proxy).map_err(|e| tr!("Программы: {e}"))?;
    for r in s.rules.iter().filter(|r| r.enabled) {
        validate_rule(r)?;
    }
    if s.site_servers.len() > SITE_SERVERS_MAX {
        return Err(tr!("Сайт → сервер: не больше {SITE_SERVERS_MAX} правил"));
    }
    for r in &s.site_servers {
        validate_site_server(r)?;
    }
    if let Some(k) = &s.hybrid_services {
        if k.len() > HYBRID_SERVICES.len() || k.iter().any(|k| !HYBRID_SERVICES.iter().any(|x| x.key == k)) {
            return Err(trs!("Через zapret: непонятный сервис").into());
        }
    }
    if s.hybrid_sites.len() > HYBRID_SITES_MAX {
        return Err(tr!("Через zapret: не больше {HYBRID_SITES_MAX} сайтов"));
    }
    for l in real_lines(&s.hybrid_sites) {
        if zapret_target(l).is_none() {
            return Err(tr!("Через zapret: «{l}» — нужен адрес сайта (site.com), не IP и не geosite"));
        }
    }
    if s.tor_sites.len() > 500 {
        return Err(trs!("Сайт → Tor: больше 500 строк").into());
    }
    validate_rules(&s.tor_sites).map_err(|e| tr!("Сайт → Tor: {e}"))?;
    if s.tor_mode == TorMode::Sites && real_lines(&s.tor_sites).next().is_none() {
        return Err(trs!("Сайт → Tor: впиши хотя бы один сайт").into());
    }
    let plain = |x: &str| x.len() <= 128 && x.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !plain(&s.wl_server) || !plain(&s.wl_server_sub) || s.wl_server == crate::store::AUTO_ID {
        return Err(trs!("Белые списки: сервер — не тот").into());
    }
    if s.trusted_nets.len() > TRUSTED_NETS_MAX {
        return Err(tr!("Своих сетей — не больше {TRUSTED_NETS_MAX}"));
    }
    for t in &s.trusted_nets {
        if t.ssid.is_empty() || t.ssid.len() > 32 || t.ssid.chars().any(char::is_control) || !valid_bssid(&t.bssid) {
            return Err(trs!("Своя сеть: странное имя или адрес точки").into());
        }
    }
    if s.node_tweaks.len() > NODE_TWEAKS_MAX {
        return Err(trs!("слишком много подобранных обходов").into());
    }
    for (id, t) in &s.node_tweaks {
        if id.is_empty() || id.len() > 128 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(trs!("обход: странный id сервера").into());
        }
        validate_tweak(t)?;
    }
    parse_hosts(&s.hosts)?;
    for (what, d) in [(trs!("DNS через VPN"), &s.dns_remote), (trs!("DNS напрямую"), &s.dns_direct)] {
        if d.trim().is_empty() {
            return Err(tr!("{what}: пусто"));
        }
        if d.trim() != "localhost" && dns_host(d).is_none() {
            return Err(tr!("{what}: не понял адрес «{d}»"));
        }
    }
    if !["auto", "AsIs", "IPIfNonMatch", "IPOnDemand"].contains(&s.domain_strategy.as_str()) {
        return Err(tr!("непонятная стратегия «{}»", s.domain_strategy));
    }
    for t in s.zapret_targets.iter().filter(|t| !t.trim().is_empty() && !t.trim_start().starts_with('#')) {
        zapret_target(t).ok_or_else(|| tr!("Zapret, сайт для проверки «{t}»: нужен домен или https://адрес"))?;
    }
    if s.zapret_targets.len() > 50 {
        return Err(trs!("Zapret: сайтов для проверки больше 50 — подбор займёт вечность").into());
    }
    if !s.zapret_dir.is_empty() && !local_dir(&s.zapret_dir) {
        return Err(tr!("Папка zapret «{}»: нужна папка на этом компе (C:\\…), не сетевая", s.zapret_dir));
    }
    if s.zapret_strategy.chars().count() > 200 || s.zapret_strategy.chars().any(char::is_control) {
        return Err(trs!("Zapret: странное имя стратегии").into());
    }
    if s.fragment {
        check_range(&s.fragment_length, 1, 16_384).map_err(|e| tr!("Размер кусков: {e}"))?;
        check_range(&s.fragment_delay, 0, 1_000).map_err(|e| tr!("Пауза между кусками: {e}"))?;
    }
    Ok(())
}

/// Гибрид: сервисы, которые можно пустить мимо VPN через zapret.
/// (ключ, название, домены, адреса для «Подобрать лучшую»).
pub struct HybridService {
    pub key: &'static str,
    pub name: &'static str,
    pub domains: &'static [&'static str],
    /// Программы сервиса — мимо VPN целиком: голос Discord идёт по UDP прямо на IP
    /// голосового сервера, имени сайта в нём нет, и правило по доменам его не ловит.
    pub apps: &'static [&'static str],
    pub targets: &'static [(&'static str, &'static str)],
}

pub const HYBRID_SERVICES: &[HybridService] = &[
    HybridService {
        key: "youtube",
        name: "YouTube",
        domains: &[
            "youtube.com", "youtu.be", "ytimg.com", "ggpht.com", "googlevideo.com", "youtube-nocookie.com",
            "youtubekids.com", "youtubei.googleapis.com", "youtube.googleapis.com", "youtubeembeddedplayer.googleapis.com",
            "jnn-pa.googleapis.com", "yt3.googleusercontent.com", "yt-video-upload.l.google.com",
            "wide-youtube.l.google.com", "youtube-ui.l.google.com", "ytimg.l.google.com",
        ],
        apps: &[],
        targets: &[
            ("YouTube", "https://www.youtube.com"),
            ("youtu.be", "https://youtu.be"),
            ("YouTube images", "https://i.ytimg.com"),
            ("YouTube video", "https://redirector.googlevideo.com"),
        ],
    },
    HybridService {
        key: "discord",
        name: "Discord",
        domains: &[
            "discord.com", "discord.gg", "discord.media", "discordapp.com", "discordapp.net", "discordcdn.com",
            "discord.app", "discord.co", "discord.dev", "discord.gift", "discord.gifts", "discord.new", "discord.store",
            "discord.status", "discordstatus.com", "dis.gd", "discord-activities.com", "discordactivities.com",
            "discord-attachments-uploads-prd.storage.googleapis.com",
            // discordsays.com — не здесь: через него «Активности» Discord ходят на сервера
            // сторонних разработчиков, и любой сайт может дёрнуть его мимо VPN.
        ],
        apps: &["Discord", "DiscordPTB", "DiscordCanary"],
        targets: &[
            ("Discord", "https://discord.com"),
            ("Discord Gateway", "https://gateway.discord.gg"),
            ("Discord CDN", "https://cdn.discordapp.com"),
            ("Discord Updates", "https://updates.discord.com"),
        ],
    },
    // Домены — как в v2fly domain-list-community (data/twitch), без CloudFront-адресов.
    HybridService {
        key: "twitch",
        name: "Twitch",
        domains: &["twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "twitchsvc.net", "live-video.net", "ext-twitch.tv"],
        apps: &[],
        targets: &[
            ("Twitch", "https://www.twitch.tv"),
            ("Twitch images", "https://static-cdn.jtvnw.net"),
            ("Twitch video", "https://usher.ttvnw.net"),
        ],
    },
];

/// Сколько своих сайтов в гибриде.
pub const HYBRID_SITES_MAX: usize = 200;

/// Включённые сервисы гибрида (старый state.json — YouTube и Discord).
pub fn hybrid_on(s: &Settings) -> Vec<&'static HybridService> {
    let legacy = ["youtube".to_string(), "discord".to_string()];
    let keys: &[String] = s.hybrid_services.as_deref().unwrap_or(&legacy);
    HYBRID_SERVICES.iter().filter(|x| keys.iter().any(|k| k == x.key)).collect()
}

/// Имена своих сайтов гибрида («site.com»), только годные.
pub fn hybrid_site_hosts(s: &Settings) -> Vec<String> {
    real_lines(&s.hybrid_sites).filter_map(zapret_target).map(|u| u.trim_start_matches("https://").to_string()).collect()
}

/// Все имена гибрида — для списка winws (list-general-user.txt).
pub fn hybrid_hosts(s: &Settings) -> Vec<String> {
    let mut v: Vec<String> = hybrid_on(s).iter().flat_map(|x| x.domains.iter().map(|d| d.to_string())).collect();
    v.extend(hybrid_site_hosts(s));
    v
}

/// Правило Xray «напрямую» для гибрида.
pub fn hybrid_domains(s: &Settings) -> Vec<String> {
    hybrid_hosts(s).into_iter().map(|d| format!("domain:{d}")).collect()
}

/// Что проверять в «Подобрать лучшую» в гибриде.
pub fn hybrid_targets(s: &Settings) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = hybrid_on(s).iter().flat_map(|x| x.targets.iter().map(|(n, u)| (n.to_string(), u.to_string()))).collect();
    for h in hybrid_site_hosts(s) {
        let u = format!("https://{h}");
        if !v.iter().any(|x| x.1 == u) {
            v.push((h, u));
        }
    }
    v
}

/// Папка на локальном диске: «C:\…» (на Windows). Сетевые пути (\\сервер,
/// \\?\UNC) нельзя: одно чтение такой папки — и Windows сама отдаёт
/// чужому серверу хеш пароля (NTLM).
pub fn local_dir(p: &str) -> bool {
    if p.len() > 1024 || p.chars().any(char::is_control) {
        return false;
    }
    if cfg!(windows) {
        let b = p.as_bytes();
        b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && (b[2] == b'\\' || b[2] == b'/')
            && !p.contains("..")
            && !crate::winsys::is_remote_drive(p) // «Z:» — подключённый сетевой диск
    } else {
        p.starts_with('/') && !p.starts_with("//") && !p.contains("..")
    }
}

/// Сайт для проверки zapret: "youtube.com" или "https://site/путь" → https://host.
pub fn zapret_target(t: &str) -> Option<String> {
    match parse_rule(t.trim()).ok()? {
        RuleTarget::Domain(d) => {
            let host = d.strip_prefix("domain:").or_else(|| d.strip_prefix("full:"))?.to_ascii_lowercase();
            let fine = host.contains('.')
                && host.len() <= 253
                && host.split('.').all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
            fine.then(|| format!("https://{host}"))
        }
        RuleTarget::Ip(_) => None,
    }
}

/// "100-200" или "150", числа в пределах [min, max], первое не больше второго.
fn check_range(v: &str, min: u32, max: u32) -> Result<(), String> {
    let v = v.trim();
    let (a, b) = v.split_once('-').unwrap_or((v, v));
    let num = |x: &str| x.trim().parse::<u32>().map_err(|_| tr!("«{v}» — нужно число или «от-до», например 100-200"));
    let (a, b) = (num(a)?, num(b)?);
    if a > b {
        return Err(tr!("«{v}»: первое число больше второго"));
    }
    if a < min || b > max {
        return Err(tr!("«{v}»: можно от {min} до {max}"));
    }
    Ok(())
}

/// Анти-DPI для исходящих к серверам (FinalMask Xray: работает поверх TLS
/// и REALITY, на уровне TCP/UDP). None — всё выключено.
pub fn finalmask(s: &Settings) -> Option<Value> {
    let mut m = Map::new();
    if s.fragment {
        // tlshello: режем только ClientHello — в нём имя сайта (SNI), по
        // которому ТСПУ и решает, рвать ли соединение. Остальное идёт как есть.
        m.insert(
            "tcp".into(),
            json!([{ "type": "fragment", "settings": {
                "packets": "tlshello",
                "lengths": [s.fragment_length.trim()],
                "delays": [s.fragment_delay.trim()]
            }}]),
        );
    }
    if s.udp_noise {
        m.insert(
            "udp".into(),
            json!([{ "type": "noise", "settings": {
                "noise": [{ "rand": "10-20", "delay": "10-16" }]
            }}]),
        );
    }
    (!m.is_empty()).then_some(Value::Object(m))
}

/// Навесить маску на исходящие, которые сами ходят в сеть к серверу.
/// Не трогаем: служебные (freedom/blackhole/dns), звенья цепочек, которые
/// подключаются через другой исходящий (dialerProxy/proxySettings — маска нужна
/// тому, кто реально выходит в сеть), и тех, у кого своя маска из JSON-подписки.
pub fn apply_finalmask(cfg: &mut Value, mask: &Value) {
    let Some(outs) = cfg["outbounds"].as_array_mut() else { return };
    for o in outs.iter_mut() {
        mask_one(o, mask);
    }
}

fn mask_one(o: &mut Value, mask: &Value) {
    if !o.is_object() {
        return;
    }
    let proto = o["protocol"].as_str().unwrap_or("");
    if matches!(proto, "" | "freedom" | "blackhole" | "dns" | "loopback") {
        return;
    }
    let chained = o.pointer("/streamSettings/sockopt/dialerProxy").is_some() || o.get("proxySettings").is_some();
    if chained || o.pointer("/streamSettings/finalmask").is_some() {
        return;
    }
    if !o["streamSettings"].is_object() {
        o["streamSettings"] = json!({});
    }
    o["streamSettings"]["finalmask"] = mask.clone();
}

/// Анти-DPI для конфига проверки (`build_test_config`): исходящие «o{i}-…»
/// принадлежат i-му серверу из `nodes`.
pub fn mask_test_config(cfg: &mut Value, nodes: &[&Node], tweaks: &std::collections::BTreeMap<String, Tweak>, global: Option<&Value>) {
    let Some(outs) = cfg["outbounds"].as_array_mut() else { return };
    for o in outs.iter_mut() {
        let idx = o["tag"].as_str().and_then(|t| t.strip_prefix('o')).and_then(|t| t.split('-').next()).and_then(|i| i.parse::<usize>().ok());
        let Some(n) = idx.and_then(|i| nodes.get(i)) else { continue };
        let tweak = tweaks.get(&n.id).filter(|t| validate_tweak(t).is_ok());
        mask_outbound(o, tweak, global);
    }
}

/// Конфиг для «Подобрать обход»: один сервер в нескольких вариантах, у каждого
/// свой SOCKS-вход.
pub fn build_variant_config(node: &Node, variants: &[(Tweak, u16)]) -> Value {
    let pairs: Vec<(&Node, u16)> = variants.iter().map(|(_, p)| (node, *p)).collect();
    let mut cfg = build_test_config(&pairs);
    if let Some(outs) = cfg["outbounds"].as_array_mut() {
        for o in outs.iter_mut() {
            let idx = o["tag"].as_str().and_then(|t| t.strip_prefix('o')).and_then(|t| t.split('-').next()).and_then(|i| i.parse::<usize>().ok());
            if let Some((t, _)) = idx.and_then(|i| variants.get(i)) {
                mask_outbound(o, Some(t), None);
            }
        }
    }
    cfg
}

/// Хост DNS-сервера для правила маршрутизации: "1.1.1.1", "https://1.1.1.1/dns-query",
/// "tcp://8.8.8.8:53", "https://dns.google/dns-query". Для "localhost"
/// (системный DNS) и "+local" (Xray ходит сам, мимо маршрутизации) — None.
fn dns_host(addr: &str) -> Option<RuleTarget> {
    let a = addr.trim();
    if a == "localhost" || a.contains("+local://") {
        return None;
    }
    let rest = a.split_once("://").map(|(_, r)| r).unwrap_or(a);
    let host = rest.split('/').next().unwrap_or("");
    let host = if let Some(h) = host.strip_prefix('[') {
        h.split(']').next().unwrap_or("")
    } else if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or("")
    } else {
        host
    };
    if host.is_empty() {
        return None;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => Some(RuleTarget::Ip(ip.to_string())),
        Err(_) if host.contains('.') => Some(RuleTarget::Domain(format!("full:{host}"))),
        Err(_) => None,
    }
}

/// Полный конфиг Xray для одного сервера (для «JSON» и тестов — без служебного).
pub fn build_config(node: &Node, s: &Settings) -> Value {
    build_run_config(&Upstream::Single(node), s, &RunOpts::default())
}

/// Конфиг для запуска.
pub fn build_run_config(up: &Upstream, s: &Settings, o: &RunOpts) -> Value {
    let auto = matches!(up, Upstream::Auto { .. });
    let listen = if s.allow_lan { "0.0.0.0" } else { "127.0.0.1" };
    let sniff = sniffing();

    // SOCKS/HTTP-входы есть всегда: через HTTP идёт системный прокси,
    // а в TUN-режиме они не мешают и пригодятся программам с настройкой прокси.
    let mut inbounds = vec![
        json!({
            "tag": "socks",
            "listen": listen,
            "port": s.socks_port,
            "protocol": "socks",
            "settings": { "udp": true, "auth": "noauth" },
            "sniffing": sniff
        }),
        json!({
            "tag": "http",
            "listen": listen,
            "port": s.http_port,
            "protocol": "http",
            "settings": {},
            "sniffing": sniff
        }),
    ];
    if let Some(port) = o.probe_port {
        inbounds.push(json!({
            "tag": "probe",
            "listen": "127.0.0.1",
            "port": port,
            "protocol": "socks",
            "settings": { "udp": false, "auth": "noauth" }
        }));
    }
    if let Some((_, up)) = o.tor.filter(|_| s.tor_mode != TorMode::Off) {
        inbounds.push(json!({
            "tag": "tor-up", "listen": "127.0.0.1", "port": up,
            "protocol": "socks", "settings": { "udp": false, "auth": "noauth" }
        }));
    }
    if let Some((port, pass)) = o.direct {
        inbounds.push(json!({
            "tag": "direct-probe", "listen": "127.0.0.1", "port": port,
            "protocol": "socks", "settings": { "udp": false, "auth": "password", "accounts": [{ "user": "rxvpn", "pass": pass }] }
        }));
    }
    if s.tun {
        inbounds.push(tun_inbound());
    }

    // owners[i] — чей исходящий outs[i] (для анти-DPI, подобранного серверу).
    let mut owners: Vec<&Node> = Vec::new();
    let (mut outs, mut servers): (Vec<Value>, Vec<&str>) = match up {
        Upstream::Single(n) => {
            let v = node_outbounds(n);
            owners.extend(std::iter::repeat_n(*n, v.len()));
            (v, vec![n.address.as_str()])
        }
        Upstream::Auto { nodes, .. } => {
            let mut v = Vec::new();
            for (i, n) in nodes.iter().enumerate() {
                let o = retag(node_outbounds(n), &auto_tag(i), &format!("aux-{i}-"));
                owners.extend(std::iter::repeat_n(n, o.len()));
                v.extend(o);
            }
            (v, nodes.iter().map(|n| n.address.as_str()).collect())
        }
    };
    // «Сайт → свой сервер»: серверов, которых нет в подключении, — по исходящему.
    let plan = site_plan(up, o.sites);
    const SITE_PREFIXES: &[&str] = &["site-", "sp-", "sb-", "sh-", "bal-"];
    if matches!(up, Upstream::Single(_))
        && !plan.outs.is_empty()
        && outs.iter().any(|x| x["tag"].as_str().is_some_and(|t| SITE_PREFIXES.iter().any(|p| t.starts_with(p))))
    {
        // Помощник сервера из чужого JSON назван «site-…» (или «sp-…» — тогда его
        // выбрал бы балансировщик) — переименовываем помощников основного.
        outs = retag(outs, "proxy", "main-");
    }
    for (node, tag, aux) in &plan.outs {
        let v = retag(node_outbounds(node), tag, aux);
        owners.extend(std::iter::repeat_n(*node, v.len()));
        outs.extend(v);
        servers.push(node.address.as_str());
    }
    let site_rules: Vec<(&[String], &str, bool)> = o.sites.iter().zip(&plan.to).map(|(r, (t, bal))| (r.sites, t.as_str(), *bal)).collect();
    outs.push(json!({ "tag": "direct", "protocol": "freedom" }));
    if s.allow_lan {
        // Прокси открыт для всей сети: не пускаем устройства из неё к службам,
        // которые слушают только этот комп (127.0.0.1). И в нашем direct, и в
        // freedom-помощниках из JSON-подписок.
        for o in outs.iter_mut().filter(|o| o["protocol"].as_str().is_some_and(|p| crate::defang::fold(p) == "freedom")) {
            lan_guard(o);
        }
    }
    outs.push(json!({ "tag": "block", "protocol": "blackhole" }));
    if s.tor_mode != TorMode::Off {
        // Arti не запустилась — «tor» тоже чёрная дыра: мимо Tor ничего не уйдёт.
        outs.push(match o.tor {
            Some((port, _)) => json!({ "tag": "tor", "protocol": "socks", "settings": { "servers": [{ "address": "127.0.0.1", "port": port }] } }),
            None => json!({ "tag": "tor", "protocol": "blackhole" }),
        });
    }
    if s.tun {
        // Отвечает на DNS-запросы программ встроенным DNS Xray (см. dns_section).
        outs.push(json!({ "tag": "dns-out", "protocol": "dns" }));
    }

    // «Авто»: трафик через один выбранный сервер (сайты видят один IP, сессии
    // не рвутся). Без API Xray: его нельзя защитить паролем, и любая программа
    // на компе могла бы переписать маршруты. Сервер меняем перезапуском.
    let px = match up {
        Upstream::Auto { nodes, prefer } => auto_tag((*prefer).min(nodes.len().saturating_sub(1))),
        Upstream::Single(_) => "proxy".to_string(),
    };
    let mut routing = routing(s, &px, auto, o, &site_rules);
    if !plan.balancers.is_empty() {
        routing["balancers"] = Value::Array(plan.balancers.clone());
    }

    // state.json мог поправить кто угодно, а при загрузке настройки не проверяются:
    // в конфиг Xray — только уровень из списка.
    let loglevel = if ["debug", "info", "warning", "error", "none"].contains(&s.log_level.as_str()) { s.log_level.as_str() } else { "warning" };
    let mut cfg = json!({
        "log": { "loglevel": loglevel },
        "inbounds": inbounds,
        "outbounds": outs,
        "routing": routing
    });
    cfg["dns"] = dns_section(s, &servers);
    // Сначала чистим чужое, потом добавляем свой анти-DPI: подобранный серверу
    // («Подобрать обход») или общий из настроек. defang место исходящих не меняет.
    defang(&mut cfg);
    let global = finalmask(s);
    if let Some(list) = cfg["outbounds"].as_array_mut() {
        for (i, o) in list.iter_mut().enumerate() {
            if o["tag"] == "tor" {
                continue; // локальный SOCKS Arti — анти-DPI ему не нужен
            }
            let tweak = owners.get(i).and_then(|n| s.node_tweaks.get(&n.id)).filter(|t| validate_tweak(t).is_ok());
            mask_outbound(o, tweak, global.as_ref());
        }
    }
    if s.tun && s.kill_switch {
        resolve_servers_inside(&mut cfg, s);
    }
    if let Some(port) = o.metrics_port {
        cfg["stats"] = json!({});
        cfg["policy"] = json!({
            "system": { "statsOutboundUplink": true, "statsOutboundDownlink": true }
        });
        cfg["metrics"] = json!({ "tag": "metrics", "listen": format!("127.0.0.1:{port}") });
    }
    // Замеры: «Авто» — все node-N; запасные серверы сайтов — их основные sp-NN.
    let mut subjects: Vec<&str> = Vec::new();
    let mut interval = 30;
    if let Upstream::Auto { nodes, .. } = up {
        subjects.push("node-");
        interval = observe_interval_secs(nodes.len());
    }
    if !plan.balancers.is_empty() {
        subjects.push("sp-");
    }
    if !subjects.is_empty() {
        cfg["observatory"] = json!({
            "subjectSelector": subjects,
            "probeURL": PROBE_URLS_HTTP[0],
            "probeInterval": format!("{interval}s"),
            "enableConcurrency": true
        });
    }
    cfg
}

/// Kill switch: адрес сервера Xray узнаёт своим DNS (`dns_section` отдаёт адреса серверов
/// «напрямую» — это соединения самого xray.exe, kill switch их пускает), а не системным
/// DNS Windows. Системный DNS при kill switch ходит только через туннель — а при
/// перезапуске Xray («Авто», смена сервера) туннеля ещё нет, и VPN бы не поднялся.
fn resolve_servers_inside(cfg: &mut Value, s: &Settings) {
    const SERVERS: &[&str] = &["vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2", "socks", "http"];
    let strategy = if s.dns_ipv6 { "UseIP" } else { "UseIPv4" };
    let Some(list) = cfg["outbounds"].as_array_mut() else { return };
    for o in list.iter_mut() {
        if !o["protocol"].as_str().is_some_and(|p| SERVERS.contains(&p)) || o["tag"] == "tor" {
            continue;
        }
        if !o["streamSettings"].is_object() {
            o["streamSettings"] = json!({});
        }
        let ss = &mut o["streamSettings"];
        if !ss["sockopt"].is_object() {
            ss["sockopt"] = json!({});
        }
        if ss["sockopt"]["domainStrategy"].is_null() {
            ss["sockopt"]["domainStrategy"] = json!(strategy);
        }
    }
}

/// sniffing вытаскивает домен из TLS/HTTP — чтобы правила по доменам работали,
/// даже если программа подключается по IP.
fn sniffing() -> Value {
    json!({
        "enabled": true,
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": true
    })
}

/// TUN-вход: Xray сам создаёт адаптер (wintun.dll), прописывает маршруты
/// и привязывает свои исходящие к физической сетке, чтобы не было петли.
fn tun_inbound() -> Value {
    json!({
        "tag": "tun",
        "protocol": "tun",
        "settings": {
            "name": TUN_NAME,
            "desc": "rxvpn",
            "mtu": 1500,
            "gateway": [TUN_GATEWAY_V4, TUN_GATEWAY_V6],
            "dns": TUN_DNS,
            "autoSystemRoutingTable": ["0.0.0.0/0", "::/0"],
            "autoOutboundsInterface": "auto",
            // Windows: DNS только через TUN — иначе Windows параллельно спросит
            // DNS провайдера, и тот подсунет заглушку для заблокированного сайта.
            "autoSystemWfpBlockLeak": ["dns"]
        },
        "sniffing": sniffing()
    })
}

/// Встроенный DNS Xray. Запросы самого DNS-модуля помечаются тегом
/// dns-internal: «DNS напрямую» идёт напрямую, «DNS через VPN» — через VPN.
///  - «Всё» и «Обход РФ»: по умолчанию DNS через VPN, напрямую — .ru и адреса серверов;
///  - «Только заблокированное»: наоборот, через VPN — только заблокированное.
fn dns_section(s: &Settings, servers: &[&str]) -> Value {
    let mut direct_domains: Vec<String> = Vec::new();
    let mut remote_domains: Vec<String> = Vec::new();
    let add = |list: &mut Vec<String>, d: String| {
        if !list.contains(&d) {
            list.push(d);
        }
    };
    for addr in servers {
        if addr.parse::<std::net::IpAddr>().is_err() && addr.contains('.') {
            add(&mut direct_domains, format!("full:{addr}"));
        }
    }
    let domains_of = |lines: &[String]| -> Vec<String> {
        real_lines(lines)
            .filter_map(|l| match parse_rule(l) {
                Ok(RuleTarget::Domain(d)) => Some(d),
                _ => None,
            })
            .collect()
    };
    for d in domains_of(&s.direct) {
        add(&mut direct_domains, d);
    }
    for d in domains_of(&s.proxy) {
        add(&mut remote_domains, d);
    }
    // «Сайт → свой сервер»: адреса — через VPN, не от местного DNS (тот может подменять).
    for r in site_rules(s) {
        for d in domains_of(&r.sites) {
            add(&mut remote_domains, d);
        }
    }
    // Сайты через Tor — не спрашиваем у местного DNS (он видит и может подменить).
    if s.tor_mode == TorMode::Sites {
        for d in domains_of(&s.tor_sites) {
            add(&mut remote_domains, d);
        }
    }
    // Правила редактора без условий по программам/портам — их домены тоже
    // разумно резолвить там, куда пойдёт трафик.
    for r in s.rules.iter().filter(|r| r.enabled && r.apps.is_empty() && r.ports.trim().is_empty()) {
        for d in domains_of(&r.sites) {
            match r.action {
                Action::Direct => add(&mut direct_domains, d),
                Action::Proxy => add(&mut remote_domains, d),
                Action::Block => {}
            }
        }
    }
    // Гибрид: YouTube и Discord идут напрямую — и адреса им нужны «местные»,
    // ближайшие к человеку (не к VPN-серверу), иначе видео тянется из-за границы.
    if s.zapret_hybrid && !s.zapret {
        for d in hybrid_domains(s) {
            add(&mut direct_domains, d);
        }
    }
    // «Всё через Tor»: ни одно имя — местному DNS (кроме адресов VPN-серверов:
    // без них не подключиться); всё — через DNS VPN.
    let all_tor = s.tor_mode == TorMode::All;
    if all_tor {
        let servers_only: Vec<String> = servers.iter().filter(|a| a.parse::<std::net::IpAddr>().is_err() && a.contains('.')).map(|a| format!("full:{a}")).collect();
        direct_domains.retain(|d| servers_only.contains(d));
    }
    match s.route {
        _ if all_tor => {}
        RouteMode::BypassRu => {
            for d in ["domain:ru", "domain:su", "domain:xn--p1ai"] {
                add(&mut direct_domains, d.to_string());
            }
        }
        RouteMode::Blocked => add(&mut remote_domains, format!("ext:{GEOSITE_RU}:ru-blocked")),
        RouteMode::Global => {}
    }

    let mut dns_servers = Vec::new();
    if !direct_domains.is_empty() {
        dns_servers.push(json!({ "address": s.dns_direct.trim(), "domains": direct_domains, "skipFallback": true }));
    }
    if s.route == RouteMode::Blocked && !all_tor {
        if !remote_domains.is_empty() {
            dns_servers.push(json!({ "address": s.dns_remote.trim(), "domains": remote_domains, "skipFallback": true }));
        }
        dns_servers.push(json!(s.dns_direct.trim()));
    } else {
        if !remote_domains.is_empty() {
            dns_servers.push(json!({ "address": s.dns_remote.trim(), "domains": remote_domains, "skipFallback": true }));
        }
        dns_servers.push(json!(s.dns_remote.trim()));
    }
    let mut dns = json!({
        "tag": "dns-internal",
        // Только IPv4 по умолчанию: если у сервера нет IPv6, сайты по IPv6
        // не откроются, а так программы просто пойдут по IPv4.
        "queryStrategy": if s.dns_ipv6 { "UseIP" } else { "UseIPv4" },
        "servers": dns_servers
    });
    if let Ok(mut h) = parse_hosts(&s.hosts) {
        if s.tor_mode != TorMode::Off {
            h.insert("domain:onion".into(), json!(ONION_STUB));
        }
        if !h.is_empty() {
            dns["hosts"] = Value::Object(h);
        }
    }
    dns
}

/// Исходящие сервера без наших direct/block: главный (tag "proxy") +
/// помощники из JSON-подписки (fragment и т.п.).
pub fn node_outbounds(node: &Node) -> Vec<Value> {
    if crate::singbox::is_sidecar_link(&node.link) {
        return vec![outbound(node)];
    }
    match node.raw.as_ref().and_then(|r| r["outbounds"].as_array()) {
        // Каждый раз чистим заново: raw мог прийти из старого state.json или бэкапа.
        Some(raw) if !raw.is_empty() => crate::jsonsub::sanitize_outbounds(raw.clone()).0,
        _ => vec![outbound(node)],
    }
}

/// Все адреса, к которым Xray подключается ради этого сервера: основной и всё,
/// что в его исходящих (vnext/servers, цепочки dialerProxy из JSON-подписки,
/// downloadSettings у xhttp, peers.endpoint у WireGuard). Нужны гибриду: winws
/// эти соединения не трогает.
pub fn server_hosts(node: &Node) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>, depth: u32) {
        if depth > 24 || out.len() >= 64 {
            return;
        }
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    if let Some(a) = x.as_str() {
                        if k.eq_ignore_ascii_case("address") {
                            out.push(a.trim().trim_start_matches('[').trim_end_matches(']').to_string());
                        } else if k.eq_ignore_ascii_case("endpoint") {
                            // WireGuard: "хост:порт" или "[IPv6]:порт"
                            let a = a.trim();
                            let host = match a.strip_prefix('[') {
                                Some(r) => r.split(']').next().unwrap_or(""),
                                None => a.rsplit_once(':').map_or(a, |x| x.0),
                            };
                            out.push(host.to_string());
                        }
                    }
                    walk(x, out, depth + 1);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out, depth + 1)),
            _ => {}
        }
    }
    let mut out = vec![node.address.clone()];
    for o in node_outbounds(node) {
        walk(&o, &mut out, 0);
    }
    out.retain(|h| !h.is_empty() && h.len() <= 253);
    out.sort();
    out.dedup();
    out
}

/// Порядок правил важен: Xray берёт первое совпавшее.
fn routing(s: &Settings, px: &str, auto: bool, o: &RunOpts, sites: &[(&[String], &str, bool)]) -> Value {
    let mode = s.route;
    let mut rules = Vec::new();

    // 0. Служебные: проверки rxvpn и подключение Arti к сети Tor — всегда через
    //    VPN, мимо любых правил (в том числе «Всё через Tor» — иначе петля);
    //    проверка белых списков — всегда напрямую.
    if o.probe_port.is_some() {
        rules.push(put(json!({ "inboundTag": ["probe"] }), To::Proxy, px));
    }
    if o.tor.is_some() && s.tor_mode != TorMode::Off {
        rules.push(put(json!({ "inboundTag": ["tor-up"] }), To::Proxy, px));
    }
    if o.direct.is_some() {
        rules.push(put(json!({ "inboundTag": ["direct-probe"] }), To::Direct, px));
    }

    if s.tun {
        // 1. DNS-запросы программ (на порт 53 через TUN) — во встроенный DNS.
        rules.push(put(json!({ "inboundTag": ["tun"], "port": "53" }), To::DnsOut, px));
    }
    // 2. Запросы самого DNS-модуля: «DNS напрямую» — напрямую, остальные — через VPN.
    match dns_host(&s.dns_direct) {
        Some(RuleTarget::Ip(ip)) => rules.push(put(json!({ "inboundTag": ["dns-internal"], "ip": [ip] }), To::Direct, px)),
        Some(RuleTarget::Domain(d)) => rules.push(put(json!({ "inboundTag": ["dns-internal"], "domain": [d] }), To::Direct, px)),
        None => {}
    }
    rules.push(put(json!({ "inboundTag": ["dns-internal"] }), To::Proxy, px));
    // Отдельного правила «адреса серверов — напрямую» нет: свои соединения Xray
    // в TUN и так идут мимо туннеля (autoOutboundsInterface), а такое правило
    // позволило бы подписке вывести из туннеля любой IP, назвав его сервером.

    // Адрес-заглушка для .onion из DNS (см. dns_section) — в никуда.
    if s.tor_mode != TorMode::Off {
        rules.push(put(json!({ "ip": [format!("{ONION_STUB}/32")] }), To::Block, px));
    }
    rules.push(put(json!({ "ip": ["geoip:private"] }), To::Direct, px));

    // 3¼. Tor. .onion — только через Tor (иначе ушли бы на VPN или к DNS);
    //     «Всё через Tor» — главнее любых своих правил, UDP — в блок.
    let tor = |r: Value| {
        let mut r = r;
        r["type"] = json!("field");
        r["outboundTag"] = json!("tor");
        r
    };
    if s.tor_mode != TorMode::Off {
        rules.push(tor(json!({ "domain": ["regexp:\\.onion$"] })));
    }
    if s.tor_mode == TorMode::All {
        rules.push(tor(json!({ "network": "tcp" })));
        rules.push(put(json!({ "network": "udp" }), To::Block, px));
    }
    // Сайт → Tor — тоже раньше правил редактора и программ: иначе «Steam мимо VPN»
    // или «только браузер через VPN» увели бы эти сайты мимо Tor. UDP — в блок.
    if s.tor_mode == TorMode::Sites {
        for mut r in rules_for(&s.tor_sites, To::Block, px) {
            r["network"] = json!("udp");
            let mut t = r.clone();
            t["network"] = json!("tcp");
            t["outboundTag"] = json!("tor");
            rules.push(t);
            rules.push(r);
        }
    }

    // 3½. Правила из редактора — самые главные после служебных.
    for r in s.rules.iter().filter(|r| r.enabled && validate_rule(r).is_ok()) {
        rules.extend(build_rule(r, px));
    }

    // 4. Программы. Раньше сайтов: «Steam мимо VPN» — значит весь Steam.
    match s.apps_mode {
        AppsMode::Except => {
            let names = app_names(&s.apps_direct);
            if !names.is_empty() {
                rules.push(put(json!({ "process": names }), To::Direct, px));
            }
        }
        AppsMode::Only => {
            let names = app_names(&s.apps_proxy);
            if !names.is_empty() {
                rules.push(put(json!({ "process": names }), To::Proxy, px));
            }
        }
    }

    // 4½. Сайт → свой сервер. Раньше «Своих сайтов» и всех режимов: человек
    //     выбрал сервер для этих сайтов явно — это главнее «напрямую» и «.ru».
    for (lines, tag, bal) in sites {
        for mut r in rules_for(lines, To::Proxy, tag) {
            if *bal {
                if let Some(m) = r.as_object_mut() {
                    m.remove("outboundTag");
                    m.insert("balancerTag".into(), json!(tag));
                }
            }
            rules.push(r);
        }
    }

    // 5. Свои сайты. Раньше встроенного «Обхода РФ», поэтому
    //    «всегда через VPN» перебивает .ru, а «напрямую» работает в любом режиме.
    rules.extend(rules_for(&s.proxy, To::Proxy, px));
    rules.extend(rules_for(&s.direct, To::Direct, px));

    // 6. Реклама. После своих списков: если блокировка сломала нужный сайт,
    //    достаточно добавить его в «Свои сайты».
    if s.block_ads {
        rules.push(put(json!({ "domain": ["geosite:category-ads-all"] }), To::Block, px));
    }

    // 6½. Гибрид: YouTube и Discord — мимо VPN, их «пробивает» zapret. После своих
    //     сайтов и рекламы (их слово главнее), но раньше режима маршрутизации.
    let hybrid = hybrid_domains(s);
    if s.zapret_hybrid && !s.zapret && !hybrid.is_empty() {
        rules.push(put(json!({ "domain": hybrid }), To::Direct, px));
    }
    // …и их программы (Discord.exe): иначе голос уходил в VPN, пока человек сам не
    // добавит Discord в «Программы мимо VPN».
    let hybrid_apps: Vec<String> = hybrid_on(s).iter().flat_map(|x| x.apps.iter().map(|a| a.to_string())).collect();
    if s.zapret_hybrid && !s.zapret && !hybrid_apps.is_empty() {
        rules.push(put(json!({ "process": app_names(&hybrid_apps) }), To::Direct, px));
    }

    match mode {
        RouteMode::BypassRu => {
            // Домены по зонам .ru .su .рф — не зависят от geosite.dat, не сломаются.
            rules.push(put(json!({ "domain": ["domain:ru", "domain:su", "domain:xn--p1ai"] }), To::Direct, px));
            // Всё, что резолвится в российские IP (yandex.com, vk.com, банки на .com...).
            rules.push(put(json!({ "ip": ["geoip:ru"] }), To::Direct, px));
        }
        RouteMode::Blocked => {
            rules.push(put(json!({ "domain": [format!("ext:{GEOSITE_RU}:ru-blocked")] }), To::Proxy, px));
            rules.push(put(json!({ "ip": [format!("ext:{GEOIP_RU}:ru-blocked"), format!("ext:{GEOIP_RU}:re-filter")] }), To::Proxy, px));
        }
        RouteMode::Global => {}
    }

    // 7. Остальное. «Только заблокированное» и «только эти программы через VPN» —
    //    значит прочее напрямую. В «Авто» по умолчанию первый исходящий (node-0)
    //    может быть мёртвым, поэтому явно отправляем в балансировщик.
    let only_apps = s.apps_mode == AppsMode::Only && real_lines(&s.apps_proxy).next().is_some();
    if mode == RouteMode::Blocked || only_apps {
        rules.push(put(json!({ "network": "tcp,udp" }), To::Direct, px));
    } else if auto {
        rules.push(put(json!({ "network": "tcp,udp" }), To::Proxy, px));
    }

    // IPIfNonMatch: если по домену правило не нашлось — резолвим и проверяем
    // IP-правила. Нужно для geoip и подсетей. «auto» — включаем, только когда
    // IP-правила есть: иначе лишний DNS-запрос на каждое соединение.
    let has_ip = |lines: &[String]| real_lines(lines).any(|l| matches!(parse_rule(l), Ok(RuleTarget::Ip(_))));
    let need_ip = mode != RouteMode::Global
        || has_ip(&s.direct)
        || has_ip(&s.proxy)
        || (s.tor_mode == TorMode::Sites && has_ip(&s.tor_sites))
        || s.rules.iter().any(|r| r.enabled && has_ip(&r.sites))
        || sites.iter().any(|(l, ..)| has_ip(l));
    let strategy = match s.domain_strategy.as_str() {
        "AsIs" | "IPIfNonMatch" | "IPOnDemand" => s.domain_strategy.as_str(),
        _ if need_ip => "IPIfNonMatch",
        _ => "AsIs",
    };
    json!({
        "domainStrategy": strategy,
        "rules": rules
    })
}

/// Конфиг для «Проверить все»: один Xray, на каждый сервер свой SOCKS-вход
/// и свой исходящий, без всякой маршрутизации — проверяем именно сервер.
pub fn build_test_config(nodes: &[(&Node, u16)]) -> Value {
    let mut inbounds = Vec::new();
    let mut outbounds = Vec::new();
    let mut rules = Vec::new();
    for (i, (node, port)) in nodes.iter().enumerate() {
        let inb = format!("t{i}");
        let main = format!("o{i}-proxy");
        inbounds.push(json!({
            "tag": inb, "listen": "127.0.0.1", "port": port,
            "protocol": "socks", "settings": { "udp": false }
        }));
        outbounds.extend(retag(node_outbounds(node), &main, &format!("o{i}-")));
        rules.push(json!({ "type": "field", "inboundTag": [inb], "outboundTag": main }));
    }
    // Ничего не совпало — в чёрную дыру, а не напрямую в интернет.
    outbounds.push(json!({ "tag": "block", "protocol": "blackhole" }));
    let mut cfg = json!({
        "log": { "loglevel": "error" },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": { "rules": rules }
    });
    defang(&mut cfg);
    cfg
}

/// Последний рубеж перед записью config.json: каждый исходящий проходит
/// crate::defang::check — откуда бы ни пришёл сервер: JSON-подписка, бэкап,
/// старый state.json или обычная ссылка (её xhttp `extra` — произвольный JSON).
/// Не прошёл — вместо него blackhole с тем же тегом: сервер просто не работает.
/// freedom не выпускает к адресам этого компа. Проверка — после резолва, поэтому и
/// «localhost», и домены на 127.0.0.1 не пройдут. `redirect` убираем: он увёл бы
/// соединение на любой адрес в обход проверки.
fn lan_guard(o: &mut Value) {
    let Some(obj) = o.as_object_mut() else { return };
    let settings = obj.entry("settings").or_insert_with(|| json!({}));
    if !settings.is_object() {
        *settings = json!({});
    }
    let m = settings.as_object_mut().expect("settings — объект");
    let mut rules = vec![json!({ "action": "block", "ip": ["127.0.0.0/8", "::1/128", "0.0.0.0/8", "::/128"] })];
    let keys: Vec<String> = m
        .keys()
        .filter(|k| matches!(crate::defang::fold(k).as_str(), "redirect" | "finalrules"))
        .cloned()
        .collect();
    for k in keys {
        if let Some(Value::Array(old)) = m.remove(&k).filter(|_| crate::defang::fold(&k) == "finalrules") {
            rules.extend(old); // наш запрет — первым: первое совпавшее правило решает
        }
    }
    m.insert("finalRules".into(), Value::Array(rules));
}

fn defang(cfg: &mut Value) {
    if let Some(outs) = cfg["outbounds"].as_array_mut() {
        for o in outs.iter_mut() {
            if crate::defang::check(o).is_err() {
                let tag = o["tag"].clone();
                *o = json!({ "tag": tag, "protocol": "blackhole" });
            }
        }
    }
}

/// Переименовать теги исходящих одного сервера: главный ("proxy") → `main`,
/// помощники → `aux_prefix + тег`. Ссылки на них (dialerProxy, proxySettings)
/// правятся следом, чтобы у разных серверов не было одинаковых тегов.
fn retag(list: Vec<Value>, main: &str, aux_prefix: &str) -> Vec<Value> {
    let tags: std::collections::BTreeSet<String> = list
        .iter()
        .filter_map(|o| o["tag"].as_str().map(str::to_string))
        .collect();
    let rename = |t: &str| -> String {
        if t == "proxy" {
            main.to_string()
        } else {
            format!("{aux_prefix}{t}")
        }
    };
    list.into_iter()
        .map(|mut o| {
            if let Some(t) = o["tag"].as_str().map(str::to_string) {
                o["tag"] = json!(rename(&t));
            }
            if let Some(sock) = o.pointer_mut("/streamSettings/sockopt") {
                if let Some(t) = sock["dialerProxy"].as_str().map(str::to_string) {
                    if tags.contains(&t) {
                        sock["dialerProxy"] = json!(rename(&t));
                    }
                }
            }
            if let Some(t) = o["proxySettings"]["tag"].as_str().map(str::to_string) {
                if tags.contains(&t) {
                    o["proxySettings"]["tag"] = json!(rename(&t));
                }
            }
            o
        })
        .collect()
}

/// Исходящее подключение к серверу (tag "proxy").
pub fn outbound(n: &Node) -> Value {
    // TUIC: Xray — SOCKS к sing-box на 127.0.0.1 (его поднимает runner).
    if crate::singbox::is_sidecar_link(&n.link) {
        return crate::singbox::xray_outbound(&n.link).unwrap_or_else(|| json!({"tag": "proxy", "protocol": "blackhole"}));
    }
    let settings = match n.protocol {
        Protocol::Vless => {
            let mut user = Map::new();
            user.insert("id".into(), json!(n.uuid.clone().unwrap_or_default()));
            user.insert(
                "encryption".into(),
                json!(n.encryption.clone().unwrap_or_else(|| "none".into())),
            );
            if let Some(flow) = &n.flow {
                user.insert("flow".into(), json!(flow));
            }
            json!({ "vnext": [{ "address": n.address, "port": n.port, "users": [user] }] })
        }
        Protocol::Vmess => json!({
            "vnext": [{
                "address": n.address,
                "port": n.port,
                "users": [{
                    "id": n.uuid.clone().unwrap_or_default(),
                    "alterId": n.alter_id,
                    "security": n.method.clone().unwrap_or_else(|| "auto".into())
                }]
            }]
        }),
        Protocol::Trojan => json!({
            "servers": [{ "address": n.address, "port": n.port,
                          "password": n.password.clone().unwrap_or_default() }]
        }),
        Protocol::Shadowsocks => json!({
            "servers": [{ "address": n.address, "port": n.port,
                          "method": n.method.clone().unwrap_or_default(),
                          "password": n.password.clone().unwrap_or_default() }]
        }),
        // Такие сервера бывают только из JSON-подписки и строятся из raw.
        Protocol::Other => json!({}),
    };

    json!({
        "tag": "proxy",
        "protocol": n.protocol.as_str(),
        "settings": settings,
        "streamSettings": stream_settings(n)
    })
}

fn stream_settings(n: &Node) -> Value {
    let t = &n.transport;
    let sec = &n.security;
    let mut ss = Map::new();
    ss.insert("network".into(), json!(t.network));
    ss.insert("security".into(), json!(sec.kind));

    // --- транспорт ---
    match t.network.as_str() {
        "ws" => {
            ss.insert(
                "wsSettings".into(),
                json!({ "path": t.path.clone().unwrap_or_else(|| "/".into()),
                        "host": t.host.clone().unwrap_or_default() }),
            );
        }
        "grpc" => {
            ss.insert(
                "grpcSettings".into(),
                json!({ "serviceName": t.service_name.clone().unwrap_or_default(),
                        "multiMode": t.mode.as_deref() == Some("multi") }),
            );
        }
        "xhttp" => {
            let mut x = Map::new();
            x.insert("path".into(), json!(t.path.clone().unwrap_or_else(|| "/".into())));
            if let Some(h) = &t.host {
                x.insert("host".into(), json!(h));
            }
            x.insert("mode".into(), json!(t.mode.clone().unwrap_or_else(|| "auto".into())));
            if let Some(extra) = &t.extra {
                x.insert("extra".into(), extra.clone());
            }
            ss.insert("xhttpSettings".into(), Value::Object(x));
        }
        "httpupgrade" => {
            ss.insert(
                "httpupgradeSettings".into(),
                json!({ "path": t.path.clone().unwrap_or_else(|| "/".into()),
                        "host": t.host.clone().unwrap_or_default() }),
            );
        }
        "tcp" if t.header_type.as_deref() == Some("http") => {
            let mut req = json!({ "path": [t.path.clone().unwrap_or_else(|| "/".into())] });
            if let Some(h) = &t.host {
                req["headers"] = json!({ "Host": h.split(',').map(str::trim).collect::<Vec<_>>() });
            }
            ss.insert(
                "tcpSettings".into(),
                json!({ "header": { "type": "http", "request": req } }),
            );
        }
        _ => {}
    }

    // --- шифрование ---
    let sni = sec
        .sni
        .clone()
        .or_else(|| t.host.clone().filter(|h| !h.contains(',')))
        .unwrap_or_else(|| n.address.clone());

    match sec.kind.as_str() {
        "reality" => {
            let mut r = Map::new();
            r.insert("serverName".into(), json!(sni));
            r.insert(
                "fingerprint".into(),
                json!(sec.fingerprint.clone().unwrap_or_else(|| "chrome".into())),
            );
            r.insert("publicKey".into(), json!(sec.public_key.clone().unwrap_or_default()));
            r.insert("shortId".into(), json!(sec.short_id.clone().unwrap_or_default()));
            r.insert("spiderX".into(), json!(sec.spider_x.clone().unwrap_or_else(|| "/".into())));
            if let Some(v) = &sec.mldsa65_verify {
                r.insert("mldsa65Verify".into(), json!(v));
            }
            ss.insert("realitySettings".into(), Value::Object(r));
        }
        "tls" => {
            let mut tls = Map::new();
            tls.insert("serverName".into(), json!(sni));
            tls.insert(
                "fingerprint".into(),
                json!(sec.fingerprint.clone().unwrap_or_else(|| "chrome".into())),
            );
            if !sec.alpn.is_empty() {
                tls.insert("alpn".into(), json!(sec.alpn));
            }
            // allowInsecure Xray 26 убрал (конфиг с ним не запускается) — не пишем:
            // сервер с самоподписанным сертификатом просто не подключится.
            ss.insert("tlsSettings".into(), Value::Object(tls));
        }
        _ => {}
    }

    Value::Object(ss)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link::parse_link;

    /// Правила без служебных (DNS-модуль, probe) — то, что задаёт человек и режим.
    fn user_rules(c: &Value) -> Vec<Value> {
        c["routing"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r.get("inboundTag").is_none())
            .cloned()
            .collect()
    }

    /// Куда уйдёт трафик по правилу: "proxy" / "direct" / "block" / "auto"(балансировщик).
    fn dest(r: &Value) -> String {
        r["outboundTag"].as_str().or(r["balancerTag"].as_str()).unwrap_or("?").to_string()
    }

    #[test]
    fn hotkey_and_connect_apps_are_checked() {
        let ok = Settings { hotkey: "Ctrl+Alt+V".into(), connect_apps: vec!["Discord.exe".into(), "cs2.exe".into(), "Telegram (1).exe".into()], ..Default::default() };
        assert!(validate_settings(&ok).is_ok());
        assert!(validate_settings(&Settings { hotkey: String::new(), ..Default::default() }).is_ok(), "пусто — выключена");
        for bad in [r"C:\Games\cs2.exe", "../x.exe", "Discord", "a\"b.exe", "x.exe;calc"] {
            assert!(validate_settings(&Settings { connect_apps: vec![bad.into()], ..Default::default() }).is_err(), "{bad}");
        }
        assert!(validate_settings(&Settings { hotkey: "Ctrl+Alt+V; rm".into(), ..Default::default() }).is_err());
        assert!(validate_settings(&Settings { connect_apps: vec!["a.exe".into(); 51], ..Default::default() }).is_err());
    }

    #[test]
    fn kill_switch_resolves_servers_inside_xray() {
        let n = parse_link("vless://u@nl1.example.com:443?type=tcp&security=reality&pbk=K&sid=a&sni=x.com#t").unwrap();
        let mut s = Settings { tun: true, kill_switch: true, ..Default::default() };
        let c = build_config(&n, &s);
        let out = |c: &Value, tag: &str| c["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == tag).unwrap().clone();
        assert_eq!(out(&c, "proxy")["streamSettings"]["sockopt"]["domainStrategy"], "UseIPv4");
        assert!(out(&c, "direct")["streamSettings"]["sockopt"]["domainStrategy"].is_null(), "freedom не трогаем");
        // Адрес сервера — в «прямом» DNS Xray: его спросит сам xray.exe, kill switch его пускает.
        assert!(c["dns"].to_string().contains("full:nl1.example.com"));
        s.kill_switch = false;
        let c = build_config(&n, &s);
        assert!(out(&c, "proxy")["streamSettings"]["sockopt"]["domainStrategy"].is_null(), "без kill switch — как было");
    }

    fn node() -> Node {
        parse_link("trojan://p@a.b:443#t").unwrap()
    }

    #[test]
    fn reality_xhttp_config() {
        let n = parse_link("vless://u@1.2.3.4:443?type=xhttp&path=%2Fapi&mode=packet-up&security=reality&pbk=PK&sid=ab&sni=amsterdam.ubea.net&fp=chrome#x").unwrap();
        let c = build_config(&n, &Settings::default());
        let out = &c["outbounds"][0];
        assert_eq!(out["protocol"], "vless");
        assert_eq!(out["settings"]["vnext"][0]["users"][0]["encryption"], "none");
        let ss = &out["streamSettings"];
        assert_eq!(ss["network"], "xhttp");
        assert_eq!(ss["xhttpSettings"]["mode"], "packet-up");
        assert_eq!(ss["realitySettings"]["serverName"], "amsterdam.ubea.net");
        assert_eq!(ss["realitySettings"]["publicKey"], "PK");
        assert_eq!(c["inbounds"][0]["port"], 10900);
        // private + .ru-домены + geoip:ru
        assert_eq!(user_rules(&c).len(), 3);
    }

    #[test]
    fn tun_config_shape() {
        let n = parse_link("vless://u@nl1.example.com:443?type=tcp&security=reality&pbk=K&sid=a&sni=x.com#t").unwrap();
        let s = Settings { tun: true, ..Default::default() };
        let c = build_run_config(&Upstream::Single(&n), &s, &RunOpts { metrics_port: Some(5555), ..Default::default() });
        let tun = c["inbounds"].as_array().unwrap().iter().find(|i| i["protocol"] == "tun").unwrap();
        assert_eq!(tun["settings"]["autoSystemWfpBlockLeak"][0], "dns");
        assert_eq!(tun["settings"]["autoOutboundsInterface"], "auto");
        assert!(tun["settings"]["dns"].as_array().is_some_and(|d| !d.is_empty()), "WFP dns требует dns");
        // DNS-перехват — самое первое правило, иначе запросы уйдут не туда
        assert_eq!(c["routing"]["rules"][0]["outboundTag"], "dns-out");
        // адрес сервера резолвится напрямую, а не через сам себя
        assert_eq!(c["dns"]["servers"][0]["domains"][0], "full:nl1.example.com");
        assert!(c["outbounds"].as_array().unwrap().iter().any(|o| o["tag"] == "dns-out"));
        assert_eq!(c["metrics"]["listen"], "127.0.0.1:5555");
        // IP серверов из списка не выводятся из туннеля (подписка не может так «спрятать» адрес)
        let tun_ip = parse_link("vless://u@8.8.8.8:443?type=tcp#t").unwrap();
        let c2 = build_run_config(&Upstream::Single(&tun_ip), &s, &RunOpts::default());
        assert!(!c2["routing"]["rules"].as_array().unwrap().iter().any(|r| r["ip"].as_array().is_some_and(|a| a.iter().any(|x| x == "8.8.8.8"))));
        // LAN открыт — к localhost через прокси не пускаем
        let lan = build_run_config(&Upstream::Single(&n), &Settings { allow_lan: true, ..Default::default() }, &RunOpts::default());
        let d = lan["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "direct").unwrap();
        assert_eq!(d["settings"]["finalRules"][0]["action"], "block");
        assert_eq!(d["settings"]["finalRules"][0]["ip"][0], "127.0.0.0/8");
        // …и через freedom-помощника из JSON-подписки (redirect на localhost) — тоже нет.
        let sub = r#"[{"remarks":"x","outbounds":[
            {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"e.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","sockopt":{"dialerProxy":"frag"}}},
            {"tag":"frag","protocol":"freedom","settings":{"redirect":"127.0.0.1:3389","finalRules":[{"action":"allow"}]}}]}]"#;
        let (nodes, _) = crate::jsonsub::parse_json_subscription(sub).unwrap();
        let lan = build_run_config(&Upstream::Single(&nodes[0]), &Settings { allow_lan: true, ..Default::default() }, &RunOpts::default());
        for f in lan["outbounds"].as_array().unwrap().iter().filter(|o| o["protocol"] == "freedom") {
            assert!(f["settings"].get("redirect").is_none(), "{f}");
            assert_eq!(f["settings"]["finalRules"][0]["action"], "block", "{f}");
        }
        assert!(lan["outbounds"].as_array().unwrap().iter().filter(|o| o["protocol"] == "freedom").count() >= 2);
        // без allow_lan помощник не трогаем
        let home = build_run_config(&Upstream::Single(&nodes[0]), &Settings::default(), &RunOpts::default());
        assert!(home.to_string().contains("127.0.0.1:3389"));
        // без TUN нет ни TUN-входа, ни перехвата DNS, ни счётчиков
        let p = build_run_config(&Upstream::Single(&n), &Settings::default(), &RunOpts::default());
        assert!(p.get("metrics").is_none());
        assert_eq!(p["inbounds"].as_array().unwrap().len(), 2);
        assert!(!p["outbounds"].as_array().unwrap().iter().any(|o| o["tag"] == "dns-out"));
    }

    #[test]
    fn json_sub_node_uses_raw_outbounds() {
        let (nodes, _) = crate::parse_many(crate::jsonsub::tests::REMNA);
        let c = build_config(&nodes[0], &Settings::default());
        let tags: Vec<&str> = c["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["tag"].as_str().unwrap())
            .collect();
        assert_eq!(tags, ["proxy", "sub-fragment", "direct", "block"]);
        // наши инбаунды, а не 10808 из подписки
        assert_eq!(c["inbounds"][0]["port"], 10900);
    }

    #[test]
    fn parse_rule_variants() {
        use RuleTarget::*;
        let d = |s: &str| Domain(s.to_string());
        let i = |s: &str| Ip(s.to_string());
        assert_eq!(parse_rule("youtube.com"), Ok(d("domain:youtube.com")));
        assert_eq!(parse_rule("https://www.YouTube.com/watch?v=1"), Ok(d("domain:youtube.com")));
        assert_eq!(parse_rule("*.example.org"), Ok(d("domain:example.org")));
        assert_eq!(parse_rule("site.ru:8443/path"), Ok(d("domain:site.ru")));
        assert_eq!(parse_rule("госуслуги.рф"), Ok(d("domain:xn--c1aapkosapc.xn--p1ai")));
        assert_eq!(parse_rule("geosite:category-ads"), Ok(d("geosite:category-ads")));
        assert_eq!(parse_rule("1.2.3.4"), Ok(i("1.2.3.4")));
        assert_eq!(parse_rule("10.0.0.0/8"), Ok(i("10.0.0.0/8")));
        assert_eq!(parse_rule("http://8.8.8.8/dns"), Ok(i("8.8.8.8")));
        assert_eq!(parse_rule("geoip:CN"), Ok(i("geoip:cn")));
        assert_eq!(parse_rule("ext:geoip-ru.dat:ru-blocked"), Ok(i("ext:geoip-ru.dat:ru-blocked")));
        assert_eq!(parse_rule("ext:my.dat:games"), Ok(d("ext:my.dat:games")));
        assert!(parse_rule("ext:broken").is_err());
        for bad in ["ext:../../etc/passwd.dat:x", "ext:C:\\Windows\\x.dat:y", "ext:\\\\host\\s\\x.dat:y", "ext:x.txt:y", "ext:.dat:y", "ext:a/b.dat:c"] {
            assert!(parse_rule(bad).is_err(), "{bad}");
        }
        assert!(parse_rule("localhost").is_err());
        assert!(parse_rule("два слова.com").is_err());
    }

    #[test]
    fn user_rules_order() {
        let s = Settings {
            direct: vec!["sberbank.com".into(), "# комментарий".into(), "".into(), "95.0.0.0/8".into()],
            proxy: vec!["kinopoisk.ru".into()],
            ..Default::default()
        };
        let c = build_config(&node(), &s);
        let r = user_rules(&c);
        // private, proxy(домен), direct(домен), direct(ip), ru-домены, geoip:ru
        assert_eq!(r.len(), 6);
        assert_eq!(dest(&r[1]), "proxy");
        assert_eq!(r[1]["domain"][0], "domain:kinopoisk.ru");
        assert_eq!(r[2]["domain"][0], "domain:sberbank.com");
        assert_eq!(r[3]["ip"][0], "95.0.0.0/8");
        assert_eq!(c["routing"]["domainStrategy"], "IPIfNonMatch");
    }

    #[test]
    fn old_settings_json_still_loads() {
        // state.json от версии без списков сайтов
        let old = r#"{"socks_port":10900,"http_port":10901,"route":"global","system_proxy":true,"allow_lan":false,"log_level":"warning"}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert_eq!(s.route, RouteMode::Global);
        assert!(s.direct.is_empty() && s.rules.is_empty());
        assert_eq!(s.dns_direct, "77.88.8.8");
    }

    #[test]
    fn global_mode_minimal() {
        let s = Settings { route: RouteMode::Global, ..Default::default() };
        let c = build_config(&node(), &s);
        assert_eq!(user_rules(&c).len(), 1, "только локальная сеть напрямую");
        assert_eq!(c["routing"]["domainStrategy"], "AsIs", "без IP-правил — без лишних DNS-запросов");
        assert_eq!(c["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"], "a.b");
        // DNS: всё через VPN
        assert_eq!(c["dns"]["servers"].as_array().unwrap().last().unwrap(), "1.1.1.1");
    }

    #[test]
    fn blocked_mode() {
        let s = Settings { route: RouteMode::Blocked, ..Default::default() };
        let c = build_config(&node(), &s);
        let r = user_rules(&c);
        assert!(r.iter().any(|x| x["domain"][0] == "ext:geosite-ru.dat:ru-blocked" && dest(x) == "proxy"));
        assert!(r.iter().any(|x| x["ip"][0] == "ext:geoip-ru.dat:ru-blocked" && dest(x) == "proxy"));
        let last = r.last().unwrap();
        assert_eq!((last["network"].as_str(), dest(last).as_str()), (Some("tcp,udp"), "direct"), "остальное напрямую");
        // DNS: заблокированное — через VPN-DNS, остальное — прямым
        let dns = c["dns"]["servers"].as_array().unwrap();
        assert_eq!(dns.last().unwrap(), "77.88.8.8");
        assert!(dns.iter().any(|d| d["address"] == "1.1.1.1" && d["domains"][0] == "ext:geosite-ru.dat:ru-blocked"));
    }

    #[test]
    fn rule_editor() {
        let torrents = Rule { name: "Торренты".into(), protocols: vec!["bittorrent".into()], action: Action::Direct, ..Default::default() };
        let quic = Rule { name: "QUIC".into(), network: "udp".into(), ports: "443".into(), action: Action::Block, ..Default::default() };
        let tg = Rule {
            name: "Telegram".into(),
            sites: vec!["geosite:telegram".into(), "geoip:telegram".into()],
            apps: vec!["telegram.exe".into()],
            ..Default::default()
        };
        let off = Rule { enabled: false, sites: vec!["x.com".into()], action: Action::Block, ..Default::default() };
        let s = Settings { rules: vec![torrents, quic, tg, off], ..Default::default() };
        validate_settings(&s).unwrap();
        let r = user_rules(&build_config(&node(), &s));
        // private, торренты, quic, telegram-домены, telegram-ip, затем .ru и geoip:ru
        assert_eq!(dest(&r[1]), "direct");
        assert_eq!(r[1]["protocol"][0], "bittorrent");
        assert_eq!((r[2]["network"].as_str(), r[2]["port"].as_str(), dest(&r[2]).as_str()), (Some("udp"), Some("443"), "block"));
        assert_eq!(r[3]["domain"][0], "geosite:telegram");
        assert_eq!(r[4]["ip"][0], "geoip:telegram");
        assert!(r[3]["process"].as_array().unwrap().contains(&json!("Telegram")), "имя программы и с большой буквы");
        assert_eq!(r[3]["process"], r[4]["process"], "условие по программе в обоих");
        assert!(!r.iter().any(|x| x["domain"][0] == "domain:x.com"), "выключенное правило не попадает");

        let empty = Rule::default();
        assert!(validate_rule(&empty).unwrap_err().contains("нет ни одного условия"));
        let bad = Rule { ports: "80,99999".into(), ..Default::default() };
        assert!(validate_rule(&bad).is_err());
        assert_eq!(parse_ports(" 80, 443 ;1000-2000").unwrap(), "80,443,1000-2000");
    }

    #[test]
    fn rules_in_auto_go_to_pinned_node() {
        let a = node();
        let b = parse_link("trojan://q@c.d:443#u").unwrap();
        let nodes = vec![a, b];
        let s = Settings {
            route: RouteMode::Global,
            proxy: vec!["x.com".into()],
            rules: vec![Rule { sites: vec!["y.com".into()], ..Default::default() }],
            ..Default::default()
        };
        let c = build_run_config(
            &Upstream::Auto { nodes: &nodes, prefer: 1 },
            &s,
            &RunOpts { probe_port: Some(2), metrics_port: Some(3), ..Default::default() },
        );
        let all = c["routing"]["rules"].as_array().unwrap();
        assert!(all.iter().all(|r| r["outboundTag"] != "proxy"), "в «Авто» нет исходящего proxy");
        assert_eq!(all[0]["inboundTag"][0], "probe");
        assert_eq!(dest(&all[0]), "node-1");
        assert_eq!(dest(all.last().unwrap()), "node-1", "остальное — в выбранный, не в node-0");
        assert!(c["routing"].get("balancers").is_none() && c.get("api").is_none(), "никакого API Xray: его не защитить паролем");
        assert_eq!(c["observatory"]["probeInterval"], "60s");
        assert_eq!(c["observatory"]["subjectSelector"][0], "node-");
        let tags: Vec<&str> = c["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap()).collect();
        assert_eq!(tags, ["node-0", "node-1", "direct", "block"]);
    }

    #[test]
    fn sites_through_own_server() {
        let main = node();
        let us = parse_link("trojan://q@us.example.com:443#us").unwrap();
        let nl = parse_link("trojan://w@nl.example.com:443#nl").unwrap();
        let all = vec![main.clone(), us.clone(), nl.clone()];
        let rule = |name: &str, sites: &[&str], server: &str| SiteServer {
            name: name.into(),
            sites: sites.iter().map(|x| x.to_string()).collect(),
            server: server.into(),
            ..Default::default()
        };
        let s = Settings {
            direct: vec!["chatgpt.com".into()],
            site_servers: vec![
                rule("ChatGPT", &["chatgpt.com", "openai.com"], &us.id),
                rule("YouTube", &["youtube.com"], &nl.id),
                rule("Свой", &["a.ru"], &main.id),
                rule("Ещё US", &["203.0.113.0/24"], &us.id),
                rule("Удалён", &["gone.com"], "deadbeef"),
            ],
            ..Default::default()
        };
        validate_settings(&s).unwrap();
        let routes = site_routes(&s, &all);
        assert_eq!(routes.len(), 5);
        assert!(routes[4].node.is_none());
        let c = build_run_config(&Upstream::Single(&main), &s, &RunOpts { sites: &routes, ..Default::default() });
        let tags: Vec<&str> = c["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap()).collect();
        assert_eq!(tags, ["proxy", "site-0", "site-1", "direct", "block"], "один сервер в двух правилах — одно подключение");
        assert_eq!(c["outbounds"][1]["settings"]["servers"][0]["address"], "us.example.com");
        let r = user_rules(&c);
        let pos = |d: &str, to: &str| r.iter().position(|x| x.to_string().contains(d) && dest(x) == to);
        let chat = pos("domain:chatgpt.com", "site-0").expect("ChatGPT — через US");
        assert!(chat < pos("domain:chatgpt.com", "direct").unwrap(), "выбранный сервер главнее «напрямую»");
        assert!(pos("domain:youtube.com", "site-1").is_some());
        assert!(pos("domain:a.ru", "proxy").unwrap() < pos("domain:ru", "direct").unwrap(), "главнее «Обхода РФ»");
        assert!(pos("203.0.113.0/24", "site-0").is_some());
        assert!(pos("domain:gone.com", "block").is_some(), "сервер удалили — сайты закрыты, а не мимо него");
        let dns = c["dns"].to_string();
        assert!(dns.contains("full:us.example.com") && dns.contains("full:nl.example.com"), "адреса серверов — местным DNS");

        // «Авто»: сервер уже есть среди node-N — отдельное подключение не нужно.
        let a = build_run_config(&Upstream::Auto { nodes: &all, prefer: 0 }, &s, &RunOpts { sites: &routes, ..Default::default() });
        let tags: Vec<&str> = a["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap()).collect();
        assert_eq!(tags, ["node-0", "node-1", "node-2", "direct", "block"]);
        assert!(user_rules(&a).iter().any(|x| x.to_string().contains("domain:openai.com") && dest(x) == "node-1"));

        // Чужая подписка с тем же id — не тот сервер.
        let mut fake = us.clone();
        fake.sub_id = Some("evil".into());
        let r = site_routes(&s, std::slice::from_ref(&fake));
        assert!(r[0].node.is_none());
        let mut bound = s.clone();
        bound.site_servers[0].sub = "evil".into();
        assert!(site_routes(&bound, std::slice::from_ref(&fake))[0].node.is_some());

        // Помощник основного сервера назван «site-0» — переименовывается, теги не совпадают.
        let main_out = json!({"tag": "proxy", "protocol": "vless", "settings": {}, "streamSettings": {"sockopt": {"dialerProxy": "site-0"}}});
        let tags_of = |c: &Value| c["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap().to_string()).collect::<Vec<_>>();
        let helper = json!({"tag": "site-0", "protocol": "freedom"});
        let mut raw = main.clone();
        raw.raw = Some(json!({ "outbounds": [main_out, helper] }));
        let c = build_run_config(&Upstream::Single(&raw), &s, &RunOpts { sites: &routes, ..Default::default() });
        let t = tags_of(&c);
        let mut uniq = t.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), t.len(), "{t:?}");
        assert!(t.contains(&"main-site-0".to_string()) && t.contains(&"site-0".to_string()), "{t:?}");

        // Проверка ввода.
        for bad in [
            rule("x", &[], &us.id),
            rule("x", &["не сайт"], &us.id),
            rule("x", &["a.com"], ""),
            rule("x", &["a.com"], crate::store::AUTO_ID),
            rule("x", &["a.com"], "../x"),
            rule(&"я".repeat(61), &["a.com"], &us.id),
            rule("x\u{202E}y", &["a.com"], &us.id),
            SiteServer { sub: "../x".into(), ..rule("x", &["a.com"], &us.id) },
        ] {
            assert!(validate_site_server(&bad).is_err(), "{bad:?}");
        }
        let many = Settings { site_servers: vec![rule("x", &["a.com"], &us.id); SITE_SERVERS_MAX + 1], ..Default::default() };
        assert!(validate_settings(&many).is_err());
    }

    #[test]
    fn tor_modes() {
        let n = node();
        let opts = RunOpts { probe_port: Some(1), tor: Some((9150, 9151)), direct: Some((2, "pw")), ..Default::default() };
        let all_rules = |c: &Value| c["routing"]["rules"].as_array().unwrap().clone();
        let to = |c: &Value, needle: &str| all_rules(c).iter().find(|r| r.to_string().contains(needle)).map(dest);
        // Выключено — ни Arti, ни правил.
        let off = build_run_config(&Upstream::Single(&n), &Settings::default(), &opts);
        assert!(!off.to_string().contains("\"tor\"") && !off.to_string().contains("tor-up"));
        assert_eq!(to(&off, "direct-probe").as_deref(), Some("direct"));

        let s = Settings { tor_mode: TorMode::Onion, direct: vec!["x.onion".into()], ..Default::default() };
        let c = build_run_config(&Upstream::Single(&n), &s, &opts);
        let outs = c["outbounds"].as_array().unwrap();
        let t = outs.iter().find(|o| o["tag"] == "tor").unwrap();
        assert_eq!(t["settings"]["servers"][0]["port"], 9150);
        assert!(t.pointer("/streamSettings/finalmask").is_none());
        let r = all_rules(&c);
        let pos = |needle: &str| r.iter().position(|x| x.to_string().contains(needle)).unwrap();
        assert_eq!(dest(&r[pos("tor-up")]), "proxy", "Arti ходит в Tor через VPN");
        assert!(pos("tor-up") < pos("regexp"), "и это раньше любых правил Tor (иначе петля)");
        assert!(pos("regexp") < pos("x.onion"), ".onion главнее своих сайтов");
        assert_eq!(dest(&r[pos("regexp")]), "tor");
        assert!(c["inbounds"].as_array().unwrap().iter().any(|i| i["tag"] == "tor-up" && i["listen"] == "127.0.0.1"));

        // Сайт → Tor: TCP через Tor, UDP этих сайтов — в блок.
        let s = Settings { tor_mode: TorMode::Sites, tor_sites: vec!["check.torproject.org".into()], ..Default::default() };
        validate_settings(&s).unwrap();
        let c = build_run_config(&Upstream::Single(&n), &s, &opts);
        let r = all_rules(&c);
        let site: Vec<&Value> = r.iter().filter(|x| x.to_string().contains("domain:check.torproject.org")).collect();
        assert_eq!(site.len(), 2);
        assert_eq!((site[0]["network"].as_str(), dest(site[0]).as_str()), (Some("tcp"), "tor"));
        assert_eq!((site[1]["network"].as_str(), dest(site[1]).as_str()), (Some("udp"), "block"));
        assert!(c["dns"].to_string().contains("check.torproject.org"));
        assert!(validate_settings(&Settings { tor_mode: TorMode::Sites, ..Default::default() }).is_err());

        // Всё через Tor: раньше своих правил; UDP — в блок.
        let s = Settings { tor_mode: TorMode::All, proxy: vec!["a.com".into()], ..Default::default() };
        let c = build_run_config(&Upstream::Single(&n), &s, &opts);
        let r = all_rules(&c);
        let tcp = r.iter().position(|x| x["network"] == "tcp" && dest(x) == "tor").unwrap();
        let udp = r.iter().position(|x| x["network"] == "udp" && dest(x) == "block").unwrap();
        assert!(tcp < udp && udp < r.iter().position(|x| x.to_string().contains("domain:a.com")).unwrap());
        assert!(r.iter().position(|x| x.to_string().contains("tor-up")).unwrap() < tcp);

        // Сайт → Tor главнее программ «мимо VPN» и правил редактора «напрямую».
        let s = Settings {
            tor_mode: TorMode::Sites,
            tor_sites: vec!["t.com".into()],
            apps_direct: vec!["firefox.exe".into()],
            rules: vec![Rule { name: "x".into(), sites: vec!["t.com".into()], action: Action::Direct, ..Default::default() }],
            ..Default::default()
        };
        let c = build_run_config(&Upstream::Single(&n), &s, &opts);
        let r = all_rules(&c);
        let first = r.iter().position(|x| x.to_string().contains("domain:t.com")).unwrap();
        assert_eq!(dest(&r[first]), "tor");
        assert!(first < r.iter().position(|x| x.to_string().contains("firefox")).unwrap());
        // .onion — заглушка в DNS, сама она — в блок раньше «локальные — напрямую».
        assert_eq!(c["dns"]["hosts"]["domain:onion"], ONION_STUB);
        let stub = r.iter().position(|x| x.to_string().contains(ONION_STUB)).unwrap();
        assert_eq!(dest(&r[stub]), "block");
        assert!(stub < r.iter().position(|x| x.to_string().contains("geoip:private")).unwrap());
        // Вход «напрямую» — только с паролем.
        let dp = c["inbounds"].as_array().unwrap().iter().find(|i| i["tag"] == "direct-probe").unwrap().clone();
        assert_eq!(dp["settings"]["auth"], "password");

        // «Всё через Tor»: местному DNS — только адреса серверов, никаких .ru.
        for route in [RouteMode::BypassRu, RouteMode::Blocked] {
            let s = Settings { tor_mode: TorMode::All, route, direct: vec!["bank.ru".into()], ..Default::default() };
            let d = build_run_config(&Upstream::Single(&n), &s, &opts)["dns"].clone();
            let txt = d.to_string();
            assert!(!txt.contains("domain:ru") && !txt.contains("bank.ru"), "{txt}");
            let last = d["servers"].as_array().unwrap().last().unwrap().clone();
            assert_eq!(last, json!(s.dns_remote), "по умолчанию — DNS через VPN");
        }

        // Arti не запустилась — «tor» чёрная дыра, мимо не уходит.
        let s = Settings { tor_mode: TorMode::All, ..Default::default() };
        let c = build_run_config(&Upstream::Single(&n), &s, &RunOpts::default());
        assert_eq!(c["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "tor").unwrap()["protocol"], "blackhole");
    }

    #[test]
    fn site_backup_server() {
        let main = node();
        let us = parse_link("trojan://q@us.example.com:443#us").unwrap();
        let nl = parse_link("trojan://w@nl.example.com:443#nl").unwrap();
        let all = vec![main.clone(), us.clone(), nl.clone()];
        let rule = |sites: &[&str], server: &str, backup: &str| SiteServer {
            name: "ChatGPT".into(),
            sites: sites.iter().map(|x| x.to_string()).collect(),
            server: server.into(),
            backup: backup.into(),
            ..Default::default()
        };
        let s = Settings {
            site_servers: vec![rule(&["chatgpt.com"], &us.id, &nl.id), rule(&["x.com"], &main.id, &us.id), rule(&["y.com"], "gone", &nl.id), rule(&["z.com"], "gone", "gone2")],
            ..Default::default()
        };
        validate_settings(&s).unwrap();
        let routes = site_routes(&s, &all);
        assert_eq!(routes[2].node.map(|n| n.id.as_str()), Some(nl.id.as_str()), "основного нет — через запасной");
        assert!(routes[2].backup.is_none() && routes[3].node.is_none());
        let c = build_run_config(&Upstream::Single(&main), &s, &RunOpts { sites: &routes, ..Default::default() });
        let tags: Vec<&str> = c["outbounds"].as_array().unwrap().iter().map(|o| o["tag"].as_str().unwrap()).collect();
        assert_eq!(tags, ["proxy", "sp-00", "sb-00", "sp-01", "sb-01", "site-0", "direct", "block"]);
        let bal = c["routing"]["balancers"].as_array().unwrap();
        assert_eq!(bal.len(), 2);
        assert_eq!(bal[0], json!({"tag": "bal-00", "selector": ["sp-00"], "fallbackTag": "sb-00", "strategy": {"type": "leastPing"}}));
        assert_eq!(c["observatory"]["subjectSelector"], json!(["sp-"]));
        let r = user_rules(&c);
        let to = |d: &str| r.iter().find(|x| x.to_string().contains(d)).map(dest).unwrap();
        assert_eq!(to("domain:chatgpt.com"), "bal-00");
        assert!(r.iter().find(|x| x.to_string().contains("domain:chatgpt.com")).unwrap().get("outboundTag").is_none());
        assert_eq!(to("domain:x.com"), "bal-01");
        assert_eq!(to("domain:y.com"), "site-0");
        assert_eq!(to("domain:z.com"), "block", "нет ни основного, ни запасного — закрыто");
        // Никакой другой исходящий не начинается с «sp-0…»: селектор — префикс.
        for t in &tags {
            for b in ["sp-00", "sp-01"] {
                assert!(*t == b || !t.starts_with(b), "{t}");
            }
        }
        let tags_stat = site_tags(&Upstream::Single(&main), &routes);
        assert_eq!(tags_stat, ["site-0", "sp-00", "sb-00", "sp-01", "sb-01"]);

        // «Авто»: замеры и node-, и sp-.
        let a = build_run_config(&Upstream::Auto { nodes: &all, prefer: 0 }, &s, &RunOpts { sites: &routes, ..Default::default() });
        assert_eq!(a["observatory"]["subjectSelector"], json!(["node-", "sp-"]));

        // Помощник основного из чужого JSON назван «sp-00» — переименовывается.
        let mut raw = main.clone();
        raw.raw = Some(json!({ "outbounds": [{"tag": "proxy", "protocol": "vless", "settings": {}}, {"tag": "sp-00", "protocol": "freedom"}] }));
        let c = build_run_config(&Upstream::Single(&raw), &s, &RunOpts { sites: &routes, ..Default::default() });
        let n = c["outbounds"].as_array().unwrap().iter().filter(|o| o["tag"] == "sp-00").count();
        assert_eq!(n, 1);
        assert_eq!(c["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "sp-00").unwrap()["protocol"], "trojan");

        // Запасной = основной, «Авто», кривой — нельзя.
        for bad in [rule(&["a.com"], &us.id, &us.id), rule(&["a.com"], &us.id, crate::store::AUTO_ID), rule(&["a.com"], &us.id, "../x")] {
            assert!(validate_site_server(&bad).is_err(), "{bad:?}");
        }
        assert!(validate_site_server(&SiteServer { backup_sub: "x".into(), ..rule(&["a.com"], &us.id, "") }).is_err());
    }

    #[test]
    fn node_tweaks() {
        let a = parse_link("vless://u@a.example:443?type=tcp&security=reality&pbk=PK&sid=ab&sni=x.com&fp=chrome#a").unwrap();
        let b = parse_link("vless://u@b.example:443?type=tcp&security=tls&sni=b.example#b").unwrap();
        let c = parse_link("vless://u@c.example:443?type=tcp&security=tls&sni=c.example#c").unwrap();
        let nodes = vec![a.clone(), b.clone(), c.clone()];
        let mut s = Settings { fragment: true, ..Default::default() };
        s.node_tweaks.insert(a.id.clone(), Tweak { fp: "firefox".into(), fragment: "1-5".into(), delay: "1-3".into(), noise: false });
        s.node_tweaks.insert(b.id.clone(), Tweak::default()); // «без обхода»: общий анти-DPI не нужен
        validate_settings(&s).unwrap();
        let cfg = build_run_config(&Upstream::Auto { nodes: &nodes, prefer: 0 }, &s, &RunOpts::default());
        let out = |tag: &str| cfg["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == tag).unwrap().clone();
        let (oa, ob, oc) = (out("node-0"), out("node-1"), out("node-2"));
        assert_eq!(oa["streamSettings"]["realitySettings"]["fingerprint"], "firefox");
        assert_eq!(oa["streamSettings"]["finalmask"]["tcp"][0]["settings"]["lengths"][0], "1-5");
        assert!(ob["streamSettings"].get("finalmask").is_none(), "подобрано «без обхода»");
        assert_eq!(oc["streamSettings"]["finalmask"]["tcp"][0]["settings"]["lengths"][0], "100-200", "остальным — общий");
        // Варианты: TCP+TLS — нарезки и отпечатки, первым — «без обхода».
        let v = tweak_variants(&a);
        assert_eq!(v[0], Tweak::default());
        assert!(v.iter().any(|t| t.fp == "firefox") && v.iter().any(|t| t.fragment == "1-5"));
        assert!(v.iter().all(|t| validate_tweak(t).is_ok()));
        // Неправильное — отказ.
        for bad in [
            Tweak { fp: "evil".into(), ..Default::default() },
            Tweak { fragment: "100-200".into(), ..Default::default() },
            Tweak { fragment: "0-99999".into(), delay: "1".into(), ..Default::default() },
        ] {
            assert!(validate_tweak(&bad).is_err(), "{bad:?}");
        }
        let mut s2 = Settings::default();
        s2.node_tweaks.insert("../x".into(), Tweak::default());
        assert!(validate_settings(&s2).is_err());
        assert_eq!(tweak_label(&Tweak { fp: "safari".into(), fragment: "10-30".into(), delay: "5-10".into(), noise: false }), "нарезка 10-30 байт + отпечаток safari");
    }

    #[test]
    fn net_profiles() {
        let home = TrustedNet { ssid: "Дом".into(), bssid: "aa:bb:cc:dd:ee:ff".into() };
        let list = vec![home.clone()];
        assert!(net_trusted(&list, Some(&("Дом".into(), "aa:bb:cc:dd:ee:ff".into()))));
        assert!(!net_trusted(&list, Some(&("Дом".into(), "11:22:33:44:55:66".into()))), "поддельная точка с тем же именем");
        assert!(!net_trusted(&list, None));
        let mut s = Settings { trusted_nets: list, net_profiles: true, ..Default::default() };
        validate_settings(&s).unwrap();
        s.trusted_nets.push(TrustedNet { ssid: "x".into(), bssid: "AA:BB:CC:DD:EE:FF".into() });
        assert!(validate_settings(&s).is_err());
        let d = Settings::default();
        assert_eq!((d.away.route, d.away.vpn, d.home.vpn), (Some(RouteMode::Global), NetVpn::On, NetVpn::Keep));
        let back: Settings = serde_json::from_str(&serde_json::to_string(&d).unwrap()).unwrap();
        assert_eq!(back.away, d.away);
    }

    #[test]
    fn apps_modes() {
        let except = Settings { apps_direct: vec!["steam.exe".into(), "D:\\Games\\".into()], ..Default::default() };
        let r = user_rules(&build_config(&node(), &except));
        let p = r.iter().find(|x| x.get("process").is_some()).unwrap();
        assert_eq!(dest(p), "direct");
        let names = p["process"].as_array().unwrap();
        assert!(names.contains(&json!("steam")) && names.contains(&json!("Steam")));
        assert!(names.contains(&json!("D:/Games/")), "папка — как есть, слэши для Xray");

        let only = Settings { apps_mode: AppsMode::Only, apps_proxy: vec!["Telegram.exe".into()], route: RouteMode::Global, ..Default::default() };
        let r = user_rules(&build_config(&node(), &only));
        assert_eq!(dest(r.iter().find(|x| x.get("process").is_some()).unwrap()), "proxy");
        assert_eq!(dest(r.last().unwrap()), "direct", "остальные программы — напрямую");
        // пустой список «только эти» не должен выключать VPN для всех
        let only_empty = Settings { apps_mode: AppsMode::Only, route: RouteMode::Global, ..Default::default() };
        assert_eq!(user_rules(&build_config(&node(), &only_empty)).len(), 1);
    }

    #[test]
    fn ads_after_user_lists() {
        let s = Settings { block_ads: true, direct: vec!["ads.example.com".into()], ..Default::default() };
        let r = user_rules(&build_config(&node(), &s));
        let i_user = r.iter().position(|x| x["domain"][0] == "domain:ads.example.com").unwrap();
        let i_ads = r.iter().position(|x| x["domain"][0] == "geosite:category-ads-all").unwrap();
        assert!(i_user < i_ads, "свои сайты можно «разблокировать»");
        assert_eq!(dest(&r[i_ads]), "block");
    }

    #[test]
    fn dns_settings() {
        let s = Settings {
            dns_remote: "https://1.1.1.1/dns-query".into(),
            dns_direct: "tcp://77.88.8.8:53".into(),
            dns_ipv6: true,
            hosts: vec!["router.lan 192.168.1.1".into(), "10.0.0.5 nas.home".into()],
            ..Default::default()
        };
        validate_settings(&s).unwrap();
        let c = build_config(&node(), &s);
        assert_eq!(c["dns"]["queryStrategy"], "UseIP");
        assert_eq!(c["dns"]["hosts"]["router.lan"], "192.168.1.1");
        assert_eq!(c["dns"]["hosts"]["nas.home"], "10.0.0.5", "порядок как в hosts-файле тоже понимает");
        let rules = c["routing"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["inboundTag"][0] == "dns-internal" && r["ip"][0] == "77.88.8.8" && dest(r) == "direct"));
        assert_eq!(dns_host("https://dns.google/dns-query"), Some(RuleTarget::Domain("full:dns.google".into())));
        assert_eq!(dns_host("[2606:4700::1111]:53"), Some(RuleTarget::Ip("2606:4700::1111".into())));
        assert_eq!(dns_host("localhost"), None);
        assert!(validate_settings(&Settings { hosts: vec!["просто текст".into()], ..Default::default() }).is_err());
        assert!(validate_settings(&Settings { dns_remote: "".into(), ..Default::default() }).is_err());
        // системный DNS напрямую — без правила для него
        let sys = build_config(&node(), &Settings { dns_direct: "localhost".into(), ..Default::default() });
        assert_eq!(sys["routing"]["rules"].as_array().unwrap().iter().filter(|r| r["inboundTag"][0] == "dns-internal").count(), 1);
    }

    #[test]
    fn anti_dpi_finalmask() {
        let masked = |c: &Value| -> Vec<String> {
            c["outbounds"].as_array().unwrap().iter()
                .filter(|o| o.pointer("/streamSettings/finalmask").is_some())
                .map(|o| o["tag"].as_str().unwrap().to_string())
                .collect()
        };
        // выключено — никаких масок
        assert!(masked(&build_config(&node(), &Settings::default())).is_empty());

        let s = Settings { fragment: true, udp_noise: true, ..Default::default() };
        validate_settings(&s).unwrap();
        let c = build_config(&node(), &s);
        assert_eq!(masked(&c), ["proxy"], "только сервер, не direct/block");
        let fm = &c["outbounds"][0]["streamSettings"]["finalmask"];
        assert_eq!(fm["tcp"][0]["type"], "fragment");
        assert_eq!(fm["tcp"][0]["settings"]["packets"], "tlshello");
        assert_eq!(fm["tcp"][0]["settings"]["lengths"][0], "100-200");
        assert_eq!(fm["udp"][0]["type"], "noise");

        // «Авто»: на каждом сервере
        let nodes = vec![node(), node()];
        let a = build_run_config(&Upstream::Auto { nodes: &nodes, prefer: 0 }, &s, &RunOpts::default());
        assert_eq!(masked(&a), ["node-0", "node-1"]);

        // JSON-подписка со своей цепочкой (proxy -> dialerProxy sub-fragment):
        // не лезем — у неё своя фрагментация.
        let (sub, _) = crate::parse_many(crate::jsonsub::tests::REMNA);
        assert!(masked(&build_config(&sub[0], &s)).is_empty());

        // только шумы
        let n = finalmask(&Settings { udp_noise: true, ..Default::default() }).unwrap();
        assert!(n.get("tcp").is_none() && n["udp"].is_array());

        // проверка «от-до»
        let bad = |len: &str, delay: &str| {
            validate_settings(&Settings { fragment: true, fragment_length: len.into(), fragment_delay: delay.into(), ..Default::default() }).is_err()
        };
        assert!(!bad("150", "0"));
        assert!(!bad(" 50-100 ", "5-10"));
        assert!(bad("200-100", "10-20"), "наоборот");
        assert!(bad("0-10", "10-20"), "кусок 0 байт");
        assert!(bad("abc", "10-20"));
        assert!(bad("100-200", "10-5000"), "пауза 5 с — это сломать всё");
    }

    #[test]
    fn link_xhttp_extra_cannot_touch_files() {
        // Обычная ссылка, в extra — downloadSettings с masterKeyLog/certificateFile
        // в разных написаниях (Xray сопоставляет ключи как Go: без регистра).
        let extra = r#"{"xPaddingBytes":"100-1000","downloadSettings":{"address":"d.com","port":443,"network":"xhttp","security":"tls",
            "tlsSettings":{"serverName":"d.com","MasterKeyLog":"C:\\Windows\\x.txt","certificates":[{"certificateFile":"C:\\a.pem"}]},
            "xhttpSettings":{"path":"/d"}}}"#;
        let link = format!(
            "vless://b831381d-6324-4d53-ad4f-8cda48b30811@e.com:443?type=xhttp&security=tls&sni=e.com&path=%2Fx&extra={}#x",
            percent_encoding::utf8_percent_encode(extra, percent_encoding::NON_ALPHANUMERIC)
        );
        let n = crate::parse_link(&link).unwrap();
        // При разборе уже чисто…
        let e = serde_json::to_string(n.transport.extra.as_ref().unwrap()).unwrap().to_lowercase();
        assert!(!e.contains("masterkeylog") && !e.contains("certificatefile"), "{e}");
        assert!(e.contains("xpaddingbytes"), "полезное осталось");
        // …и даже если старый state.json хранит грязный extra — конфиг всё равно чистый.
        let mut dirty = n.clone();
        dirty.transport.extra = Some(serde_json::json!({"downloadSettings":{"tlsSettings":{"maſterKeyLog":"/etc/x"}}}));
        for c in [build_config(&dirty, &Settings::default()), build_test_config(&[(&dirty, 1)])] {
            let t = c.to_string().to_lowercase();
            assert!(!t.contains("keylog"), "{t}");
        }
    }

    #[test]
    fn zapret_settings_checked() {
        assert_eq!(zapret_target("youtube.com").as_deref(), Some("https://youtube.com"));
        assert_eq!(zapret_target("https://www.rutracker.org/forum/").as_deref(), Some("https://rutracker.org"));
        assert_eq!(zapret_target("full:cdn.x.com").as_deref(), Some("https://cdn.x.com"));
        for bad in ["1.2.3.4", "geosite:youtube", "regexp:.*", "domain:a b.com", "domain:x", "keyword:yt"] {
            assert!(zapret_target(bad).is_none(), "{bad}");
        }
        let ok = |dir: &str| {
            let s = Settings { zapret_dir: dir.into(), ..Settings::default() };
            validate_settings(&s).is_ok()
        };
        assert!(ok(""));
        for bad in ["\\\\attacker\\share\\zapret", "//attacker/share", "\\\\?\\UNC\\a\\b", "relative\\dir", "C:\\a\\..\\..\\x"] {
            assert!(!ok(bad), "{bad}");
        }
        if cfg!(windows) {
            assert!(ok("C:\\zapret-discord-youtube-1.9.3") && ok("d:/z"));
        } else {
            assert!(ok("/home/u/zapret") && !ok("C:\\zapret"));
        }
        let mut s = Settings { zapret_targets: vec!["# коммент".into(), "rutracker.org".into()], ..Settings::default() };
        assert!(validate_settings(&s).is_ok());
        s.zapret_targets.push("кривое значение".into());
        assert!(validate_settings(&s).is_err());
        let s = Settings { zapret_strategy: "a\nb".into(), ..Settings::default() };
        assert!(validate_settings(&s).is_err());
    }

    #[test]
    fn hybrid_routes_youtube_direct() {
        let n = parse_link("vless://u@nl1.example.com:443?type=tcp&security=reality&pbk=K&sid=a&sni=x.com#t").unwrap();
        for route in [RouteMode::BypassRu, RouteMode::Global, RouteMode::Blocked] {
            let s = Settings { zapret_hybrid: true, route, ..Default::default() };
            let c = build_run_config(&Upstream::Single(&n), &s, &RunOpts::default());
            let rules = c["routing"]["rules"].as_array().unwrap();
            let hy = rules.iter().position(|r| r["domain"].as_array().is_some_and(|d| d.iter().any(|x| x == "domain:googlevideo.com"))).expect("правило гибрида");
            assert_eq!(rules[hy]["outboundTag"], "direct");
            // Раньше режима: «Всё через VPN»/«Обход РФ» его не перебивают.
            let ru = rules.iter().position(|r| r["domain"].as_array().is_some_and(|d| d.iter().any(|x| x == "domain:ru")));
            assert!(ru.is_none_or(|ru| hy < ru));
            // DNS для них — «напрямую» (местные адреса YouTube, а не у VPN-сервера).
            let dns = c["dns"]["servers"].as_array().unwrap();
            assert!(dns.iter().any(|d| d["domains"].as_array().is_some_and(|x| x.iter().any(|v| v == "domain:youtube.com"))));
        }
        // Свои сайты «через VPN» главнее гибрида.
        let s = Settings { zapret_hybrid: true, proxy: vec!["youtube.com".into()], ..Default::default() };
        let c = build_run_config(&Upstream::Single(&n), &s, &RunOpts::default());
        let rules = c["routing"]["rules"].as_array().unwrap();
        let mine = rules.iter().position(|r| r["domain"].as_array().is_some_and(|d| d.iter().any(|x| x == "domain:youtube.com")) && r["outboundTag"] == "proxy").unwrap();
        let hy = rules.iter().position(|r| r["domain"].as_array().is_some_and(|d| d.iter().any(|x| x == "domain:googlevideo.com"))).unwrap();
        assert!(mine < hy);
        // Twitch и свой сайт — галочкой; YouTube выключен — его нет.
        let s = Settings { zapret_hybrid: true, hybrid_services: Some(vec!["twitch".into(), "discord".into()]), hybrid_sites: vec!["https://Kick.com/x".into(), "# комментарий".into()], ..Default::default() };
        validate_settings(&s).unwrap();
        let c = build_run_config(&Upstream::Single(&n), &s, &RunOpts::default()).to_string();
        assert!(c.contains("domain:ttvnw.net") && c.contains("domain:discord.gg") && c.contains("domain:kick.com") && !c.contains("googlevideo"));
        // Discord в гибриде — и его программа мимо VPN (голос по UDP без имени сайта).
        let cv = build_run_config(&Upstream::Single(&n), &s, &RunOpts::default());
        let pr = cv["routing"]["rules"].as_array().unwrap().iter().find(|r| r["process"].as_array().is_some_and(|p| p.iter().any(|x| x == "Discord"))).expect("правило для Discord.exe");
        assert_eq!(pr["outboundTag"], "direct");
        assert!(pr["process"].as_array().unwrap().iter().any(|x| x == "discord"));
        let yt_only = Settings { zapret_hybrid: true, hybrid_services: Some(vec!["youtube".into()]), ..Default::default() };
        assert!(!build_run_config(&Upstream::Single(&n), &yt_only, &RunOpts::default()).to_string().contains("\"Discord\""));
        assert!(hybrid_hosts(&s).contains(&"twitch.tv".to_string()) && hybrid_hosts(&s).contains(&"kick.com".to_string()));
        let t = hybrid_targets(&s);
        assert!(t.iter().any(|x| x.1 == "https://www.twitch.tv") && t.iter().any(|x| x.1 == "https://kick.com") && !t.iter().any(|x| x.0.starts_with("YouTube")));
        // Старый state.json (поля нет) — YouTube и Discord, как было.
        let old: Settings = serde_json::from_str(r#"{"zapret_hybrid": true}"#).unwrap();
        assert_eq!(hybrid_on(&old).iter().map(|x| x.key).collect::<Vec<_>>(), ["youtube", "discord"]);
        // Ничего не выбрано — правила нет, конфиг рабочий.
        let none = Settings { zapret_hybrid: true, hybrid_services: Some(vec![]), ..Default::default() };
        assert!(!build_run_config(&Upstream::Single(&n), &none, &RunOpts::default()).to_string().contains("\"direct\",\"type\":\"field\",\"domain\""));
        for bad in [vec!["evil".to_string()], vec!["youtube".into(); 9]] {
            assert!(validate_settings(&Settings { hybrid_services: Some(bad), ..Default::default() }).is_err());
        }
        for bad in ["1.2.3.4", "geosite:google", "a b"] {
            assert!(validate_settings(&Settings { hybrid_sites: vec![bad.into()], ..Default::default() }).is_err(), "{bad}");
        }
        // В режиме zapret (без VPN) и без гибрида — правила нет.
        for s in [Settings::default(), Settings { zapret_hybrid: true, zapret: true, ..Default::default() }] {
            let c = build_run_config(&Upstream::Single(&n), &s, &RunOpts::default());
            assert!(!c.to_string().contains("googlevideo.com"));
        }
    }

    #[test]
    fn server_hosts_include_chains() {
        let n = parse_link("vless://u@nl1.example.com:443?type=tcp&security=reality&pbk=K&sid=a&sni=x.com#t").unwrap();
        assert_eq!(server_hosts(&n), vec!["nl1.example.com"]);
        // JSON-подписка: сервер через цепочку (dialerProxy) и xhttp с отдельной загрузкой.
        let mut j = n.clone();
        j.raw = Some(json!({ "outbounds": [
            { "tag": "proxy", "protocol": "vless",
              "settings": { "vnext": [{ "address": "exit.example.com", "port": 443, "users": [{ "id": "u", "encryption": "none" }] }] },
              "streamSettings": { "network": "xhttp", "security": "tls",
                  "xhttpSettings": { "path": "/x", "downloadSettings": { "address": "[2001:db8::5]", "port": 443, "network": "xhttp", "security": "tls" } },
                  "sockopt": { "dialerProxy": "hop" } } },
            { "tag": "hop", "protocol": "trojan",
              "settings": { "servers": [{ "address": "203.0.113.9", "port": 443, "password": "p" }] } }
        ]}));
        let h = server_hosts(&j);
        for want in ["nl1.example.com", "exit.example.com", "2001:db8::5", "203.0.113.9"] {
            assert!(h.iter().any(|x| x == want), "{want} нет в {h:?}");
        }
        // WireGuard-помощник: адрес — в endpoint.
        let mut w = n.clone();
        w.raw = Some(json!({ "outbounds": [
            { "tag": "proxy", "protocol": "wireguard", "settings": { "secretKey": "x",
              "peers": [{ "publicKey": "y", "endpoint": "wg.example.com:51820" }, { "publicKey": "z", "endpoint": "[2001:db8::7]:51820" }] } }
        ]}));
        let h = server_hosts(&w);
        for want in ["wg.example.com", "2001:db8::7"] {
            assert!(h.iter().any(|x| x == want), "{want} нет в {h:?}");
        }
    }
}
