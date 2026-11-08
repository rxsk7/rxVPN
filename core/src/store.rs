//! Хранилище: сервера, подписки, настройки. Один JSON-файл.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::link::parse_many;
use crate::node::{fnv64, Node};
use crate::xray::Settings;

/// Особый «сервер» — режим «Авто»: самый быстрый из рабочих, с переключением.
pub const AUTO_ID: &str = "auto";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    /// unix-время последнего обновления
    #[serde(default)]
    pub updated_at: Option<i64>,
    /// Трафик и срок от панели (если она их отдаёт).
    #[serde(default)]
    pub usage: Option<SubUsage>,
    /// Фильтр (страны, слова). Живёт в подписке — обновление его не трогает.
    #[serde(default, skip_serializing_if = "crate::filter::SubFilter::is_empty")]
    pub filter: crate::filter::SubFilter,
}

/// Остаток подписки из заголовка `subscription-userinfo`. Байты; 0 — без лимита.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubUsage {
    pub upload: u64,
    pub download: u64,
    /// Лимит трафика, 0 — безлимит.
    pub total: u64,
    /// До какого числа оплачено (unix-время), 0 — бессрочно.
    pub expire: i64,
}

impl SubUsage {
    /// `upload=123; download=456; total=789; expire=1700000000` (порядок любой,
    /// лишние поля и пробелы — не страшно). Совсем мусор — None.
    pub fn parse(h: &str) -> Option<Self> {
        if h.len() > 1024 {
            return None;
        }
        let mut u = SubUsage::default();
        let mut any = false;
        for part in h.split(';') {
            let Some((k, v)) = part.split_once('=') else { continue };
            // Бывает «1.5e10» и отрицательное — берём целую часть, отрицательное = 0.
            let num = v.trim().parse::<f64>().ok().filter(|x| x.is_finite()).map(|x| x.clamp(0.0, 9.0e18) as u64);
            let Some(n) = num else { continue };
            match k.trim().to_ascii_lowercase().as_str() {
                "upload" => u.upload = n,
                "download" => u.download = n,
                "total" => u.total = n,
                "expire" => u.expire = n.min(i64::MAX as u64) as i64,
                _ => continue,
            }
            any = true;
        }
        any.then_some(u)
    }

    pub fn used(&self) -> u64 {
        self.upload.saturating_add(self.download)
    }

    /// О чём предупредить: срок кончается через ≤3 дня или трафика осталось ≤10%.
    pub fn warning(&self, now: i64) -> Option<String> {
        if self.expire > 0 {
            let left = self.expire - now;
            if left <= 0 {
                return Some(trs!("подписка закончилась").into());
            }
            if left <= 3 * 86400 {
                let days = (left + 86399) / 86400;
                return Some(tr!("подписка кончается через {days} {}", plural_days(days)));
            }
        }
        if self.total > 0 && self.used() >= self.total / 10 * 9 {
            return Some(if self.used() >= self.total { trs!("трафик подписки закончился").into() } else { trs!("трафика подписки осталось меньше 10%").into() });
        }
        None
    }
}

fn plural_days(n: i64) -> &'static str {
    if crate::i18n::en() {
        return if n == 1 { "day" } else { "days" }; // i18n: en-only
    }
    match (n % 10, n % 100) {
        (1, x) if x != 11 => "день", // i18n-skip
        (2..=4, x) if !(12..=14).contains(&x) => "дня", // i18n-skip
        _ => "дней", // i18n-skip
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub servers: Vec<Node>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default)]
    pub selected: Option<String>,
    /// Свои сервера, поставленные rxvpn по SSH («Свой сервер»).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub vps: Vec<crate::vps::Vps>,
    /// WARP поверх серверов: из них собираются сервера «WARP · …» (`sync_warp`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warp: Vec<crate::warp::Warp>,
    /// «Скрыть мёртвые», «убрать дубли» — для всех серверов.
    #[serde(default)]
    pub list_filter: crate::filter::ListFilter,
}

#[derive(Debug, Default, Serialize)]
pub struct ImportResult {
    pub added: usize,
    pub updated: usize,
    pub errors: Vec<String>,
}

/// Случайная пара соседних портов для SOCKS/HTTP (20000–39998, ниже динамических 49152+
/// и типичных диапазонов, которые резервирует Hyper-V). Обе свободны сейчас — иначе
/// следующая попытка; не нашлось — привычные 10900/10901.
fn random_port_pair() -> (u16, u16) {
    for _ in 0..32 {
        let mut b = [0u8; 2];
        if getrandom::getrandom(&mut b).is_err() {
            break;
        }
        let p = 20000 + (u16::from_le_bytes(b) % 10000) * 2;
        if crate::runner::port_free(p) && crate::runner::port_free(p + 1) {
            return (p, p + 1);
        }
    }
    let d = crate::xray::Settings::default();
    (d.socks_port, d.http_port)
}

impl Store {
    pub fn load(path: &Path) -> Self {
        Self::load_ex(path).0
    }

    /// Первый запуск (state.json ещё нет). Отличия от `default()` — только для новых,
    /// у старых пользователей ничего не меняется:
    /// * порты SOCKS/HTTP — случайная пара 20000–59999, а не известные всем 10900/10901:
    ///   программы (в том числе SDK «определения VPN») перебирают типичные порты
    ///   клиентов на 127.0.0.1, чтобы найти прокси и узнать IP VPN-сервера;
    /// * state.json шифруется (DPAPI) — пароли серверов не лежат открытым текстом.
    ///   Перенос на другой комп — через бэкап (как и раньше при включённой галочке).
    pub fn fresh() -> Self {
        let mut s = Self::default();
        let (socks, http) = random_port_pair();
        s.settings.socks_port = socks;
        s.settings.http_port = http;
        s.settings.encrypt_state = cfg!(windows);
        s
    }

    /// Как `load`, плюс true, если файл зашифрован (DPAPI) и расшифровать его тут
    /// нельзя: другой комп или другая учётка. Такой файл не трогаем и не затираем —
    /// вызывающий не должен сохранять поверх него.
    pub fn load_ex(path: &Path) -> (Self, bool) {
        let Ok(bytes) = std::fs::read(path) else {
            // Нет state.json — первый запуск: настройки «для новых» (fresh).
            return (if path.exists() { Self::default() } else { Self::fresh() }, false);
        };
        let text = match unseal(&bytes) {
            Some(Ok(plain)) => String::from_utf8_lossy(&plain).into_owned(),
            Some(Err(_)) => return (Self::default(), true),
            None => String::from_utf8_lossy(&bytes).into_owned(),
        };
        (Self::parse_or_set_aside(path, &text), false)
    }

    fn parse_or_set_aside(path: &Path, text: &str) -> Self {
        match serde_json::from_str::<Self>(text) {
            Ok(mut s) => {
                s.fix_names();
                s.vps.retain(|v| v.sane());
                s.sync_warp();
                s
            }
            Err(_) => {
                // Битый файл не затираем молча пустым: откладываем в сторону,
                // чтобы сервера можно было достать руками.
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let _ = std::fs::rename(path, path.with_extension(format!("broken-{stamp}.json")));
                Self::default()
            }
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Пишем во временный файл и переименовываем — чтобы не потерять всё,
        // если комп выключится посреди записи.
        let tmp = path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(self).unwrap();
        let data = if self.settings.encrypt_state && cfg!(windows) {
            seal(&json).map_err(std::io::Error::other)?
        } else {
            json
        };
        std::fs::write(&tmp, data)?;
        std::fs::rename(tmp, path)
    }

    /// Запасной вариант того же сервера: та же подписка и тот же адрес, но другой протокол
    /// или порт (у сервисов часто есть и VLESS, и Hysteria2 на одной машине). Сначала —
    /// другой протокол, потом — другой порт. `tried` — уже пробованные в этой сессии.
    pub fn same_server_other_protocol(&self, id: &str, tried: &std::collections::HashSet<String>) -> Option<&Node> {
        let cur = self.servers.iter().find(|n| n.id == id)?;
        let mut cands: Vec<&Node> = self
            .servers
            .iter()
            .filter(|n| n.id != cur.id && !tried.contains(&n.id))
            .filter(|n| n.sub_id == cur.sub_id && n.address.eq_ignore_ascii_case(&cur.address))
            .filter(|n| n.protocol != cur.protocol || n.port != cur.port)
            .collect();
        cands.sort_by_key(|n| (n.protocol == cur.protocol, n.port == cur.port));
        cands.first().copied()
    }

    pub fn is_auto(&self) -> bool {
        self.selected.as_deref() == Some(AUTO_ID)
    }

    /// Привести в порядок после загрузки со стороны (бэкап): выбранный сервер,
    /// папки (кривое имя — сервер просто без папки) и т.п.
    pub fn normalize(&mut self) {
        self.fix_names();
        self.vps.retain(|v| v.sane());
        self.fix_selection();
    }

    /// Имена серверов, папок и подписок — без невидимых символов и не длиннее
    /// положенного. При каждой загрузке state.json (выбор сервера не трогаем).
    pub fn fix_names(&mut self) {
        self.settings.lang = crate::i18n::sanitize(&self.settings.lang);
        for n in &mut self.servers {
            tidy_server(n);
            let g = n.group.as_deref().map(|g| tidy_name(g, MAX_GROUP_NAME)).filter(|g| !g.is_empty() && g.to_lowercase() != LOOSE_GROUP.to_lowercase());
            n.group = if n.sub_id.is_none() { g } else { None };
        }
        for s in &mut self.subscriptions {
            s.filter.sanitize();
            s.name = tidy_name(&s.name, MAX_SUB_NAME);
            if s.name.is_empty() {
                s.name = trs!("Подписка").into();
            }
        }
    }

    /// Сложить сервера в папку (`None` — вынуть из папки). Только добавленные
    /// руками: сервера подписки живут в ней. Возвращает, сколько переложили.
    pub fn set_group(&mut self, ids: &[String], group: Option<&str>) -> Result<usize, String> {
        let group = match group {
            Some(g) => folder_name(g)?,
            None => None,
        };
        let ids: HashSet<&str> = ids.iter().take(self.servers.len()).map(String::as_str).collect();
        let mut n = 0;
        for s in self.servers.iter_mut().filter(|s| s.sub_id.is_none() && ids.contains(s.id.as_str())) {
            s.group = group.clone();
            n += 1;
        }
        Ok(n)
    }

    /// Переименовать папку (пустое имя — разобрать: сервера остаются, без папки).
    /// Есть уже папка с таким именем — сервера сливаются в неё.
    pub fn rename_group(&mut self, old: &str, new: &str) -> Result<usize, String> {
        let new = folder_name(new)?;
        let mut n = 0;
        for s in self.servers.iter_mut().filter(|s| s.sub_id.is_none() && s.group.as_deref() == Some(old)) {
            s.group = new.clone();
            n += 1;
        }
        Ok(n)
    }

    /// Переименовать подписку (имя обязательно).
    pub fn rename_subscription(&mut self, id: &str, name: &str) -> Result<(), String> {
        let name = clean_name(name, MAX_SUB_NAME)?;
        if name.is_empty() {
            return Err(trs!("Название не может быть пустым").into());
        }
        let s = self.subscriptions.iter_mut().find(|s| s.id == id).ok_or(trs!("Подписки уже нет"))?;
        s.name = name;
        Ok(())
    }

    /// Выбран несуществующий сервер (удалили, подписка обновилась) — выбрать первый.
    /// «Авто» не трогаем: он живёт, пока есть хоть один сервер.
    fn fix_selection(&mut self) {
        self.sync_warp();
        if self.is_auto() && !self.servers.is_empty() {
            return;
        }
        if self.selected_node().is_none() {
            self.selected = self.servers.first().map(|n| n.id.clone());
        }
    }

    /// Пересобрать сервера «WARP · …» из `warp`: исходящие «подложки» — свежие,
    /// нет «подложки» — нет и WARP-сервера (правила на него закрыты, а не напрямую).
    /// Любой сервер с id `warp-…`, которого нет в `warp` (чужой бэкап), убирается.
    pub fn sync_warp(&mut self) {
        let mut seen = HashSet::new();
        self.warp.retain(|w| w.sane() && seen.insert(w.node_id()));
        self.warp.truncate(crate::warp::WARP_MAX);
        let built: Vec<Node> = self
            .warp
            .iter()
            .filter_map(|w| {
                let via = self.servers.iter().find(|n| !crate::warp::is_warp(&n.id) && n.id == w.via && n.sub_id.as_deref().unwrap_or("") == w.via_sub);
                crate::warp::node(w, via)
            })
            .collect();
        let mut fresh: HashMap<String, Node> = built.iter().map(|n| (n.id.clone(), n.clone())).collect();
        let mut out = Vec::with_capacity(self.servers.len() + fresh.len());
        for n in std::mem::take(&mut self.servers) {
            if crate::warp::is_warp(&n.id) {
                if let Some(f) = fresh.remove(&n.id) {
                    out.push(f); // на своём месте в списке
                }
            } else {
                out.push(n);
            }
        }
        out.extend(built.into_iter().filter(|n| fresh.contains_key(&n.id)));
        self.servers = out;
    }

    pub fn selected_node(&self) -> Option<&Node> {
        let id = self.selected.as_ref()?;
        self.servers.iter().find(|n| &n.id == id)
    }

    /// Добавить ссылки из текста (вручную). Дубли обновляются, а не плодятся.
    pub fn import_links(&mut self, text: &str) -> ImportResult {
        let (mut nodes, mut errors) = parse_many(text);
        cap(&mut nodes, &mut errors);
        nodes.iter_mut().for_each(tidy_server);
        let mut res = ImportResult { errors, ..Default::default() };
        let mut pos: HashMap<String, usize> = self.servers.iter().enumerate().map(|(i, n)| (n.id.clone(), i)).collect();
        for n in nodes {
            if let Some(&i) = pos.get(&n.id) {
                let sub = self.servers[i].sub_id.clone();
                let group = self.servers[i].group.clone();
                self.servers[i] = n;
                self.servers[i].sub_id = sub;
                self.servers[i].group = group; // обновили ссылку — из папки не выпадает
                res.updated += 1;
            } else {
                pos.insert(n.id.clone(), self.servers.len());
                self.servers.push(n);
                res.added += 1;
            }
        }
        self.fix_selection();
        res
    }

    pub fn add_subscription(&mut self, name: &str, url: &str) -> String {
        let id = fnv64(url);
        if !self.subscriptions.iter().any(|s| s.id == id) {
            let name = if name.trim().is_empty() {
                url::Url::parse(url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_string))
                    .unwrap_or_else(|| trs!("Подписка").into())
            } else {
                name.trim().to_string()
            };
            let name = Some(tidy_name(&name, MAX_SUB_NAME)).filter(|n| !n.is_empty()).unwrap_or_else(|| trs!("Подписка").into());
            self.subscriptions.push(Subscription {
                id: id.clone(),
                name,
                url: url.trim().to_string(),
                updated_at: None,
                usage: None,
                filter: Default::default(),
            });
        }
        id
    }

    /// Заменить сервера подписки свежим содержимым.
    pub fn apply_subscription(&mut self, sub_id: &str, body: &str, now: i64) -> ImportResult {
        let (nodes, errors) = parse_subscription(body);
        self.apply_parsed(sub_id, nodes, errors, now)
    }

    /// То же, но уже разобранное — чтобы разбирать большую подписку
    /// без блокировки хранилища (окно и трей в это время не ждут).
    pub fn apply_parsed(&mut self, sub_id: &str, nodes: Vec<Node>, errors: Vec<String>, now: i64) -> ImportResult {
        let mut res = ImportResult { errors, ..Default::default() };
        if nodes.is_empty() {
            // Пустой ответ — скорее всего ошибка на стороне панели. Старые не трогаем.
            res.errors.push(trs!("в подписке нет ни одного рабочего сервера").into());
            return res;
        }
        self.servers.retain(|n| n.sub_id.as_deref() != Some(sub_id));
        let mut have: HashSet<String> = self.servers.iter().map(|n| n.id.clone()).collect();
        for mut n in nodes {
            tidy_server(&mut n);
            n.sub_id = Some(sub_id.to_string());
            if !have.insert(n.id.clone()) {
                continue; // этот сервер уже добавлен руками (или повтор в подписке)
            }
            self.servers.push(n);
            res.added += 1;
        }
        if let Some(s) = self.subscriptions.iter_mut().find(|s| s.id == sub_id) {
            s.updated_at = Some(now);
        }
        self.fix_selection();
        res
    }

    pub fn remove_subscription(&mut self, sub_id: &str) {
        self.subscriptions.retain(|s| s.id != sub_id);
        self.warp.retain(|w| w.via_sub != sub_id);
        self.servers.retain(|n| n.sub_id.as_deref() != Some(sub_id));
        self.fix_selection();
    }

    pub fn remove_server(&mut self, id: &str) {
        // Убрали WARP-сервер — забываем и учётку; убрали «подложку» — и её WARP.
        self.warp.retain(|w| w.node_id() != id && w.via != id);
        self.servers.retain(|n| n.id != id);
        self.fix_selection();
    }
}

pub const MAX_GROUP_NAME: usize = 40;
pub const MAX_SUB_NAME: usize = 60;

/// Имя папки или подписки, как его ввёл человек: без пробелов по краям, не
/// длиннее `max` символов, без управляющих и «невидимых» символов Юникода
/// (U+202E и компания переворачивают текст и путают имена). Пустое — можно.
/// Управляющие, «невидимые» и меняющие направление текста символы. ZWJ/ZWNJ
/// (U+200C/U+200D), селекторы вариантов и теги U+E0020…E007F можно: на них
/// держатся эмодзи вроде «👨‍💻» и флага Шотландии и письменности вроде персидской.
pub(crate) fn invisible(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200B}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{00AD}'
                | '\u{2028}' | '\u{2029}' | '\u{061C}' | '\u{180E}' | '\u{115F}' | '\u{1160}' | '\u{3164}' | '\u{FFA0}'
                | '\u{2800}' | '\u{E0000}'..='\u{E001F}'
        )
}

/// Видно ли в имени хоть что-то (не одни пробелы и склейки).
fn visible(s: &str) -> bool {
    s.chars().any(|c| !c.is_whitespace() && !matches!(c, '\u{200C}' | '\u{200D}' | '\u{FE00}'..='\u{FE0F}' | '\u{E0020}'..='\u{E007F}'))
}

/// Имя сервера для показа (ссылка остаётся как была): без невидимых символов, до 120 знаков.
pub const MAX_SERVER_NAME: usize = 120;
fn tidy_server(n: &mut Node) {
    n.name = tidy_name(&n.name, MAX_SERVER_NAME);
    if n.name.is_empty() {
        n.name = n.address.clone();
    }
}

/// Так в окне и трее называется группа «без папки» — папку так не назвать.
// Имя-признак «без папки» (в state.json не пишется, окно показывает его переводом).
pub const LOOSE_GROUP: &str = "Добавлены вручную"; // i18n-skip

/// Как `clean_name`, но молча: невидимое выкинуть, длинное обрезать (для того,
/// что уже лежит в state.json или бэкапе — человек не вводил это только что).
pub fn tidy_name(name: &str, max: usize) -> String {
    let s: String = name.chars().filter(|c| !invisible(*c)).collect();
    let s = s.trim().chars().take(max).collect::<String>().trim_end().to_string();
    if visible(&s) { s } else { String::new() }
}

/// Имя папки от человека: пустое — «без папки».
fn folder_name(g: &str) -> Result<Option<String>, String> {
    let g = clean_name(g, MAX_GROUP_NAME)?;
    if g.to_lowercase() == LOOSE_GROUP.to_lowercase() || g.to_lowercase() == trs!("Добавлены вручную").to_lowercase() {
        return Err(tr!("«{}» — это сервера без папки, назови папку по-другому", trs!("Добавлены вручную")));
    }
    Ok(Some(g).filter(|g| !g.is_empty()))
}

pub fn clean_name(name: &str, max: usize) -> Result<String, String> {
    let name = name.trim();
    if name.chars().any(invisible) {
        return Err(trs!("В названии есть невидимые символы").into());
    }
    if name.chars().count() > max {
        return Err(tr!("Название длиннее {max} символов"));
    }
    if !name.is_empty() && !visible(name) {
        return Err(trs!("Название пустое на вид").into());
    }
    Ok(name.to_string())
}

/// Начало зашифрованного файла (state.json, страховочная копия): дальше — base64 от DPAPI.
pub const SEALED: &[u8] = b"RXVPN-DPAPI1\n";
const ENTROPY: &[u8] = b"rxvpn state v1";

/// Зашифровать для этой учётки Windows.
pub fn seal(plain: &[u8]) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let blob = crate::winsys::dpapi(plain, ENTROPY, true)?;
    let mut out = SEALED.to_vec();
    out.extend_from_slice(base64::engine::general_purpose::STANDARD.encode(blob).as_bytes());
    Ok(out)
}

/// Расшифровать. None — файл не зашифрован (обычный JSON).
pub fn unseal(data: &[u8]) -> Option<Result<Vec<u8>, String>> {
    use base64::Engine;
    let rest = data.strip_prefix(SEALED)?;
    let blob = match base64::engine::general_purpose::STANDARD.decode(rest.trim_ascii()) {
        Ok(b) => b,
        Err(_) => return Some(Err(trs!("зашифрованный файл испорчен").into())),
    };
    Some(crate::winsys::dpapi(&blob, ENTROPY, false))
}

/// Больше серверов в одной подписке не берём: такая «подписка» — либо ошибка,
/// либо попытка повесить программу (миллион строк).
pub const MAX_SERVERS_PER_SUB: usize = 3000;

fn cap(nodes: &mut Vec<Node>, errors: &mut Vec<String>) {
    if nodes.len() > MAX_SERVERS_PER_SUB {
        errors.push(tr!("серверов {} — беру первые {MAX_SERVERS_PER_SUB}", nodes.len()));
        nodes.truncate(MAX_SERVERS_PER_SUB);
    }
}

/// Разобрать тело подписки (с потолком на число серверов).
pub fn parse_subscription(body: &str) -> (Vec<Node>, Vec<String>) {
    let (mut nodes, mut errors) = parse_many(body);
    cap(&mut nodes, &mut errors);
    (nodes, errors)
}

#[cfg(test)]
mod tests {
    #[test]
    fn warp_servers_follow_their_base() {
        use crate::warp::{new_keypair, Warp, WarpKey};
        let mut st = Store::default();
        st.import_links("trojan://q@nl.example.com:443#NL\ntrojan://w@us.example.com:443#US");
        let nl = st.servers[0].clone();
        let (secret, peer) = new_keypair();
        let key = WarpKey { secret, peer, v4: "172.16.0.2".into(), v6: String::new(), reserved: [1, 2, 3], endpoint: "162.159.192.1:2408".into() };
        let w = Warp { via: nl.id.clone(), via_sub: String::new(), key: key.clone() };
        let wid = w.node_id();
        st.warp.push(w.clone());
        // Чужой «warp-…» из бэкапа без учётки — убирается; кривая учётка — тоже.
        let mut fake = nl.clone();
        fake.id = "warp-0123456789ab".into();
        st.servers.push(fake);
        st.warp.push(Warp { key: WarpKey { endpoint: "127.0.0.1:1".into(), ..key.clone() }, via: st.servers[1].id.clone(), ..Default::default() });
        st.sync_warp();
        let ids: Vec<&str> = st.servers.iter().map(|n| n.id.as_str()).collect();
        assert_eq!(ids, [nl.id.as_str(), st.servers[1].id.as_str(), wid.as_str()]);
        assert_eq!(st.warp.len(), 1);
        assert_eq!(st.servers[2].name, "WARP · NL");
        // Подложку переименовали — WARP следом; повторный sync ничего не плодит.
        st.servers[0].name = "Нидерланды".into();
        st.sync_warp();
        st.sync_warp();
        assert_eq!(st.servers.len(), 3);
        assert_eq!(st.servers[2].name, "WARP · Нидерланды");
        // Удалили подложку — WARP и его учётка уходят.
        st.selected = Some(wid.clone());
        st.remove_server(&nl.id);
        assert!(st.warp.is_empty() && !st.servers.iter().any(|n| n.id == wid));
        assert_ne!(st.selected.as_deref(), Some(wid.as_str()));
        // Учётка есть, подложка пропала из подписки — WARP-сервера нет, учётка ждёт.
        st.warp.push(Warp { via: "aaaa".into(), via_sub: "sub1".into(), key });
        st.sync_warp();
        assert_eq!(st.warp.len(), 1);
        assert!(!st.servers.iter().any(|n| crate::warp::is_warp(&n.id)));
        st.remove_subscription("sub1");
        assert!(st.warp.is_empty());
    }

    use super::*;

    #[test]
    fn fallback_prefers_other_protocol_then_other_port() {
        let mut st = Store::default();
        st.import_links(
            "vless://u@nl.example.com:443?type=tcp&security=reality&pbk=K&sid=a&sni=x.com#VLESS\n\
             vless://u@nl.example.com:2083?type=tcp&security=reality&pbk=K&sid=a&sni=x.com#VLESS-2083\n\
             trojan://p@NL.example.com:8443#Trojan\n\
             trojan://p@de.example.com:443#DE",
        );
        let id = |name: &str| st.servers.iter().find(|n| n.name == name).unwrap().id.clone();
        let mut tried = std::collections::HashSet::new();
        let first = st.same_server_other_protocol(&id("VLESS"), &tried).unwrap();
        assert_eq!(first.name, "Trojan", "сначала другой протокол того же адреса (регистр не важен)");
        tried.insert(first.id.clone());
        let second = st.same_server_other_protocol(&id("VLESS"), &tried).unwrap();
        assert_eq!(second.name, "VLESS-2083", "потом тот же протокол на другом порту");
        tried.insert(second.id.clone());
        assert!(st.same_server_other_protocol(&id("VLESS"), &tried).is_none(), "другой сервер (DE) — не запасной");
        assert!(st.same_server_other_protocol(&id("DE"), &Default::default()).is_none());
    }

    #[test]
    fn first_run_gets_random_ports_and_encryption() {
        let d = std::env::temp_dir().join(format!("rxvpn-fresh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let (s, locked) = Store::load_ex(&d.join("state.json"));
        assert!(!locked);
        assert_eq!(s.settings.http_port, s.settings.socks_port + 1);
        assert!(s.settings.socks_port >= 20000 && s.settings.http_port < 40000 || s.settings.socks_port == 10900);
        assert_eq!(s.settings.encrypt_state, cfg!(windows));
        assert!(crate::xray::validate_settings(&s.settings).is_ok());
        // У старых пользователей (state.json есть) — без изменений.
        let d0 = Settings::default();
        assert_eq!((d0.socks_port, d0.encrypt_state), (10900, false));
    }

    #[test]
    fn folders() {
        let mut st = Store::default();
        st.import_links("trojan://a@a.example:443#A\ntrojan://b@b.example:443#B\ntrojan://c@c.example:443#C");
        let id = st.add_subscription("", "https://x.example/s");
        st.apply_subscription(&id, "trojan://s@s.example:443#S", 0);
        let ids: Vec<String> = st.servers.iter().map(|n| n.id.clone()).collect();
        // В папку — только свои; сервер подписки не трогаем.
        assert_eq!(st.set_group(&ids, Some("  Мой VPS  ")).unwrap(), 3);
        assert!(st.servers.iter().filter(|n| n.sub_id.is_none()).all(|n| n.group.as_deref() == Some("Мой VPS")));
        assert!(st.servers.iter().find(|n| n.sub_id.is_some()).unwrap().group.is_none());
        // Обновил ссылку — остался в папке.
        st.import_links("trojan://a@a.example:443#A-new");
        assert_eq!(st.servers[0].name, "A-new");
        assert_eq!(st.servers[0].group.as_deref(), Some("Мой VPS"));
        // Переименование, слияние, «разобрать».
        st.set_group(&ids[..1], Some("Друг")).unwrap();
        assert_eq!(st.rename_group("Друг", "Мой VPS").unwrap(), 1);
        assert_eq!(st.servers.iter().filter(|n| n.group.as_deref() == Some("Мой VPS")).count(), 3);
        assert_eq!(st.rename_group("Мой VPS", " ").unwrap(), 3);
        assert!(st.servers.iter().all(|n| n.group.is_none()));
        // Кривые имена — нет.
        for bad in ["a\u{202E}b", "x\ny", &"я".repeat(41)] {
            assert!(st.set_group(&ids, Some(bad)).is_err(), "{bad:?}");
        }
        for bad in ["a\u{202E}b", "x\ny", &"я".repeat(61)] {
            assert!(st.rename_subscription(&id, bad).is_err(), "{bad:?}");
        }
        assert!(st.rename_subscription(&id, "  ").is_err());
        // Эмодзи со склейкой (ZWJ) — можно; «пустое на вид» и имя группы «без папки» — нет.
        assert_eq!(st.set_group(&ids[..1], Some("👨\u{200D}💻 Работа")).unwrap(), 1);
        // Флаг Шотландии — с тегами U+E0067…: тоже можно.
        assert!(st.set_group(&ids[..1], Some("\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F} Scot")).is_ok());
        for bad in ["\u{3164}", "\u{200D}", "\u{E0067}\u{E0062}", "Добавлены вручную", "добавлены ВРУЧНУЮ"] {
            assert!(st.set_group(&ids, Some(bad)).is_err(), "{bad:?}");
        }
        st.set_group(&ids[..1], None).unwrap();
        // Имя сервера с переворотом текста — чистится при добавлении.
        st.import_links("trojan://z@z.example:443#ab%E2%80%AEcd");
        assert_eq!(st.servers.last().unwrap().name, "abcd");
        let z = st.servers.pop().unwrap();
        assert_eq!(z.address, "z.example");
        st.rename_subscription(&id, " Провайдер ").unwrap();
        assert_eq!(st.subscriptions[0].name, "Провайдер");
        // Бэкап с кривым: папка у сервера подписки — убираем; невидимые символы
        // выкидываем, длинное обрезаем (а не теряем имя целиком).
        st.servers[3].group = Some("x".into());
        st.servers[0].group = Some("ba\u{200B}d".into());
        st.servers[1].group = Some("\u{202E}".into());
        st.servers[2].group = Some("я".repeat(50));
        st.subscriptions[0].name = "\u{202E}".into();
        st.normalize();
        assert_eq!((st.servers[3].group.as_deref(), st.servers[0].group.as_deref(), st.servers[1].group.as_deref()), (None, Some("bad"), None));
        assert_eq!(st.servers[2].group.as_ref().unwrap().chars().count(), MAX_GROUP_NAME);
        assert_eq!(st.subscriptions[0].name, "Подписка");
        let long = format!("https://{}.example.com/s", "a".repeat(70));
        let id2 = st.add_subscription("", &long);
        assert_eq!(st.subscriptions.iter().find(|s| s.id == id2).unwrap().name.chars().count(), MAX_SUB_NAME);
        st.servers[2].group = None;
        // В state.json пустая папка не пишется (старые версии читают как раньше).
        let j = serde_json::to_value(&st.servers[2]).unwrap();
        assert!(j.get("group").is_none());
    }

    #[test]
    fn huge_subscription_is_fast_and_capped() {
        let body: String = (0..100_000).map(|i| format!("trojan://p{i}@a.b:443#x\n")).collect();
        let mut st = Store::default();
        let id = st.add_subscription("", "https://x.example/s");
        let t = std::time::Instant::now();
        let r = st.apply_subscription(&id, &body, 0);
        assert_eq!(r.added, MAX_SERVERS_PER_SUB);
        assert!(r.errors.iter().any(|e| e.contains("беру первые")));
        let r2 = st.import_links(&body);
        assert_eq!(r2.added + r2.updated, MAX_SERVERS_PER_SUB);
        assert!(t.elapsed() < std::time::Duration::from_secs(20), "{:?}", t.elapsed());
    }

    #[test]
    fn broken_state_is_kept_aside() {
        let dir = std::env::temp_dir().join(format!("rxvpn-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("state.json");
        std::fs::write(&p, "{ битый json").unwrap();
        let s = Store::load(&p);
        assert!(s.servers.is_empty());
        assert!(!p.exists(), "битый файл убран с дороги");
        let kept: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert!(kept.iter().any(|n| n.starts_with("state.broken-")), "{kept:?}");
        assert_eq!(std::fs::read_to_string(dir.join(&kept[0])).unwrap(), "{ битый json", "содержимое на месте");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn subscription_refresh_replaces_old() {
        let mut s = Store::default();
        let id = s.add_subscription("", "https://panel.example.com/sub/abc");
        assert_eq!(s.subscriptions[0].name, "panel.example.com");
        let r = s.apply_subscription(&id, "trojan://a@x.y:443#1\ntrojan://b@x.y:443#2", 1);
        assert_eq!(r.added, 2);
        let r = s.apply_subscription(&id, "trojan://c@x.y:443#3", 2);
        assert_eq!(r.added, 1);
        assert_eq!(s.servers.len(), 1);
        // пустая подписка не стирает сервера
        let r = s.apply_subscription(&id, "", 3);
        assert_eq!(r.added, 0);
        assert_eq!(s.servers.len(), 1);
    }

    #[test]
    fn auto_selection_survives_updates() {
        let mut s = Store::default();
        let id = s.add_subscription("", "https://p.example/sub");
        s.apply_subscription(&id, "trojan://a@x.y:443#1\ntrojan://b@x.y:443#2", 1);
        s.selected = Some(AUTO_ID.into());
        s.apply_subscription(&id, "trojan://c@x.y:443#3", 2);
        assert!(s.is_auto(), "обновление подписки не сбрасывает «Авто»");
        s.remove_subscription(&id);
        assert!(!s.is_auto() && s.selected.is_none(), "серверов не осталось — «Авто» снят");
    }

    #[test]
    fn manual_import_dedup() {
        let mut s = Store::default();
        s.import_links("trojan://a@x.y:443#1");
        let r = s.import_links("trojan://a@x.y:443#renamed");
        assert_eq!(r.updated, 1);
        assert_eq!(s.servers.len(), 1);
        assert_eq!(s.servers[0].name, "renamed");
    }

    #[test]
    fn subscription_userinfo() {
        let u = SubUsage::parse("upload=1073741824; download=40802189312; total=107374182400; expire=1767225600").unwrap();
        assert_eq!((u.used(), u.total, u.expire), (41875931136, 107374182400, 1767225600));
        assert!(u.warning(1767225600 - 10 * 86400).is_none());
        assert_eq!(u.warning(1767225600 - 2 * 86400 - 5).as_deref(), Some("подписка кончается через 3 дня"));
        assert_eq!(u.warning(1767225600 - 86000).as_deref(), Some("подписка кончается через 1 день"));
        assert_eq!(u.warning(1767225601).as_deref(), Some("подписка закончилась"));
        let t = SubUsage { upload: 0, download: 95, total: 100, expire: 0 };
        assert_eq!(t.warning(0).as_deref(), Some("трафика подписки осталось меньше 10%"));
        assert!(SubUsage { download: 50, total: 100, ..Default::default() }.warning(0).is_none());
        assert!(SubUsage { download: 50, total: 0, expire: 0, upload: 0 }.warning(0).is_none(), "безлимит");
        // Кривое — не падаем.
        assert_eq!(SubUsage::parse(" Upload = 5 ;garbage; total=1e3; expire=-4").unwrap(), SubUsage { upload: 5, download: 0, total: 1000, expire: 0 });
        for bad in ["", "nothing", "upload=abc", &"x".repeat(2000)] {
            assert!(SubUsage::parse(bad).is_none(), "{bad:.20}");
        }
    }
}
