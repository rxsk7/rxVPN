//! Фильтры серверов: у подписки — страны и слова («только NL, DE»), для всех —
//! «скрыть мёртвые» (последняя проверка не прошла) и «убрать дубли» (тот же
//! сервер пришёл из двух подписок). Сервера не удаляются: фильтр только решает,
//! что видно в окне и трее и из чего выбирают «Авто» и «Скорость всех». Фильтр
//! подписки лежит в самой подписке — обновление его не трогает.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::node::Node;
use crate::store::{clean_name, Store};

/// Фильтр подписки. Пустой — показывать всё.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubFilter {
    /// Коды стран (NL, DE…): сервер — хоть одной из них. Пусто — любые.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub countries: Vec<String>,
    /// Слова: без минуса — в имени хоть одно из них, с минусом («-test») — ни одного.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub words: Vec<String>,
}

impl SubFilter {
    pub fn is_empty(&self) -> bool {
        self.countries.is_empty() && self.words.is_empty()
    }

    /// Привести в порядок то, что пришло из state.json или бэкапа (не из окна):
    /// коды — две латинские заглавные, слова — без невидимых и не длиннее
    /// положенного, всего — не больше лимитов, без повторов.
    pub fn sanitize(&mut self) {
        let mut cc: Vec<String> = Vec::new();
        for c in self.countries.iter().take(MAX_COUNTRIES * 4) {
            let c = c.trim().to_ascii_uppercase();
            if c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()) && !cc.contains(&c) {
                cc.push(c);
            }
        }
        cc.truncate(MAX_COUNTRIES);
        let mut ws: Vec<String> = Vec::new();
        for w in self.words.iter().take(MAX_WORDS * 4) {
            let w = crate::store::tidy_name(w, MAX_WORD).to_lowercase();
            if !w.is_empty() && w != "-" && !w.contains(char::is_whitespace) && !ws.contains(&w) {
                ws.push(w);
            }
        }
        ws.truncate(MAX_WORDS);
        (self.countries, self.words) = (cc, ws);
    }

    /// Проходит ли сервер с таким именем.
    pub fn matches(&self, name: &str) -> bool {
        if !self.countries.is_empty() {
            let cc = countries_of(name);
            if !self.countries.iter().any(|c| cc.contains(c.as_str())) {
                return false;
            }
        }
        let low = name.to_lowercase();
        let (minus, plus): (Vec<&String>, Vec<&String>) = self.words.iter().partition(|w| w.starts_with('-'));
        if minus.iter().any(|w| low.contains(&w[1..])) {
            return false;
        }
        plus.is_empty() || plus.iter().any(|w| low.contains(w.as_str()))
    }
}

/// Общие фильтры (для всех серверов).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListFilter {
    #[serde(default)]
    pub hide_dead: bool,
    #[serde(default)]
    pub dedup: bool,
}

/// Почему сервер не видно.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Hide {
    /// Не прошёл фильтр подписки (страны, слова).
    Filter,
    /// Такой же сервер уже есть выше (своё или другая подписка).
    Dup,
    /// Последняя проверка не прошла.
    Dead,
    /// Без шифрования (`Node::plain`): в «Авто» не идёт, пока человек не выберет его сам.
    Plain,
}

pub const MAX_COUNTRIES: usize = 40;
pub const MAX_WORDS: usize = 30;
pub const MAX_WORD: usize = 40;

/// Разобрать то, что ввёл человек: страны («NL, DE», «Нидерланды», «🇳🇱») и слова
/// через пробел или запятую («premium -test»). Ошибка — понятным текстом (какую страну не узнали).
pub fn parse(countries: &str, words: &str) -> Result<SubFilter, String> {
    let mut f = SubFilter::default();
    for item in split(countries) {
        let found = country_of_input(&item).ok_or_else(|| {
            tr!("Не знаю страну «{item}». Напиши код из двух букв (NL, DE) или название (Германия)")
        })?;
        for c in found {
            if !f.countries.contains(&c) {
                f.countries.push(c);
            }
        }
    }
    for item in words.chars().take(4000).collect::<String>().split(|c: char| c == ',' || c == ';' || c.is_whitespace()).filter(|x| !x.is_empty()) {
        let w = clean_name(item, MAX_WORD).map_err(|e| tr!("Слово «{}»: {e}", item.chars().take(MAX_WORD).collect::<String>()))?;
        let w = w.to_lowercase();
        if w.is_empty() || w == "-" {
            continue;
        }
        if !f.words.contains(&w) {
            f.words.push(w);
        }
    }
    if f.countries.len() > MAX_COUNTRIES {
        return Err(tr!("Стран больше {MAX_COUNTRIES}"));
    }
    if f.words.len() > MAX_WORDS {
        return Err(tr!("Слов больше {MAX_WORDS}"));
    }
    Ok(f)
}

/// Страны: через запятую, точку с запятой или с новой строки; пробелы — тоже, если
/// запятых нет (так «NL DE» и «Южная Корея, Германия» оба работают).
fn split(s: &str) -> Vec<String> {
    let s: String = s.chars().take(4000).collect();
    let by_comma = s.contains([',', ';', '\n']);
    s.split(|c: char| if by_comma { matches!(c, ',' | ';' | '\n') } else { c.is_whitespace() })
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

/// Ввод человека → коды стран. Флаги (можно несколько), код (любые две
/// латинские буквы: страны нет в нашей таблице — флаг в имени всё равно найдётся),
/// UK → GB, или название из таблицы.
fn country_of_input(item: &str) -> Option<Vec<String>> {
    let flags = flags_of(item);
    if !flags.is_empty() {
        return Some(flags);
    }
    let t = item.trim();
    if t.len() == 2 && t.chars().all(|c| c.is_ascii_alphabetic()) {
        let up = t.to_ascii_uppercase();
        return Some(vec![if up == "UK" { "GB".into() } else { up }]);
    }
    let words = words_of(t);
    if words.is_empty() {
        return None;
    }
    // Всё введённое — про одну страну («Южная Корея», «Нидерланды»).
    COUNTRIES
        .iter()
        .find(|(_, stems)| stems.iter().any(|st| stem_match(&words, st)))
        .map(|(cc, _)| vec![cc.to_string()])
}

/// Страны в имени сервера. Есть флаги — только они (самое надёжное); иначе
/// названия (по началу слова: «Германия-2», «Germany #3») и коды заглавными
/// буквами отдельным словом («NL-1», «[DE]»).
pub fn countries_of(name: &str) -> HashSet<String> {
    let flags = flags_of(name);
    if !flags.is_empty() {
        return flags.into_iter().collect();
    }
    let mut out = HashSet::new();
    let words = words_of(name);
    for (cc, stems) in COUNTRIES {
        if stems.iter().any(|st| stem_match(&words, st)) {
            out.insert(cc.to_string());
        }
    }
    for tok in name.split(|c: char| !c.is_ascii_alphanumeric()) {
        if tok.len() == 2 && tok.chars().all(|c| c.is_ascii_uppercase()) {
            let t = if tok == "UK" { "GB" } else { tok };
            if COUNTRIES.iter().any(|(cc, _)| *cc == t) {
                out.insert(t.to_string());
            }
        }
    }
    out
}

/// Флаги-эмодзи: пара «региональных букв» U+1F1E6…1F1FF.
fn flags_of(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut prev: Option<char> = None;
    for c in s.chars() {
        let ri = ('\u{1F1E6}'..='\u{1F1FF}').contains(&c).then(|| (b'A' + (c as u32 - 0x1F1E6) as u8) as char);
        match (prev, ri) {
            (Some(a), Some(b)) => {
                let cc = format!("{a}{b}");
                if !out.contains(&cc) {
                    out.push(cc);
                }
                prev = None;
            }
            (None, Some(b)) => prev = Some(b),
            (_, None) => prev = None,
        }
    }
    out
}

fn words_of(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(|w| w.to_lowercase()).collect()
}

/// Основа «=слово» — только целое слово (для коротких: «оаэ», «usa»), иначе — начало слова.
/// Основа из двух слов («hong kong») — два слова подряд.
fn stem_match(words: &[String], stem: &str) -> bool {
    let parts: Vec<&str> = stem.split(' ').collect();
    if parts.len() > 1 {
        return words.windows(parts.len()).any(|w| w.iter().zip(&parts).all(|(a, b)| one(a, b)));
    }
    words.iter().any(|w| one(w, stem))
}

fn one(word: &str, stem: &str) -> bool {
    match stem.strip_prefix('=') {
        Some(exact) => word == exact,
        None => word.starts_with(stem),
    }
}

/// Страны, которые встречаются у VPN-сервисов: код и основы названий (ru, en, столицы и
/// частые города). Короткие и двусмысленные — целым словом («=вена», «=usa»).
// i18n-skip-begin: основы названий стран для поиска в именах серверов — данные, не текст окна.
pub const COUNTRIES: &[(&str, &[&str])] = &[
    ("NL", &["netherland", "holland", "amsterdam", "нидерланд", "голланд", "амстердам"]),
    ("DE", &["german", "deutschland", "frankfurt", "berlin", "falkenstein", "nuremberg", "герман", "франкфурт", "берлин", "фалькенштейн", "нюрнберг"]),
    ("FI", &["finland", "helsinki", "финлянд", "хельсинк"]),
    ("FR", &["france", "paris", "франци", "франция", "париж"]),
    ("GB", &["united kingdom", "britain", "england", "london", "британ", "великобритан", "англи", "лондон"]),
    ("US", &["=usa", "america", "united states", "new york", "los angeles", "сша", "америк", "нью йорк"]),
    ("RU", &["russia", "moscow", "росси", "москв", "петербург", "питер"]),
    ("PL", &["poland", "warsaw", "польш", "варшав"]),
    ("SE", &["sweden", "stockholm", "швеци", "стокгольм"]),
    ("NO", &["norway", "oslo", "норвеги", "осло"]),
    ("DK", &["denmark", "copenhagen", "=дания", "=дании", "копенгаген"]),
    ("EE", &["estonia", "tallinn", "эстони", "таллин"]),
    ("LV", &["latvia", "riga", "латви", "=рига"]),
    ("LT", &["lithuania", "vilnius", "литв", "вильнюс"]),
    ("CH", &["switzerland", "swiss", "zurich", "швейцари", "цюрих"]),
    ("AT", &["austria", "vienna", "австри", "=вена"]),
    ("CZ", &["czech", "prague", "чехи", "чешск", "праг"]),
    ("SK", &["slovakia", "bratislava", "словаки", "братислав"]),
    ("TR", &["turkey", "turkiye", "türkiye", "istanbul", "турци", "стамбул"]),
    ("KZ", &["kazakhstan", "almaty", "astana", "казахстан", "алмат", "астан"]),
    ("UA", &["ukrain", "kyiv", "kiev", "украин", "киев"]),
    ("BY", &["belarus", "minsk", "беларус", "белорус", "минск"]),
    ("AM", &["armenia", "yerevan", "армени", "ереван"]),
    ("GE", &["georgia", "tbilisi", "грузи", "тбилиси"]),
    ("AZ", &["azerbaijan", "baku", "азербайджан", "=баку"]),
    ("UZ", &["uzbekistan", "tashkent", "узбекистан", "ташкент"]),
    ("KG", &["kyrgyzstan", "bishkek", "киргиз", "кыргыз", "бишкек"]),
    ("JP", &["japan", "tokyo", "япони", "токио"]),
    ("SG", &["singapore", "сингапур"]),
    ("HK", &["hong kong", "hongkong", "гонконг"]),
    ("KR", &["korea", "seoul", "корея", "кореи", "сеул"]),
    ("IN", &["india", "mumbai", "индия", "индии", "мумбаи"]),
    ("CA", &["canada", "toronto", "канад", "торонто"]),
    ("AE", &["emirates", "dubai", "=uae", "эмират", "=оаэ", "дубай", "дубаи"]),
    ("IL", &["israel", "израил"]),
    ("IT", &["italy", "milan", "итали", "милан"]),
    ("ES", &["spain", "madrid", "испани", "мадрид"]),
    ("PT", &["portugal", "lisbon", "португали", "лиссабон"]),
    ("BG", &["bulgaria", "sofia", "болгари", "=софия"]),
    ("RO", &["romania", "bucharest", "румыни", "бухарест"]),
    ("HU", &["hungary", "budapest", "венгри", "будапешт"]),
    ("RS", &["serbia", "belgrade", "серби", "белград"]),
    ("MD", &["moldova", "chisinau", "молдав", "молдов", "кишин"]),
    ("IE", &["ireland", "dublin", "ирланди", "дублин"]),
    ("BE", &["belgium", "brussels", "бельги", "брюссел"]),
    ("LU", &["luxembourg", "люксембург"]),
    ("GR", &["greece", "athens", "греци", "афин"]),
    ("CY", &["cyprus", "кипр"]),
    ("IS", &["iceland", "исланди"]),
    ("AU", &["australia", "sydney", "австрали", "сидней"]),
    ("BR", &["brazil", "бразили"]),
    ("AR", &["argentina", "аргентин"]),
    ("MX", &["mexico", "мексик"]),
    ("CN", &["china", "китай", "китая"]),
    ("TW", &["taiwan", "тайван"]),
    ("VN", &["vietnam", "вьетнам"]),
    ("TH", &["thailand", "таиланд", "тайланд"]),
    ("MY", &["malaysia", "малайзи"]),
    ("ID", &["indonesia", "индонези"]),
];
// i18n-skip-end

/// Всё, что фильтры скрывают: id → почему. `dead` — последняя проверка не прошла.
/// Выбранный руками сервер не скрывается никогда. Если «мёртвыми» оказались все
/// оставшиеся (скорее всего, лёг интернет во время проверки) — мёртвых не скрываем.
pub fn hidden(store: &Store, dead: impl Fn(&str) -> bool) -> HashMap<String, Hide> {
    let mut out = HashMap::new();
    let selected = store.selected.as_deref();
    let filters: HashMap<&str, &SubFilter> =
        store.subscriptions.iter().filter(|s| !s.filter.is_empty()).map(|s| (s.id.as_str(), &s.filter)).collect();
    for n in &store.servers {
        if Some(n.id.as_str()) == selected {
            continue;
        }
        let f = n.sub_id.as_deref().and_then(|s| filters.get(s));
        if f.is_some_and(|f| !f.matches(&n.name)) {
            out.insert(n.id.clone(), Hide::Filter);
        } else if n.plain() {
            out.insert(n.id.clone(), Hide::Plain);
        }
    }
    if store.list_filter.dedup {
        // Победитель в каждой группе одинаковых: выбранный, потом свой (не из
        // подписки), потом кто выше в списке.
        let mut win: BTreeMap<String, (u8, usize, &str)> = BTreeMap::new();
        for (i, n) in store.servers.iter().enumerate().filter(|(_, n)| !out.contains_key(&n.id)) {
            let rank = if Some(n.id.as_str()) == selected { 0 } else if n.sub_id.is_none() { 1 } else { 2 };
            let e = win.entry(same_key(n)).or_insert((rank, i, n.id.as_str()));
            if (rank, i) < (e.0, e.1) {
                *e = (rank, i, n.id.as_str());
            }
        }
        let keep: HashSet<&str> = win.values().map(|x| x.2).collect();
        let dups: Vec<String> = store
            .servers
            .iter()
            .filter(|n| !out.contains_key(&n.id) && !keep.contains(n.id.as_str()))
            .map(|n| n.id.clone())
            .collect();
        for id in dups {
            out.insert(id, Hide::Dup);
        }
    }
    if store.list_filter.hide_dead {
        let rest: Vec<&Node> = store.servers.iter().filter(|n| !out.contains_key(&n.id) && Some(n.id.as_str()) != selected).collect();
        let dead_ids: Vec<&str> = rest.iter().filter(|n| dead(&n.id)).map(|n| n.id.as_str()).collect();
        let alive_left = store.servers.iter().any(|n| !out.contains_key(&n.id) && !dead(&n.id));
        if alive_left {
            for id in dead_ids {
                out.insert(id.to_string(), Hide::Dead);
            }
        }
    }
    out
}

/// Видимые сервера (для «Авто», «Скорость всех», трея), в порядке списка.
pub fn visible(store: &Store, dead: impl Fn(&str) -> bool) -> Vec<Node> {
    let h = hidden(store, dead);
    store.servers.iter().filter(|n| !h.contains_key(&n.id)).cloned().collect()
}

/// Для «Проверить все»: видимые и мёртвые (иначе мёртвый не воскреснет никогда —
/// его бы больше никто не проверял).
pub fn checkable(store: &Store) -> Vec<Node> {
    visible(store, |_| false)
}

/// «Тот же сервер»: всё, что определяет подключение, без имени и id (у одного
/// сервера в двух подписках ссылки часто разные: порядок параметров, #имя).
/// Адрес и SNI — без учёта регистра. Сервер из JSON-подписки — по его outbound.
pub fn same_key(n: &Node) -> String {
    if let Some(raw) = &n.raw {
        let mut o = raw["outbounds"][0].clone();
        if let Some(m) = o.as_object_mut() {
            m.remove("tag");
        }
        return format!("raw|{o}");
    }
    let mut c = n.clone();
    c.id.clear();
    c.name.clear();
    c.link.clear();
    c.sub_id = None;
    c.group = None;
    c.address = c.address.trim_matches(['[', ']']).to_ascii_lowercase();
    c.security.sni = c.security.sni.map(|s| s.to_ascii_lowercase());
    c.transport.host = c.transport.host.map(|s| s.to_ascii_lowercase());
    serde_json::to_string(&c).unwrap_or_default()
}

/// Сколько серверов подписки из какой страны (для флажков в окне), по убыванию.
pub fn sub_countries(store: &Store, sub_id: &str) -> Vec<(String, usize)> {
    let mut m: HashMap<String, usize> = HashMap::new();
    let mut none = 0;
    for n in store.servers.iter().filter(|n| n.sub_id.as_deref() == Some(sub_id)) {
        let cc = countries_of(&n.name);
        if cc.is_empty() {
            none += 1;
        }
        for c in cc {
            *m.entry(c).or_default() += 1;
        }
    }
    let mut v: Vec<(String, usize)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    if none > 0 {
        v.push((String::new(), none)); // «страна не понятна»
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Subscription;

    fn cc(name: &str) -> Vec<String> {
        let mut v: Vec<String> = countries_of(name).into_iter().collect();
        v.sort();
        v
    }

    #[test]
    fn countries_from_names() {
        assert_eq!(cc("🇳🇱 Amsterdam #1"), ["NL"]);
        assert_eq!(cc("🇷🇺→🇩🇪 relay"), ["DE", "RU"]);
        // Флаг есть — названия не смотрим (NL в имени «🇩🇪 via NL» — не страна сервера).
        assert_eq!(cc("🇩🇪 via NL"), ["DE"]);
        assert_eq!(cc("Германия-2"), ["DE"]);
        assert_eq!(cc("Нидерланды | 10 Gbit"), ["NL"]);
        assert_eq!(cc("Germany #3 premium"), ["DE"]);
        assert_eq!(cc("NL-1"), ["NL"]);
        assert_eq!(cc("[DE] fast"), ["DE"]);
        assert_eq!(cc("UK London"), ["GB"]);
        assert_eq!(cc("Hong Kong 2"), ["HK"]);
        assert_eq!(cc("ОАЭ Дубай"), ["AE"]);
        assert_eq!(cc("USA West"), ["US"]);
        // Не страны: строчные коды, буквы внутри слова, похожие слова.
        assert!(cc("de-fra.example.com").is_empty());
        assert!(cc("VLESS NLX").is_empty());
        assert!(cc("Данные · задание").is_empty());
        assert!(cc("Венец").is_empty());
        assert!(cc("server 1").is_empty());
        // Неполный флаг (одна буква) — ничего.
        assert!(cc("\u{1F1F3} x").is_empty());
    }

    #[test]
    fn parse_input() {
        let f = parse("NL, de, Германия, 🇫🇮🇸🇪, uk", "premium -test, -резерв").unwrap();
        assert_eq!(f.countries, ["NL", "DE", "FI", "SE", "GB"]);
        assert_eq!(f.words, ["premium", "-test", "-резерв"]);
        let f = parse("NL DE", "premium -test").unwrap();
        assert_eq!(f.countries, ["NL", "DE"]);
        assert_eq!(f.words, ["premium", "-test"]);
        assert!(parse("Нарния", "").unwrap_err().contains("Нарния"));
        assert!(parse("", "a\u{202E}b").is_err());
        assert!(parse("", &"x".repeat(41)).is_err());
        assert!(parse("", "  -  ").unwrap().is_empty());
        // Код, которого нет в таблице, — можно (флаг в имени найдётся).
        assert_eq!(parse("pe", "").unwrap().countries, ["PE"]);
        assert!(parse(&(0..41).map(|i| format!("{}{}", (b'A' + i / 26) as char, (b'A' + i % 26) as char)).collect::<Vec<_>>().join(","), "").is_err());
    }

    #[test]
    fn sanitize_foreign() {
        let mut f = SubFilter {
            countries: vec!["nl".into(), "NL".into(), "DEU".into(), "<b>".into(), "1A".into()],
            words: vec!["Ok".into(), "a\u{202E}b".into(), "x".repeat(500), " ".into(), "-".into(), "two words".into()],
        };
        f.words.extend((0..100_000).map(|i| format!("w{i}")));
        f.sanitize();
        assert_eq!(f.countries, ["NL"]);
        assert_eq!(f.words.len(), MAX_WORDS);
        assert_eq!(f.words[0], "ok");
        assert_eq!(f.words[1], "ab");
        assert_eq!(f.words[2].chars().count(), MAX_WORD);
        assert!(f.words.iter().all(|w| !w.contains(' ')));
    }

    #[test]
    fn big_list_is_fast() {
        let mut s = Store::default();
        let sub = |id: &str| Subscription { id: id.into(), name: id.into(), url: format!("https://{id}"), updated_at: None, usage: None, hwid: None, filter: parse("NL, DE, FI", "-test premium x y z").unwrap() };
        s.subscriptions = (0..4).map(|i| sub(&format!("s{i}"))).collect();
        for i in 0..12_000 {
            let mut n = node(&format!("n{i}"), "", &format!("h{}.example", i % 6000), "11111111-1111-1111-1111-111111111111", Some(&format!("s{}", i % 4)));
            n.name = format!("🇳🇱 Нидерланды premium сервер номер {i}");
            s.servers.push(n);
        }
        s.list_filter = ListFilter { hide_dead: true, dedup: true };
        let t = std::time::Instant::now();
        let h = hidden(&s, |id| id.ends_with('7'));
        let ms = t.elapsed().as_millis();
        assert_eq!(h.values().filter(|x| **x == Hide::Dup).count(), 6000);
        assert!(ms < if cfg!(debug_assertions) { 3000 } else { 300 }, "{ms} мс");
    }

    #[test]
    fn matching() {
        let f = parse("NL, DE", "").unwrap();
        assert!(f.matches("🇳🇱 NL-1") && f.matches("Германия") && !f.matches("🇫🇮 Helsinki") && !f.matches("server"));
        let f = parse("", "premium, -test").unwrap();
        assert!(f.matches("DE Premium 1") && !f.matches("DE premium TEST") && !f.matches("DE basic"));
        let f = parse("", "-ru").unwrap();
        assert!(f.matches("DE 1") && !f.matches("RU 1"));
        let f = parse("NL", "-резерв").unwrap();
        assert!(f.matches("🇳🇱 основной") && !f.matches("🇳🇱 резервный"));
        assert!(SubFilter::default().matches("что угодно"));
    }

    fn node(id: &str, name: &str, addr: &str, uuid: &str, sub: Option<&str>) -> Node {
        let link = format!("vless://{uuid}@{addr}:443?type=tcp&security=tls#{name}");
        let mut n = crate::link::parse_link(&link).unwrap();
        n.id = id.into();
        n.sub_id = sub.map(String::from);
        n
    }

    fn store() -> Store {
        let mut s = Store::default();
        let sub = |id: &str| Subscription { id: id.into(), name: id.into(), url: format!("https://{id}"), updated_at: None, usage: None, hwid: None, filter: SubFilter::default() };
        s.subscriptions = vec![sub("a"), sub("b")];
        let u1 = "11111111-1111-1111-1111-111111111111";
        let u2 = "22222222-2222-2222-2222-222222222222";
        s.servers = vec![
            node("m1", "мой", "my.example", u2, None),
            node("a1", "🇳🇱 NL 1", "nl.example", u1, Some("a")),
            node("a2", "🇩🇪 DE 1", "de.example", u1, Some("a")),
            node("a3", "🇫🇮 FI 1", "fi.example", u1, Some("a")),
            node("b1", "Netherlands", "NL.Example", u1, Some("b")), // тот же, что a1
            node("b2", "Финляндия", "fi2.example", u1, Some("b")),
            node("b3", "дубль своего", "MY.example", u2, Some("b")), // тот же, что m1
        ];
        s
    }

    fn ids(v: &[Node]) -> Vec<&str> {
        v.iter().map(|n| n.id.as_str()).collect()
    }

    #[test]
    fn hide_and_visible() {
        let mut s = store();
        assert_eq!(visible(&s, |_| false).len(), 7);
        s.subscriptions[0].filter = parse("NL, DE", "").unwrap();
        assert_eq!(ids(&visible(&s, |_| false)), ["m1", "a1", "a2", "b1", "b2", "b3"]);
        assert_eq!(hidden(&s, |_| false)["a3"], Hide::Filter);

        // Дубли: своё важнее подписки, выше — важнее ниже; отфильтрованный не «побеждает».
        s.list_filter.dedup = true;
        let h = hidden(&s, |_| false);
        assert_eq!(h.get("b1"), Some(&Hide::Dup));
        assert_eq!(h.get("b3"), Some(&Hide::Dup));
        assert_eq!(ids(&visible(&s, |_| false)), ["m1", "a1", "a2", "b2"]);
        // Выбранный — всегда виден и сам «побеждает» в своей группе.
        s.selected = Some("b1".into());
        assert_eq!(hidden(&s, |_| false).get("a1"), Some(&Hide::Dup));
        s.selected = Some("a3".into());
        assert!(!hidden(&s, |_| false).contains_key("a3"));
        s.selected = None;

        // Мёртвые.
        s.list_filter.hide_dead = true;
        assert_eq!(ids(&visible(&s, |id| id == "a2")), ["m1", "a1", "b2"]);
        assert_eq!(ids(&checkable(&s)), ["m1", "a1", "a2", "b2"]);
        // Все мёртвые (лёг интернет) — не прячем никого.
        assert_eq!(ids(&visible(&s, |_| true)), ["m1", "a1", "a2", "b2"]);
        // Выбранный мёртвый виден, и остальные мёртвые тоже (живых, кроме него, нет).
        s.selected = Some("m1".into());
        assert_eq!(ids(&visible(&s, |id| id != "a1")), ["m1", "a1"]);
    }

    #[test]
    fn same_server_keys() {
        let u = "11111111-1111-1111-1111-111111111111";
        let a = crate::link::parse_link(&format!("vless://{u}@Host.example:443?security=reality&sni=A.com&pbk=k&type=tcp#x")).unwrap();
        let b = crate::link::parse_link(&format!("vless://{u}@host.example:443?type=tcp&sni=a.com&pbk=k&security=reality#y")).unwrap();
        let c = crate::link::parse_link(&format!("vless://{u}@host.example:8443?type=tcp&sni=a.com&pbk=k&security=reality#y")).unwrap();
        assert_ne!(a.id, b.id);
        assert_eq!(same_key(&a), same_key(&b));
        assert_ne!(same_key(&a), same_key(&c));
    }

    #[test]
    fn plain_servers_stay_out_of_auto() {
        let u = "11111111-1111-1111-1111-111111111111";
        let mut s = Store::default();
        s.import_links(&format!("vless://{u}@safe.example:443?type=tcp&security=tls#safe
vless://{u}@open.example:80?type=ws#open"));
        let open = s.servers.iter().find(|n| n.name == "open").unwrap().id.clone();
        s.selected = Some(crate::store::AUTO_ID.into());
        assert_eq!(hidden(&s, |_| false).get(&open), Some(&Hide::Plain));
        assert_eq!(visible(&s, |_| false).iter().map(|n| n.name.as_str()).collect::<Vec<_>>(), ["safe"]);
        // Выбрал сам — не скрываем: это его решение.
        s.selected = Some(open.clone());
        assert!(!hidden(&s, |_| false).contains_key(&open));
    }

    #[test]
    fn filter_survives_refresh_and_backup() {
        let mut s = store();
        s.subscriptions[0].filter = parse("NL", "-test").unwrap();
        s.list_filter = ListFilter { hide_dead: true, dedup: true };
        let body = "vless://11111111-1111-1111-1111-111111111111@x.example:443?type=tcp&security=tls#🇩🇪 new\n\
                    vless://11111111-1111-1111-1111-111111111111@y.example:443?type=tcp&security=tls#🇳🇱 new";
        s.apply_subscription("a", body, 1);
        assert_eq!(s.subscriptions[0].filter.countries, ["NL"]);
        let vis = visible(&s, |_| false);
        let names: Vec<&str> = vis.iter().filter(|n| n.sub_id.as_deref() == Some("a")).map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["🇳🇱 new"]);
        // Через state.json / бэкап.
        let back: Store = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(back.subscriptions[0].filter, s.subscriptions[0].filter);
        assert_eq!(back.list_filter, s.list_filter);
        // Старый state.json без полей — пустые фильтры.
        let old: Store = serde_json::from_str(r#"{"subscriptions":[{"id":"a","name":"a","url":"https://a"}]}"#).unwrap();
        assert!(old.subscriptions[0].filter.is_empty() && old.list_filter == ListFilter::default());
        assert_eq!(sub_countries(&s, "a"), [("DE".to_string(), 1), ("NL".to_string(), 1)]);
    }
}
