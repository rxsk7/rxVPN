//! Импорт из v2rayN: подписки и добавленные вручную сервера из guiNDB.db.
//!
//! v2rayN хранит всё в SQLite (`guiConfigs\guiNDB.db`). Схема меняется от
//! версии к версии: в новых часть полей переехала в JSON-колонки ProtoExtra
//! (ConfigVersion ≥ 3) и TransportExtra (≥ 4), в старых лежит в отдельных
//! колонках. Мы читаем обе раскладки и собираем из строки обычную ссылку —
//! теми же правилами, что и «Экспорт ссылки» в самом v2rayN, — а её уже
//! разбирает наш парсер. Так нет второго, отдельного пути разбора серверов.
//!
//! Базу самого v2rayN не трогаем: копируем во временную папку и открываем копию
//! (заодно не мешаем запущенному v2rayN и забираем его WAL-журнал).

use std::collections::HashMap;
use std::path::Path;

use base64::Engine;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use rusqlite::types::Value as Sql;
use serde_json::{json, Value};

/// Что нашлось в базе.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Found {
    /// (имя, url) подписок.
    pub subs: Vec<(String, String)>,
    /// Ссылки серверов, добавленных вручную.
    pub links: Vec<String>,
    /// Что пропустили и почему: "имя — причина".
    pub skipped: Vec<String>,
}

/// Самая большая база, которую готовы читать (у живого v2rayN — единицы МБ).
const MAX_DB: u64 = 200 << 20;

pub fn read_db(path: &Path) -> Result<Found, String> {
    let meta = std::fs::metadata(path).map_err(|e| tr!("не открыть файл: {e}"))?;
    if meta.len() > MAX_DB {
        return Err(trs!("файл слишком большой для базы v2rayN").into());
    }
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("rxvpn-v2rayn-{}-{stamp}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let copy = tmp.join("guiNDB.db");
    std::fs::copy(path, &copy).map_err(|e| tr!("не скопировать базу: {e}"))?;
    // Свежие изменения v2rayN могут лежать в журнале рядом.
    for ext in ["-wal", "-shm"] {
        let side = path.with_file_name(format!("{}{ext}", path.file_name().unwrap_or_default().to_string_lossy()));
        if side.is_file() {
            let _ = std::fs::copy(&side, tmp.join(format!("guiNDB.db{ext}")));
        }
    }
    let r = read_copy(&copy);
    let _ = std::fs::remove_dir_all(&tmp);
    r
}

fn read_copy(db: &Path) -> Result<Found, String> {
    let conn = rusqlite::Connection::open(db).map_err(|e| tr!("не SQLite: {e}"))?;
    let has = |t: &str| -> bool {
        conn.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1", [t], |r| r.get::<_, i64>(0))
            .map(|n| n > 0)
            .unwrap_or(false)
    };
    if !has("ProfileItem") {
        return Err(trs!("это не база v2rayN (нет таблицы ProfileItem). Нужен файл guiConfigs\\guiNDB.db").into());
    }
    let mut out = Found::default();
    if has("SubItem") {
        for row in rows(&conn, "SubItem")? {
            let url = text(&row, "Url");
            if url.is_empty() {
                continue; // группа без адреса — просто папка в v2rayN
            }
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                out.skipped.push(tr!("подписка «{}» — адрес не http(s)", text(&row, "Remarks")));
                continue;
            }
            if num(&row, "Enabled") == Some(0) {
                out.skipped.push(tr!("подписка «{}» — выключена в v2rayN", text(&row, "Remarks")));
                continue;
            }
            out.subs.push((text(&row, "Remarks"), url));
        }
    }
    for row in rows(&conn, "ProfileItem")? {
        // Сервера из подписок придут заново при её обновлении — берём только свои.
        let from_sub = match num(&row, "IsSub") {
            Some(v) => v != 0,
            None => !text(&row, "Subid").is_empty(),
        };
        if from_sub {
            continue;
        }
        let name = text(&row, "Remarks");
        match profile_link(&row) {
            Ok(l) => out.links.push(l),
            Err(why) => out.skipped.push(format!("«{name}» — {why}")),
        }
    }
    Ok(out)
}

type Row = HashMap<String, Sql>;

/// Все строки таблицы как «колонка → значение». `table` — только наши константы.
///
/// Имена колонок берём из PRAGMA table_info как обычные значения: методы rusqlite
/// column_name()/column_names() паникуют на битом UTF-8 в повреждённой базе,
/// а импорт должен на любом файле отвечать ошибкой, а не падать.
fn rows(conn: &rusqlite::Connection, table: &str) -> Result<Vec<Row>, String> {
    use rusqlite::types::ValueRef;
    let lossy = |v: ValueRef<'_>| match v {
        ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned(),
        _ => String::new(),
    };
    let broken = |e: rusqlite::Error| tr!("база повреждена: {e}");
    let names: Vec<String> = {
        let mut st = conn.prepare(&format!("PRAGMA table_info({table})")).map_err(broken)?;
        let it = st.query_map([], |r| Ok(lossy(r.get_ref(1)?))).map_err(broken)?;
        it.collect::<Result<_, _>>().map_err(broken)?
    };
    let mut st = conn.prepare(&format!("SELECT * FROM {table}")).map_err(broken)?;
    if st.column_count() != names.len() {
        return Err(trs!("база повреждена: не сходятся колонки").into());
    }
    let it = st
        .query_map([], |r| {
            let mut m = HashMap::new();
            for (i, n) in names.iter().enumerate() {
                // Текст — терпимо к битым байтам: один кривой символ не роняет импорт.
                let v = match r.get_ref(i)? {
                    ValueRef::Null => Sql::Null,
                    ValueRef::Integer(x) => Sql::Integer(x),
                    ValueRef::Real(x) => Sql::Real(x),
                    ValueRef::Text(t) => Sql::Text(String::from_utf8_lossy(t).into_owned()),
                    ValueRef::Blob(b) => Sql::Blob(b.to_vec()),
                };
                m.insert(n.clone(), v);
            }
            Ok(m)
        })
        .map_err(broken)?;
    it.collect::<Result<Vec<_>, _>>().map_err(broken)
}

fn text(r: &Row, col: &str) -> String {
    match r.get(col) {
        Some(Sql::Text(s)) => s.trim().to_string(),
        Some(Sql::Integer(i)) => i.to_string(),
        _ => String::new(),
    }
}

fn num(r: &Row, col: &str) -> Option<i64> {
    match r.get(col) {
        Some(Sql::Integer(i)) => Some(*i),
        Some(Sql::Text(s)) => s.trim().parse().ok(),
        _ => None,
    }
}

/// JSON-колонка (ProtoExtra / TransportExtra) → поле.
fn extra(r: &Row, col: &str) -> Value {
    serde_json::from_str(&text(r, col)).unwrap_or(Value::Null)
}

fn ex(v: &Value, key: &str) -> String {
    match &v[key] {
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

/// Что оставлять как есть в значениях параметров ссылки (как Uri.EscapeDataString).
const QV: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

fn enc(s: &str) -> String {
    utf8_percent_encode(s, QV).to_string()
}

fn host(addr: &str) -> String {
    if addr.contains(':') && !addr.starts_with('[') {
        format!("[{addr}]")
    } else {
        addr.to_string()
    }
}

/// Транспорт строки в обеих раскладках: (network для ссылки, host, path, header/mode, extra).
struct Tr {
    net: String,
    host: String,
    path: String,
    kind: String,
    extra: String,
}

fn transport(r: &Row, ver: i64) -> Tr {
    let mut net = text(r, "Network").to_ascii_lowercase();
    if net.is_empty() || net == "raw" {
        net = "tcp".into();
    }
    if ver >= 4 {
        let t = extra(r, "TransportExtra");
        let (host, path, kind) = match net.as_str() {
            "grpc" => (ex(&t, "GrpcAuthority"), ex(&t, "GrpcServiceName"), ex(&t, "GrpcMode")),
            "kcp" => (String::new(), ex(&t, "KcpSeed"), ex(&t, "KcpHeaderType")),
            "xhttp" => (ex(&t, "Host"), ex(&t, "Path"), ex(&t, "XhttpMode")),
            "ws" | "httpupgrade" => (ex(&t, "Host"), ex(&t, "Path"), String::new()),
            _ => (ex(&t, "Host"), ex(&t, "Path"), ex(&t, "RawHeaderType")),
        };
        Tr { net, host, path, kind, extra: ex(&t, "XhttpExtra") }
    } else {
        Tr {
            net,
            host: text(r, "RequestHost"),
            path: text(r, "Path"),
            kind: text(r, "HeaderType"),
            extra: text(r, "Extra"),
        }
    }
}

/// Параметры шифрования и транспорта для vless/trojan (как ToUriQuery в v2rayN).
fn std_query(r: &Row, q: &mut Vec<(String, String)>, tr: &Tr) {
    let push = |q: &mut Vec<(String, String)>, k: &str, v: String| {
        if !v.is_empty() {
            q.push((k.into(), v));
        }
    };
    let sec = text(r, "StreamSecurity");
    push(q, "security", sec.clone());
    push(q, "sni", text(r, "Sni"));
    push(q, "fp", text(r, "Fingerprint"));
    push(q, "pbk", text(r, "PublicKey"));
    push(q, "sid", text(r, "ShortId"));
    push(q, "spx", text(r, "SpiderX"));
    push(q, "pqv", text(r, "Mldsa65Verify"));
    if sec == "tls" {
        push(q, "alpn", text(r, "Alpn"));
    }
    if text(r, "AllowInsecure").eq_ignore_ascii_case("true") {
        q.push(("allowInsecure".into(), "1".into()));
    }
    q.push(("type".into(), tr.net.clone()));
    match tr.net.as_str() {
        "grpc" => {
            push(q, "serviceName", tr.path.clone());
            push(q, "authority", tr.host.clone());
            if tr.kind == "gun" || tr.kind == "multi" {
                q.push(("mode".into(), tr.kind.clone()));
            }
        }
        "kcp" => {
            q.push(("headerType".into(), if tr.kind.is_empty() { "none".into() } else { tr.kind.clone() }));
            push(q, "seed", tr.path.clone());
        }
        "xhttp" => {
            push(q, "host", tr.host.clone());
            push(q, "path", tr.path.clone());
            push(q, "mode", tr.kind.clone());
            push(q, "extra", tr.extra.clone());
        }
        "ws" | "httpupgrade" => {
            push(q, "host", tr.host.clone());
            push(q, "path", tr.path.clone());
        }
        _ => {
            q.push(("headerType".into(), if tr.kind.is_empty() { "none".into() } else { tr.kind.clone() }));
            push(q, "host", tr.host.clone());
            push(q, "path", tr.path.clone());
        }
    }
}

fn uri(scheme: &str, user: &str, r: &Row, q: &[(String, String)]) -> String {
    let query: Vec<String> = q.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect();
    let name = text(r, "Remarks");
    let frag = if name.is_empty() { String::new() } else { format!("#{}", enc(&name)) };
    format!("{scheme}://{}@{}:{}?{}{frag}", enc(user), host(&text(r, "Address")), text(r, "Port"), query.join("&"))
}

/// Строка ProfileItem → ссылка.
fn profile_link(r: &Row) -> Result<String, String> {
    let ver = num(r, "ConfigVersion").unwrap_or(0);
    let proto = if ver >= 3 { extra(r, "ProtoExtra") } else { Value::Null };
    // С версии 3 пароль/UUID в Password, раньше — в Id.
    let mut cred = if ver >= 3 { text(r, "Password") } else { text(r, "Id") };
    if cred.is_empty() {
        cred = if ver >= 3 { text(r, "Id") } else { text(r, "Password") };
    }
    let pick = |new_key: &str, old_col: &str| -> String {
        let v = ex(&proto, new_key);
        if ver >= 3 {
            v
        } else {
            text(r, old_col)
        }
    };
    if text(r, "Address").is_empty() || num(r, "Port").unwrap_or(0) <= 0 {
        return Err(trs!("нет адреса или порта").into());
    }
    let tr = transport(r, ver);
    match num(r, "ConfigType").unwrap_or(0) {
        5 => {
            let mut q = vec![];
            let enc_ = pick("VlessEncryption", "Security");
            q.push(("encryption".to_string(), if enc_.is_empty() { "none".into() } else { enc_ }));
            let flow = pick("Flow", "Flow");
            if !flow.is_empty() {
                q.push(("flow".into(), flow));
            }
            std_query(r, &mut q, &tr);
            Ok(uri("vless", &cred, r, &q))
        }
        6 => {
            let mut q = vec![];
            let flow = pick("Flow", "Flow");
            if !flow.is_empty() {
                q.push(("flow".into(), flow));
            }
            std_query(r, &mut q, &tr);
            Ok(uri("trojan", &cred, r, &q))
        }
        1 => {
            let (kind, host, path) = (tr.kind.clone(), tr.host.clone(), tr.path.clone());
            let v = json!({
                "v": "2", "ps": text(r, "Remarks"), "add": text(r, "Address"), "port": text(r, "Port"),
                "id": cred, "aid": pick("AlterId", "AlterId"), "scy": pick("VmessSecurity", "Security"),
                "net": tr.net, "type": if kind.is_empty() { "none".to_string() } else { kind },
                "host": host, "path": path, "tls": text(r, "StreamSecurity"),
                "sni": text(r, "Sni"), "alpn": text(r, "Alpn"), "fp": text(r, "Fingerprint"),
            });
            Ok(format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(v.to_string())))
        }
        3 => {
            if tr.net == "ws" || tr.kind == "http" {
                return Err(trs!("shadowsocks с плагином — Xray такое не умеет").into());
            }
            let method = pick("SsMethod", "Security");
            if method.is_empty() {
                return Err(trs!("shadowsocks без метода шифрования").into());
            }
            let user = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{method}:{cred}"));
            let name = text(r, "Remarks");
            let frag = if name.is_empty() { String::new() } else { format!("#{}", enc(&name)) };
            Ok(format!("ss://{user}@{}:{}{frag}", host(&text(r, "Address")), text(r, "Port")))
        }
        7 => Err(trs!("hysteria2 — rxvpn пока не поддерживает").into()),
        8 => Err(trs!("TUIC — rxvpn пока не поддерживает").into()),
        9 => Err(trs!("WireGuard — rxvpn пока не поддерживает").into()),
        4 | 10 => Err(trs!("обычный SOCKS/HTTP-прокси — это не VPN-сервер").into()),
        2 | 13 => Err(trs!("свой конфиг v2rayN — перенеси вручную").into()),
        101 | 102 => Err(trs!("группа/цепочка v2rayN — перенеси вручную").into()),
        t => Err(tr!("тип {t} — не знаю такой")),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// База как у v2rayN: колонки = свойства ProfileItem/SubItem (sqlite-net).
    /// Две записи в старой раскладке (ConfigVersion 2), две — в новой (4).
    pub fn make_db(path: &Path) {
        let c = rusqlite::Connection::open(path).unwrap();
        c.execute_batch(
            "CREATE TABLE ProfileItem (IndexId varchar PRIMARY KEY, ConfigType integer, CoreType integer, ConfigVersion integer,
                Subid varchar, IsSub integer, PreSocksPort integer, DisplayLog integer, Remarks varchar, Address varchar,
                Port integer, Password varchar, Username varchar, Network varchar, HeaderType varchar, RequestHost varchar,
                Path varchar, StreamSecurity varchar, AllowInsecure varchar, Sni varchar, Alpn varchar, Fingerprint varchar,
                PublicKey varchar, ShortId varchar, SpiderX varchar, Mldsa65Verify varchar, Extra varchar, MuxEnabled integer,
                Cert varchar, CertSha varchar, EchConfigList varchar, VerifyPeerCertByName varchar, Finalmask varchar,
                ProtoExtra varchar, TransportExtra varchar, Ports varchar, AlterId integer, Flow varchar, Id varchar, Security varchar);
             CREATE TABLE SubItem (Id varchar PRIMARY KEY, Remarks varchar, Url varchar, MoreUrl varchar, Enabled integer,
                UserAgent varchar, Sort integer, Filter varchar, AutoUpdateInterval integer, UpdateTime integer);
             INSERT INTO SubItem (Id, Remarks, Url, Enabled) VALUES ('s1', 'Моя подписка', 'https://sub.example.com/abc', 1),
                ('s2', 'Группа без адреса', '', 1), ('s3', 'Выключенная', 'https://off.example.com/x', 0);",
        )
        .unwrap();
        let ins = "INSERT INTO ProfileItem (IndexId, ConfigType, ConfigVersion, Subid, IsSub, Remarks, Address, Port, Password,
            Network, HeaderType, RequestHost, Path, StreamSecurity, AllowInsecure, Sni, Alpn, Fingerprint, PublicKey, ShortId,
            SpiderX, Extra, ProtoExtra, TransportExtra, AlterId, Flow, Id, Security)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, ?28)";
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        type P<'a> = [&'a dyn rusqlite::ToSql; 28];
        let none: Option<String> = None;
        // 1. Новый формат: VLESS Reality + Vision (как сервер Нидерланды).
        let p1: P = [&"p1", &5, &4, &"", &0, &"NL Reality", &"79.137.195.200", &443, &uuid, &"raw", &none, &none, &none,
            &"reality", &"false", &"www.microsoft.com", &"", &"chrome", &"PUBKEY123", &"ab12", &"/", &none,
            &r#"{"Flow":"xtls-rprx-vision","VlessEncryption":"none"}"#, &r#"{"RawHeaderType":"none"}"#, &0, &none, &none, &none];
        // 2. Новый формат: VLESS xhttp + TLS с extra.
        let p2: P = [&"p2", &5, &4, &"", &0, &"FI xhttp", &"fi.example.com", &8443, &uuid, &"xhttp", &none, &none, &none,
            &"tls", &"false", &"fi.example.com", &"h2,http/1.1", &"firefox", &"", &"", &"", &none,
            &r#"{"VlessEncryption":"none"}"#, &r#"{"Host":"cdn.example.com","Path":"/xh","XhttpMode":"packet-up","XhttpExtra":"{\"xPaddingBytes\":\"100-1000\"}"}"#,
            &0, &none, &none, &none];
        // 3. Старый формат (ConfigVersion 2): VMess ws + TLS, всё в отдельных колонках.
        let p3: P = [&"p3", &1, &2, &"", &0, &"Old VMess", &"vm.example.com", &443, &"", &"ws", &"none", &"vm.example.com",
            &"/ws", &"tls", &"false", &"", &"", &"", &"", &"", &"", &none, &none, &none, &0, &"", &uuid, &"auto"];
        // 4. Старый формат: Trojan gRPC.
        let p4: P = [&"p4", &6, &2, &"", &0, &"Old Trojan", &"tr.example.com", &443, &"", &"grpc", &"multi", &"",
            &"grpcsvc", &"tls", &"false", &"tr.example.com", &"", &"", &"", &"", &"", &none, &none, &none, &0, &"", &"secretpw", &""];
        // 5. Новый формат: Shadowsocks 2022.
        let p5: P = [&"p5", &3, &4, &"", &0, &"SS", &"ss.example.com", &8388, &"pass:word", &"raw", &none, &none, &none,
            &"", &"", &"", &"", &"", &"", &"", &"", &none, &r#"{"SsMethod":"2022-blake3-aes-128-gcm"}"#, &"{}", &0, &none, &none, &none];
        // 6. Из подписки — пропускаем. 7. Hysteria2 — не умеем.
        let p6: P = [&"p6", &5, &4, &"s1", &1, &"From sub", &"x.example.com", &443, &uuid, &"raw", &none, &none, &none,
            &"", &"", &"", &"", &"", &"", &"", &"", &none, &"{}", &"{}", &0, &none, &none, &none];
        let p7: P = [&"p7", &7, &4, &"", &0, &"Hy2", &"h.example.com", &443, &"pw", &"", &none, &none, &none,
            &"tls", &"", &"", &"", &"", &"", &"", &"", &none, &"{}", &"{}", &0, &none, &none, &none];
        for p in [p1, p2, p3, p4, p5, p6, p7] {
            c.execute(ins, p).unwrap();
        }
    }

    #[test]
    fn imports_both_layouts() {
        let dir = std::env::temp_dir().join(format!("rxvpn-v2n-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("guiNDB.db");
        let _ = std::fs::remove_file(&db);
        make_db(&db);
        let f = read_db(&db).unwrap();
        assert_eq!(f.subs, vec![("Моя подписка".to_string(), "https://sub.example.com/abc".to_string())]);
        assert_eq!(f.links.len(), 5, "{:#?}", f);
        assert!(f.skipped.iter().any(|s| s.contains("Hy2") && s.contains("hysteria2")));
        assert!(f.skipped.iter().any(|s| s.contains("Выключенная")));

        let nodes: Vec<crate::Node> = f.links.iter().map(|l| crate::parse_link(l).unwrap()).collect();
        let nl = &nodes[0];
        assert_eq!((nl.name.as_str(), nl.address.as_str(), nl.port), ("NL Reality", "79.137.195.200", 443));
        assert_eq!(nl.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(nl.security.kind, "reality");
        assert_eq!(nl.security.public_key.as_deref(), Some("PUBKEY123"));
        assert_eq!(nl.security.short_id.as_deref(), Some("ab12"));
        assert_eq!(nl.security.sni.as_deref(), Some("www.microsoft.com"));
        assert_eq!(nl.transport.network, "tcp");

        let fi = &nodes[1];
        assert_eq!(fi.transport.network, "xhttp");
        assert_eq!((fi.transport.host.as_deref(), fi.transport.path.as_deref()), (Some("cdn.example.com"), Some("/xh")));
        assert_eq!(fi.transport.mode.as_deref(), Some("packet-up"));
        assert_eq!(fi.transport.extra.as_ref().unwrap()["xPaddingBytes"], "100-1000");
        assert_eq!(fi.security.alpn, vec!["h2", "http/1.1"]);

        let vm = &nodes[2];
        assert_eq!(vm.protocol, crate::Protocol::Vmess);
        assert_eq!(vm.uuid.as_deref(), Some("b831381d-6324-4d53-ad4f-8cda48b30811"));
        assert_eq!((vm.transport.network.as_str(), vm.transport.path.as_deref()), ("ws", Some("/ws")));
        assert_eq!(vm.security.kind, "tls");

        let tr = &nodes[3];
        assert_eq!(tr.password.as_deref(), Some("secretpw"));
        assert_eq!(tr.transport.service_name.as_deref(), Some("grpcsvc"));
        assert_eq!(tr.transport.mode.as_deref(), Some("multi"));

        let ss = &nodes[4];
        assert_eq!(ss.method.as_deref(), Some("2022-blake3-aes-128-gcm"));
        assert_eq!(ss.password.as_deref(), Some("pass:word"), "двоеточие в пароле не ломает");

        // Не база v2rayN.
        let junk = dir.join("junk.db");
        let _ = std::fs::remove_file(&junk);
        rusqlite::Connection::open(&junk).unwrap().execute_batch("CREATE TABLE x (a)").unwrap();
        assert!(read_db(&junk).unwrap_err().contains("не база v2rayN"));
        std::fs::write(&junk, b"not sqlite at all").unwrap();
        assert!(read_db(&junk).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// v2rayN запущен: база в режиме WAL, свежие записи ещё в журнале -wal.
    #[test]
    fn reads_wal_of_running_v2rayn() {
        let dir = std::env::temp_dir().join(format!("rxvpn-v2n-wal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("guiNDB.db");
        make_db(&db);
        let live = rusqlite::Connection::open(&db).unwrap();
        live.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(())).unwrap();
        live.execute_batch("PRAGMA wal_autocheckpoint=0; INSERT INTO SubItem (Id, Remarks, Url, Enabled) VALUES ('s9', 'Свежая', 'https://new.example.com/s', 1);").unwrap();
        assert!(dir.join("guiNDB.db-wal").metadata().unwrap().len() > 0, "запись лежит в журнале");
        let f = read_db(&db).unwrap();
        assert!(f.subs.iter().any(|(n, _)| n == "Свежая"), "{:?}", f.subs);
        drop(live);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
