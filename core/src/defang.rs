//! Обезвреживание JSON, который пришёл со стороны и попадёт в конфиг Xray:
//! outbounds из JSON-подписок и бэкапов, `extra` из xhttp-ссылок.
//!
//! Подписку или ссылку контролирует чужой человек, а Xray в режиме TUN работает
//! с правами администратора. Поэтому всё, что не нужно для соединения с
//! сервером и умеет трогать комп, — вырезаем, а подозрительное — отвергаем.
//!
//! Главная тонкость: Xray читает конфиг через Go `encoding/json`, а тот
//! сопоставляет ключи без учёта регистра и с юникодными особыми случаями
//! (`ſ` → `s`, знак Кельвина `K` → `k`). Поэтому:
//!   * ключи сравниваем так же (`fold`);
//!   * если в одном объекте два ключа, которые Xray считает одним
//!     («address» и «Address»), — отвергаем: непонятно, какой победит;
//!   * важные ключи принимаем только в каноническом написании — иначе наши
//!     проверки по точному имени («protocol») смотрели бы мимо.

use serde_json::{Map, Value};

/// Как Go encoding/json сравнивает ключи: без регистра, плюс ſ → s, K → k.
pub fn fold(k: &str) -> String {
    k.chars()
        .flat_map(char::to_lowercase)
        .map(|c| if c == 'ſ' { 's' } else { c })
        .collect()
}

/// Ключи, которые мы проверяем по точному имени, — только в таком написании.
const CANONICAL: &[&str] = &[
    "protocol", "tag", "settings", "streamSettings", "network", "method", "security",
    "sockopt", "dialerProxy", "proxySettings", "finalmask", "downloadSettings",
    "xhttpSettings", "tlsSettings", "realitySettings", "extra", "type", "tcp", "udp",
    "quicParams", "noise", "fragment", "noises", "redirect", "address", "port", "vnext",
    "servers", "users", "peers",
];

/// Ключи, которых в чужом конфиге быть не должно (свёрнутые):
///   masterkeylog — Xray пишет TLS-ключи в файл по пути;
///   script — Lua-скрипт шумов FinalMask, читается с диска/шары и выполняется;
///   remotefolder / xdrivesettings — транспорт xdrive пишет файлы в папку
///     (а на Windows по UNC-пути лезет на чужую шару и отдаёт NTLM-хеш);
///   reverse — обратный туннель: сервер заводит соединения в маршрутизацию клиента.
/// Плюс всё, что кончается на «file» (certificateFile, keyFile…) — чтение файлов.
///   masquerade — у hysteria это настройка сервера (раздаёт файлы из папки).
const DROP: &[&str] = &["masterkeylog", "script", "remotefolder", "xdrivesettings", "reverse", "masquerade"];

/// Транспорты, которые умеют наши сервера. Всё прочее (xdrive и что появится
/// в Xray завтра) из чужого конфига не пускаем.
const NETWORKS: &[&str] = &[
    "tcp", "raw", "ws", "websocket", "grpc", "gun", "xhttp", "splithttp", "httpupgrade",
    "kcp", "mkcp", "hysteria",
];

/// Что можно оставить в чужом FinalMask: тип → разрешённые ключи settings.
const MASK_TCP: &[(&str, &[&str])] = &[("fragment", &["packets", "lengths", "delays", "maxSplit"])];
const MASK_UDP: &[(&str, &[&str])] = &[
    ("noise", &["reset", "noise"]),
    // обфускация hysteria2
    ("salamander", &["password", "packetSize"]),
    // «прыжки» по портам hysteria2 (без remoteIPs: адрес сервера задаёт сам outbound)
    ("udphop", &["mode", "interval", "remotePorts"]),
];
const NOISE_ITEM: &[&str] = &["rand", "randRange", "type", "packet", "delay"];
const QUIC_PARAMS: &[&str] = &["congestion", "bbrProfile", "brutalUp", "brutalDown", "udpHop"];

/// Обезвредить кусок чужого JSON (outbound целиком или `extra`).
/// Ok — что пришлось убрать (для заметки человеку), Err — отвергнуть целиком.
pub fn check(v: &mut Value) -> Result<Vec<String>, String> {
    let mut removed = Vec::new();
    walk(v, None, &mut removed)?;
    removed.sort();
    removed.dedup();
    Ok(removed)
}

fn walk(v: &mut Value, key: Option<&str>, removed: &mut Vec<String>) -> Result<(), String> {
    match v {
        Value::Object(m) => {
            // 1. Два ключа, которые для Xray — один.
            let mut seen: std::collections::HashMap<String, &str> = Default::default();
            for k in m.keys() {
                if let Some(other) = seen.insert(fold(k), k) {
                    return Err(tr!("ключи «{other}» и «{k}» Xray считает одним — подозрительно"));
                }
            }
            // 2. Важный ключ в нестандартном написании.
            for k in m.keys() {
                let f = fold(k);
                if let Some(c) = CANONICAL.iter().find(|c| fold(c) == f) {
                    if k != c {
                        return Err(tr!("ключ «{k}» вместо «{c}» — подозрительно"));
                    }
                }
            }
            // 3. Опасные ключи — прочь.
            let bad: Vec<String> = m
                .keys()
                .filter(|k| {
                    let f = fold(k);
                    DROP.contains(&f.as_str()) || f.ends_with("file")
                })
                .cloned()
                .collect();
            for k in bad {
                m.remove(&k);
                removed.push(k);
            }
            // 4. Транспорт — только из списка (у самих streamSettings/downloadSettings).
            if matches!(key, Some("streamSettings" | "downloadSettings")) {
                for k in ["network", "method"] {
                    if let Some(n) = m.get(k) {
                        let ok = n.as_str().is_some_and(|s| NETWORKS.contains(&fold(s).as_str()));
                        if !ok {
                            return Err(tr!("транспорт {n} — не пускаю"));
                        }
                    }
                }
            }
            // 5. FinalMask — только известные кусочки.
            if let Some(fm) = m.get_mut("finalmask") {
                finalmask(fm, removed)?;
            }
            for (k, x) in m.iter_mut() {
                if k != "finalmask" {
                    walk(x, Some(k.as_str()), removed)?;
                }
            }
            Ok(())
        }
        Value::Array(a) => {
            for x in a {
                walk(x, key, removed)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn keep_keys(m: &mut Map<String, Value>, allowed: &[&str], removed: &mut Vec<String>) {
    let extra: Vec<String> = m.keys().filter(|k| !allowed.contains(&k.as_str())).cloned().collect();
    for k in extra {
        m.remove(&k);
        removed.push(format!("finalmask.{k}"));
    }
}

fn mask_items(list: &mut Value, table: &[(&str, &[&str])], removed: &mut Vec<String>) -> Result<(), String> {
    let Some(items) = list.as_array_mut() else {
        *list = Value::Array(vec![]);
        return Ok(());
    };
    let mut kept = Vec::new();
    for mut it in std::mem::take(items) {
        let ty = it["type"].as_str().unwrap_or("").to_string();
        let Some((_, keys)) = table.iter().find(|(t, _)| *t == ty) else {
            removed.push(format!("finalmask «{ty}»"));
            continue;
        };
        let Some(obj) = it.as_object_mut() else { continue };
        keep_keys(obj, &["type", "settings"], removed);
        if let Some(st) = obj.get_mut("settings").and_then(Value::as_object_mut) {
            keep_keys(st, keys, removed);
            if let Some(noise) = st.get_mut("noise").and_then(Value::as_array_mut) {
                for n in noise.iter_mut().filter_map(Value::as_object_mut) {
                    keep_keys(n, NOISE_ITEM, removed);
                }
            }
        }
        // Что осталось — только простые значения и списки (никаких вложенных конфигов).
        walk(&mut it, None, removed)?;
        kept.push(it);
    }
    *items = kept;
    Ok(())
}

fn finalmask(fm: &mut Value, removed: &mut Vec<String>) -> Result<(), String> {
    let Some(m) = fm.as_object_mut() else {
        *fm = Value::Object(Map::new());
        return Ok(());
    };
    keep_keys(m, &["tcp", "udp", "quicParams"], removed);
    if let Some(t) = m.get_mut("tcp") {
        mask_items(t, MASK_TCP, removed)?;
    }
    if let Some(u) = m.get_mut("udp") {
        mask_items(u, MASK_UDP, removed)?;
    }
    if let Some(q) = m.get_mut("quicParams") {
        match q.as_object_mut() {
            Some(qm) => keep_keys(qm, QUIC_PARAMS, removed),
            None => *q = Value::Object(Map::new()),
        }
        walk(q, None, removed)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_and_strips() {
        // Регистр и юникод — как в Go.
        assert_eq!(fold("MaſterKeyLog"), "masterkeylog");
        assert_eq!(fold("\u{212A}eyFile"), "keyfile");

        // xdrive в любом написании и через alias method — отказ.
        for ss in [
            json!({"streamSettings": {"network": "xdrive"}}),
            json!({"streamSettings": {"network": "XDRIVE"}}),
            json!({"streamSettings": {"method": "xdrive"}}),
            json!({"streamSettings": {"network": "xhttp", "xhttpSettings": {"extra": {"downloadSettings": {"network": "xdrive"}}}}}),
        ] {
            let mut v = ss.clone();
            assert!(check(&mut v).is_err(), "{ss}");
        }
        // Обычный HTTP-заголовок с method: GET — это не транспорт, его не трогаем.
        let mut v = json!({"streamSettings": {"network": "tcp", "tcpSettings": {"header": {"type": "http", "request": {"method": "GET"}}}}});
        assert!(check(&mut v).unwrap().is_empty());

        // Дубли и нестандартное написание важных ключей — отказ.
        for bad in [
            json!({"tag": "proxy", "Protocol": "freedom"}),
            json!({"protocol": "vless", "Protocol": "freedom"}),
            json!({"protocol": "vless", "ſettings": {}}),
            json!({"settings": {"address": "a", "Address": "b"}}),
        ] {
            let mut v = bad.clone();
            assert!(check(&mut v).is_err(), "{bad}");
        }

        // Опасные ключи вырезаются на любой глубине, полезное остаётся.
        let mut v = json!({"protocol": "vless", "settings": {"reverse": {"tag": "tun"}},
            "streamSettings": {"network": "xhttp", "tlsSettings": {"serverName": "a", "MasterKeyLog": "C:\\x"},
              "xhttpSettings": {"extra": {"xPaddingBytes": "100", "downloadSettings": {"network": "xhttp",
                "xdriveSettings": {"remoteFolder": "\\\\evil\\s"},
                "finalmask": {"udp": [{"type": "noise", "settings": {"script": "\\\\evil\\n.lua", "noise": [{"rand": "1-8", "evil": 1}]}},
                                      {"type": "sudoku", "settings": {}}],
                              "tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["1-2"], "keyFile": "x"}}],
                              "quicParams": {"congestion": "bbr", "weird": {"script": "x"}}}}}}}});
        let removed = check(&mut v).unwrap();
        let t = v.to_string().to_lowercase();
        for bad in ["masterkeylog", "reverse", "xdrive", "remotefolder", "script", "sudoku", "keyfile", "evil\":1", "weird"] {
            assert!(!t.contains(bad), "{bad} остался: {t}");
        }
        assert!(t.contains("xpaddingbytes") && t.contains("tlshello") && t.contains("\"rand\"") && t.contains("bbr"), "{t}");
        assert!(!removed.is_empty());
    }
}
