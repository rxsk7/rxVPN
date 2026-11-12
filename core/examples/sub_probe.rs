//! Диагностика HWID: что сервис подписки отвечает на разные наборы заголовков.
//!   cargo run -p rxvpn-core --example sub_probe -- <state.json>
//! Адрес подписки и сам HWID не печатаются. Запросы — те же, что делает rxvpn, с тем же HWID
//! (новое устройство у сервиса не появляется). state.json только читается.
// i18n-skip-begin: инструмент автора, не для пользователя.
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let path = std::env::args().nth(1).expect("state.json");
    let (store, locked) = rxvpn_core::Store::load_ex(std::path::Path::new(&path));
    if locked {
        return println!("state.json не открылся");
    }
    for sub in &store.subscriptions {
        let mine: Vec<&str> = store.servers.iter().filter(|n| n.sub_id.as_deref() == Some(sub.id.as_str())).map(|n| n.name.as_str()).collect();
        let host = url::Url::parse(&sub.url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
        println!("\n=== «{}» ({host}) HWID в rxvpn: {}; серверов сейчас: {}", sub.name, if sub.hwid.is_some() { "включён" } else { "ВЫКЛЮЧЕН" }, mine.len());
        for n in mine.iter().take(4) {
            println!("      {n}");
        }
        let h = sub.hwid.as_deref();
        let v2 = "v2rayN/7.17.1";
        let mut variants: Vec<(&str, &str, Vec<(&str, &str)>)> = vec![("без HWID", v2, vec![])];
        if let Some(h) = h {
            variants.push(("как rxvpn сейчас", v2, vec![("x-hwid", h), ("x-device-os", "Windows"), ("x-device-model", "rxvpn")]));
            variants.push(("+ x-ver-os", v2, vec![("x-hwid", h), ("x-device-os", "Windows"), ("x-ver-os", "11"), ("x-device-model", "rxvpn")]));
            variants.push(("+ x-ver-os, User-Agent Happ", "Happ/2.0.0", vec![("x-hwid", h), ("x-device-os", "Windows"), ("x-ver-os", "11"), ("x-device-model", "rxvpn")]));
            variants.push(("только x-hwid", v2, vec![("x-hwid", h)]));
        }
        for (title, ua, headers) in variants {
            let c = reqwest::Client::builder().timeout(Duration::from_secs(20)).user_agent(ua).redirect(reqwest::redirect::Policy::none()).build().unwrap();
            let mut req = c.get(&sub.url);
            for (k, v) in &headers {
                req = req.header(*k, *v);
            }
            match req.send().await {
                Err(e) => println!("  [{title}] не скачалась: {e}"),
                Ok(r) => {
                    let status = r.status();
                    let loc = r.headers().get("location").and_then(|v| v.to_str().ok()).and_then(|l| url::Url::parse(l).ok()).and_then(|u| u.host_str().map(str::to_string));
                    let hdrs: Vec<String> = r.headers().iter().filter(|(k, _)| { let k = k.as_str(); k.contains("hwid") || k == "announce" || k == "profile-title" || k == "content-type" }).map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("?").chars().take(80).collect::<String>())).collect();
                    let body = r.text().await.unwrap_or_default();
                    let (nodes, errors) = rxvpn_core::store::parse_subscription(&body);
                    println!("  [{title}] {status}{}; байт {}; серверов {}; ошибок разбора {}; {}", loc.map(|l| format!(" → {l}")).unwrap_or_default(), body.len(), nodes.len(), errors.len(), hdrs.join("; "));
                    for n in nodes.iter().take(3) {
                        println!("      {}", n.name);
                    }
                    if title == "как rxvpn сейчас" {
                        // Какие FinalMask присылает сервис: тип и «форма» настроек (без значений).
                        fn shape(v: &serde_json::Value) -> String {
                            match v {
                                serde_json::Value::Object(m) => format!("{{{}}}", m.iter().map(|(k, v)| format!("{k}: {}", shape(v))).collect::<Vec<_>>().join(", ")),
                                serde_json::Value::Array(a) => format!("[{}]", a.first().map(shape).unwrap_or_default()),
                                serde_json::Value::String(s) => format!("строка({})", s.len()),
                                serde_json::Value::Number(_) => "число".into(),
                                serde_json::Value::Bool(_) => "да/нет".into(),
                                serde_json::Value::Null => "null".into(),
                            }
                        }
                        fn find(v: &serde_json::Value, out: &mut std::collections::BTreeMap<String, usize>) {
                            match v {
                                serde_json::Value::Object(m) => {
                                    if let Some(fm) = m.get("finalmask") {
                                        for side in ["tcp", "udp"] {
                                            for it in fm.get(side).and_then(|x| x.as_array()).into_iter().flatten() {
                                                *out.entry(format!("{side} {}", shape(it))).or_default() += 1;
                                            }
                                        }
                                        for k in fm.as_object().into_iter().flat_map(|o| o.keys()).filter(|k| !["tcp", "udp"].contains(&k.as_str())) {
                                            *out.entry(format!("ключ finalmask.{k}")).or_default() += 1;
                                        }
                                    }
                                    m.values().for_each(|x| find(x, out));
                                }
                                serde_json::Value::Array(a) => a.iter().for_each(|x| find(x, out)),
                                _ => {}
                            }
                        }
                        let mut masks = Default::default();
                        if let Ok(j) = serde_json::from_str::<serde_json::Value>(&body) {
                            find(&j, &mut masks);
                        }
                        println!("      finalmask в подписке: {masks:#?}");
                        // Сервера с маскировкой sudoku / header-custom: подключаются ли через настоящий Xray.
                        if let Some(core) = std::env::args().nth(2) {
                            let masked: Vec<rxvpn_core::Node> = nodes
                                .iter()
                                .filter(|n| {
                                    let j = serde_json::to_string(n).unwrap_or_default();
                                    j.contains("sudoku") || j.contains("header-custom")
                                })
                                .cloned()
                                .collect();
                            println!("      с маскировкой sudoku/header-custom после разбора: {}", masked.len());
                            if !masked.is_empty() {
                                match rxvpn_core::batch::test_all(std::path::Path::new(&core), &masked, None, Default::default(), |_| {}).await {
                                    Err(e) => println!("      проверка не запустилась: {e}"),
                                    Ok(res) => {
                                        let ok = res.iter().filter(|r| r.ms.is_some()).count();
                                        println!("      отвечают: {ok} из {}", res.len());
                                        for r in &res {
                                            let name = masked.iter().find(|n| n.id == r.id).map(|n| n.name.as_str()).unwrap_or("?");
                                            println!("        {name}: {}", r.ms.map(|m| format!("{m} мс")).unwrap_or_else(|| r.error.clone().unwrap_or_default()));
                                        }
                                    }
                                }
                            }
                        }
                        let ids: std::collections::HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
                        let mut kinds: std::collections::BTreeMap<String, usize> = Default::default();
                        for e in &errors {
                            *kinds.entry(e.chars().filter(|c| !c.is_ascii_digit()).take(110).collect()).or_default() += 1;
                        }
                        println!("      разных id: {}; виды ошибок: {kinds:#?}", ids.len());
                        let mut proto: std::collections::BTreeMap<String, usize> = Default::default();
                        for n in &nodes {
                            *proto.entry(format!("{:?}", n.protocol)).or_default() += 1;
                        }
                        println!("      протоколы: {proto:?}");
                    }
                    if nodes.is_empty() {
                        println!("      тело: {:?}", body.chars().take(160).collect::<String>());
                    }
                }
            }
        }
    }
}
// i18n-skip-end
