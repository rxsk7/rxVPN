//! Грубый фаззинг парсеров чужих данных: ссылки, подписки (вкл. JSON),
//! бэкап, ответы сервисов проверки, списки блокировок, база v2rayN.
//! Ищем паники: на любом входе — ошибка, а не падение программы.
use std::panic::{catch_unwind, AssertUnwindSafe};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const SEEDS: &[&str] = &[
    "vless://b831381d-6324-4d53-ad4f-8cda48b30811@1.2.3.4:443?type=xhttp&security=reality&pbk=K&sid=ab&sni=a.com&fp=chrome&flow=xtls-rprx-vision&path=%2Fx&mode=auto&extra=%7B%22a%22%3A1%7D#NL",
    "vless://u@[2001:db8::1]:8443?type=grpc&serviceName=s&mode=multi&security=tls&alpn=h2,http/1.1#v6",
    "trojan://p%40ss@t.example.org:443?type=ws&path=%2Fws&sni=t.example.org#tr",
    "vmess://eyJ2IjoiMiIsInBzIjoieCIsImFkZCI6ImEuY29tIiwicG9ydCI6NDQzLCJpZCI6ImI4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMSIsIm5ldCI6IndzIiwidGxzIjoidGxzIn0=",
    "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206a2V5@9.9.9.9:443#ss",
    "ss://YWVzLTI1Ni1nY206cGFzc0AxLjIuMy40Ojg0NDM=#old",
    "hysteria2://p%40ss@hy.example.com:443,20000-30000/?sni=cdn.example.com&obfs=salamander&obfs-password=ob&pinSHA256=ABCD#hy",
    "hy2://pw@[2001:db8::1]?mport=20000-20010&insecure=0#x",
    "upload=1073741824; download=40802189312; total=107374182400; expire=1767225600",
    r#"[{"remarks":"x","outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"a.com","port":443,"users":[{"id":"u"}]}]},"streamSettings":{"sockopt":{"dialerProxy":"f"},"tlsSettings":{"masterKeyLog":"/x"}}},{"tag":"f","protocol":"freedom","settings":{"fragment":{}}},{"tag":"l","protocol":"loopback"}]}]"#,
    r#"{"kind":"rxvpn-backup","format":1,"app_version":"0.4.0","created_at":1,"store":{"servers":[],"subscriptions":[],"settings":{},"selected":null}}"#,
    r#"[{"ip":"1.1.1.1","country":"NL","country_name":"Netherlands","asn":"AS1","type":"dns"},{"ip":"DNS is not leaking.","type":"conclusion"}]"#,
    r#"{"status":"success","country":"Нидерланды","countryCode":"NL","isp":"x","query":"1.2.3.4"}"#,
    "dmxlc3M6Ly91QGguY29tOjQ0Mz90eXBlPXRjcCN4",
];

fn mutate(r: &mut Rng, s: &[u8]) -> Vec<u8> {
    let mut v = s.to_vec();
    for _ in 0..1 + r.below(6) {
        let len = v.len();
        match r.below(7) {
            0 if len > 0 => {
                let i = r.below(len);
                v[i] = r.next() as u8;
            }
            1 if len > 0 => {
                v.truncate(r.below(len));
            }
            2 => {
                let i = r.below(len + 1);
                let junk: &[&[u8]] = &[b"%", b"%ZZ", b"@", b":", b"[", b"]", b"#", b"?", b"&", b"=", b"\"", b"{", b"}", b"\\", b"\0", b"\xff", "ё".as_bytes(), b"-1", b"99999999999999999999", b"null", b"[]", b"{}", b"//", b"\n"];
                let j = junk[r.below(junk.len())];
                v.splice(i..i, j.iter().copied());
            }
            3 if len > 2 => {
                let a = r.below(len);
                let b = (a + r.below(len - a)).min(len);
                let seg = v[a..b].to_vec();
                let i = r.below(len + 1);
                v.splice(i..i, seg);
            }
            4 if len > 0 => {
                let a = r.below(len);
                v.remove(a);
            }
            5 => {
                v = (0..r.below(200)).map(|_| r.next() as u8).collect();
            }
            _ => {}
        }
    }
    v
}


#[test]
fn text_parsers_never_panic() {
    let mut r = Rng(0x9E37_79B9_7F4A_7C15);
    let settings = rxvpn_core::Settings { fragment: true, udp_noise: true, ..Default::default() };
    let mut dat = Vec::new();
    for (code, items) in [("RU-BLOCKED", 3u8), ("RE-FILTER", 2), ("GOOGLE", 1)] {
        let mut e = vec![0x0a, code.len() as u8];
        e.extend_from_slice(code.as_bytes());
        for i in 0..items {
            e.extend_from_slice(&[0x12, 3, b'a', b'b', b'0' + i]);
        }
        dat.push(0x0a);
        dat.push(e.len() as u8);
        dat.extend(e);
    }
    let mut parsed = 0;
    for i in 0..30_000 {
        let seed = SEEDS[r.below(SEEDS.len())].as_bytes();
        let input = mutate(&mut r, seed);
        let text = String::from_utf8_lossy(&input).into_owned();
        let d = mutate(&mut r, &dat);
        let res = catch_unwind(AssertUnwindSafe(|| {
            let (nodes, _) = rxvpn_core::parse_many(&text);
            for n in &nodes {
                let _ = rxvpn_core::build_config(n, &settings);
            }
            let _ = rxvpn_core::backup::parse(&text);
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                let _ = rxvpn_core::checks::parse_dnsleak(&v);
                let _ = rxvpn_core::checks::parse_ip_info(&v);
            }
            let _ = rxvpn_core::parse_rule(&text);
            if let Some(u) = rxvpn_core::store::SubUsage::parse(&text) {
                let _ = u.warning(1_700_000_000);
            }
            let _ = rxvpn_core::geodata::extract(&d, &["RU-BLOCKED", "RE-FILTER"]);
            let _ = rxvpn_core::geodata::count(&d, &["RU-BLOCKED"]);
            nodes.len()
        }));
        match res {
            Ok(n) => parsed += n,
            Err(_) => panic!("паника на итерации {i}, вход: {text:?}"),
        }
    }
    assert!(parsed > 1000, "мутации доходят до глубины парсеров: {parsed}");
}

#[test]
fn v2rayn_db_reader_never_panics() {
    let dir = std::env::temp_dir().join(format!("rxvpn-fuzzdb-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("guiNDB.db");
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(
            "CREATE TABLE ProfileItem (IndexId varchar, ConfigType integer, ConfigVersion integer, IsSub integer, Remarks varchar,
               Address varchar, Port integer, Password varchar, Network varchar, StreamSecurity varchar, Sni varchar,
               PublicKey varchar, ShortId varchar, ProtoExtra varchar, TransportExtra varchar);
             CREATE TABLE SubItem (Id varchar, Remarks varchar, Url varchar, Enabled integer);
             INSERT INTO SubItem VALUES ('s','sub','https://s.example.com/x',1);
             INSERT INTO ProfileItem VALUES ('a',5,4,0,'NL','1.2.3.4',443,'b831381d-6324-4d53-ad4f-8cda48b30811','raw','reality','a.com','K','ab','{\"Flow\":\"xtls-rprx-vision\"}','{}');
             INSERT INTO ProfileItem VALUES ('b',1,2,0,'VM','v.com',443,'','ws','tls','','','','','');",
        )
        .unwrap();
    }
    let orig = std::fs::read(&db).unwrap();
    assert!(rxvpn_core::v2rayn::read_db(&db).unwrap().links.len() == 2);
    let mut r = Rng(42);
    let broken = dir.join("broken.db");
    for i in 0..2_000 {
        let mut v = orig.clone();
        for _ in 0..1 + r.below(20) {
            let k = r.below(v.len());
            v[k] = r.next() as u8;
        }
        if r.below(4) == 0 {
            v.truncate(r.below(v.len()));
        }
        std::fs::write(&broken, &v).unwrap();
        if catch_unwind(|| rxvpn_core::v2rayn::read_db(&broken)).is_err() {
            panic!("паника на повреждённой базе, итерация {i}");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
