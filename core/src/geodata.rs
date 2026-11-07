//! Списки для режима «Только заблокированное».
//!
//! runetfreedom/russia-v2ray-rules-dat обновляет geosite.dat/geoip.dat каждые
//! 6 часов, но файлы огромные (70 + 17 МБ). Нам из них нужны 2 % — категории
//! заблокированного в РФ. Скачиваем, вырезаем эти категории в маленькие
//! geosite-ru.dat / geoip-ru.dat (~2,5 МБ) рядом с xray.exe, большие выкидываем.
//!
//! Формат .dat — protobuf: список записей (поле 1), у записи поле 1 — код
//! категории (строка), поле 2 — повторяющиеся домены/подсети. Полноценный
//! protobuf не нужен: режем на уровне «запись целиком».

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::xray::{GEOIP_RU, GEOSITE_RU};

const BASE: &str = "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release";
/// Категории доменов: заблокированное (antifilter community + re:filter) и
/// «работает только изнутри РФ» (на будущее — для правил).
pub const SITE_CATS: &[&str] = &["RU-BLOCKED", "RU-AVAILABLE-ONLY-INSIDE"];
/// Категории IP: заблокированные адреса (antifilter) и re:filter.
pub const IP_CATS: &[&str] = &["RU-BLOCKED", "RE-FILTER"];

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ListsInfo {
    /// Сколько заблокированных доменов (RU-BLOCKED).
    pub domains: usize,
    /// Сколько заблокированных подсетей/IP (RU-BLOCKED + RE-FILTER).
    pub ips: usize,
    /// unix-время файла.
    pub updated_at: i64,
}

fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
    let mut r = 0u64;
    let mut shift = 0;
    loop {
        let x = *b.get(*i)?;
        *i += 1;
        r |= ((x & 0x7f) as u64) << shift;
        if x < 0x80 {
            return Some(r);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

fn put_varint(out: &mut Vec<u8>, mut n: u64) {
    loop {
        let x = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(x);
            return;
        }
        out.push(x | 0x80);
    }
}

/// Поля верхнего уровня protobuf-сообщения: (номер, тип, байты/значение).
fn fields(b: &[u8]) -> Result<Vec<(u64, &[u8])>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let key = varint(b, &mut i).ok_or(trs!("битый .dat"))?;
        match key & 7 {
            2 => {
                let len = varint(b, &mut i).ok_or(trs!("битый .dat"))? as usize;
                let end = i.checked_add(len).filter(|&e| e <= b.len()).ok_or(trs!("битый .dat"))?;
                out.push((key >> 3, &b[i..end]));
                i = end;
            }
            0 => {
                varint(b, &mut i).ok_or(trs!("битый .dat"))?;
            }
            _ => return Err(trs!("битый .dat: неизвестный тип поля").into()),
        }
    }
    Ok(out)
}

/// Код категории записи (поле 1).
fn code(entry: &[u8]) -> Option<String> {
    fields(entry)
        .ok()?
        .into_iter()
        .find(|(n, _)| *n == 1)
        .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
}

/// Оставить в .dat только нужные категории. Ошибка — если какой-то не нашлось
/// (значит, формат у источника поменялся, и старый файл лучше не трогать).
pub fn extract(dat: &[u8], wanted: &[&str]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut found = Vec::new();
    for (num, entry) in fields(dat)? {
        if num != 1 {
            continue;
        }
        let Some(c) = code(entry) else { continue };
        if wanted.iter().any(|w| w.eq_ignore_ascii_case(&c)) {
            found.push(c.to_uppercase());
            out.push(0x0a);
            put_varint(&mut out, entry.len() as u64);
            out.extend_from_slice(entry);
        }
    }
    if let Some(miss) = wanted.iter().find(|w| !found.iter().any(|f| f.eq_ignore_ascii_case(w))) {
        return Err(tr!("в списке нет категории {miss}"));
    }
    Ok(out)
}

/// Сколько доменов/подсетей в категориях (поле 2 записи).
pub fn count(dat: &[u8], cats: &[&str]) -> usize {
    let Ok(list) = fields(dat) else { return 0 };
    list.into_iter()
        .filter(|(n, _)| *n == 1)
        .filter(|(_, e)| code(e).is_some_and(|c| cats.iter().any(|w| w.eq_ignore_ascii_case(&c))))
        .map(|(_, e)| fields(e).map(|f| f.iter().filter(|(n, _)| *n == 2).count()).unwrap_or(0))
        .sum()
}

fn mtime(p: &Path) -> i64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Что сейчас лежит рядом с ядром. None — списков нет.
pub fn info(core_dir: &Path) -> Option<ListsInfo> {
    let core_dir = &crate::runner::asset_dir(core_dir);
    let site = std::fs::read(core_dir.join(GEOSITE_RU)).ok()?;
    let ip = std::fs::read(core_dir.join(GEOIP_RU)).ok()?;
    Some(ListsInfo {
        domains: count(&site, &SITE_CATS[..1]),
        ips: count(&ip, IP_CATS),
        updated_at: mtime(&core_dir.join(GEOSITE_RU)),
    })
}

pub fn present(core_dir: &Path) -> bool {
    let core_dir = &crate::runner::asset_dir(core_dir);
    core_dir.join(GEOSITE_RU).exists() && core_dir.join(GEOIP_RU).exists()
}

/// Пора ли обновлять (старше `days` дней). days = 0 — никогда.
pub fn stale(core_dir: &Path, days: u32) -> bool {
    if days == 0 {
        return false;
    }
    let core_dir = &crate::runner::asset_dir(core_dir);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    now - mtime(&core_dir.join(GEOSITE_RU)) > days as i64 * 86_400
}

/// Скачать свежие списки и вырезать нужное. `proxy` — "socks5h://127.0.0.1:port",
/// чтобы качать через VPN (GitHub бывает недоступен напрямую).
pub async fn update(core_dir: &Path, proxy: Option<&str>) -> Result<ListsInfo, String> {
    let mut b = reqwest::Client::builder().timeout(Duration::from_secs(600)).https_only(true);
    if let Some(p) = proxy {
        b = b.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?);
    }
    let client = b.build().map_err(|e| e.to_string())?;
    let get = |name: &'static str| {
        let client = client.clone();
        async move {
            let r = client
                .get(format!("{BASE}/{name}"))
                .send()
                .await
                .and_then(|r| r.error_for_status())
                .map_err(|e| tr!("не скачался {name}: {e}"))?;
            // Оригиналы ~70 и ~17 МБ; потолок — чтобы не съесть память.
            crate::net::read_capped(r, 400 << 20).await.map_err(|e| format!("{name}: {e}"))
        }
    };
    let (site, ip) = tokio::join!(get("geosite.dat"), get("geoip.dat"));
    let site = extract(&site?, SITE_CATS)?;
    let ip = extract(&ip?, IP_CATS)?;

    let core_dir = &crate::runner::asset_dir(core_dir);
    std::fs::create_dir_all(core_dir).map_err(|e| e.to_string())?;
    // Пишем во временные и переименовываем: работающий Xray уже прочитал
    // старые файлы при старте, а новые подхватит при следующем подключении.
    for (name, data) in [(GEOSITE_RU, &site), (GEOIP_RU, &ip)] {
        let tmp = core_dir.join(format!("{name}.tmp"));
        std::fs::write(&tmp, data).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, core_dir.join(name)).map_err(|e| e.to_string())?;
    }
    info(core_dir).ok_or_else(|| trs!("списки не записались").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(code: &str, items: &[&str]) -> Vec<u8> {
        let mut e = vec![0x0a];
        put_varint(&mut e, code.len() as u64);
        e.extend_from_slice(code.as_bytes());
        for it in items {
            e.push(0x12);
            put_varint(&mut e, it.len() as u64);
            e.extend_from_slice(it.as_bytes());
        }
        let mut out = vec![0x0a];
        put_varint(&mut out, e.len() as u64);
        out.extend(e);
        out
    }

    #[test]
    fn extract_and_count() {
        let mut dat = entry("GOOGLE", &["g1", "g2"]);
        dat.extend(entry("RU-BLOCKED", &["a", "b", "c"]));
        dat.extend(entry("RE-FILTER", &["x"]));
        let small = extract(&dat, &["ru-blocked", "re-filter"]).unwrap();
        assert_eq!(count(&small, &["RU-BLOCKED"]), 3);
        assert_eq!(count(&small, &["RU-BLOCKED", "RE-FILTER"]), 4);
        assert_eq!(count(&small, &["GOOGLE"]), 0, "лишнее вырезано");
        assert!(extract(&dat, &["NOPE"]).is_err());
        assert!(extract(&dat[..dat.len() - 1], &["GOOGLE"]).is_err(), "обрезанный файл — ошибка, а не мусор");
    }

    /// RUDAT_DIR=папка с настоящими geosite.dat/geoip.dat от runetfreedom
    #[test]
    #[ignore]
    fn real_files() {
        let Some(dir) = std::env::var_os("RUDAT_DIR").map(std::path::PathBuf::from) else { return };
        let site = extract(&std::fs::read(dir.join("geosite.dat")).unwrap(), SITE_CATS).unwrap();
        let ip = extract(&std::fs::read(dir.join("geoip.dat")).unwrap(), IP_CATS).unwrap();
        let (d, i) = (count(&site, &SITE_CATS[..1]), count(&ip, IP_CATS));
        eprintln!("доменов {d}, подсетей {i}, файлы {} + {} КБ", site.len() / 1024, ip.len() / 1024);
        assert!(d > 10_000 && i > 1_000);
        assert!(site.len() < 10 << 20, "маленький файл");
    }
}
