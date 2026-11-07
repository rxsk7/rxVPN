//! Стабильность серверов: как часто сервер отвечал за последние 7 дней.
//! Копим по часам (сколько проверок прошло, сколько нет, суммарная задержка) —
//! из «Проверить все», замеров «Авто» и проверок связи подключения.
//! И скорость из «Проверить скорость всех» (Мбит/с ×10 по часам).
//! Лежит в data\stats.json: только id серверов (хеши) и цифры, без адресов и паролей.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

const DAYS: u32 = 7;
const MAX_NODES: usize = 5000;
const MAX_FILE: u64 = 4 << 20;
/// Меньше проверок — процент ничего не значит, не показываем.
pub const MIN_CHECKS: u32 = 5;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Bucket {
    /// Час с 1970 года.
    pub h: u32,
    pub ok: u16,
    pub fail: u16,
    /// Сумма задержек удачных проверок, мс.
    pub ms: u32,
    /// Скорость: сумма замеров (Мбит/с ×10) и их число. Старый stats.json — нули.
    #[serde(default, skip_serializing_if = "is_zero32")]
    pub sp: u32,
    #[serde(default, skip_serializing_if = "is_zero16")]
    pub sn: u16,
}

fn is_zero32(v: &u32) -> bool {
    *v == 0
}
fn is_zero16(v: &u16) -> bool {
    *v == 0
}

/// Скорость «не знаем» для «Авто»: как у сервера ~7 Мбит/с — середнячок.
const UNKNOWN_SPEED_COST: u64 = 300;

/// Ключ выбора для «Авто» (меньше — лучше): сначала надёжность (ярус по проценту
/// ответов за неделю), потом «цена» = задержка + штраф за медленность.
/// Штраф 2000 / Мбит/с: 1 Мбит/с → +2000 мс, 10 → +200, 100 → +20. Так сервер
/// 120 мс / 5 Мбит/с (520) уступает серверу 250 мс / 80 Мбит/с (275), а 20 мс
/// разницы между двумя быстрыми ничего не решают.
pub fn auto_key(ms: u64, pct: Option<u8>, mbps: Option<f32>) -> (u8, u64) {
    let tier = match pct {
        Some(p) if p >= 95 => 0,
        None => 1, // мало данных — как «средний»
        Some(p) if p >= 80 => 1,
        Some(_) => 2,
    };
    let slow = match mbps {
        Some(m) if m.is_finite() => (2000.0 / m.max(0.5)).min(2000.0) as u64,
        _ => UNKNOWN_SPEED_COST,
    };
    (tier, ms.saturating_add(slow))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    pub nodes: BTreeMap<String, Vec<Bucket>>,
    /// Последняя проверка сервера провалилась (id → когда). Удачная — убирает.
    /// Для «скрыть мёртвые»; старше `DEAD_TTL` не в счёт (пора проверить снова).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dead: BTreeMap<String, i64>,
}

/// Сколько держится метка «мёртв» без новой проверки: сутки.
pub const DEAD_TTL: i64 = 24 * 3600;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct Score {
    /// Процент удачных проверок за 7 дней.
    pub pct: u8,
    pub checks: u32,
    pub avg_ms: Option<u32>,
    /// Последние сутки заметно хуже прошлой недели.
    pub degraded: bool,
}

fn hour(now: i64) -> u32 {
    (now.max(0) / 3600) as u32
}

impl Stats {
    pub fn load(path: &Path) -> Self {
        let small = std::fs::metadata(path).is_ok_and(|m| m.len() <= MAX_FILE);
        let mut s: Self = small
            .then(|| std::fs::read(path).ok())
            .flatten()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        // Чужой или испорченный файл не должен раздуть память.
        if s.nodes.len() > MAX_NODES {
            s.nodes.clear();
        }
        if s.dead.len() > MAX_NODES {
            s.dead.clear();
        }
        for v in s.nodes.values_mut() {
            v.truncate((DAYS * 24) as usize + 1);
        }
        s
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(self).unwrap())?;
        std::fs::rename(tmp, path)
    }

    /// Результат одной проверки: `ms` — задержка, None — не ответил.
    pub fn record(&mut self, id: &str, now: i64, ms: Option<u64>) {
        if id.is_empty() || id.len() > 128 || (!self.nodes.contains_key(id) && self.nodes.len() >= MAX_NODES) {
            return;
        }
        let h = hour(now);
        let v = self.nodes.entry(id.to_string()).or_default();
        let i = match v.iter().position(|b| b.h == h) {
            Some(i) => i,
            None => {
                v.push(Bucket { h, ..Default::default() });
                v.sort_by_key(|b| b.h);
                v.iter().position(|b| b.h == h).unwrap()
            }
        };
        let b = &mut v[i];
        match ms {
            Some(ms) => {
                b.ok = b.ok.saturating_add(1);
                b.ms = b.ms.saturating_add(ms.min(60_000) as u32);
            }
            None => b.fail = b.fail.saturating_add(1),
        }
        match ms {
            Some(_) => {
                self.dead.remove(id);
            }
            None => {
                // Более старой проверкой свежую не перебиваем.
                let t = self.dead.entry(id.to_string()).or_insert(now);
                *t = (*t).max(now);
            }
        }
        let v = self.nodes.get_mut(id).unwrap();
        // Окно — 7 дней от самого свежего часа.
        let newest = v.last().map_or(h, |b| b.h);
        let old = newest.saturating_sub(DAYS * 24);
        v.retain(|b| b.h > old);
    }

    /// Замер скорости (Мбит/с). Неудачный не пишем: Cloudflare мог быть закрыт,
    /// а не сервер плох — за «не отвечает» и так отвечают проверки задержки.
    pub fn record_speed(&mut self, id: &str, now: i64, mbps: f64) {
        if id.is_empty() || id.len() > 128 || !mbps.is_finite() || mbps < 0.0 || (!self.nodes.contains_key(id) && self.nodes.len() >= MAX_NODES) {
            return;
        }
        let h = hour(now);
        let v = self.nodes.entry(id.to_string()).or_default();
        let i = match v.iter().position(|b| b.h == h) {
            Some(i) => i,
            None => {
                v.push(Bucket { h, ..Default::default() });
                v.sort_by_key(|b| b.h);
                v.iter().position(|b| b.h == h).unwrap()
            }
        };
        let b = &mut v[i];
        b.sp = b.sp.saturating_add((mbps * 10.0).round().min(100_000.0) as u32);
        b.sn = b.sn.saturating_add(1);
        let newest = v.last().map_or(h, |b| b.h);
        let old = newest.saturating_sub(DAYS * 24);
        v.retain(|b| b.h > old);
    }

    /// Скорость сервера, Мбит/с: среднее по трём последним часам с замерами
    /// за 7 дней (свежее важнее — канал у сервера меняется). None — не мерили.
    pub fn speed(&self, id: &str, now: i64) -> Option<f32> {
        let old = hour(now).saturating_sub(DAYS * 24);
        let per: Vec<f32> = self.nodes.get(id)?.iter().rev().filter(|b| b.h > old && b.sn > 0).take(3).map(|b| b.sp as f32 / 10.0 / b.sn as f32).collect();
        (!per.is_empty()).then(|| (per.iter().sum::<f32>() / per.len() as f32 * 10.0).round() / 10.0)
    }

    /// Ключ «Авто» для сервера по накопленному (см. `auto_key`).
    pub fn auto_key(&self, id: &str, now: i64, ms: u64) -> (u8, u64) {
        auto_key(ms, self.score(id, now).map(|s| s.pct), self.speed(id, now))
    }

    /// Последняя проверка (за сутки) — «не отвечает».
    pub fn is_dead(&self, id: &str, now: i64) -> bool {
        self.dead.get(id).is_some_and(|t| now - t < DEAD_TTL)
    }

    /// Убрать старше 7 дней и серверов, которых больше нет.
    pub fn prune(&mut self, now: i64, keep: &HashSet<&str>) {
        self.dead.retain(|id, t| keep.contains(id.as_str()) && now - *t < DEAD_TTL);
        let old = hour(now).saturating_sub(DAYS * 24);
        self.nodes.retain(|id, v| {
            v.retain(|b| b.h > old);
            keep.contains(id.as_str()) && !v.is_empty()
        });
    }

    pub fn score(&self, id: &str, now: i64) -> Option<Score> {
        let h = hour(now);
        let v = self.nodes.get(id)?;
        let sum = |from: u32, to: u32| {
            v.iter().filter(|b| b.h > from && b.h <= to).fold((0u32, 0u32, 0u64), |a, b| {
                (a.0 + b.ok as u32, a.1 + b.fail as u32, a.2 + b.ms as u64)
            })
        };
        let (ok, fail, ms) = sum(h.saturating_sub(DAYS * 24), h);
        let checks = ok + fail;
        if checks < MIN_CHECKS {
            return None;
        }
        let pct = |ok: u32, all: u32| (ok as u64 * 100 / all.max(1) as u64) as u8;
        let (dok, dfail, _) = sum(h.saturating_sub(24), h);
        let (wok, wfail, _) = sum(h.saturating_sub(DAYS * 24), h.saturating_sub(24));
        let degraded = dok + dfail >= MIN_CHECKS
            && wok + wfail >= MIN_CHECKS
            && pct(dok, dok + dfail) < 70
            && pct(wok, wok + wfail) >= 90;
        Some(Score { pct: pct(ok, checks), checks, avg_ms: (ok > 0).then(|| (ms / ok as u64) as u32), degraded })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores() {
        let mut s = Stats::default();
        let day = 24 * 3600;
        let now = 1_800_000_000i64;
        assert!(s.score("a", now).is_none());
        // Неделю стабилен, последние сутки падает.
        for d in 1..7 {
            for i in 0..10 {
                s.record("a", now - d * day + i * 60, Some(100));
            }
        }
        for i in 0..10 {
            s.record("a", now - 3600 + i * 60, if i < 3 { Some(150) } else { None });
        }
        let sc = s.score("a", now).unwrap();
        assert_eq!(sc.checks, 70);
        assert!(sc.degraded, "{sc:?}");
        assert_eq!(sc.pct, 90);
        assert_eq!(sc.avg_ms, Some(102));
        // Старше 7 дней — не в счёт.
        s.record("b", now - 9 * day, Some(1));
        for _ in 0..5 {
            s.record("b", now, None);
        }
        assert_eq!(s.score("b", now).unwrap().pct, 0);
        s.prune(now, &HashSet::from(["a"]));
        assert!(s.nodes.contains_key("a") && !s.nodes.contains_key("b"));
    }

    #[test]
    fn speed_and_auto() {
        let mut s = Stats::default();
        let now = 1_800_000_000i64;
        assert_eq!(s.speed("a", now), None);
        s.record_speed("a", now - 5 * 3600, 10.0);
        s.record_speed("a", now - 3600, 40.0);
        s.record_speed("a", now - 3600, 20.0); // тот же час: среднее 30
        s.record_speed("a", now, 50.0);
        assert_eq!(s.speed("a", now), Some(30.0)); // (10 + 30 + 50) / 3
        s.record_speed("a", now, f64::NAN);
        s.record_speed("a", now, -1.0);
        assert_eq!(s.speed("a", now), Some(30.0));
        // Четвёртый час — самый старый выпадает.
        s.record_speed("a", now - 2 * 3600, 90.0);
        assert_eq!(s.speed("a", now), Some(56.7)); // (30 + 90 + 50) / 3
        // Задержка без скорости не ломает процент: часы только со скоростью — не проверки.
        assert!(s.score("a", now).is_none());
        // Старый файл без sp/sn читается.
        let old: Stats = serde_json::from_str(r#"{"nodes":{"x":[{"h":1,"ok":2,"fail":0,"ms":200}]}}"#).unwrap();
        assert_eq!(old.nodes["x"][0].sn, 0);
        // Медленный близкий уступает быстрому подальше; ненадёжный — всем.
        assert!(auto_key(250, Some(99), Some(80.0)) < auto_key(120, Some(99), Some(5.0)));
        assert!(auto_key(120, Some(99), None) < auto_key(500, Some(99), None));
        assert!(auto_key(900, Some(97), Some(1.0)) < auto_key(50, Some(60), Some(500.0)));
        assert_eq!(auto_key(100, Some(99), Some(0.0)), (0, 2100));
    }

    #[test]
    fn dead_mark() {
        let mut s = Stats::default();
        let now = 1_800_000_000i64;
        s.record("a", now - 100, None);
        assert!(s.is_dead("a", now));
        s.record("a", now - 200, Some(50)); // удачная — снимает метку
        assert!(!s.is_dead("a", now));
        s.record("a", now, None);
        s.record("a", now - 50, None); // старая не сдвигает назад
        assert_eq!(s.dead["a"], now);
        assert!(!s.is_dead("a", now + DEAD_TTL)); // сутки без проверок — уже не «мёртв»
        // Сохраняется, старый файл без поля читается, prune чистит.
        let back: Stats = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert!(back.is_dead("a", now));
        s.prune(now, &HashSet::new());
        assert!(s.dead.is_empty());
        s.record("b", now - DEAD_TTL - 1, None);
        s.prune(now, &HashSet::from(["b"]));
        assert!(s.dead.is_empty());
    }

    #[test]
    fn hostile_file() {
        let dir = std::env::temp_dir().join(format!("rxvpn-stats-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("stats.json");
        std::fs::write(&p, b"{not json").unwrap();
        assert!(Stats::load(&p).nodes.is_empty());
        let mut big = Stats::default();
        big.nodes.insert("x".into(), vec![Bucket { h: 1, ok: 1, fail: 0, ms: 1, ..Default::default() }; 1000]);
        big.save(&p).unwrap();
        assert_eq!(Stats::load(&p).nodes["x"].len(), 169);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
