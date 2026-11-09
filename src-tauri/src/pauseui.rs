//! «Пауза»: выключить VPN на 15 минут / час / до включения вручную — для банков,
//! Госуслуг и магазинов, которые не пускают с VPN. По таймеру rxvpn подключается сам,
//! так что человек не забудет включить VPN обратно.
//!
//! Пауза — это обычное «Отключить» (вместе с kill switch и zapret) плюс таймер.
//! Любое подключение (гора, трей, автозапуск) паузу снимает: см. `clear` в connect_any.

use rxvpn_core::{tr, trs};

use super::*;

/// Пауза идёт. `until` — unix-время, когда подключиться самим; None — до включения вручную.
#[derive(Clone, Copy)]
pub(crate) struct Pause {
    pub until: Option<i64>,
    gen: u64,
}

/// Какие паузы бывают (минуты; 0 — до включения вручную). Трей и окно — из одного списка.
pub(crate) const CHOICES: [u32; 3] = [15, 60, 0];

/// Снять паузу (таймер увидит другой номер и ничего не включит).
pub(crate) fn clear(st: &AppState) {
    st.pause_gen.fetch_add(1, Ordering::SeqCst);
    st.pause.lock().unwrap().take();
}

pub(crate) fn current(st: &AppState) -> Option<Pause> {
    *st.pause.lock().unwrap()
}

/// Сколько минут осталось (вверх: «ещё 1 мин», пока не подключились).
pub(crate) fn minutes_left(p: &Pause) -> Option<i64> {
    p.until.map(|t| ((t - now()).max(0) + 59) / 60)
}

/// Строка состояния для трея.
pub(crate) fn tray_status(p: &Pause) -> String {
    match minutes_left(p) {
        Some(m) => tr!("⏸ Пауза: VPN включится через {m} мин"),
        None => trs!("⏸ Пауза: VPN выключен до включения вручную").to_string(),
    }
}

/// Подпись пункта меню паузы.
pub(crate) fn choice_label(min: u32) -> String {
    match min {
        0 => trs!("До включения вручную").to_string(),
        60 => trs!("На 1 час").to_string(),
        m => tr!("На {m} минут"),
    }
}

/// Поставить на паузу: отключиться и, если задано время, подключиться самим потом.
pub(crate) fn start(app: &AppHandle, minutes: u32) -> Res<()> {
    let st = app.state::<AppState>();
    if !CHOICES.contains(&minutes) {
        return Err(trs!("такой паузы нет").into());
    }
    if !running(&st) {
        return Err(trs!("VPN и так выключен — ставить на паузу нечего").into());
    }
    stop_everything(app, &st, trs!("пауза"));
    let gen = st.pause_gen.fetch_add(1, Ordering::SeqCst) + 1;
    let until = (minutes > 0).then(|| now() + i64::from(minutes) * 60);
    *st.pause.lock().unwrap() = Some(Pause { until, gen });
    log(
        app,
        match minutes {
            0 => trs!("пауза: VPN выключен до включения вручную").to_string(),
            m => tr!("пауза на {m} мин: потом VPN включится сам"),
        },
    );
    if let Some(t) = until {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            // Короткими шагами по часам: компьютер мог уснуть, и долгий sleep проспал бы срок.
            loop {
                tokio::time::sleep(Duration::from_secs(20)).await;
                let st = app.state::<AppState>();
                if st.pause.lock().unwrap().is_none_or(|p| p.gen != gen) {
                    return; // паузу сняли или поставили новую
                }
                if now() >= t {
                    break;
                }
                refresh_tray(&app); // «через N мин» в трее
            }
            let st = app.state::<AppState>();
            {
                let mut p = st.pause.lock().unwrap();
                if p.is_none_or(|p| p.gen != gen) {
                    return;
                }
                *p = None;
            }
            if running(&st) {
                return changed(&app); // человек уже подключился сам
            }
            notify(&app, trs!("Пауза закончилась"), trs!("rxvpn снова подключается"));
            connect_in_background(app.clone(), true, false);
            changed(&app);
        });
    }
    changed(app);
    Ok(())
}

#[tauri::command]
pub(crate) async fn pause_vpn(app: AppHandle, st: State<'_, AppState>, minutes: u32) -> Res<View> {
    start(&app, minutes)?;
    Ok(view(&st))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minutes_round_up() {
        let t = now();
        assert_eq!(minutes_left(&Pause { until: Some(t + 61), gen: 0 }), Some(2));
        assert_eq!(minutes_left(&Pause { until: Some(t + 60), gen: 0 }), Some(1));
        assert_eq!(minutes_left(&Pause { until: Some(t - 5), gen: 0 }), Some(0));
        assert_eq!(minutes_left(&Pause { until: None, gen: 0 }), None);
    }
}
