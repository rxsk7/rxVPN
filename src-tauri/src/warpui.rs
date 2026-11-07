//! WARP поверх сервера в окне: зарегистрировать учётку и добавить сервер
//! «WARP · <сервер>». Удаляется он как обычный сервер (✕).

use rxvpn_core::{tr, trs};
use super::*;
use rxvpn_core::warp::{self, Warp};

/// Добавить WARP через сервер `via` ("" — напрямую, «попробовать»).
#[tauri::command]
pub(crate) async fn warp_add(app: AppHandle, st: State<'_, AppState>, via: String) -> Res<View> {
    let (via_sub, via_name) = {
        let s = st.store.lock().unwrap();
        if s.warp.len() >= warp::WARP_MAX {
            return Err(tr!("WARP-серверов уже {} — больше не нужно", warp::WARP_MAX));
        }
        if via.is_empty() {
            (String::new(), trs!("напрямую").to_string())
        } else {
            let n = s.servers.iter().find(|n| n.id == via).ok_or(trs!("Сервер не найден"))?;
            if warp::is_warp(&n.id) {
                return Err(trs!("WARP поверх WARP не нужен — выбери обычный сервер").into());
            }
            (n.sub_id.clone().unwrap_or_default(), n.name.clone())
        }
    };
    {
        let s = st.store.lock().unwrap();
        if s.warp.iter().any(|w| w.via == via && w.via_sub == via_sub) {
            return Err(trs!("WARP для этого сервера уже есть — он в папке «WARP»").into());
        }
    }
    if st.svc_busy.swap(true, Ordering::SeqCst) {
        return Err(trs!("Уже идёт проверка или регистрация — дождись конца").into());
    }
    let _busy = Busy(&st.svc_busy);
    // Регистрация — через VPN, если подключены (API Cloudflare из РФ открыт не везде).
    let proxy = probe_proxy(&st).map(|p| format!("socks5h://127.0.0.1:{p}"));
    log(&app, tr!("WARP: регистрирую учётку Cloudflare{}…", if proxy.is_some() { trs!(" через VPN") } else { "" }));
    let key = match warp::register(proxy.as_deref(), unix_now()).await {
        Ok(k) => k,
        Err(e) if proxy.is_none() => return Err(tr!("{e}. Подключись к VPN и повтори — регистрация пойдёт через него")),
        Err(e) => return Err(e),
    };
    {
        let mut s = st.store.lock().unwrap();
        let w = Warp { via: via.clone(), via_sub, key };
        let id = w.node_id();
        s.warp.push(w);
        s.sync_warp();
        if !s.servers.iter().any(|n| n.id == id) {
            s.warp.retain(|w| w.node_id() != id);
            return Err(trs!("Сервер пропал, пока шла регистрация").into());
        }
    }
    persist(&st);
    log(&app, tr!("WARP: добавлен «WARP · {via_name}» (папка «WARP»). Выбери его или поставь в «Сайт → сервер»"));
    if via.is_empty() {
        log(&app, trs!("WARP напрямую: в России WireGuard обычно режут — не подключится, бери WARP поверх своего сервера"));
    }
    Ok(view(&st))
}
