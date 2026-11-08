//! «Свой сервер» в окне: установка VPN на VPS по SSH и управление им.
//! Пароль и чужой ключ живут только в этом вызове (Zeroizing), секреты
//! сервера — в state.json под DPAPI (`vps::seal`).

use rxvpn_core::{tr, trs};
use super::*;
use rxvpn_core::vps::{self, plan, Friend, Login, Target, Vps};
use zeroize::Zeroizing;

/// Папка в списке серверов, куда кладутся свои.

#[derive(Serialize, Clone)]
pub(crate) struct FriendView {
    id: String,
    name: String,
    enabled: bool,
    /// Лимит, ГБ (0 — без лимита) и срок (unix, 0 — бессрочно).
    limit_gb: u32,
    expires: i64,
}

#[derive(Serialize, Clone)]
pub(crate) struct VpsView {
    id: String,
    name: String,
    host: String,
    ssh_port: u16,
    port: u16,
    sni: String,
    xray_version: String,
    os: String,
    arch: String,
    host_key: String,
    key_fp: String,
    password_off: bool,
    node_id: String,
    friends: Vec<FriendView>,
    /// Мост для белых списков: id и имя выходного сервера (пусто — обычный сервер).
    exit_id: String,
    exit_name: String,
}

pub(crate) fn views(s: &Store) -> Vec<VpsView> {
    s.vps
        .iter()
        .map(|v| VpsView {
            id: v.id.clone(),
            name: v.name.clone(),
            host: v.host.clone(),
            ssh_port: v.ssh_port,
            port: v.port,
            sni: v.sni.clone(),
            xray_version: v.xray_version.clone(),
            os: v.os.clone(),
            arch: v.arch.clone(),
            host_key: v.host_key.clone(),
            key_fp: v.key_fp.clone(),
            password_off: v.password_off,
            node_id: v.node_id.clone(),
            friends: v
                .friends
                .iter()
                .map(|f| FriendView { id: f.id.clone(), name: f.name.clone(), enabled: f.enabled, limit_gb: f.limit_gb, expires: f.expires })
                .collect(),
            exit_id: s.servers.iter().find(|n| !v.exit.is_empty() && n.link == v.exit).map(|n| n.id.clone()).unwrap_or_default(),
            exit_name: if v.exit.is_empty() {
                String::new()
            } else {
                s.servers.iter().find(|n| n.link == v.exit).map(|n| n.name.clone()).unwrap_or_else(|| trs!("сервер не из списка").to_string())
            },
        })
        .collect()
}

fn busy(st: &AppState) -> Res<Busy<'_>> {
    if st.vps_busy.swap(true, Ordering::SeqCst) {
        return Err(trs!("С сервером уже что-то делается — дождись конца").into());
    }
    Ok(Busy(&st.vps_busy))
}

fn get(st: &AppState, id: &str) -> Res<(Vps, vps::Secrets)> {
    let v = st.store.lock().unwrap().vps.iter().find(|v| v.id == id).cloned().ok_or(trs!("Сервер не найден"))?;
    let sec = vps::unseal(&v)?;
    Ok((v, sec))
}

fn save(st: &AppState, v: Vps) {
    let mut s = st.store.lock().unwrap();
    if let Some(x) = s.vps.iter_mut().find(|x| x.id == v.id) {
        *x = v;
    }
    drop(s);
    persist(st);
}

fn fetcher(socks: Option<u16>) -> impl Fn(&'static str) -> futures_util::future::BoxFuture<'static, Result<Vec<u8>, String>> + Send + Sync {
    move |asset| Box::pin(net::fetch_xray_asset(asset, socks))
}

fn port_of(p: u32, what: &str) -> Res<u16> {
    u16::try_from(p).ok().filter(|p| *p > 0).ok_or_else(|| tr!("{what}: порт 1–65535"))
}

/// Шаг 1: отпечаток ключа сервера, чтобы человек сверил его («это твой сервер?»).
#[tauri::command]
pub(crate) async fn vps_probe(host: String, ssh_port: u32) -> Res<String> {
    let host = plan::valid_host(&host)?;
    let port = port_of(ssh_port, "SSH")?;
    vps::host_fingerprint(&host, port).await
}

/// Шаг 2: установка. `fingerprint` — тот, что человек подтвердил.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn vps_install(
    app: AppHandle,
    st: State<'_, AppState>,
    host: String,
    ssh_port: u32,
    password: Option<String>,
    key: Option<String>,
    key_pass: Option<String>,
    fingerprint: String,
    name: String,
) -> Res<View> {
    // Всё секретное — сразу в Zeroizing: затрётся при выходе из функции.
    let password = password.map(Zeroizing::new);
    let key = key.map(Zeroizing::new);
    let key_pass = key_pass.map(Zeroizing::new).filter(|p| !p.is_empty());
    let host = plan::valid_host(&host)?;
    let ssh_port = port_of(ssh_port, "SSH")?;
    if !fingerprint.starts_with("SHA256:") || fingerprint.len() > 80 {
        return Err(trs!("Сначала проверь отпечаток сервера").into());
    }
    let name = match store_name(&name)? {
        n if n.is_empty() => format!("VPS {host}"),
        n => n,
    };
    let login = match (password, key) {
        (_, Some(k)) if !k.trim().is_empty() => Login::KeyText { key: k, passphrase: key_pass },
        (Some(p), _) if !p.is_empty() => Login::Password(p),
        _ => return Err(trs!("Впиши пароль root или вставь SSH-ключ").into()),
    };
    // Ключ сервера хранится только под DPAPI: если шифровать нечем, не начинаем
    // (иначе пароль выключим, а ключ сохранить не сможем).
    vps::seal(&vps::Secrets { ssh_key: Zeroizing::new("x".into()), reality_private: Zeroizing::new("x".into()), host: String::new(), ssh_port: 0, host_key: String::new() })
        .map_err(|e| tr!("Свой сервер пока только в Windows: ключ хранится под DPAPI ({e})"))?;
    if st.store.lock().unwrap().vps.iter().any(|v| v.host == host && v.ssh_port == ssh_port) {
        return Err(trs!("Этот сервер уже в списке — удали его с сервера или из списка, чтобы поставить заново").into());
    }
    let _b = busy(&st)?;
    let t = Target { host: host.clone(), port: ssh_port, user: "root".into(), host_key: Some(fingerprint) };
    let a = app.clone();
    let lg = move |s: String| log(&a, tr!("свой сервер: {s}"));
    let f = fetcher(probe_proxy(&st));
    let r = vps::install(&t, login, vps::InstallOpts { name: name.clone(), port: 443 }, &f, &lg).await;
    let (mut v, sec) = match r {
        Ok(x) => x,
        Err(e) => {
            log(&app, tr!("свой сервер: ошибка — {e}"));
            return Err(e);
        }
    };
    v.sealed = vps::seal(&sec)?;
    let link = v.owner_link(&name);
    {
        let mut s = st.store.lock().unwrap();
        s.import_links(&link);
        let node_id = s.servers.iter().find(|n| n.link == link).map(|n| n.id.clone()).unwrap_or_default();
        let _ = s.set_group(std::slice::from_ref(&node_id), Some(trs!("Мои сервера")));
        v.node_id = node_id;
        s.vps.push(v);
    }
    persist(&st);
    log(&app, tr!("свой сервер «{name}» готов и добавлен в список (папка «{}»)", trs!("Мои сервера")));
    changed(&app);
    Ok(view(&st))
}

fn store_name(n: &str) -> Res<String> {
    rxvpn_core::store::clean_name(n, 40)
}

#[tauri::command]
pub(crate) async fn vps_restart(app: AppHandle, st: State<'_, AppState>, id: String) -> Res<View> {
    let _b = busy(&st)?;
    let (v, sec) = get(&st, &id)?;
    vps::restart(&v, &sec).await?;
    log(&app, tr!("свой сервер «{}»: Xray перезапущен", v.name));
    Ok(view(&st))
}

#[tauri::command]
pub(crate) async fn vps_update(app: AppHandle, st: State<'_, AppState>, id: String) -> Res<View> {
    let _b = busy(&st)?;
    let (mut v, sec) = get(&st, &id)?;
    log(&app, tr!("свой сервер «{}»: качаю свежий Xray…", v.name));
    let f = fetcher(probe_proxy(&st));
    let ver = vps::update_xray(&v, &sec, &f).await?;
    log(&app, tr!("свой сервер «{}»: Xray {} → {ver}", v.name, v.xray_version));
    v.xray_version = ver;
    save(&st, v);
    Ok(view(&st))
}

/// Убрать Xray с сервера и сервер из rxvpn. Защита сервера остаётся.
#[tauri::command]
pub(crate) async fn vps_uninstall(app: AppHandle, st: State<'_, AppState>, id: String, only_list: bool) -> Res<View> {
    let _b = busy(&st)?;
    let v = st.store.lock().unwrap().vps.iter().find(|v| v.id == id).cloned().ok_or(trs!("Сервер не найден"))?;
    if !only_list {
        let sec = vps::unseal(&v)?;
        vps::uninstall(&v, &sec).await?;
        log(&app, tr!("свой сервер «{}»: Xray удалён, вход по паролю снова включён (ufw и fail2ban остались)", v.name));
    }
    {
        let mut s = st.store.lock().unwrap();
        s.vps.retain(|x| x.id != id);
        s.remove_server(&v.node_id);
    }
    persist(&st);
    changed(&app);
    Ok(view(&st))
}

async fn apply_friends(app: &AppHandle, st: &AppState, v: Vps, sec: &vps::Secrets, what: String) -> Res<View> {
    vps::apply(&v, sec).await?;
    log(app, tr!("свой сервер «{}»: {what}", v.name));
    save(st, v);
    Ok(view(st))
}

#[tauri::command]
pub(crate) async fn vps_friend_add(app: AppHandle, st: State<'_, AppState>, id: String, name: String) -> Res<View> {
    let name = plan::friend_name(&name)?;
    let _b = busy(&st)?;
    let (mut v, sec) = get(&st, &id)?;
    if v.friends.len() >= 50 {
        return Err(trs!("Больше 50 друзей на сервер — перебор").into());
    }
    v.friends.push(Friend { id: plan::friend_id(), name: name.clone(), uuid: plan::uuid_v4(), enabled: true, limit_gb: 0, expires: 0 });
    apply_friends(&app, &st, v, &sec, tr!("добавлен друг «{name}»")).await
}

#[tauri::command]
pub(crate) async fn vps_friend_set(app: AppHandle, st: State<'_, AppState>, id: String, fid: String, enabled: Option<bool>, delete: bool) -> Res<View> {
    let _b = busy(&st)?;
    let (mut v, sec) = get(&st, &id)?;
    let i = v.friends.iter().position(|f| f.id == fid).ok_or(trs!("Друга уже нет"))?;
    let name = v.friends[i].name.clone();
    let what = if delete {
        v.friends.remove(i);
        tr!("друг «{name}» удалён")
    } else {
        let on = enabled.unwrap_or(!v.friends[i].enabled);
        v.friends[i].enabled = on;
        tr!("друг «{name}» {}", if on { trs!("включён") } else { trs!("отключён") })
    };
    apply_friends(&app, &st, v, &sec, what).await
}

/// Лимит трафика (ГБ, 0 — без лимита) и срок (дней от сегодня, 0 — бессрочно) для друга.
/// Сервер сам отключит его, когда кончится одно из двух, — даже если этот комп выключен.
#[tauri::command]
pub(crate) async fn vps_friend_limits(app: AppHandle, st: State<'_, AppState>, id: String, fid: String, limit_gb: u32, days: u32) -> Res<View> {
    if limit_gb > 100_000 || days > 3650 {
        return Err(trs!("Лимит — до 100 000 ГБ, срок — до 10 лет").into());
    }
    let _b = busy(&st)?;
    let (mut v, sec) = get(&st, &id)?;
    let i = v.friends.iter().position(|f| f.id == fid).ok_or(trs!("Друга уже нет"))?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    v.friends[i].limit_gb = limit_gb;
    v.friends[i].expires = if days == 0 { 0 } else { now + days as i64 * 86_400 };
    let name = v.friends[i].name.clone();
    let lim = if limit_gb == 0 { trs!("без лимита").to_string() } else { tr!("{limit_gb} ГБ") };
    let till = if days == 0 { trs!("бессрочно").to_string() } else { tr!("на {days} дн.") };
    apply_friends(&app, &st, v, &sec, tr!("друг «{name}»: {lim}, {till}")).await
}

/// Мост для белых списков: этот VPS (в российском облаке) отправляет весь трафик на
/// выходной сервер из списка (`exit` — id сервера; пусто — снова обычный сервер).
/// Если сервер для белых списков ещё не выбран — им становится этот мост.
#[tauri::command]
pub(crate) async fn vps_set_exit(app: AppHandle, st: State<'_, AppState>, id: String, exit: String) -> Res<View> {
    let _b = busy(&st)?;
    let (mut v, sec) = get(&st, &id)?;
    let name = if exit.is_empty() {
        v.exit.clear();
        None
    } else {
        let n = {
            let s = st.store.lock().unwrap();
            s.servers.iter().find(|n| n.id == exit).cloned().ok_or(trs!("Сервер не найден"))?
        };
        if n.id == v.node_id || n.link == v.owner_link(&v.name) {
            return Err(trs!("Выходной сервер — другой сервер, не сам мост").into());
        }
        rxvpn_core::parse_link(&n.link).map_err(|e| tr!("выходной сервер: {e}"))?;
        v.exit = n.link.clone();
        Some(n.name)
    };
    let what = match &name {
        Some(n) => tr!("мост для белых списков, выход через «{n}»"),
        None => trs!("снова обычный сервер, без моста").to_string(),
    };
    let node_id = v.node_id.clone();
    let r = apply_friends(&app, &st, v, &sec, what).await?;
    if name.is_some() {
        let mut s = st.store.lock().unwrap();
        if s.settings.wl_server.is_empty() && s.servers.iter().any(|n| n.id == node_id) {
            let sub = s.servers.iter().find(|n| n.id == node_id).and_then(|n| n.sub_id.clone()).unwrap_or_default();
            s.settings.wl_server = node_id;
            s.settings.wl_server_sub = sub;
            drop(s);
            persist(&st);
            log(&app, trs!("мост выбран сервером для белых списков"));
        }
    }
    Ok(r)
}

/// Обнулить накопленный трафик друга (например, новый месяц) — и снять отключение по лимиту.
#[tauri::command]
pub(crate) async fn vps_friend_reset(app: AppHandle, st: State<'_, AppState>, id: String, fid: String) -> Res<View> {
    let _b = busy(&st)?;
    let (v, sec) = get(&st, &id)?;
    let f = v.friends.iter().find(|f| f.id == fid).ok_or(trs!("Друга уже нет"))?.clone();
    vps::reset_usage(&v, &sec, &f).await?;
    // Отключённого по лимиту вернуть в работающий Xray — переписываем конфиг.
    apply_friends(&app, &st, v, &sec, tr!("трафик друга «{}» обнулён", f.name)).await
}

fn link_of(st: &AppState, id: &str, fid: Option<&str>) -> Res<String> {
    let s = st.store.lock().unwrap();
    let v = s.vps.iter().find(|v| v.id == id).ok_or(trs!("Сервер не найден"))?;
    Ok(match fid {
        Some(f) => v.friend_link(v.friends.iter().find(|x| x.id == f).ok_or(trs!("Друга уже нет"))?),
        None => v.owner_link(&v.name),
    })
}

#[tauri::command]
pub(crate) async fn vps_qr(st: State<'_, AppState>, id: String, fid: Option<String>) -> Res<String> {
    qr::svg(&link_of(&st, &id, fid.as_deref())?)
}

#[tauri::command]
pub(crate) async fn vps_copy(st: State<'_, AppState>, id: String, fid: Option<String>) -> Res<()> {
    let link = link_of(&st, &id, fid.as_deref())?;
    arboard::Clipboard::new().and_then(|mut c| c.set_text(link)).map_err(|e| tr!("буфер обмена: {e}"))
}

#[derive(Serialize)]
pub(crate) struct Traffic {
    /// id друга или "owner" → (вверх, вниз, отключён сервером по лимиту/сроку), байты.
    by: HashMap<String, (u64, u64, bool)>,
}

#[tauri::command]
pub(crate) async fn vps_traffic(st: State<'_, AppState>, id: String) -> Res<Traffic> {
    let _b = busy(&st)?;
    let (v, sec) = get(&st, &id)?;
    let raw = vps::traffic(&v, &sec).await?;
    let mut by = HashMap::new();
    if let Some(x) = raw.get(plan::OWNER_EMAIL) {
        by.insert("owner".to_string(), (x.up, x.down, false));
    }
    for f in &v.friends {
        if let Some(x) = raw.get(&f.email()) {
            by.insert(f.id.clone(), (x.up, x.down, x.blocked));
        }
    }
    Ok(Traffic { by })
}

/// Сохранить ключ SSH rxvpn в файл: без него, если Windows переставят или
/// сменится комп, в сервер (пароль выключен) не попасть.
#[tauri::command]
pub(crate) async fn vps_export_key(app: AppHandle, st: State<'_, AppState>, id: String) -> Res<Option<String>> {
    let (v, sec) = get(&st, &id)?;
    let name = format!("rxvpn-{}.key", v.host.replace(':', "_"));
    let Some(path) = pick_file(&app, trs!("Сохранить ключ SSH сервера"), (trs!("Ключ OpenSSH"), &["key"]), Some(name)).await? else {
        return Ok(None);
    };
    std::fs::write(&path, sec.ssh_key.as_bytes()).map_err(|e| tr!("не записать: {e}"))?;
    log(&app, tr!("свой сервер «{}»: ключ SSH сохранён в {}", v.name, path.display()));
    Ok(Some(path.display().to_string()))
}
