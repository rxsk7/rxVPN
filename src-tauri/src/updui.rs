//! Обновление rxvpn по кнопке (проверка — сама каждые 3 часа, с уведомлением, и кнопкой «Обновления» на главной).

use rxvpn_core::{tr, trs};
use super::*;
use rxvpn_core::update::{self, Manifest};

#[derive(Serialize, Clone)]
pub(crate) struct UpdateInfo {
    /// Обновления настроены в этой сборке (вшиты репозиторий и ключ).
    configured: bool,
    current: String,
    /// Есть новее — версия и заметки.
    version: Option<String>,
    notes: Option<String>,
}

static FOUND: Mutex<Option<Manifest>> = Mutex::new(None);

/// Найденное обновление — для плашки на главной: (версия, что нового).
pub(crate) fn found() -> Option<UpdateBrief> {
    FOUND.lock().unwrap().as_ref().map(|m| UpdateBrief { version: m.version.clone(), notes: m.notes.chars().take(300).collect() })
}

/// Есть версия новее (уже проверенная: подпись, хеш, версия) — коротко для главной.
#[derive(Serialize, Clone)]
pub(crate) struct UpdateBrief {
    version: String,
    notes: String,
}

fn info() -> UpdateInfo {
    let m = FOUND.lock().unwrap().clone();
    UpdateInfo {
        configured: update::REPO.is_some() && update::PUBKEY_HEX.is_some(),
        current: env!("CARGO_PKG_VERSION").into(),
        version: m.as_ref().map(|m| m.version.clone()),
        notes: m.map(|m| m.notes.chars().take(500).collect()),
    }
}

async fn check_now(st: &AppState) -> Res<UpdateInfo> {
    let proxy = probe_proxy(st).map(|p| format!("socks5h://127.0.0.1:{p}"));
    let cur = env!("CARGO_PKG_VERSION");
    // Через VPN (вдруг GitHub режут); не вышло — VPN мог как раз перезапускаться — напрямую.
    // Подмены можно не бояться: manifest подписан, exe сверяется по хешу.
    let m = match update::check(proxy.as_deref(), cur).await {
        Err(e) if proxy.is_some() => update::check(None, cur).await.map_err(|_| e)?,
        r => r?,
    };
    *FOUND.lock().unwrap() = m;
    Ok(info())
}

#[tauri::command]
pub(crate) async fn update_check(st: State<'_, AppState>) -> Res<UpdateInfo> {
    if update::REPO.is_none() || update::PUBKEY_HEX.is_none() {
        return Ok(info());
    }
    check_now(&st).await
}

/// Скачать, проверить, подменить exe и перезапуститься новым.
#[tauri::command]
pub(crate) async fn update_apply(app: AppHandle, st: State<'_, AppState>) -> Res<()> {
    let m = FOUND.lock().unwrap().clone().ok_or(trs!("Сначала «Проверить обновления»"))?;
    // Ещё раз целиком: между проверкой и кнопкой могло пройти время.
    update::verify(&m, update::PUBKEY_HEX.unwrap_or(""), update::REPO.unwrap_or(""), env!("CARGO_PKG_VERSION"))?;
    let proxy = probe_proxy(&st).map(|p| format!("socks5h://127.0.0.1:{p}"));
    log(&app, tr!("обновление: качаю rxvpn {}…", m.version));
    let exe_bytes = match update::download(&m, proxy.as_deref()).await {
        Err(e) if proxy.is_some() => update::download(&m, None).await.map_err(|_| e)?,
        r => r?,
    };
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    update::swap(&exe, &exe_bytes)?;
    // Это копия в Program Files: портативный rxvpn.exe (рядом с папкой data) — тоже
    // новый, иначе запуск с рабочего стола показал бы старую версию и спросил про
    // «другой rxvpn.exe».
    if let Some(p) = portable_exe(&st.paths) {
        match update::swap(&p, &exe_bytes) {
            Ok(()) => log(&app, tr!("обновление: портативный {} тоже обновлён", p.display())),
            Err(e) => log(&app, tr!("обновление: портативный {} не обновился ({e}) — распакуй новую версию туда сам", p.display())),
        }
    }
    log(&app, tr!("обновление: rxvpn {} на месте, перезапускаюсь", m.version));
    let was = running(&st);
    let mut cmd = std::process::Command::new(&exe);
    if st.paths.protected {
        // Без этого копия не знает, где сервера и настройки, и открылась бы пустой.
        cmd.arg("--data").arg(&st.paths.data);
    }
    cmd.arg("--relaunched");
    if was {
        cmd.arg("--connect");
    }
    if let Err(e) = cmd.spawn() {
        return Err(tr!("новая версия стоит, но не запустилась ({e}) — запусти rxvpn.exe сам"));
    }
    stop_core(&st);
    stop_zapret(&st);
    app.exit(0);
    Ok(())
}

/// rxvpn.exe портативной, от которой запущена копия: `<папка>\data` → `<папка>\rxvpn.exe`.
fn portable_exe(paths: &Paths) -> Option<PathBuf> {
    if !paths.protected || !paths.data.file_name().is_some_and(|n| n.eq_ignore_ascii_case("data")) {
        return None;
    }
    paths.data.parent().map(|d| d.join(rxvpn_core::protect::EXE)).filter(|p| p.is_file())
}

/// Каждые 3 часа (раз в сутки было мало: свежий релиз ждали до суток): есть новее —
/// уведомление и плашка на главной (ставится только по кнопке).
pub(crate) fn spawn_daily(app: AppHandle) {
    if update::REPO.is_none() || update::PUBKEY_HEX.is_none() {
        return;
    }
    if let Ok(exe) = std::env::current_exe() {
        update::cleanup(&exe);
    }
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(90)).await;
        let mut told: Option<String> = None;
        loop {
            let st = app.state::<AppState>();
            match check_now(&st).await {
                Ok(UpdateInfo { version: Some(v), .. }) if told.as_deref() != Some(v.as_str()) => {
                    notify(&app, trs!("Есть обновление rxvpn"), tr!("Версия {v}: Ещё → Настройки → «Обновить»"));
                    log(&app, tr!("обновление: есть rxvpn {v}"));
                    told = Some(v);
                    changed(&app);
                }
                Ok(_) => {}
                Err(e) => log(&app, tr!("обновление: проверить не вышло — {e}")),
            }
            tokio::time::sleep(Duration::from_secs(3 * 3600)).await;
        }
    });
}
