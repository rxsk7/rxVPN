# rxvpn — памятка для следующего чата

## Где что
- `core/` — вся логика (без окна). Главное: `xray.rs` (конфиг Xray, Settings, маршруты, site_servers,
  node_tweaks), `runner.rs` (xray только через stdin, core_guard), `store.rs` (state.json, DPAPI),
  `checks.rs` (IP, DNS-утечка, IPv6, скорость), `batch.rs`, `stats.rs`, `services.rs`, `diag.rs`,
  `zapret.rs`, `tgproxy.rs`, `net.rs`, `winsys.rs`, `defang.rs`, `export.rs`.
- `src-tauri/src/lib.rs` — команды окна, «Авто», трей, монитор, профили по сети. `ui/` — окно
  (только textContent, строгий CSP, без inline-обработчиков).

## Сборка в облачном контейнере (важно!)
static.rust-lang.org закрыт — `rustup target add x86_64-pc-windows-gnu` не работает. Обход:
1. Исходники std той же версии, что rustc (1.97.0, коммит 2d8144b7…): sparse-клон
   `rust-lang/rust` (только `library/`) + подмодуль `library/backtrace` по коммиту из дерева →
   положить в `$(rustc --print sysroot)/lib/rustlib/src/rust/library`.
2. `mkdir $(rustc --print sysroot)/lib/rustlib/x86_64-pc-windows-gnu` и обёртка `rustup` в PATH,
   которая в `rustup target list` дописывает `(installed)` у x86_64-pc-windows-gnu (tauri проверяет так).
3. `export RUSTC_BOOTSTRAP=1 CARGO_UNSTABLE_BUILD_STD=std,panic_abort` — и как обычно:
   `cargo tauri build --target x86_64-pc-windows-gnu --no-bundle`, тесты `--target x86_64-pc-windows-gnu --no-run` → wine.
- apt: `mingw-w64 wine wine64`; tauri-cli: `cargo install tauri-cli --version '^2' --locked`.
- Docker Hub закрыт; тестовый «VPS» для этапа 1: debootstrap noble (+systemd, openssh-server) →
  `docker import` → `docker run --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw
  --tmpfs /run --tmpfs /run/lock -p 2222:22 IMG /sbin/init`. dockerd запускать руками.
- Linux-xray 26.10.21: GitHub release, сверка .dgst (SHA2-256 0eec3ed4…1978).
- Исходники std кладутся заново в каждом контейнере; `library/backtrace` — отдельный клон backtrace-rs по коммиту
  из `git ls-tree HEAD library/backtrace`. Живые тесты: `XRAY_DIR=… cargo test -p rxvpn-core --test runner -- --ignored --test-threads=1`.
- Макет окна: скрипт Playwright с заглушкой `window.__TAURI__` (invoke: get_view → View-JSON) — в репо не лежит,
  пишется за 5 минут (минимальный View: servers, settings{…списки пустые}, tg{}).
- clippy на linux — только `-p rxvpn-core` (для src-tauri нужен GTK; с `libgtk-3-dev libwebkit2gtk-4.1-dev
  libayatana-appindicator3-dev librsvg2-dev libsoup-3.0-dev` работает и `cargo check -p rxvpn` — быстрее Windows-сборки).
- Wine: `WINEPREFIX` — в папке, которой владеет root (не /home/claude), напр. /root/wine/pfx. Тесты `doh.rs` — из
  папки `core` (фикстуры по относительному пути). Windows-xray — из portable `data/core`, `XRAY_DIR='Z:\…'`.
- Если в контейнере нет коммита 2d8144b78 для `git fetch` — тег `1.97.0` (тот же коммит).

## Сделано
- 0.12.0 — аудит перед публикацией:
  - `src-tauri/build.rs`: релиз без RXVPN_UPDATE_REPO/RXVPN_UPDATE_PUBKEY падает (обход — RXVPN_ALLOW_NO_UPDATES=1).
    Сборка 0.14.2+: репозиторий `rxsk7/rxVPN` (0.12–0.14.1 собраны с несуществующим `rxmv/rxvpn` — у них обновления не найдутся), публичный ключ f5df55b7…88b8; приватный — у владельца, НЕ в репозитории.
  - `webview_dir`: копия с правами — профиль WebView2 в `%ProgramFiles%\rxvpn\webview`.
  - `core/src/guard.rs`: снимок охраняемых настроек в `%ProgramFiles%\rxvpn\settings-guard.json`, пишется в `persist`
    копией с правами; при старте с правами — `guard_settings` (MessageBox, по умолчанию «Нет» → revert).
  - `Store::fresh` (нет state.json): случайные порты 20000–39999 + encrypt_state=true. `Settings::default` не менялся.
  - Не сделано: kill switch (WFP) в TUN, подпись exe, SOCKS с паролем (сломает программы, настроенные на прокси).
- 0.11.0 — с правами администратора rxvpn работает только из защищённой копии (защита от «вирус → админ»).
  Установщика нет (решение владельца: только портативная).
  - `core/src/protect.rs`: копия в `%ProgramFiles%\rxvpn` (KnownFolder): rxvpn.exe (сам себя — доверие с
    первого раза), WebView2Loader.dll / xray.exe / wintun.dll — только с хешами из `KNOWN` (обновить при
    смене версии Xray/webview2-com-sys!), иначе ядро — с GitHub со сверкой .dgst (`net::fetch_core_zip`).
    `state()` → Ready / Missing / Different (сверка sha256 rxvpn.exe). Сначала проверка всего, потом запись.
  - lib.rs `run()`: запущены с правами НЕ из копии → `protect_and_launch` (Different — MessageBox «Да/Нет»:
    обновлял сам?), запуск копии с теми же аргументами + `--data <папка data портативной>` + `--relaunched`,
    выход. `elevate()`: копия Ready — UAC сразу на неё (в окне путь Program Files), иначе UAC на себя.
    Копия: `Paths.protected`, core/zapret_bin — в Program Files, данные — из `--data`
    (`protect::valid_data_dir`: абсолютный, есть, не UNC/сетевой), списки geo*.dat — `data\core`
    (`runner::set_asset_dir`, `sync_assets`). «Скачать ядро» в копии без прав — ошибка.
  - Автозапуск с правами — задача планировщика `rxvpn\Autostart` на копию (`core/src/autostart.rs`, XML с SID,
    LogonTrigger + InteractiveToken + HighestAvailable, аргументы `--data "…" --autostart --relaunched`;
    XML — во временный файл в папке копии). Создаёт её копия с правами; ключ HKCU Run удаляется.
    Пришли без прав по `--autostart` с run_as_admin — UAC НЕ просим (лог-подсказка).
  - Аудит 0.10.1 + N1: `open_tg_link` от админа не открывает tg:// (обработчик из HKCU), ссылка — в буфер.
  - Слабое место: rxvpn.exe копируется из портативной папки (первый раз и при «Да» на обновление).
    Закрыть — только подписью exe.
  - **Живьём на Windows не проверено**: UAC на копию, задача планировщика, вход без UAC, обновление копии.
- 0.10.0, этап 5 — фильтры серверов:
  - `core/src/filter.rs`: `SubFilter{countries, words}` в `Subscription.filter` (serde default/skip — старый state.json
    читается, обновление подписки фильтр не трогает), `ListFilter{hide_dead, dedup}` в `Store.list_filter`.
    `parse(страны, слова)` — ввод из окна (ошибка — какую страну не узнали), `sanitize()` — для state.json/бэкапа
    (в `fix_names`). Страна: флаги → иначе названия из `COUNTRIES` (по началу слова, «=слово» — целиком) + коды
    заглавными отдельным словом. `hidden(store, dead) -> id→Hide{Filter,Dup,Dead}`: выбранный не скрывается;
    дубли — `same_key` (узел без id/имени/ссылки, адрес/SNI/host в нижнем регистре; raw — outbound без tag),
    победитель: выбранный → свой → выше; мёртвые — если остался хоть один живой. `visible`, `checkable` (без dead).
  - `stats.rs`: `Stats.dead` (id → время провала, удачная проверка снимает, `DEAD_TTL` сутки, prune).
  - lib.rs: `dead_ids` (замок stats отдельно, ДО замка store), `visible_servers`; «Авто» в `start_core_ex`,
    `speed_all`, трей — видимые; `test_all` — `checkable`. Команды `set_sub_filter`, `set_list_filter`
    (`apply_filter`: в «Авто» поменялся набор — `connect_any`), `sub_countries`. `ServerView.hidden`, `View.list_filter`.
  - Окно: «Фильтр» у подписки и «Фильтры» над списком — один `dlg-filter`; «Скрыто N» (`showHidden`, localStorage
    `show-hidden`) — скрытые тусклые с причиной (`HIDE_TEXT`). `shown()`/`checkable()` в app.js — для счётчиков,
    «Самый быстрый», «Скорость всех», «Проверить все».
  - Тесты: `filter::tests` (страны, ввод, дубли, мёртвые, переживает обновление/бэкап, чужой фильтр, 12 000 серверов
    <300 мс в release), `stats::tests::dead_mark`.
- 0.10.0, этап 2 — «Сообщить о проблеме» + Telegram без VPN на главной:
  - `core/src/report.rs`: `Secrets::from_store` (адреса/SNI/host серверов → `<сервер-N>` целым словом; ссылки, UUID,
    пароли, pbk/sid, путь ws, поля raw JSON, URL подписок, VPS, WARP, tg_secret, SSID/BSSID) + шаблоны (ссылки кроме
    `PUBLIC_HOSTS`, UUID, публичные IPv4/IPv6 кроме DNS/Telegram, ключи ≥32, логин@хост, `Users\имя`, имя из env).
    `report::build` — текст целиком через `redact`. Тесты `report::tests` (cuts_all_secrets — что вырезано и что осталось).
  - `src-tauri/src/reportui.rs`: `problem_report(error)` (версия Xray — `xray version`, Windows — реестр
    `winsys::windows_version`), `problem_report_copy/save` берут `AppState.last_report` (что показали, то и уходит).
    Итоги проверок — `note_check(st, вид, текст)` в diagnose/check_services/test_all/real_delay/check_ip/check_dns/
    speed_test/zapret_test (`AppState.checks`, по одной на вид).
  - Окно: `dlg-report`, кнопка в «Ещё», «Сообщить о проблеме» в красном тосте (`toast-report`, `lastError`).
  - Главная: `#tg-home` (галочка `chk-tg-home` → `tg_set`, при первом включении `tg_open`, localStorage `tg-linked`);
    счётчики обновляются раз в 5 с на главной/«Обходе».
  - «Мой IP и утечки» / «Скорость» — одно `dlg-checks`, но показывается только свой раздел (`openChecks(kind)`).
- 0.10.0, этап 3 — скорость серверов:
  - `checks::quick_speed` (один поток, время с первого куска, байты после него; таймаут → по скачанному ≥256 КБ),
    `batch::speed_all(_with)` (временный Xray со всеми, `SPEED_PARALLEL`=3, задержка → скачивание, `cancel`,
    кривой сервер — `runner::test_config` по одному и запуск без него). Живой тест `speed_all_live` (быстрый,
    медленный ~10 Мбит/с с таймаутом 2 с, мёртвый, «Стоп») — и на Linux-xray, и на Windows-xray под Wine.
  - `stats.rs`: `Bucket.sp/sn` (serde default — старый stats.json читается), `record_speed`, `speed()` (3 последних
    часа с замерами), `auto_key(ms, pct, mbps)` — общая формула «Авто». В lib.rs: `prefer` в `launch` и `best_alive`
    (через `net::pick_alive_by`) — по `stats.auto_key`.
  - Команды `speed_all` / `speed_all_cancel` (флаги `speed_all_busy`, `speed_all_cancel`), событие `speed-all-result`,
    `ServerView.mbps`, `View.speed_all`, итог — в `note_check("скорость серверов")` и лог.
  - Окно: «Скорость всех» (confirm с объёмом трафика; во время — «Стоп · n/N»), `speeds`, `.srv-nums` (мс + Мбит/с),
    `sortMode` "" / "1" / "mbps" (localStorage `sort`), `bestId()` по той же цене, что «Авто».
- 0.10.0, этап 4 — DNS без подмены:
  - `core/src/doh.rs`: `start(Config{upstream, listen, extra_root_pem})` → `Running{stats, addrs}`; `upstream(key, url)`
    (свой — `validate_url` + lookup_host до смены DNS, loopback-адреса отбрасываются); строгий разбор запроса
    (`parse_query`), ответ проверяется на тот же вопрос (`parse_response`), кэш ≤4096 с переписью TTL, TC для UDP,
    SERVFAIL при сбое, FORMERR на мусор. `extra_root_pem` — только тесты.
  - `core/src/sysdns.rs`: `targets(tun, v6)` (GetAdaptersAddresses: up, не loopback, со шлюзом, не TUN; DNS из реестра
    NameServer/DhcpNameServer), `apply/add/restore`, `apply_cmds/restore_cmds` (netsh, тесты планов), запись возврата —
    HKLM\SOFTWARE\rxvpn\DnsRestore (не в data\: её подменила бы программа без прав, а netsh запускается от админа);
    вне Windows — файл. netsh/ipconfig — через `GetSystemDirectoryW` + `runner::clean_env`.
  - `src-tauri/src/dohui.rs`: `doh_sync` раз в 3 с (галочка + «Без VPN» + zapret работает → вкл.; VPN/галочка/режим →
    сразу выкл.; zapret пропал — 20 с ждём), новые карты — `sysdns::add`; пауза 2 мин после ошибки; `doh_stop_now`
    в disconnect/трее; `doh_restore_blocking` в RunEvent::Exit и panic hook; при старте — возврат, если запись осталась
    (`doh_stuck` → health «dnsfix» → `doh_restore`, NEED_ADMIN → перезапуск от админа). `Settings.doh_sys/doh_provider/
    doh_url` меняет только `doh_set` (save_settings и бэкап их не трогают). Отчёт: DoH в «Состоянии», doh_url вырезается.
  - `diag::run(…, sys_doh, …)`: системный DNS — DoH → шаг DNS «через DoH rxvpn», адрес системы не сверяется как
    провайдерский. Тесты: `core/tests/doh.rs` (свой HTTPS DoH на тестовом CA из fixtures — живые UDP/TCP, кэш, TC,
    сертификат, чужой ответ, мусор; под Wine тоже), `system_resolver_sees_doh_not_spoof` (ignored, RXVPN_RESOLV_TEST=1,
    Linux root: «провайдер» с заглушкой на 127.0.0.2 → resolv.conf на наш DoH → getaddrinfo видит настоящий адрес).
  - **Живьём на Windows не проверено**: netsh на настоящих картах (Wi-Fi/Ethernet, IPv6), возврат после kill через
    диспетчер задач и после перезагрузки, Cloudflare/Google DoH из РФ.
- 0.9.0 (этап 1 нового плана) — гибрид для любых сайтов: `Settings.hybrid_services: Option<Vec<key>>` (None —
  старый state.json → YouTube+Discord), `hybrid_sites` (только имена, `zapret_target`). `xray::HYBRID_SERVICES`
  (youtube/discord/twitch; Twitch — по v2fly domain-list-community). Одна галочка = правило «напрямую» +
  DNS напрямую + хост в list-general-user.txt (`ZapretCfg.hybrid_hosts`, и в «Без VPN» тоже) + цели подбора в
  гибриде (`hybrid_targets`). `diag_apply("zapret")` в режиме VPN → `hybrid_sites` + `zapret_hybrid = true` +
  перезапуск VPN. Фоновая проверка гибрида (HEALTH_TARGETS) по-прежнему смотрит YouTube/Discord.
  Дальше по плану из промпта: этап 2 «Сообщить о проблеме», 3 скорость серверов, 4 DoH в «Без VPN»,
  5 фильтры подписок, 6 английский интерфейс.
- 0.8.1 — раскладка окна: вкладки Главная · Сервера · Маршруты · Обход · Ещё (`PAGES` в app.js). «Обход» — zapret
  (гибрид), Telegram без VPN, Tor, WARP; «Маршруты» — режим, «Сайты и программы», «Где ты подключаешься» (профили,
  белые списки). У сервера — «Сервисы» + меню «⋯» (`openMenu` в app.js). «Что нового в 0.8» в «Ещё» (скрывается,
  localStorage `wn-0.8`), плашки `.new-tag`. Макеты/скриншоты окна без Tauri: открыть ui/index.html в Chromium
  (Playwright) с заглушкой `window.__TAURI__` (invoke → View из JSON).
- 0.8.0 — этапы 3, 6, 5:
  - WARP (`core/src/warp.rs`, `src-tauri/src/warpui.rs`): учётка как у wgcf (API v0a5641, TLS 1.2, AES-256-GCM),
    `Store.warp` → сервера `warp-…` (`Store::sync_warp`, вызывается в fix_selection/load). Wireguard (noKernelTun,
    MTU 1280) с `dialerProxy: warp-via` на исходящие «подложки». Живой тест `warp_over_server_live` — WG внутри VLESS
    до локального Xray с wireguard-входом (на 127.0.0.1 стек WG Xray не ходит — сайт на IP сетевой карты).
    **Регистрация у Cloudflare живьём не проверена** (из контейнера API закрыт).
  - Запасной в «Сайт → сервер» (`SiteServer.backup/backup_sub`, `site_plan` в xray.rs): копии `sp-NN`/`sb-NN`,
    помощники `sh-NN-…` (селектор — префикс!), balancer `bal-NN` leastPing + fallbackTag, observatory `sp-`.
    Живой тест `site_backup_live`.
  - Tor (`core/src/tor.rs`, feature `tor` — включает src-tauri): arti-client =0.47.0 (rustls, без compression),
    свой SOCKS5 (только CONNECT, 127.0.0.1) + IsolationToken по сайту; `channel.outbound_proxy` = вход Xray `tor-up`
    (→ VPN). rusqlite понижен до 0.40 (tor-dirmgr <0.41). `TorMode` Off/Onion/Sites/All, `RunOpts.tor`; Arti не
    запустилась — исходящий `tor` = blackhole. Arti живёт в AppState между перезапусками Xray (`ensure_tor`).
    **Сеть Tor живьём не проверена** (из контейнера закрыта); мосты/PT не делали — только VPN → Tor.
  - Белые списки (`core/src/whitelist.rs`): «белые» .ru + обычные по IP (1.1.1.1/8.8.8.8/9.9.9.9) и 2 по имени,
    через вход Xray `direct-probe` (мимо VPN и TUN). `wl_react` в мониторе при fails==2: Whitelist → selected =
    `wl_server`, `wl_prev` = откуда; раз в 5 минут проверка, Normal → обратно. Ручной выбор/подключение — `reset_auto`
    чистит `wl_prev`. Живьём не проверено (нужен мобильный интернет с режимом).
- 0.7.0 — этапы 1, 2, 4:
  - «Свой сервер» (`core/src/vps/`: `ssh.rs` — russh+SFTP с TOFU, `plan.rs` — конфиг/ключи/скрипты,
    `mod.rs` — install/apply/restart/update_xray/traffic/uninstall; окно — `src-tauri/src/vpsui.rs`,
    диалоги `dlg-vps`, `dlg-vpsman`). Живой тест `core/tests/vps.rs` (контейнер, см. ниже):
    TOFU-отказ, установка, пароль выключен, трафик через сервер, локалка сервера закрыта, друзья,
    статистика, обновление, удаление. Секреты сервера — `Vps.sealed` (DPAPI, всегда).
    Debian 12 живьём не гонял — только Ubuntu 24.04 (и Windows-сборка под Wine против того же контейнера).
    После проверки агентом исправлено: «Удалить с сервера» возвращает вход по паролю; кнопка
    «Сохранить ключ SSH»; ufw/fail2ban — на порт sshd с сервера ($SSH_CONNECTION), откат ufw если вход
    по ключу не прошёл; «пароль выключен» — по ответу запущенного sshd (authenticate_none); свои
    публичные IP сервера закрыты для клиентов; секреты привязаны к host/порту/отпечатку (подмена в бэкапе).
    Не сделано: `::ffff:0:0/96` в блок (Xray 26.10.21 не принимает такой CIDR в routing).
  - Автообновление (`core/src/update.rs`, `src-tauri/src/updui.rs`, утилита `core/examples/sign.rs`).
    Включается сборкой с `RXVPN_UPDATE_REPO=owner/repo` и `RXVPN_UPDATE_PUBKEY=<hex>`; без них выключено.
  - «Всё ли в порядке» (`core/src/health.rs`, `#health` на главной).
- 0.6.1 — этап 0: проверка DNS-утечки на ipleak.net (`checks::dns_leak_any`, `LeakService`,
  `IpleakApi`), bash.ws запасным, понятная ошибка. Живой тест `checks_live` проверяет оба и отказ обоих.

## Этап 6 — английский интерфейс
### Часть 1 (сделано, 0.10.0): Rust — ошибки, лог, уведомления, трей, отчёт
Решение: лог и «Сообщить о проблеме» переводятся (их читает сам пользователь; отчёт — на языке окна, в шапке
строка `lang: ru|en`; вырезание секретов от языка не зависит — тест `core/tests/i18n.rs`).
- Ключ = русский текст как в коде, английский — `locales/en.json` (корень репо, общий для core и src-tauri).
- Крейт `i18n-macros` (proc-macro, зависимость только serde_json): `en_lit!`/`en_format!` читают en.json **при
  компиляции** (OnceLock), литерал получает span русского — `format!` подхватывает `{x}` из места вызова, спецификаторы
  (`{:.1}`) работают. Нет перевода/пустой — `compile_error!`, в сборку непереведённое не попадёт. Пересборка при правке
  en.json — `cargo:rerun-if-changed` в `core/build.rs` и `src-tauri/build.rs`.
- `core/src/i18n.rs`: `tr!(…)` → String (`if en() { format!(EN) } else { format!(RU) }`), `trs!` → &'static str,
  `trc!` → `Text(ru, en)` для const (`.get()`). Язык — атомик (`set_lang`, `en()`, `lang()`), `resolve(setting)`,
  `system_lang()` (Windows: `GetUserDefaultUILanguage`, первичный 0x19/0x23/0x3F → ru, иначе en; вне Windows — LANG),
  `sanitize`. В юнит-тестах глобальный язык НЕ трогать (параллельно идут тесты с русским текстом); английский режим —
  только в `core/tests/i18n.rs` (свой процесс).
- `Settings.lang` ("" — как в Windows, "ru", "en"): меняет только команда `set_lang` (save_settings сохраняет старое,
  `validate_settings` отвергает мусор, `fix_names` чистит). При старте: язык системы → чтение state.json → язык из
  настроек. `set_lang` → `persist` + `refresh_tray`. `View.lang` — действующий язык ("ru"/"en").
- Не переводятся (пометка `// i18n-skip` или блок `i18n-skip-begin … i18n-skip-end`): основы названий стран для
  фильтра (`filter::COUNTRIES`), текст страниц-заглушек провайдера (`diag::is_stub`), `LOOSE_GROUP` (признак «без папки»,
  в ошибке — `trs!("Добавлены вручную")`), русские формы «день/дня/дней» (в en — day/days), файлы на сервере
  (`vps/plan.rs`: sysctl/sshd), Debug-вывод, eprintln. Отладочные `expect/panic!/assert!` скрипт не требует переводить.
- Имена целей проверок стали нейтральными: «YouTube video/images», «Twitch video/images», «Yandex» (они же ключи в
  `zapret::health_of`).
- Сравнения текста: `zapret.rs` — `starts_with(trs!("нет запуска winws.exe — не стратегия"))`; lib.rs `engine_warn` —
  `contains(trs!("не совпадает"))` → в en.json все 4 сообщения о подмене движка содержат «does not match» — не ломать!
- `scripts/i18n_check.py` (запускается из `cargo test`, `core/tests/i18n.rs`, на Windows пропускается): кириллический
  литерал вне tr!/trs!/trc!/тестов/комментариев/skip → ошибка; нет перевода, пустой, кириллица в переводе, другой набор
  подстановок `{…}` (позиционные — и по порядку), лишний ключ → ошибка. `--add` — дописать заготовки (пустые) и убрать
  лишние, `--missing F` — недостающие в JSON. Если есть `ui/i18n.js` — зовёт `scripts/i18n_ui.py` (`check(ROOT, check_table)`).
- Новые строки в Rust: пиши `tr!("…{x}…")`/`trs!("…")` сразу, потом `python3 scripts/i18n_check.py --add` и впиши перевод.

### Часть 2 (сделано, 0.10.0): окно
- `ui/i18n.js` (грузится после `ui/locales/en.js`, до app.js): `t(s, vars)` — `{name}` из vars, одним проходом (значение с
  `{x}` не раскрывается); таблица без прототипа. `tk(s)` — только пометка ключа для констант верхнего уровня
  (`HIDE_TEXT`, `MODE_HINT`, `ROUTE_HINT`, `PRESETS`, `ACT_LABEL`, `NET_ROUTE/NET_VPN`) — переводятся в месте
  использования `t(константа)`, иначе смена языка их бы не тронула. `i18n.lang()`, `i18n.set(l)` → true, если сменился.
- Язык: `localStorage["rxvpn.lang"]` при загрузке (окно не мигает русским) → в `render()` `i18n.set(V.lang)` →
  `langChanged()` (сброс `svcInfo`, опций `#ss-preset`, `fillPresets()`). Переключатель `#set-lang` → `set_lang` → render.
- Статичный текст index.html собирается ОДИН раз при загрузке (текстовые узлы + title/placeholder/aria-label, ключ — с
  схлопнутыми пробелами, края сохраняются); при смене языка меняются только те узлы, что всё ещё показывают наш текст
  (`shown`) — что app.js переписал сам, не трогаем. Данные пользователя (имена серверов) в перевод не попадают никогда.
  Если app.js временно меняет текст статичной кнопки — сохранять и возвращать сами узлы (`downloadCore`: childNodes).
- `translate="no"` (стандартный атрибут) — элемент и всё внутри не переводятся (переключатель «Язык · Language»).
- Локальные переменные `t` в app.js переименованы (box/bt/tg/tw/ta/lbl/nt/tr) — **не заводить переменную `t`**.
- Лог: регэксп ошибок — и «did not connect»; «[rxvpn] не подключился: » / «[rxvpn] did not connect: » — обе формы
  (лог на языке Rust в момент записи). `toLocaleString(i18n.lang())`.
- `scripts/i18n_ui.py` (зовёт i18n_check.py → идёт в `cargo test`): свой JS-лексер (строки, шаблоны с `${}` вложенно,
  комментарии, регэкспы); кириллица вне первого аргумента `t(`/`tk(` → ошибка, `${}` внутри t() → ошибка, регэксп с
  кириллицей → ошибка (пометка `// i18n-skip` / блок `i18n-skip-begin … -end`). `--add` — заготовки в en.js,
  `--list F` — все кириллические литералы. en.js: `// …` + `window.RX_EN = {JSON};`.
- Новые строки окна: `t("…{x}…", {x})` сразу, потом `python3 scripts/i18n_ui.py --add` и впиши перевод (глоссарий ниже).
- Проверено макетом (Playwright, заглушка `__TAURI__`): ru→en на лету — ни одной кириллицы во всём DOM (и в закрытых
  диалогах), en→ru — DOM совпадает с чистой русской загрузкой; ошибок консоли нет.
- Глоссарий (Rust и окно совпадают): Авто → Auto; ⚡ Авто → ⚡ Auto; Подключить/Отключить → Connect/Disconnect; Главная · Сервера · Маршруты · Обход · Ещё → Home · Servers · Routes · Bypass · More; Настройки →
  Settings; Лог → Log; «Скачать ядро» → “Download core”; «Сайт → сервер» → “Site → server”; «Только заблокированное»
  (Только блок.) → “Blocked only”; Обход РФ → Bypass Russia; Всё через VPN → Everything through VPN; «Без VPN» →
  “No VPN”; «мимо VPN» → “bypassing VPN”; «Весь комп» → “Whole PC”; «Браузер» → “Browser”; Прокси → Proxy;
  «Подобрать лучшую» → “Find the best”; «Обновить» → “Update”; «Стоп» → “Stop”; «Фильтр»/«Фильтры» → “Filter”/“Filters”;
  «Игровой фильтр» → “Game filter”; «Всё ли в порядке» → “Is everything OK”; «Вернуть DNS» → “Restore DNS”;
  «DNS без подмены» → “DNS without spoofing”; «Telegram без VPN» → “Telegram without VPN”; «Пускать устройства из
  домашней сети» → “Allow devices from home network”; «DNS через VPN» → “DNS through VPN”; «Свои сайты» → “Own sites”;
  «Через zapret, мимо VPN» → “Through zapret, bypassing VPN”; «Проверить обновления» → “Check for updates”;
  «Сообщить о проблеме» → “Report a problem”; «Правила» → “Rules”; «Обновить списки» → “Update lists”; Белые списки →
  Whitelists; Свой сервер → Own server; Мои сервера → My servers; «Добавлены вручную» → “Added manually”;
  «Скорость всех» → “Speed of all”; «Проверить все» → “Check all”; Подписка → Subscription. Кавычки «» → “”.

## Дальше
- Живьём проверить у себя: регистрацию WARP, Tor (.onion), белые списки на мобильном.
- После проверки агентом 0.8.0 исправлено: «Сайт → Tor» раньше правил редактора/программ; «Всё через Tor» — DNS
  только через VPN (местному — лишь адреса серверов); .onion в DNS → заглушка 198.51.100.254 → block; вход
  direct-probe — с паролем на запуск; порты Xray — одним вызовом и мимо порта tor-up; гонка wl_react; accept без пауз.
  Не сделано: Arti не гасится при «Отключить» (утечки нет — tor-up мёртв); изоляция по 2 меткам домена (не PSL);
  **проверить на Windows в TUN**: исходящий «tor» на 127.0.0.1 при autoOutboundsInterface (если не подключается —
  Tor в TUN закрыт, отказ закрытый). .onion в TUN не открывается (только через системный прокси, «Браузер»).
- Под Wine Xray для Windows не умеет UDP (WSAIoctl 10045): `warp_over_server_live` — только на Linux-xray.
- Tor: мосты (obfs4/snowflake — внешние lyrebird/snowflake-client, пинить хеши) для работы без VPN.
Разведка к этапам 3, 5, 6 — `docs/RESEARCH.md`. Тестовый VPS: `docs/test-vps-container.sh` (образ — из debootstrap, см. выше)
(debootstrap noble + маска-сайт openssl s_server на 443 и /etc/hosts — у контейнера нет HTTPS наружу).

### Старый план (этап 1 сделан)
1. Этап 1 — «Свой VPS одной кнопкой»: модуль `core/src/vps/` (russh 0.65 с feature `ring`+`rsa`,
   без aws-lc; russh-sftp 3; x25519 через curve25519-dalek 5 `MontgomeryPoint::mul_base_clamped`).
   План: TOFU-отпечаток → установка (фикс. команды, файлы по SFTP, служба под юзером xray, блок
   127.0.0.0/8 и локалок в конфиге сервера, ufw: сначала SSH-порт) → свой ed25519 (всегда DPAPI) →
   проверка входа по ключу новым подключением → `sshd_config.d/00-rxvpn.conf` → `sshd -t` → reload →
   повторная проверка, откат через старую сессию. Друзья = отдельные UUID, stats API 127.0.0.1.
2. Этап 2 — автообновление с подписью ed25519 (спросить репозиторий GitHub).
3. Этап 3 — WARP + запасной сервер в «Сайт → свой сервер».
4. Этап 4 — карточка «Всё ли в порядке».
5. Этап 5 — режим белых списков (сначала разведка с источниками).
6. Этап 6 — Tor на Arti (сначала доложить, что в актуальной arti реально работает: .onion, мосты,
   изоляция), выход Xray через локальный SOCKS Arti, режимы «.onion / Сайт→Tor / Всё через Tor».
