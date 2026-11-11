// Интерфейс rxvpn. Вся логика — в Rust, здесь только отрисовка и вызовы команд.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
let V = null;          // последнее состояние из Rust (View)
let pings = {};        // id сервера -> "wait" | {ms, error}
let busy = false;
let testing = false;
// Сортировка списка: "" — как в подписке, "1" — по задержке, "mbps" — по скорости.
let sortMode = ["1", "mbps"].includes(load("sort")) ? load("sort") : "";
/** Показывать скрытые фильтрами (тусклыми). */
let showHidden = load("show-hidden") === "1";
let speeds = {};       // «Скорость всех»: id -> "wait" | {mbps, error, skipped}
let speedRun = null;   // идёт «Скорость всех»: {done, total}
let autoDelays = {};   // «Авто»: id -> мс | null (живые замеры Xray)
let lastPing = null;   // задержка текущего сервера
const AUTO_ID = "auto";
let adminKind = "tun"; // зачем нужны права администратора: "tun" | "zapret" | "zapret-test"
const SPARK_LEN = 60;  // секунд на графике скорости
let spark = { down: [], up: [] };

// ---------- утилиты ----------
function store(k, v) { try { localStorage.setItem("rxvpn." + k, v); } catch {} }
function load(k) { try { return localStorage.getItem("rxvpn." + k); } catch { return null; } }

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text; // textContent — имена из подписок не исполнятся как HTML
  return e;
}

// Окна-листы открываются без «кольца» фокуса на первой кнопке — фокус на самом листе.
for (const d of document.querySelectorAll("dialog > .dlg")) { d.tabIndex = -1; d.autofocus = true; }

let toastTimer;
function toast(msg, isErr = false) {
  const box = $("toast");
  // Открытый модальный диалог лежит поверх всей страницы — сообщение, оставшись
  // снаружи, было бы под ним. Переносим его внутрь верхнего открытого диалога.
  const host = [...document.querySelectorAll("dialog[open]")].pop() || document.body;
  if (box.parentElement !== host) host.append(box);
  $("toast-text").textContent = msg;
  box.classList.toggle("err", isErr);
  // У ошибки — «Сообщить о проблеме»: отчёт сразу с её текстом (кроме окна отчёта самого).
  const canReport = isErr && host.id !== "dlg-report";
  $("toast-report").classList.toggle("hidden", !canReport);
  lastError = canReport ? msg : lastError;
  box.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => box.classList.remove("show"), canReport ? 9000 : isErr ? 6000 : 3500);
}
let lastError = null;

async function call(cmd, args) {
  try {
    return await invoke(cmd, args);
  } catch (e) {
    const msg = String(e);
    if (msg === "NEED_ADMIN") openAdmin(adminKind);
    else toast(msg, true);
    throw e;
  }
}

function msClass(ms) {
  if (ms === null || ms === undefined) return "bad";
  return ms < 300 ? "ok" : ms < 800 ? "mid" : "bad";
}

function fmtBytes(n) {
  if (n < 1024) return t("{n} Б", { n });
  const u = [t("КБ"), t("МБ"), t("ГБ"), t("ТБ")];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return `${n < 10 ? n.toFixed(1) : Math.round(n)} ${u[i]}`;
}

function ago(ts) {
  if (!ts) return t("ещё не обновлялась");
  const m = Math.round((Date.now() / 1000 - ts) / 60);
  if (m < 1) return t("только что");
  if (m < 60) return t("{m} мин назад", { m });
  if (m < 1440) return t("{n} ч назад", { n: Math.round(m / 60) });
  return t("{n} дн назад", { n: Math.round(m / 1440) });
}

/** Скорость сервера, Мбит/с: свежий замер «Скорость всех» или накопленная (stats). */
function mbpsOf(s) {
  const x = speeds[s.id];
  if (x && x !== "wait" && x.mbps != null) return x.mbps;
  return s.mbps ?? null;
}

/** «Цена» как у «Авто» (stats::auto_key без надёжности): задержка + 2000 / Мбит/с. */
function cost(s, ms) {
  const m = mbpsOf(s);
  return ms + (m == null ? 300 : Math.min(2000, 2000 / Math.max(m, 0.5)));
}

/** Видимые с учётом фильтров — из них выбирают «Авто», «Скорость всех», трей. */
const shown = () => (V?.servers ?? []).filter((s) => !s.hidden);
/** Что проверит «Проверить все»: видимые и мёртвые (чтобы ожившие вернулись). */
const checkable = () => (V?.servers ?? []).filter((s) => !s.hidden || s.hidden === "dead");
const HIDE_TEXT = { filter: tk("скрыт фильтром подписки"), dup: tk("дубль — такой же есть выше"), dead: tk("мёртвый — не ответил на последней проверке"), plain: tk("без шифрования — в «Авто» не идёт") };
const filterOn = () => !!V && (V.list_filter?.hide_dead || V.list_filter?.dedup || V.subscriptions.some((x) => x.filter?.countries?.length || x.filter?.words?.length));

/** id лучшего из проверенных: по задержке и скорости, как выбирает «Авто». */
function bestId() {
  let best = null, bestCost = Infinity;
  for (const s of shown()) {
    const p = pingOf(s.id);
    if (p && p !== "wait" && p.ms != null && cost(s, p.ms) < bestCost) { best = s.id; bestCost = cost(s, p.ms); }
  }
  return best;
}

// ---------- отрисовка ----------
/** Что-то включено: VPN или zapret. */
const isOn = () => !!V && (V.connected || V.zapret_active);
const curMode = () => (V.settings.zapret ? "zapret" : V.settings.tun ? "tun" : "proxy");
const MODE_HINT = {
  proxy: tk("Через VPN — браузер, Telegram и программы, которые слушаются системного прокси"),
  tun: tk("Через VPN — весь компьютер, включая игры (нужны права администратора)"),
  zapret: tk("VPN-сервер не нужен: YouTube и Discord напрямую, мимо «замедлялки» провайдера (zapret)"),
};
const ROUTE_HINT = {
  bypassru: tk("Российские сайты — напрямую, всё остальное — через VPN"),
  blocked: tk("Через VPN — только заблокированное в России (~75 000 сайтов), остальное напрямую"),
  global: tk("Вообще всё через VPN"),
};

// ---------- вкладки ----------
const PAGES = ["home", "servers", "routes", "bypass", "more"];
let page = "home";
function showPage(p) {
  if (!PAGES.includes(p)) p = "home";
  page = p;
  document.querySelectorAll(".page").forEach((x) => x.classList.toggle("active", x.dataset.page === p));
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.page === p));
  if (p === "home") {
    document.querySelector('#tabs button[data-page="home"]').classList.remove("alert");
    const lg = $("log");
    lg.scrollTop = 0; // новые строки — сверху
  }
  store("page", p);
}
document.querySelectorAll("#tabs button").forEach((b) => (b.onclick = () => showPage(b.dataset.page)));
showPage(load("page") || "home");

function render() {
  if (!V) return;
  if (load("simple") === null) { store("simple", V.servers.length || V.subscriptions.length ? "0" : "1"); applySimple(); }
  if (V.lang && i18n.set(V.lang)) langChanged();
  renderVps();
  renderHealth();
  const sel = V.servers.find((s) => s.id === V.selected);
  const zMode = !!V.settings.zapret;

  const st = $("status");
  st.dataset.state = busy || V.zapret_testing ? "busy" : isOn() ? "on" : "off";
  $("status-text").textContent = busy ? t("Подождите…")
    : V.zapret_testing ? t("Подбираю стратегию zapret…")
    : V.zapret_active ? t("Без VPN · zapret")
    : V.connected ? (V.tun_active ? t("Подключено · весь комп") : t("Подключено")) + (V.hybrid_active ? t(" · YouTube через zapret") : "")
    : t("Отключено");

  const p = $("btn-connect");
  p.classList.toggle("on", isOn() && !busy);
  p.classList.toggle("busy", busy);
  // Во время подбора (и фонового) кнопка — «Отключить»: останавливает и подбор.
  p.setAttribute("aria-label", isOn() || V.zapret_testing ? t("Отключить") : t("Подключить"));
  renderHero();
  renderWelcome();

  if (zMode) {
    $("cur-name").textContent = t("Zapret · без VPN");
    $("cur-meta").textContent = V.zapret_active ? t("стратегия «{zapret_name}»", { zapret_name: V.zapret_name })
      : V.settings.zapret_strategy ? t("стратегия «{zapret_strategy}»", { zapret_strategy: V.settings.zapret_strategy })
      : t("нажми, чтобы подобрать стратегию");
  } else if (!V.servers.length) {
    $("cur-name").textContent = t("Нет серверов");
    $("cur-meta").textContent = t("Нажми и вставь ссылку на сервер или подписку");
  } else if (V.auto) {
    $("cur-name").textContent = t("⚡ Авто");
    $("cur-meta").textContent = V.connected
      ? (V.active_name ? t("сейчас: {active_name}", { active_name: V.active_name }) : t("выбираю самый быстрый…"))
      : t("самый быстрый из {n}, переключается сам", { n: shown().length });
  } else {
    $("cur-name").textContent = sel ? sel.name : t("Сервер не выбран");
    $("cur-meta").textContent = sel ? sel.summary : t("Нажми и выбери сервер");
  }

  document.querySelectorAll("#seg-mode button").forEach((b) =>
    b.classList.toggle("active", b.dataset.mode === curMode()));
  $("mode-hint").textContent = t(MODE_HINT[curMode()]);
  $("routes-note").classList.toggle("hidden", !zMode);
  $("route-field").classList.toggle("dimmed", zMode);
  document.querySelector(".servers").classList.toggle("muted-mode", zMode);
  const zOn = V.zapret_active || V.hybrid_active;
  setMeta("zapret-meta", zOn ? t("работает: {zapret_name}", { zapret_name: V.zapret_name }) : V.settings.zapret_strategy || t("не выбрана"), zOn);
  renderTg();
  renderDoh();
  $("chk-hybrid").checked = !!V.settings.zapret_hybrid && !zMode;
  $("chk-hybrid").disabled = zMode || !V.is_windows;
  // Сервисы гибрида: поля нет (старый state.json) — YouTube и Discord.
  const hs = V.settings.hybrid_services ?? ["youtube", "discord"];
  document.querySelectorAll(".hyb-svc input").forEach((c) => {
    c.checked = hs.includes(c.dataset.svc);
    c.disabled = zMode || !V.is_windows;
    c.closest("label").classList.toggle("soft", !V.settings.zapret_hybrid || zMode);
  });
  $("btn-hyb-sites").classList.toggle("soft", !V.settings.zapret_hybrid || zMode);
  const hn = (V.settings.hybrid_sites || []).filter((l) => l.trim() && !l.trim().startsWith("#"));
  setMeta("hyb-sites-meta", !hn.length ? t("нет") : hn.length <= 2 ? hn.join(", ") : t("сайтов: {length}", { length: hn.length }), hn.length > 0);
  document.querySelectorAll("#seg-route button, #seg-route-home button").forEach((b) =>
    b.classList.toggle("active", b.dataset.route === V.settings.route));
  $("route-hint").textContent = t(ROUTE_HINT[V.settings.route] ?? "");
  $("route-hint-home").textContent = t(ROUTE_HINT[V.settings.route] ?? "");
  // В «Без VPN» маршрутов нет — на главной их не показываем.
  $("route-home").classList.toggle("hidden", zMode);
  // Сервисы и обход — про VPN-сервер; в «Без VPN» их не показываем.
  $("ht-svc").classList.toggle("hidden", zMode);
  $("ht-tweak").classList.toggle("hidden", zMode);

  const real = (arr) => arr.filter((l) => l.trim() && !l.trim().startsWith("#")).length;
  const nd = real(V.settings.direct), np = real(V.settings.proxy);
  setMeta("sites-count", nd || np ? t("мимо: {nd} · VPN: {np}", { nd, np }) : t("не заданы"), nd || np);
  const appsN = V.settings.apps_mode === "only" ? real(V.settings.apps_proxy) : real(V.settings.apps_direct);
  setMeta("apps-count", !appsN ? t("не заданы")
    : V.settings.apps_mode === "only" ? t("только {appsN} через VPN", { appsN }) : t("мимо VPN: {appsN}", { appsN }), appsN);
  const rulesOn = V.settings.rules.filter((r) => r.enabled).length;
  setMeta("rules-count", rulesOn ? t("{rulesOn} активн.", { rulesOn }) : t("нет"), rulesOn);
  setMeta("net-meta", V.settings.net_profiles ? t("включено · своих сетей: {n}", { n: (V.settings.trusted_nets || []).length }) : t("выключено"), V.settings.net_profiles);
  const ss = V.settings.site_servers || [];
  const ssClosed = ss.filter((r) => !ruleServer(r) && !ruleBackup(r)).length;
  setMeta("sitesrv-count", !ss.length ? t("не заданы") : ssClosed ? t("закрыто: {ssClosed} — нет сервера", { ssClosed })
    : ss.length <= 3 ? ss.map((r) => r.name || t("без названия")).join(", ")
    : `${ss.length} ${ss.length === 4 ? t("правила") : t("правил")}`, ss.length && !ssClosed);
  $("sitesrv-count").classList.toggle("warn", ssClosed > 0);
  $("chk-ads").checked = !!V.settings.block_ads;
  const nWarp = V.servers.filter((x) => isWarp(x.id)).length;
  setMeta("warp-meta", nWarp ? t("серверов: {nWarp}", { nWarp }) : t("нет"), nWarp > 0);
  $("whatsnew").classList.toggle("hidden", load("wn-0.15") === "1");
  const torNames = { off: t("выключен"), onion: t("только .onion"), sites: t("сайты из списка"), all: t("всё через Tor") };
  const tm = V.settings.tor_mode || "off";
  setMeta("tor-meta", tm === "off" ? t("выключен") : V.tor ? `${torNames[tm]} · ${V.tor[0] ? t("готов") : t("подключается")}` : torNames[tm], tm !== "off");
  const wl = V.settings.wl_server && V.servers.find((x) => x.id === V.settings.wl_server && (x.sub_id || "") === (V.settings.wl_server_sub || ""));
  setMeta("wl-meta", V.wl_switched ? t("сейчас белые списки — на запасном") : wl ? `→ ${wl.name}` + (V.settings.wl_auto ? "" : t(" · вручную")) : t("сервер не выбран"), !!wl);

  $("speed").classList.toggle("idle", !V.connected);
  // На первом запуске ядро — шаг 1 мастера, плашка не нужна.
  $("banner-core").classList.toggle("hidden", V.core_installed || (!V.servers.length && !V.settings.zapret));
  const nShown = shown().length, nHid = V.servers.length - nShown;
  $("count").textContent = nHid ? t("{nShown} из {length}", { nShown, length: V.servers.length }) : V.servers.length;
  $("btn-filters").classList.toggle("on", filterOn());
  const bh = $("btn-hidden");
  bh.classList.toggle("hidden", !nHid);
  bh.classList.toggle("on", showHidden);
  bh.textContent = showHidden ? t("Скрыть {nHid}", { nHid }) : t("Скрыто {nHid}", { nHid });
  bh.title = showHidden ? t("Убрать скрытые фильтрами из списка") : t("Показать скрытые фильтрами (тусклыми)");

  const bt = $("btn-test");
  bt.disabled = testing || V.testing;
  bt.textContent = testing || V.testing ? t("Проверяю…") : t("Проверить все");
  const so = $("btn-sort");
  so.classList.toggle("on", !!sortMode);
  so.textContent = sortMode === "mbps" ? t("⇅ Мбит/с") : sortMode ? t("⇅ мс") : "⇅";
  so.title = sortMode === "mbps" ? t("Сейчас: по скорости. Нажми — без сортировки")
    : sortMode ? t("Сейчас: по задержке. Нажми — по скорости") : t("Сортировать: по задержке, потом по скорости");
  const sa = $("btn-speed-all");
  const runningHere = !!speedRun || V.speed_all;
  sa.classList.toggle("on", runningHere);
  sa.textContent = runningHere ? (speedRun ? t("Стоп · {done}/{total}", { done: speedRun.done, total: speedRun.total }) : t("Стоп")) : t("Скорость всех");
  sa.disabled = !nShown;
  renderList();
}

// ---------- главная: состояние крупно, таймер сессии ----------
let connSince = null; // когда подключились (по часам окна) — для таймера
function fmtClock(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  const p2 = (n) => String(n).padStart(2, "0");
  return `${p2(Math.floor(s / 3600))}:${p2(Math.floor((s % 3600) / 60))}:${p2(s % 60)}`;
}
// GIF с лавиной — только пока идёт подключение (то же `busy`, что красит кнопку): при каждом
// новом подключении — с первого кадра, после — выгружаем, чтобы не крутился зря.
const K2_GIF = "img/avalanche-k2.gif";
let gifShown = false;
let connecting = false; // нажали «Подключить» и ждём ответа (busy бывает и при отключении)
function renderAvalanche() {
  const want = busy && connecting && !matchMedia("(prefers-reduced-motion: reduce)").matches;
  $("btn-connect").classList.toggle("connecting", want);
  if (want === gifShown) return;
  gifShown = want;
  const img = document.querySelector("#btn-connect .k2-anim");
  if (want) {
    img.removeAttribute("src");
    img.src = K2_GIF;
  } else {
    setTimeout(() => { if (!gifShown) img.removeAttribute("src"); }, 400); // после плавного исчезновения
  }
}

function renderHero() {
  renderAvalanche();
  const on = isOn() && !busy;
  if (on && !connSince) connSince = Date.now();
  if (!isOn()) connSince = null;
  const label = $("power-label");
  label.classList.toggle("on", on);
  label.classList.toggle("busy", busy || !!V.zapret_testing);
  label.textContent = busy ? t("Подключаюсь…")
    : V.zapret_testing ? t("Подбираю стратегию…")
    : V.zapret_active ? t("Zapret работает")
    : V.connected ? t("Подключено")
    : V.paused ? t("Пауза")
    : t("Не подключено");
  let sub;
  if (busy || V.zapret_testing) sub = t("Подождите немного");
  else if (V.zapret_active) sub = t("без VPN · {name}", { name: V.zapret_name || "" }) + " · " + fmtClock(Date.now() - connSince);
  else if (V.connected) {
    const parts = [V.active_name || $("cur-name").textContent];
    if (lastPing) parts.push(t("{ms} мс", { ms: lastPing }));
    parts.push(fmtClock(Date.now() - connSince));
    sub = parts.join(" · ");
  } else if (V.kill_on) {
    // Xray упал, kill switch держит интернет закрытым.
    sub = t("Kill switch: интернет закрыт, пока VPN не вернётся");
    label.textContent = t("VPN упал");
    label.classList.add("busy");
  } else if (V.paused) {
    sub = V.pause_until ? t("VPN включится сам в {time} — или нажми на гору", { time: hhmm(V.pause_until) })
      : t("VPN выключен, пока не нажмёшь на гору");
  } else sub = V.servers.length || V.settings.zapret ? t("Нажми кнопку, чтобы подключиться") : "";
  $("hero-sub").textContent = sub;
  $("btn-kill-release").classList.toggle("hidden", !(V.kill_on && !V.connected && !busy));
  $("pause-row").classList.toggle("hidden", !(on && !V.zapret_testing));
}
// Часы:минуты по местному времени из unix-времени.
function hhmm(unix) {
  const d = new Date(unix * 1000), p = (x) => String(x).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}
// ---------- «Что-то не работает?» ----------
$("btn-help").onclick = () => $("dlg-help").showModal();
$("btn-help-close").onclick = () => $("dlg-help").close();
const HELP = {
  // Сервер не тот: проверить все и встать на самый быстрый.
  slow: () => { showPage("servers"); $("btn-fastest").click(); },
  // YouTube/Discord: уже есть zapret — подобрать стратегию; нет — показать, где включить.
  video: () => {
    if (V.settings.zapret || V.settings.zapret_hybrid) { openZapret().then(() => $("btn-z-test").click()); return; }
    showPage("bypass");
    document.querySelector('.scen[data-scen="zapret-field"]').click();
  },
  // Telegram: включён — подключить в Telegram; нет — показать переключатель.
  tg: () => {
    if (V.tg?.running) return tgOpen();
    showPage("bypass");
    document.querySelector('.scen[data-scen="tg-field"]').click();
  },
  site: () => openDiag(""),
  bank: async () => {
    if (!isOn()) return toast(t("VPN и так выключен — банк должен открыться. Не открывается — проверь сайт: «Не открывается сайт»"));
    const v = await call("pause_vpn", { minutes: 15 }).catch(() => null);
    if (!v) return;
    V = v;
    render();
    toast(t("Пауза: VPN включится сам в {time}", { time: hhmm(V.pause_until) }));
  },
  report: () => openReport(null),
};
for (const b of document.querySelectorAll("#dlg-help [data-help]")) {
  b.onclick = () => { $("dlg-help").close(); HELP[b.dataset.help](); };
}

// ---------- простой вид ----------
// Новым (на первом запуске серверов ещё нет) — простой; у тех, кто уже пользовался, — как было.
function applySimple() { document.body.classList.toggle("simple", load("simple") === "1"); $("chk-simple").checked = load("simple") === "1"; }
$("chk-simple").onchange = (e) => {
  store("simple", e.target.checked ? "1" : "0");
  applySimple();
  if (e.target.checked && (page === "routes" || page === "bypass")) showPage("home");
};
applySimple();

for (const b of document.querySelectorAll("#pause-row [data-pause]")) {
  b.onclick = async () => {
    if (busy) return;
    const minutes = Number(b.dataset.pause);
    const v = await call("pause_vpn", { minutes }).catch(() => null);
    if (!v) return;
    V = v;
    render();
    toast(minutes ? t("Пауза: VPN включится сам в {time}", { time: hhmm(V.pause_until) }) : t("VPN на паузе — включится, когда нажмёшь на гору"));
  };
}
setInterval(() => { if (V && connSince) renderHero(); }, 1000);
$("btn-kill-release").onclick = async () => {
  const v = await call("kill_release").catch(() => null);
  if (!v) return;
  V = v;
  render();
  toast(t("Блокировка снята — интернет работает без VPN"));
};

// ---------- первый запуск ----------
// Мастер: после первой ссылки rxvpn сам докачивает ядро, проверяет серверы, выбирает быстрый
// и подключается. wiz — его шаг (null — мастер не идёт); wizPending — ссылку добавляют с
// экрана приветствия, после импорта мастер продолжит сам.
let wiz = null, wizPending = false;
const WIZ_TEXT = {
  core: tk("качаю ядро Xray, ~30 МБ…"),
  check: tk("проверяю, какие серверы отвечают…"),
  connect: tk("подключаюсь к самому быстрому…"),
};
function renderWelcome() {
  const empty = !V.servers.length && !V.settings.zapret;
  const show = empty || !!wiz;
  $("welcome").classList.toggle("hidden", !show);
  document.querySelector('.page[data-page="home"]').classList.toggle("is-empty", show);
  $("wel-step-core").classList.toggle("done", !!V.core_installed);
  $("wel-step-core").classList.toggle("busy", wiz?.stage === "core");
  $("wel-core-meta").textContent = V.core_installed ? t("скачано") : t("движок VPN, ~30 МБ с GitHub");
  const n = V.servers.length;
  $("wel-step-add").classList.toggle("done", n > 0);
  $("wel-add-meta").textContent = n ? t("серверов: {n}", { n }) : t("ссылка vless:// и другие или подписка от VPN-сервиса");
  const go = $("wel-step-go"), stage = wiz?.stage;
  go.classList.toggle("wel-dim", !wiz);
  go.classList.toggle("busy", stage === "check" || stage === "connect");
  go.classList.toggle("done", stage === "done");
  go.classList.toggle("fail", stage === "fail");
  $("wel-go-meta").textContent = stage === "done" ? t("подключено: {name}", { name: V.active_name || "" })
    : stage === "fail" ? wiz.msg
    : WIZ_TEXT[stage] ? t(WIZ_TEXT[stage])
    : t("сам проверю серверы и подключусь к самому быстрому");
  $("wel-retry").classList.toggle("hidden", stage !== "fail");
  $("wel-skip").classList.toggle("hidden", stage !== "fail");
  $("wel-done").classList.toggle("hidden", stage !== "done");
  document.querySelector(".wel-alt").classList.toggle("hidden", n > 0); // сервер уже есть — обходные пути не нужны
}
async function runWizard() {
  if (wiz && wiz.stage !== "fail") return;
  wiz = { stage: "check" };
  render();
  try {
    if (!V.core_installed) {
      wiz.stage = "core";
      render();
      V = await call("download_core");
      wiz.stage = "check";
      render();
    }
    await runTest();
    const id = bestId();
    if (!id) {
      wiz = { stage: "fail", msg: t("Ни один сервер не ответил. Проверь интернет или возьми другую ссылку") };
      return render();
    }
    wiz.stage = "connect";
    render();
    V = await call("select_server", { id });
    if (!V.connected) V = await call("connect");
    wiz = V.connected ? { stage: "done" } : { stage: "fail", msg: t("Не подключилось — причина в логе") };
  } catch (e) {
    // Нужны права администратора — про это уже открылось своё окно; мастер уступает ему.
    wiz = String(e) === "NEED_ADMIN" ? null : { stage: "fail", msg: String(e) };
    V = await invoke("get_view").catch(() => V);
  }
  render();
}
$("wel-retry").onclick = runWizard;
$("wel-done").onclick = $("wel-skip").onclick = () => { wiz = null; render(); };
$("wel-core").onclick = (e) => downloadCore(e.currentTarget);
$("wel-paste").onclick = async (e) => {
  const b = e.currentTarget;
  b.disabled = true;
  try {
    const text = await call("read_clipboard");
    if (!text || !text.trim()) return toast(t("В буфере пусто — скопируй ссылку на сервер или подписку"), true);
    wizPending = true;
    await importText(text);
  } finally {
    wizPending = false;
    b.disabled = false;
  }
};
$("wel-type").onclick = () => { wizPending = true; showPage("servers"); $("import-text").focus(); };
$("wel-vps").onclick = () => $("btn-vps-new").click();
$("wel-zapret").onclick = () => document.querySelector('#seg-mode button[data-mode="zapret"]').click();

// ---------- «Обход»: что не работает ----------
for (const b of document.querySelectorAll(".scen[data-scen]")) {
  b.onclick = () => {
    const go = b.dataset.scen;
    if (go === "diag") return $("btn-diag").click();
    const g = $(go);
    g.scrollIntoView({ behavior: "smooth", block: "start" });
    g.classList.remove("flash");
    void g.offsetWidth; // перезапустить анимацию
    g.classList.add("flash");
  };
}

function setMeta(id, text, on) {
  const e = $(id);
  e.textContent = text;
  e.classList.toggle("on", !!on);
}

/** Результат для сервера: проверка «Проверить все» или живой замер «Авто». */
function pingOf(id) {
  if (pings[id]) return pings[id];
  if (V?.auto && V.connected && id in autoDelays) return { ms: autoDelays[id] };
  return null;
}

function sortKey(id) {
  if (sortMode === "mbps") {
    const s = V.servers.find((x) => x.id === id);
    const m = s && mbpsOf(s);
    return m == null ? 1e9 : -m;            // не мерили — в конец
  }
  const p = pingOf(id);
  if (!p || p === "wait") return 1e9 + 1;   // не проверен — в конец
  if (p.ms == null) return 1e9;            // не ответил — перед непроверенными
  return p.ms;
}

function renderList() {
  const list = $("server-list");
  const scroll = list.scrollTop;
  list.replaceChildren();

  if (V.servers.length === 0 && V.subscriptions.length === 0) {
    const e = el("div", "empty");
    e.append(t("Пусто. Вставь сверху ссылку "), el("b", "", "vless://…"),
      t(" или ссылку на подписку "), el("b", "", "https://…"), t(" и нажми «Добавить»."));
    list.append(e);
    return;
  }

  const best = bestId();
  if (shown().length > 1) list.append(autoRow());
  // Свои сервера: без папки, потом папки (в порядке появления), потом подписки.
  const all = showHidden ? V.servers : shown();
  const manual = all.filter((s) => !s.sub_id);
  const loose = manual.filter((s) => !s.group);
  if (loose.length) list.append(group({ key: "m", title: t("Добавлены вручную"), loose: true }, loose, best));
  for (const f of folderNames()) {
    list.append(group({ key: "f:" + f, title: f, folder: f }, manual.filter((s) => s.group === f), best));
  }
  for (const sub of V.subscriptions) {
    const total = V.servers.filter((s) => s.sub_id === sub.id).length;
    list.append(group({ key: "s:" + sub.id, title: sub.name, sub, total }, all.filter((s) => s.sub_id === sub.id), best));
  }
  list.scrollTop = scroll;
}

// ---------- «Почему не открывается сайт» ----------
let diagHost = "", diagRunning = false, diagRun = 0;
function stepLi(s) {
  const li = el("li", s.ok === true ? "ok" : s.ok === false ? "bad" : "na");
  li.append(el("span", "mark", s.ok === true ? "✓" : s.ok === false ? "✗" : "·"), el("span", "name", s.title), el("span", "", s.detail));
  return li;
}
function diagStep(s) {
  if (!diagRunning) return; // запоздавшее событие — итог уже показан
  $("diag-steps").querySelector(".wait")?.remove();
  $("diag-steps").append(stepLi(s), el("li", "wait", t("проверяю дальше…")));
}
function openDiag(site) {
  $("diag-site").value = site || "";
  $("diag-steps").replaceChildren();
  $("diag-verdict").classList.add("hidden");
  $("dlg-diag").showModal();
  $("diag-site").focus();
}
listen("diag-step", (e) => { if ($("dlg-diag").open) diagStep(e.payload); });
$("btn-diag").onclick = () => openDiag("");
$("btn-diag-close").onclick = () => $("dlg-diag").close();
// Закрыли во время проверки — её итог в новое окно не попадёт.
$("dlg-diag").addEventListener("close", () => { diagRun++; diagRunning = false; });
$("form-diag").onsubmit = async (e) => {
  e.preventDefault();
  const site = $("diag-site").value.trim();
  if (!site) return;
  const btn = $("btn-diag-run");
  btn.disabled = true;
  btn.textContent = t("Проверяю…");
  $("diag-steps").replaceChildren(el("li", "wait", t("проверяю — до 15 секунд…")));
  $("diag-verdict").classList.add("hidden");
  diagRunning = true;
  const my = ++diagRun;
  try {
    const r = await call("diagnose", { site });
    if (my !== diagRun) return;
    diagRunning = false;
    diagHost = r.host;
    $("diag-steps").replaceChildren(...r.steps.map(stepLi));
    const good = r.verdict === "works";
    const v = $("diag-verdict");
    v.classList.remove("hidden", "good", "bad");
    v.classList.add(good ? "good" : "bad");
    $("diag-title").textContent = `${r.host}: ${r.title}`;
    $("diag-advice").textContent = r.advice;
    for (const b of $("diag-actions").querySelectorAll("button")) {
      const show = r.actions.includes(b.dataset.act) && (b.dataset.act !== "zapret" || V.is_windows);
      b.classList.toggle("hidden", !show);
    }
    // Первая кнопка — главный совет, остальные — запасные.
    $("diag-actions").querySelectorAll("button:not(.hidden)").forEach((b, i) => {
      b.classList.toggle("primary", i === 0);
      b.classList.toggle("ghost", i !== 0);
    });
  } catch {
    if (my === diagRun) $("diag-steps").querySelector(".wait")?.remove();
  } finally {
    if (my === diagRun) diagRunning = false;
    btn.disabled = false;
    btn.textContent = t("Проверить");
  }
};
$("diag-actions").querySelectorAll("button").forEach((b) => {
  b.onclick = async () => {
    const act = b.dataset.act;
    try {
      V = await call("diag_apply", { host: diagHost, action: act });
      render();
      const zMode = V.settings.zapret;
      toast({
        vpn: zMode || !V.connected ? t("{diagHost} будет идти через VPN — когда он включён", { diagHost }) : t("{diagHost} теперь всегда через VPN", { diagHost }),
        direct: t("{diagHost} теперь всегда напрямую", { diagHost }),
        zapret: zMode ? (V.zapret_active ? t("{diagHost} добавлен в zapret — уже работает", { diagHost })
            : t("{diagHost} добавлен в zapret — заработает в режиме «Без VPN». Если не поможет — «Подобрать лучшую»", { diagHost }))
          : V.hybrid_active ? t("{diagHost} теперь мимо VPN через zapret — уже работает", { diagHost })
          : t("{diagHost} — мимо VPN через zapret (Обход). Заработает с VPN, если подобрана стратегия", { diagHost }),
      }[act]);
      $("dlg-diag").close();
    } catch {}
  };
});

// ---------- Telegram без VPN ----------
function renderTg() {
  const tg = V.tg || {};
  $("chk-tg").checked = !!V.settings.tg_proxy;
  $("chk-tg-cf").checked = !!V.settings.tg_cf;
  $("chk-tg-cf").disabled = !V.settings.tg_proxy;
  $("btn-tg-open").disabled = !tg.running;
  let meta = t("выключено");
  if (tg.running) {
    const via = [tg.web && t("веб {web}", { web: tg.web }), tg.cloudflare && `Cloudflare ${tg.cloudflare}`, tg.direct && t("напрямую {direct}", { direct: tg.direct })].filter(Boolean);
    meta = tg.total ? t("работает · {via}", { via: via.join(" · ") || t("соединений {n}", { n: tg.total }) }) + (tg.failed ? t(" · сбоев {failed}", { failed: tg.failed }) : "")
      : t("ждёт Telegram · 127.0.0.1:{port}", { port: tg.port });
  }
  setMeta("tg-meta", meta, tg.running);
  $("tg-meta").title = tg.last_error ? t("Последняя ошибка: {last_error}", { last_error: tg.last_error }) : "";
  // То же на главной — коротко.
  $("chk-tg-home").checked = !!V.settings.tg_proxy;
  $("tg-home").classList.toggle("on", !!tg.running);
  $("btn-tg-home-open").classList.toggle("hidden", !tg.running);
  let hm = t("выключено · Telegram Desktop без VPN");
  if (tg.running) hm = tg.total ? t("работает · соединений {active}", { active: tg.active }) + (tg.failed ? t(" · сбоев {failed}", { failed: tg.failed }) : "") : t("включено · нажми «Подключить»");
  else if (V.settings.tg_proxy) hm = t("включено, но не запустилось — см. лог");
  setMeta("tg-home-meta", hm, tg.running && tg.total > 0);
  $("tg-home-meta").title = $("tg-meta").title;
}
async function tgSet(on, cf, msg) {
  try {
    V = await call("tg_set", { on, cf });
    if (msg) toast(msg);
  } catch { await refresh(); }
  render();
}
$("chk-tg").onchange = async (e) => {
  const on = e.target.checked;
  await tgSet(on, !!V.settings.tg_cf, on ? null
    : t("Выключено. В Telegram выключи прокси: Настройки → Продвинутые → Тип соединения"));
  // Как на главной: в первый раз rxvpn сам открывает Telegram с «Подключить прокси».
  if (on && V.tg && V.tg.running) {
    if (load("tg-linked") === "1") toast(t("Telegram без VPN включён"));
    else await tgOpen();
  }
};
$("chk-tg-cf").onchange = (e) => tgSet(true, e.target.checked, e.target.checked
  ? t("Если веб-вход не ответит — через Cloudflare-домены сообщества tg-ws-proxy")
  : t("Только веб-вход Telegram и напрямую"));
// ---------- DNS без подмены (DoH в «Без VPN») ----------
const DOH_NAMES = { cloudflare: "Cloudflare", google: "Google" };
function dohName() {
  const p = V.settings.doh_provider;
  if (p !== "custom") return DOH_NAMES[p] || p;
  try { return new URL(V.settings.doh_url).host; } catch { return t("свой"); }
}
function renderDoh() {
  const d = V.doh || {};
  $("chk-doh").checked = !!V.settings.doh_sys;
  $("chk-doh").disabled = !V.is_windows;
  let meta = dohName();
  if (d.running) meta = t("{label} · запросов {queries}", { label: d.label, queries: d.queries }) + (d.cached ? t(", из кэша {cached}", { cached: d.cached }) : "") + (d.failed ? t(" · сбоев {failed}", { failed: d.failed }) : "");
  else if (V.settings.doh_sys) meta = t("{n} · включится в «Без VPN»", { n: dohName() });
  setMeta("doh-meta", meta, !!d.running);
  $("doh-meta").title = d.last_error ? t("Последняя ошибка: {last_error}", { last_error: d.last_error }) : "";
}
async function dohSet(on, provider, url, msg) {
  adminKind = "zapret";
  try {
    V = await call("doh_set", { on, provider, url });
    if (msg) toast(msg);
  } catch { await refresh(); }
  render();
}
$("chk-doh").onchange = (e) => {
  const on = e.target.checked;
  dohSet(on, V.settings.doh_provider, V.settings.doh_url || "", on
    ? (V.settings.zapret ? t("Готово: Windows спрашивает DNS у rxvpn, rxvpn — по HTTPS") : t("Включится, когда подключишься в режиме «Без VPN»"))
    : t("Выключено: DNS Windows вернул как было"));
};
$("btn-doh").onclick = () => {
  const p = V.settings.doh_provider;
  for (const r of document.querySelectorAll('input[name="doh-p"]')) r.checked = r.value === p;
  $("doh-url").value = V.settings.doh_url || "";
  $("doh-url").disabled = p !== "custom";
  $("dlg-doh").showModal();
};
for (const r of document.querySelectorAll('input[name="doh-p"]')) {
  r.onchange = () => { $("doh-url").disabled = r.value !== "custom" || !r.checked; if (r.value === "custom") $("doh-url").focus(); };
}
$("btn-doh-cancel").onclick = () => $("dlg-doh").close();
$("btn-doh-save").onclick = async () => {
  const p = document.querySelector('input[name="doh-p"]:checked')?.value || "cloudflare";
  const url = $("doh-url").value.trim();
  try {
    V = await call("doh_set", { on: !!V.settings.doh_sys, provider: p, url: p === "custom" ? url : (V.settings.doh_url || "") });
    $("dlg-doh").close();
    toast(t("Сервер DoH: {n}", { n: dohName() }));
  } catch {}
  render();
};

// Главная: включил — сразу открываем Telegram с «Подключить прокси» (в первый раз;
// дальше Telegram помнит прокси сам, лишнее окно не нужно).
$("chk-tg-home").onchange = async (e) => {
  const on = e.target.checked;
  await tgSet(on, !!V.settings.tg_cf, on ? null
    : t("Выключено. В Telegram выключи прокси: Настройки → Продвинутые → Тип соединения"));
  if (on && V.tg && V.tg.running) {
    if (load("tg-linked") === "1") toast(t("Telegram без VPN включён"));
    else await tgOpen();
  }
};
$("btn-tg-home-open").onclick = () => tgOpen();
async function tgOpen() {
  try {
    await call("tg_open");
    store("tg-linked", "1");
    toast(t("В Telegram нажми «Подключить прокси»"));
  } catch (e) {
    try { await navigator.clipboard.writeText(V.tg.link); } catch {}
    toast(String(e) + ". " + t("Ссылка на прокси скопирована — вставь в «Избранное» в Telegram и нажми на неё"));
  }
}
$("btn-tg-open").onclick = () => tgOpen();
// Счётчики — пока открыта главная или «Обход» и окно не свёрнуто.
setInterval(() => {
  if ((page === "home" || page === "bypass") && !document.hidden && V?.tg?.running && !busy && !document.querySelector("dialog[open]")) refresh().catch(() => {});
}, 5000);

// ---------- папки ----------
/** Свои папки — в порядке, в каком встречаются в списке. */
function folderNames() {
  return [...new Set(V.servers.filter((s) => !s.sub_id && s.group).map((s) => s.group))];
}

/** Какие папки и подписки свёрнуты (только на этом компе, в кэше окна). */
let collapsed = new Set();
try { collapsed = new Set(JSON.parse(load("collapsed") || "[]")); } catch {}
function toggleGroup(key) {
  collapsed.has(key) ? collapsed.delete(key) : collapsed.add(key);
  store("collapsed", JSON.stringify([...collapsed]));
  renderList();
}

/** Окно «Папка»: сложить сервера (ids), переименовать папку (folder) или подписку (sub). */
let folderJob = null;
function openFolder(job) {
  folderJob = job;
  $("folder-title").textContent = job.title;
  $("folder-hint").textContent = job.hint || "";
  const inp = $("folder-name");
  inp.value = job.value || "";
  inp.maxLength = job.sub ? 60 : 40;
  inp.placeholder = job.sub ? t("Как назвать подписку") : t("Например: Мой VPS");
  const chips = $("folder-chips");
  chips.replaceChildren();
  if (job.ids) {
    for (const f of folderNames().filter((f) => f !== job.value)) {
      const c = el("button", "", f);
      c.type = "button";
      c.onclick = () => saveFolder(f);
      chips.append(c);
    }
  }
  $("btn-folder-none").classList.toggle("hidden", !(job.ids && job.value) && !job.folder);
  $("btn-folder-none").textContent = job.folder ? t("Разобрать папку") : t("Без папки");
  $("dlg-folder").showModal();
  inp.focus();
  inp.select();
}
async function saveFolder(name) {
  const j = folderJob;
  if (!j) return;
  try {
    if (j.sub) V = await call("rename_subscription", { id: j.sub, name });
    else if (j.folder) V = await call("rename_group", { old: j.folder, name });
    else V = await call("set_server_group", { ids: j.ids, group: name });
    // Новая папка — открыта: видно, куда легли сервера.
    if (name.trim() && !j.sub) { collapsed.delete("f:" + name.trim()); store("collapsed", JSON.stringify([...collapsed])); }
    $("dlg-folder").close();
    render();
  } catch {}
}
$("form-folder").onsubmit = (e) => { e.preventDefault(); saveFolder($("folder-name").value); };
$("btn-folder-none").onclick = () => saveFolder("");
$("btn-folder-cancel").onclick = () => $("dlg-folder").close();

/** «38 из 100 ГБ · до 15 нояб.» — по заголовку subscription-userinfo. */
function usageText(u) {
  const parts = [];
  let warn = false;
  const used = u.upload + u.download;
  if (u.total > 0) {
    parts.push(t("{n} из {n2}", { n: fmtBytes(used), n2: fmtBytes(u.total) }));
    warn ||= used >= u.total * 0.9;
  } else if (used > 0) parts.push(t("{n} · безлимит", { n: fmtBytes(used) }));
  if (u.expire > 0) {
    const left = u.expire - Date.now() / 1000;
    const d = new Date(u.expire * 1000).toLocaleDateString(i18n.lang() === "en" ? "en-GB" : "ru-RU", { day: "numeric", month: "short" });
    parts.push(left > 0 ? t("до {d}", { d }) : t("закончилась"));
    warn ||= left < 3 * 86400;
  }
  return parts.length ? { text: parts.join(" · "), warn } : null;
}

function group(g, servers, best) {
  const { title, sub } = g;
  const shut = collapsed.has(g.key);
  const box = el("div", "group" + (shut ? " shut" : ""));
  const h = el("div", "group-head");
  h.tabIndex = 0;
  h.setAttribute("role", "button");
  h.setAttribute("aria-expanded", String(!shut));
  h.title = shut ? t("Развернуть") : t("Свернуть");
  h.onclick = (e) => { if (!e.target.closest("button")) toggleGroup(g.key); };
  h.onkeydown = (e) => {
    if (e.target === h && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); toggleGroup(g.key); }
  };
  h.append(el("span", "chev-g", "›"));
  h.append(el("span", "group-name", title));
  const vis = servers.filter((s) => !s.hidden).length;
  const cnt = g.total != null && g.total !== vis ? t("{vis} из {total}", { vis, total: g.total }) : `${vis}`;
  const meta = el("span", "group-meta", sub ? `${cnt} · ${ago(sub.updated_at)}` : cnt);
  // Свёрнута, а выбранный (или текущий в «Авто») сервер — внутри: подсказка.
  const here = servers.some((s) => (!V.auto && s.id === V.selected) || (V.auto && V.connected && s.id === V.active_id));
  if (shut && here) meta.append(el("span", "here", t(" · ● выбран здесь")));
  h.append(meta);
  const btn = (text, tip, fn, cls = "ghost small") => {
    const b = el("button", cls, text);
    if (tip) b.title = tip;
    b.onclick = (e) => { e.stopPropagation(); fn(b); };
    h.append(b);
    return b;
  };
  if (g.loose && servers.length) {
    btn(t("В папку…"), t("Сложить их все в папку — например, сервера одного VPN-сервиса"), () =>
      openFolder({ ids: servers.map((s) => s.id), title: t("Сложить в папку ({length})", { length: servers.length }),
        hint: t("Все сервера из «Добавлены вручную». Потом любой можно переложить кнопкой «Папка» у сервера.") }));
  }
  if (g.folder) {
    btn("✎", t("Переименовать папку"), () =>
      openFolder({ folder: g.folder, value: g.folder, title: t("Переименовать папку"),
        hint: t("Имя другой папки — сольются в одну. «Разобрать» — сервера останутся, без папки.") }), "ghost small icon");
  }
  if (sub) {
    const fb = btn(t("Фильтр"), t("Только нужные страны и слова — например, «только NL, DE»"), () => openFilter(sub), "ghost small toggle");
    const f = sub.filter || {};
    if (f.countries?.length || f.words?.length) {
      fb.classList.add("on");
      fb.textContent = t("Фильтр: ") + [...(f.countries || []), ...(f.words || [])].join(" ").slice(0, 24);
    }
    btn("✎", t("Переименовать подписку"), () =>
      openFolder({ sub: sub.id, value: sub.name, title: t("Переименовать подписку"),
        hint: t("Например, как называется VPN-сервис. Сервера подписки и так лежат в ней.") }), "ghost small icon");
  }
  if (sub?.usage) {
    const u = usageText(sub.usage);
    if (u) {
      const e = el("span", "sub-usage" + (u.warn ? " warn" : ""), u.text);
      e.title = t("Остаток подписки — так говорит панель провайдера");
      h.append(e);
    }
  }
  if (sub) {
    const qr = el("button", "ghost small", "QR");
    qr.title = t("Перенести подписку на телефон");
    qr.onclick = () => openQr(t("Подписка «{name}»", { name: sub.name }), "qr_subscription", { id: sub.id },
      t("На телефоне в v2rayNG / v2RayTun / Happ: «+» → сканировать QR. Телефон сам скачает все сервера и будет их обновлять."));
    const up = el("button", "ghost small", t("Обновить"));
    up.onclick = async () => {
      up.disabled = true;
      try { showImport(await call("update_subscription", { id: sub.id })); await refresh(); }
      finally { up.disabled = false; }
    };
    const del = el("button", "ghost small", t("Удалить"));
    del.onclick = async () => {
      if (!confirm(t("Удалить подписку «{name}» и все её сервера?", { name: sub.name }))) return;
      V = await call("delete_subscription", { id: sub.id });
      render();
    };
    for (const b of [qr, up, del]) {
      const fn = b.onclick;
      b.onclick = (e) => { e.stopPropagation(); fn(e); };
    }
    h.append(qr, up, del);
  }
  box.append(h);
  if (shut) return box;
  const list = sortMode ? [...servers].sort((a, b) => sortKey(a.id) - sortKey(b.id)) : servers;
  for (const s of list) box.append(row(s, best));
  return box;
}

function autoRow() {
  const r = el("div", "srv auto-row" + (V.auto ? " sel" : ""));
  r.title = t("Держится за лучший рабочий сервер — по надёжности за неделю, задержке и скорости («Скорость всех») — ") +
    t("и сам переключается, если тот перестал отвечать. Раз в 1–5 минут проверяет все сервера в фоне.");
  r.append(el("span", "radio"));
  const info = el("div");
  info.append(el("div", "srv-name", t("⚡ Авто")));
  const alive = Object.values(autoDelays).filter((x) => x != null).length;
  info.append(el("div", "srv-meta", V.auto && V.connected
    ? (V.active_name ? t("сейчас: {active_name} · живых {alive} из {n}", { active_name: V.active_name, alive, n: shown().length }) : t("проверяю сервера…"))
    : t("лучший из {n} по задержке и скорости, переключается сам", { n: shown().length }) + (shown().length < V.servers.length ? t(" (с учётом фильтров)") : "")));
  r.append(info);
  const pg = el("span", "srv-ping");
  if (V.auto && V.connected && lastPing) { pg.textContent = t("{lastPing} мс", { lastPing }); pg.classList.add(msClass(lastPing)); }
  r.append(pg);
  r.append(el("div"));
  r.onclick = async () => {
    if (V.auto || busy) return;
    setBusy(V.connected);
    try { V = await call("select_server", { id: AUTO_ID }); }
    catch { await refresh(); }
    finally { setBusy(false); }
  };
  return r;
}

function row(s, best) {
  const current = V.auto && V.connected && s.id === V.active_id;
  const r = el("div", "srv" + (!V.auto && s.id === V.selected ? " sel" : "") + (s.id === best ? " best" : "") + (current ? " current" : "") + (s.hidden ? " hid" : ""));
  r.append(el("span", "radio"));

  const info = el("div");
  info.append(el("div", "srv-name", s.name));
  const tw = (V.settings.node_tweaks || {})[s.id];
  const meta = el("div", "srv-meta", `${s.summary} · ${s.address}:${s.port}` + (tw ? t(" · обход: {n}", { n: tweakLabel(tw) }) : ""));
  if (s.stab) {
    const p = s.stab.pct;
    const st = el("span", "stab " + (s.stab.degraded ? "bad" : p >= 95 ? "ok" : p >= 80 ? "mid" : "bad"),
      s.stab.degraded ? t(" · сдаёт: {p}%", { p }) : t(" · стабильность {p}%", { p }));
    st.title = t("За 7 дней: отвечал в {p}% из {checks} проверок", { p, checks: s.stab.checks }) + (s.stab.avg_ms ? t(", в среднем {avg_ms} мс", { avg_ms: s.stab.avg_ms }) : "") +
      (s.stab.degraded ? t(". Последние сутки заметно хуже, чем всю неделю") : "");
    meta.append(st);
  }
  if (s.hidden) meta.prepend(el("span", "hid-tag", t(HIDE_TEXT[s.hidden]) + " · "));
  info.append(meta);
  r.append(info);

  const nums = el("div", "srv-nums");
  const pg = el("span", "srv-ping");
  const p = pingOf(s.id);
  if (p === "wait") {
    pg.textContent = "…";
    pg.classList.add("wait");
  } else if (p) {
    pg.textContent = p.ms != null ? t("{ms} мс", { ms: p.ms }) : "×";
    pg.classList.add(msClass(p.ms));
    if (p.error) pg.title = p.error;
  }
  nums.append(pg);
  // Скорость — под задержкой: свежий замер или среднее последних (из stats).
  const sp = el("span", "srv-mbps");
  const x = speeds[s.id];
  const m = mbpsOf(s);
  if (x === "wait") { sp.textContent = "↓ …"; sp.classList.add("wait"); }
  else if (x && x.mbps == null && !x.skipped) { sp.textContent = "↓ ×"; sp.classList.add("bad"); sp.title = x.error || t("не измерилась"); }
  else if (m != null) {
    sp.textContent = t("↓ {n} Мбит/с", { n: m < 10 ? m.toFixed(1) : Math.round(m) });
    sp.classList.add(m >= 30 ? "ok" : m >= 8 ? "mid" : "bad");
    sp.title = x && x.mbps != null ? t("Только что: 3 МБ с Cloudflare через этот сервер") : t("Среднее последних замеров «Скорость всех» (до 7 дней)");
  }
  nums.append(sp);
  r.append(nums);

  const acts = el("div", "srv-actions");
  const bSvc = el("button", "", t("Сервисы"));
  bSvc.title = t("Страна сервера и работают ли через него ChatGPT, Gemini, YouTube Premium, Netflix");
  bSvc.onclick = (e) => {
    e.stopPropagation();
    openSvc(s);
  };
  const bMore = el("button", "more", "⋯");
  bMore.title = t("Ещё действия с сервером");
  bMore.onclick = (e) => {
    e.stopPropagation();
    const warp = isWarp(s.id);
    const items = [
      [t("Подобрать обход"), t("не подключается"), () => openTweak(s)],
      !warp && [t("WARP поверх"), t("выход через Cloudflare"), () => openWarp(s)],
      "-",
      !warp && [t("QR для телефона"), "", () => openQr(s.name, "qr_server", { id: s.id }, t("На телефоне в v2rayNG / v2RayTun / Happ: «+» → сканировать QR."))],
      !warp && [t("Копировать ссылку"), "", async () => { await call("copy_link", { id: s.id }); toast(t("Ссылка скопирована")); }],
      [t("Конфиг Xray (JSON)"), "", async () => { $("config-json").textContent = await call("export_config", { id: s.id }); $("dlg-config").showModal(); }],
      !s.sub_id && !warp && [t("В папку…"), s.group || "", () => openFolder({ ids: [s.id], value: s.group || "", title: t("Папка для «{name}»", { name: s.name }),
        hint: s.group ? t("Сейчас в «{group}».", { group: s.group }) : t("Новое имя — новая папка.") })],
      !s.sub_id && "-",
      !s.sub_id && [t("Удалить"), "", async () => { V = await call("delete_server", { id: s.id }); render(); }, "danger"],
    ].filter(Boolean);
    openMenu(bMore, items);
  };
  acts.append(bSvc, bMore);
  r.append(acts);

  r.onclick = async () => {
    if ((!V.auto && s.id === V.selected) || busy) return;
    setBusy(V.connected);
    try { V = await call("select_server", { id: s.id }); }
    catch { await refresh(); }
    finally { setBusy(false); }
  };
  return r;
}

// Меню «⋯»: [текст, подсказка, действие, класс] или "-" (разделитель).
let menuEl = null;
function closeMenu() { menuEl?.remove(); menuEl = null; }
function openMenu(anchor, items) {
  closeMenu();
  const m = el("div", "menu");
  let sep = false;
  for (const it of items) {
    if (it === "-") { sep = m.children.length > 0; continue; }
    if (sep) { m.append(el("hr")); sep = false; }
    const [text, key, fn, cls] = it;
    const b = el("button", cls || "");
    b.append(el("span", "", text));
    if (key) b.append(el("span", "k", key));
    b.onclick = (e) => { e.stopPropagation(); closeMenu(); fn(); };
    m.append(b);
  }
  document.body.append(m);
  const r = anchor.getBoundingClientRect();
  const top = Math.min(r.bottom + 4, innerHeight - m.offsetHeight - 8);
  m.style.top = `${Math.max(8, top)}px`;
  m.style.left = `${Math.max(8, Math.min(r.right - m.offsetWidth, innerWidth - m.offsetWidth - 8))}px`;
  menuEl = m;
}
addEventListener("click", closeMenu);
addEventListener("keydown", (e) => { if (e.key === "Escape") closeMenu(); });
addEventListener("blur", closeMenu);

function setBusy(b) { busy = b; render(); }

async function refresh() {
  V = await invoke("get_view");
  render();
}

function showImport(r) {
  const parts = [];
  if (r.added) parts.push(t("добавлено {added}", { added: r.added }));
  if (r.updated) parts.push(t("обновлено {updated}", { updated: r.updated }));
  let msg = parts.length ? parts.join(", ") : t("ничего не добавлено");
  if (r.errors.length) msg += "\n" + r.errors.slice(0, 5).join("\n");
  toast(msg[0].toUpperCase() + msg.slice(1), r.errors.length > 0 && !r.added && !r.updated);
}

// ---------- подключение ----------
$("btn-connect").onclick = async () => {
  if (busy) return;
  if (V.zapret_testing) {
    setBusy(true);
    try { V = await call("disconnect"); }
    catch { await refresh(); }
    finally { setBusy(false); }
    return;
  }
  if (!isOn() && V.settings.zapret && !V.settings.zapret_strategy) {
    toast(t("Сначала подбери стратегию zapret"));
    return openZapret();
  }
  connecting = !isOn(); // лавина — только при подключении, не при отключении
  setBusy(true);
  $("real-res").textContent = "";
  adminKind = V.settings.zapret ? "zapret" : V.settings.zapret_hybrid ? "hybrid" : "tun";
  try { V = await call(isOn() ? "disconnect" : "connect"); }
  catch { await refresh(); }
  finally { connecting = false; setBusy(false); }
};

async function saveSettingsPatch(patch, okMsg) {
  setBusy(V.connected);
  try {
    V = await call("save_settings", { settings: { ...V.settings, ...patch } });
    if (okMsg) toast(okMsg);
  } catch { await refresh(); }
  finally { setBusy(false); }
}

document.querySelectorAll("#seg-mode button").forEach((b) => {
  b.onclick = async () => {
    const m = b.dataset.mode;
    if (busy || m === curMode()) return;
    if (m === "zapret") {
      adminKind = "zapret";
      const ready = !!V.settings.zapret_strategy;
      await saveSettingsPatch({ zapret: true }, !ready ? null
        : V.zapret_active ? t("Zapret работает") : isOn() ? null : t("Zapret включится при подключении"));
      if (V.zapret_active) toast(t("Zapret включён, VPN выключен"));
      if (!ready) openZapret();
      return;
    }
    const tun = m === "tun";
    adminKind = "tun";
    saveSettingsPatch({ zapret: false, tun }, tun
      ? (isOn() ? t("TUN: весь трафик компа идёт через VPN") : t("TUN включится при подключении"))
      : t("Режим прокси"));
  };
});

document.querySelectorAll("#seg-route button, #seg-route-home button").forEach((b) => {
  b.onclick = async () => {
    if (b.dataset.route === V.settings.route) return;
    if (b.dataset.route === "blocked" && !V.lists) {
      toast(t("Сначала скачаю списки блокировок…"));
      try { V = await call("update_lists"); } catch { return; }
    }
    saveSettingsPatch({ route: b.dataset.route }, {
      bypassru: t("Обход РФ: всё через VPN, кроме российских сайтов"),
      blocked: t("Только заблокированное: через VPN ~75 000 сайтов, остальное напрямую"),
      global: t("Всё через VPN"),
    }[b.dataset.route]);
  };
});

$("chk-ads").onchange = (e) =>
  saveSettingsPatch({ block_ads: e.target.checked }, e.target.checked ? t("Реклама блокируется") : t("Блокировка рекламы выключена"));

$("btn-real").onclick = async () => {
  const out = $("real-res");
  out.className = "delay-res";
  out.textContent = "…";
  try {
    const ms = await call("real_delay");
    out.textContent = t("задержка {ms} мс", { ms });
    out.classList.add(msClass(ms));
  } catch {
    out.textContent = t("не прошло");
    out.classList.add("bad");
  }
};

// ---------- проверки: IP, DNS, скорость ----------
const dlgChecks = $("dlg-checks");
// Одно окно, два раздела: «Мой IP и утечки» и «Скорость» — каждая кнопка показывает только свой.
function openChecks(kind) {
  $("chk-sec-ip").classList.toggle("hidden", kind !== "ip");
  $("chk-sec-speed").classList.toggle("hidden", kind !== "speed");
  $("checks-title").textContent = kind === "ip" ? t("Мой IP и утечки") : t("Скорость");
  if (!dlgChecks.open) dlgChecks.showModal();
}
const fmtMbps = (x) => (x == null ? "—" : t("{n} Мбит/с", { n: x >= 100 ? Math.round(x) : x.toFixed(1).replace(".", ",") }));

function ipCard(title, side) {
  const c = el("div", "ip-card");
  c.append(el("div", "ip-title", title));
  if (side.error || !side.info) {
    c.classList.add("bad");
    c.append(el("div", "ip-err", side.error || t("не ответил")));
    return c;
  }
  const i = side.info;
  c.append(el("div", "ip-country", `${i.flag ? i.flag + " " : ""}${i.country || "?"}${i.city ? ", " + i.city : ""}`));
  c.append(el("div", "ip-addr", i.ip));
  if (i.isp) c.append(el("div", "ip-isp", i.isp));
  return c;
}

let ipBusy = false;
async function runIp() {
  if (ipBusy) return;
  ipBusy = true;
  const box = $("ip-cards");
  box.replaceChildren(el("p", "hint", t("Узнаю…")));
  try {
    const r = await call("check_ip");
    box.replaceChildren();
    if (r.vpn) box.append(ipCard(t("Через VPN — так тебя видят сайты"), r.vpn));
    if (r.direct) box.append(ipCard(r.connected ? t("Без VPN — твой провайдер") : t("Сейчас (VPN выключен)"), r.direct));
    if (r.tun) box.append(el("p", "hint", t("TUN: весь трафик компа и так идёт через VPN — «без VPN» не меряю.")));
    const v6 = {
      no_ipv6: ["ok", t("IPv6: не работает — утечки через него нет.")],
      tunneled: ["ok", t("IPv6: идёт через VPN{seen}.", { seen: r.v6.seen ? t(" (сайты видят {seen})", { seen: r.v6.seen }) : "" })],
      leak: ["bad", t("IPv6: УТЕЧКА — сайты видят твой настоящий адрес {seen}. Отключи IPv6 у сетевой карты (Свойства адаптера → снять «IP версии 6») и переподключись.", { seen: r.v6.seen })],
      direct: ["", t("IPv6: есть ({seen}). Браузер идёт через прокси VPN, а программы без прокси — напрямую. Нужен весь комп через VPN — режим «Весь комп».", { seen: r.v6.seen })],
    }[r.v6.verdict];
    if (v6) box.append(el("p", "hint " + v6[0], v6[1]));
    box.append(el("p", "hint", t("WebRTC: браузер может показать сайту твой IP в обход прокси (видеозвонки). ") +
      t("В режиме «Браузер» включи в uBlock Origin «Не допускать утечку локальных IP через WebRTC» — или используй «Весь комп».")));
  } catch {
    box.replaceChildren(el("p", "hint bad", t("Не получилось — подробности в логе")));
  } finally {
    ipBusy = false;
  }
}

let dnsBusy = false;
async function runDns() {
  if (dnsBusy) return;
  dnsBusy = true;
  const out = $("dns-out"), btn = $("btn-dns-run");
  btn.disabled = true;
  out.replaceChildren(el("p", "hint", t("Проверяю… (~10 с)")));
  try {
    const r = await call("check_dns");
    const mark = { ok: "✓ ", warn: "⚠ ", info: "" }[r.verdict.level] ?? "";
    const list = el("div", "dns-list");
    for (const d of r.leak.servers) {
      const row = el("div", "dns-row");
      row.append(el("span", "", `${d.flag || "🌐"} ${d.country || "?"}`), el("span", "ip", d.ip), el("span", "asn", d.asn));
      list.append(row);
    }
    out.replaceChildren(el("div", "verdict " + r.verdict.level, mark + r.verdict.text), list, el("p", "hint", t("Как проверял: {how}. Сервис — {service}.", { how: r.how, service: r.service })));
  } catch (e) {
    out.replaceChildren(el("p", "hint bad", String(e) || t("Не получилось — подробности в логе")));
  } finally {
    dnsBusy = false;
    btn.disabled = false;
  }
}

let speedBusy = false;
async function runSpeed() {
  if (speedBusy) return;
  speedBusy = true;
  const btn = $("btn-speed-run");
  btn.disabled = true;
  $("st-down").textContent = "…";
  $("st-up").textContent = "—";
  $("st-meta").textContent = V?.connected ? t("Меряю через VPN…") : t("VPN выключен — меряю напрямую…");
  try {
    const r = await call("speed_test");
    const x = r.result;
    $("st-down").textContent = fmtMbps(x.down_mbps);
    $("st-up").textContent = x.up_mbps == null ? t("не вышло") : fmtMbps(x.up_mbps);
    $("st-meta").textContent = t("{via} · ушло {n}", { via: r.server ? t("Через «{server}»", { server: r.server }) : t("Без VPN"), n: fmtBytes(x.down_bytes + x.up_bytes) }) +
      (x.up_error ? t(" · загрузка: {up_error}", { up_error: x.up_error }) : "");
    $("real-res").className = "delay-res";
    $("real-res").textContent = `↓ ${fmtMbps(x.down_mbps)} · ↑ ${fmtMbps(x.up_mbps)}`;
  } catch {
    $("st-down").textContent = t("не вышло");
    $("st-meta").textContent = t("Подробности в логе");
  } finally {
    speedBusy = false;
    btn.disabled = false;
  }
}
listen("speed-progress", (e) => {
  const p = e.payload;
  $(p.phase === "down" ? "st-down" : "st-up").textContent = fmtMbps(p.mbps);
});

$("btn-ip").onclick = () => { openChecks("ip"); runIp(); runDns(); };
$("btn-speed").onclick = () => { openChecks("speed"); runSpeed(); };
// Те же проверки — кнопками на главной.
$("ht-diag").onclick = () => openDiag("");
$("ht-ip").onclick = () => { openChecks("ip"); runIp(); runDns(); };
$("ht-speed").onclick = () => { openChecks("speed"); runSpeed(); };
// Сервисы и обход — для сервера на главной (в «Авто» — того, через который идёт трафик).
const homeServer = () => V.servers.find((s) => s.id === (V.auto ? V.active_id : V.selected));
const noHomeServer = () => toast(V.auto ? t("В «Авто» — для сервера, через который идёт трафик: сначала подключись") : t("Сначала выбери сервер"), true);
$("ht-svc").onclick = () => { const s = homeServer(); s ? openSvc(s) : noHomeServer(); };
$("ht-tweak").onclick = () => { const s = homeServer(); s ? openTweak(s) : noHomeServer(); };
$("btn-ip-run").onclick = runIp;
$("btn-dns-run").onclick = runDns;
$("btn-speed-run").onclick = runSpeed;
$("btn-checks-close").onclick = () => dlgChecks.close();

// ---------- права администратора (TUN, zapret) ----------
let adminFor = "tun";
// [[части текста], кнопка «Нет»] — ключи; переводятся в openAdmin (язык мог смениться).
const ADMIN_TEXT = {
  tun: [[tk("TUN создаёт в Windows виртуальный сетевой адаптер — без прав администратора это нельзя. "),
    tk("rxvpn перезапустится, Windows спросит разрешение, и сразу подключится.")], tk("Остаться в режиме прокси")],
  zapret: [[tk("Zapret перехватывает пакеты драйвером WinDivert — это можно только с правами администратора. "),
    tk("rxvpn перезапустится, Windows спросит разрешение, и сразу включит zapret.")], tk("Отмена")],
  hybrid: [[tk("Zapret для сайтов «мимо VPN» перехватывает пакеты драйвером WinDivert — это можно только с правами "),
    tk("администратора. rxvpn перезапустится, Windows спросит разрешение, и сразу подключится.")], tk("Без zapret")],
  "zapret-test": [[tk("Подбор включает zapret (драйвер WinDivert) — нужны права администратора. "),
    tk("rxvpn перезапустится, Windows спросит разрешение, и сразу начнёт подбор.")], tk("Отмена")],
  dns: [[tk("DNS сетевой карты Windows меняют только с правами администратора. "),
    tk("rxvpn перезапустится, Windows спросит разрешение, и сразу вернёт DNS как было.")], tk("Отмена")],
};
function openAdmin(kind = adminKind) {
  adminFor = ADMIN_TEXT[kind] ? kind : "tun";
  const [why, no] = ADMIN_TEXT[adminFor];
  // Портативной (и установленной не в Program Files) прав администратора не даём:
  // её папку может переписать любая программа — вирус получил бы права вместе с rxvpn.
  const noAdmin = !!V && !V.admin_ok;
  $("admin-why").textContent = !noAdmin ? why.map((x) => t(x)).join("")
    : V.portable ? t("Это нужно делать с правами администратора, а портативная версия их не получает: её папку может переписать любая программа, и вирус получил бы права вместе с rxvpn. Установи rxvpn установщиком (он ставит в Program Files) — там это работает.")
    : t("rxvpn установлен не в Program Files — права администратора ему не даю: эту папку может переписать любая программа. Переустанови в папку по умолчанию.");
  $("btn-admin-yes").hidden = noAdmin;
  $("btn-admin-no").textContent = t(no);
  if (!$("dlg-admin").open) $("dlg-admin").showModal();
}
$("btn-admin-yes").onclick = async () => {
  $("btn-admin-yes").disabled = true;
  // программа закроется и откроется заново
  try { await call("relaunch_admin", { then: adminFor === "zapret-test" ? "zapret-test" : null }); }
  finally { $("btn-admin-yes").disabled = false; }
};
$("btn-admin-no").onclick = async () => {
  $("dlg-admin").close();
  if (adminFor === "tun" && V.settings.tun) await saveSettingsPatch({ tun: false }, t("Остался в режиме прокси"));
  // Переключали работающий VPN на zapret — VPN так и работает, режим возвращаем.
  if (adminFor === "zapret" && V.settings.zapret && V.connected) await saveSettingsPatch({ zapret: false }, t("Остался на VPN"));
  if (adminFor === "hybrid" && V.settings.zapret_hybrid) {
    await saveSettingsPatch({ zapret_hybrid: false }, t("Сайты «мимо VPN» — снова через VPN"));
    if (!isOn()) $("btn-connect").click();
  }
};
// Esc — то же, что «остаться в режиме прокси», иначе TUN висел бы включённым в настройках.
$("dlg-admin").addEventListener("cancel", (e) => { e.preventDefault(); $("btn-admin-no").click(); });

// ---------- сервера ----------
async function importText(text) {
  if (!text.trim()) return toast(t("Пусто — вставь ссылку"), true);
  $("btn-add").disabled = $("btn-paste").disabled = true;
  try {
    showImport(await call("import_text", { text }));
    $("import-text").value = "";
    await refresh();
    // Первая ссылка с экрана приветствия — дальше мастер всё делает сам.
    if (wizPending && V.servers.length && !V.settings.zapret) {
      wizPending = false;
      showPage("home");
      runWizard(); // не ждём: кнопки импорта освобождаются сразу
    }
  } finally {
    $("btn-add").disabled = $("btn-paste").disabled = false;
  }
}
$("btn-add").onclick = () => importText($("import-text").value);
$("btn-paste").onclick = async () => importText(await call("read_clipboard"));
$("import-text").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) importText(e.target.value);
});

async function runTest() {
  if (testing || !checkable().length) return;
  testing = true;
  for (const s of checkable()) pings[s.id] = "wait";
  render();
  try {
    const res = await call("test_all");
    for (const r of res) pings[r.id] = r;
    const ok = res.filter((r) => r.ms != null);
    V = await call("get_view"); // мёртвые могли ожить или умереть
    const best = V.servers.find((s) => s.id === bestId());
    toast(ok.length
      ? t("Работают {ok} из {total}. Самый быстрый: {name} — {ms} мс", { ok: ok.length, total: res.length, name: best?.name, ms: pings[best?.id]?.ms })
      : t("Ни один сервер не ответил"), !ok.length);
  } catch {
    for (const id in pings) if (pings[id] === "wait") delete pings[id];
  } finally {
    testing = false;
    render();
  }
}
$("btn-test").onclick = runTest;

$("btn-fastest").onclick = async () => {
  if (V.settings.zapret) return toast(t("Сейчас режим Zapret — сервера не нужны. Переключи режим на «Прокси» или «TUN»"));
  if (!bestId()) await runTest();
  const id = bestId();
  if (!id) return;
  setBusy(true);
  try {
    V = await call("select_server", { id });
    if (!V.connected) V = await call("connect");
  } catch { await refresh(); }
  finally { setBusy(false); }
};

$("btn-hidden").onclick = () => {
  showHidden = !showHidden;
  store("show-hidden", showHidden ? "1" : "0");
  render();
};
$("btn-filters").onclick = () => openFilter(null);

// ---------- фильтры ----------
let filterSub = null;
async function openFilter(sub) {
  filterSub = sub;
  $("filter-title").textContent = sub ? t("Фильтр — «{name}»", { name: sub.name }) : t("Фильтры");
  $("filter-sub").classList.toggle("hidden", !sub);
  $("filter-cc").value = (sub?.filter?.countries || []).join(", ");
  $("filter-words").value = (sub?.filter?.words || []).join(" ");
  $("filter-dead").checked = !!V.list_filter?.hide_dead;
  $("filter-dedup").checked = !!V.list_filter?.dedup;
  $("filter-chips").replaceChildren();
  $("dlg-filter").showModal();
  if (!sub) return;
  let list = [];
  try { list = await call("sub_countries", { id: sub.id }); } catch { return; }
  const chips = $("filter-chips");
  const cur = () => $("filter-cc").value.split(/[,;\s]+/).map((x) => x.trim().toUpperCase()).filter(Boolean);
  const paint = () => { for (const b of chips.children) if (b.dataset.cc) b.classList.toggle("on", cur().includes(b.dataset.cc)); };
  for (const [cc, n] of list) {
    const b = el("button", "", cc ? `${cc} · ${n}` : t("без страны · {n}", { n }));
    b.type = "button";
    if (!cc) { b.disabled = true; b.title = t("Страну не понять по названию — фильтр по странам их скроет"); }
    else {
      b.dataset.cc = cc;
      b.onclick = () => {
        const v = cur();
        $("filter-cc").value = (v.includes(cc) ? v.filter((x) => x !== cc) : [...v, cc]).join(", ");
        paint();
      };
    }
    chips.append(b);
  }
  $("filter-cc").oninput = paint;
  paint();
}
$("btn-filter-cancel").onclick = () => $("dlg-filter").close();
$("btn-filter-reset").onclick = () => {
  $("filter-cc").value = "";
  $("filter-words").value = "";
  $("filter-dead").checked = false;
  $("filter-dedup").checked = false;
  for (const b of $("filter-chips").children) b.classList.remove("on");
};
$("form-filter").onsubmit = async (e) => {
  e.preventDefault();
  const before = shown().length;
  try {
    if (filterSub) V = await call("set_sub_filter", { id: filterSub.id, countries: $("filter-cc").value, words: $("filter-words").value });
    const lf = { hideDead: $("filter-dead").checked, dedup: $("filter-dedup").checked };
    if (lf.hideDead !== !!V.list_filter?.hide_dead || lf.dedup !== !!V.list_filter?.dedup) V = await call("set_list_filter", lf);
  } catch { return; }
  $("dlg-filter").close();
  render();
  const n = shown().length;
  toast(n ? t("Видно {n} из {total}", { n, total: V.servers.length }) + (n !== before ? "" : t(" — без изменений")) : t("Фильтр скрыл все сервера"), !n);
};

$("btn-sort").onclick = () => {
  sortMode = sortMode === "" ? "1" : sortMode === "1" ? "mbps" : "";
  store("sort", sortMode);
  render();
};

// «Скорость всех»: 3 МБ через каждый сервер, по 3 за раз. Второе нажатие — «Стоп».
$("btn-speed-all").onclick = async () => {
  if (speedRun || V.speed_all) {
    try { await call("speed_all_cancel"); toast(t("Останавливаю — начатые докачаются")); } catch {}
    return;
  }
  const n = shown().length;
  if (!confirm(t("Через каждый сервер скачается до 3 МБ с Cloudflare: {n} шт. — до {n2} МБ трафика", { n, n2: n * 3 }) +
    (V.connected ? t(" (мимо текущего VPN)") : "") + t(". По 3 сервера за раз, около {n} мин. Остановить можно в любой момент. Проверить?", { n: Math.max(1, Math.ceil(n / 3) * 8 / 60).toFixed(0) }))) return;
  speedRun = { done: 0, total: n };
  for (const s of shown()) speeds[s.id] = "wait";
  render();
  try {
    const res = await call("speed_all");
    for (const x of res) speeds[x.id] = x;
    const ok = res.filter((x) => x.mbps != null).sort((a, b) => b.mbps - a.mbps);
    const top = ok[0] && V.servers.find((s) => s.id === ok[0].id);
    toast(ok.length ? t("Измерено {ok} из {total}. Быстрее всех: {name} — {n} Мбит/с", { ok: ok.length, total: res.length, name: top?.name, n: Math.round(ok[0].mbps) })
      : t("Скорость не измерилась ни у одного — смотри лог"), !ok.length);
    if (ok.length && !sortMode) { sortMode = "mbps"; store("sort", sortMode); }
  } catch {}
  finally {
    for (const id in speeds) if (speeds[id] === "wait") delete speeds[id];
    speedRun = null;
    await refresh();
  }
};

$("btn-update-subs").onclick = async () => {
  if (!V.subscriptions.length) return toast(t("Подписок пока нет"));
  const b = $("btn-update-subs");
  b.disabled = true;
  try { showImport(await call("update_all_subscriptions")); await refresh(); }
  finally { b.disabled = false; }
};

// ---------- QR ----------
async function openQr(title, cmd, args, hint) {
  try {
    const svg = await call(cmd, args);
    $("qr-title").textContent = title;
    $("qr-box").innerHTML = svg; // SVG собран в Rust из одних квадратиков, текста ссылки в нём нет
    $("qr-hint").textContent = hint;
    $("dlg-qr").showModal();
  } catch {}
}
$("btn-qr-close").onclick = () => $("dlg-qr").close();

// ---------- скорость ----------
/** Цвет из темы (тёмная/светлая — как в Windows); `a` — прозрачность. */
function cssColor(name, a = 1) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#888";
  if (a === 1 || !v.startsWith("#")) return v;
  const n = parseInt(v.length === 4 ? [...v.slice(1)].map((c) => c + c).join("") : v.slice(1, 7), 16);
  return `rgba(${n >> 16}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
}
// Тему поменяли в Windows — перерисовать график новыми цветами.
matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => drawSpark());
const canvas = $("spark");
const ctx = canvas.getContext("2d");
function drawSpark() {
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);
  const max = Math.max(64 * 1024, ...spark.down, ...spark.up);
  // Пока точек мало — растягиваем по всей ширине, потом бегущая лента за минуту.
  const n = Math.max(spark.down.length, 2);
  const x = (i) => (w * i) / (n - 1);
  const y = (v) => h - 2 - (v / max) * (h - 6);
  if (spark.down.length > 1) {
    ctx.beginPath();
    ctx.moveTo(x(0), h);
    spark.down.forEach((v, i) => ctx.lineTo(x(i), y(v)));
    ctx.lineTo(x(spark.down.length - 1), h);
    ctx.closePath();
    ctx.fillStyle = cssColor("--green", 0.16);
    ctx.fill();
    ctx.beginPath();
    spark.down.forEach((v, i) => (i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v))));
    ctx.strokeStyle = cssColor("--green");
    ctx.lineWidth = 3;
    ctx.stroke();
  }
  if (spark.up.length > 1) {
    ctx.beginPath();
    spark.up.forEach((v, i) => (i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v))));
    ctx.strokeStyle = cssColor("--blue");
    ctx.lineWidth = 2;
    ctx.stroke();
  }
}
listen("stats", (e) => {
  const s = e.payload;
  if (!s.up_total && !s.down_total && !s.up_speed && !s.down_speed) {
    // отключились — чистим график
    spark = { down: [], up: [] };
    lastPing = null;
    $("sp-down").textContent = t("0 Б/с");
    $("sp-up").textContent = t("0 Б/с");
    $("sp-total").textContent = t("За сессию: —");
    drawSpark();
    return;
  }
  $("sp-down").textContent = fmtBytes(s.down_speed) + t("/с");
  $("sp-up").textContent = fmtBytes(s.up_speed) + t("/с");
  lastPing = s.ping ?? null;
  $("sp-total").textContent = t("За сессию: ↓ {n} · ↑ {n2}", { n: fmtBytes(s.down_total), n2: fmtBytes(s.up_total) }) +
    (s.ping ? t(" · пинг {ping} мс", { ping: s.ping }) : "");
  spark.down.push(s.down_speed);
  spark.up.push(s.up_speed);
  if (spark.down.length > SPARK_LEN) { spark.down.shift(); spark.up.shift(); }
  drawSpark();
});

// ---------- свои сайты ----------
const sitesForm = $("form-sites");
const lines = (s) => s.split("\n").map((l) => l.trim()).filter(Boolean);
$("btn-sites").onclick = () => {
  sitesForm.direct.value = V.settings.direct.join("\n");
  sitesForm.proxy.value = V.settings.proxy.join("\n");
  $("dlg-sites").showModal();
};
$("btn-sites-cancel").onclick = () => $("dlg-sites").close();
sitesForm.onsubmit = async (e) => {
  e.preventDefault();
  const settings = { ...V.settings, direct: lines(sitesForm.direct.value), proxy: lines(sitesForm.proxy.value) };
  // Ошибка (непонятная строка) покажется тостом, окно останется открытым — можно поправить.
  V = await call("save_settings", { settings });
  $("dlg-sites").close();
  render();
  toast(V.connected ? t("Сохранено, переподключился") : t("Сохранено"));
};

// ---------- сервисы через сервер ----------
let svcId = null, svcRun = 0;
const serverName = (id) => V.servers.find((s) => s.id === id)?.name;
// Сервер правила «Сайт → сервер»: тот же id и та же подписка (как в Rust).
const ruleServer = (r) => V.servers.find((s) => s.id === r.server && (s.sub_id || "") === (r.sub || ""));
const ruleBackup = (r) => r.backup ? V.servers.find((s) => s.id === r.backup && (s.sub_id || "") === (r.backup_sub || "")) : undefined;
const isWarp = (id) => id.startsWith("warp-");
function svcRow(x, id) {
  const li = el("li", x.ok === true ? "ok" : x.ok === false ? "bad" : "na");
  li.append(el("span", "mark", x.ok === true ? "✓" : x.ok === false ? "✗" : "·"), el("span", "name", x.name), el("span", "", x.detail));
  const rule = (V.settings.site_servers || []).find((r) => r.name === x.name);
  if (rule && rule.server === id && ruleServer(rule)) {
    li.append(el("span", "svc-on", t("идёт через него")));
  } else if (x.ok !== false) {
    const b = el("button", "ghost small", t("Пускать через него"));
    const now = rule && ruleServer(rule)?.name;
    b.title = now ? t("Сейчас {name} идёт через «{now}»", { name: x.name, now }) : t("{name} — всегда через этот сервер, остальное — как обычно", { name: x.name });
    b.onclick = async () => {
      b.disabled = true;
      try {
        V = await call("site_server_add", { key: x.key, id });
        render();
        toast(t("{name} теперь через «{n}»", { name: x.name, n: serverName(id) }) + (V.connected && !V.settings.zapret ? "" : t(" — когда VPN включён")));
        li.replaceWith(svcRow(x, id));
      } catch { b.disabled = false; }
    };
    li.append(b);
  } else {
    li.append(el("span"));
  }
  return li;
}
async function runSvc() {
  const id = svcId, my = ++svcRun;
  $("svc-land").textContent = t("Проверяю — до 20 секунд. Подключение при этом не трогаю.");
  $("svc-list").replaceChildren(el("li", "wait", t("запускаю сервер отдельно…")));
  $("btn-svc-again").disabled = true;
  try {
    const r = await invoke("check_services", { id });
    if (my !== svcRun) return;
    $("svc-land").textContent = r.country
      ? t("Сайты видят: {flag} {country_name}{n}", { flag: r.flag, country_name: r.country_name, n: r.ip ? " · " + r.ip : "" })
      : t("Страну узнать не вышло{n}", { n: r.ip ? " · " + r.ip : "" });
    $("svc-list").replaceChildren(...r.services.map((x) => svcRow(x, id)));
  } catch (e) {
    if (my !== svcRun) return;
    $("svc-land").textContent = String(e);
    $("svc-list").replaceChildren();
  } finally {
    if (my === svcRun) $("btn-svc-again").disabled = false;
  }
}
function openSvc(s) {
  svcId = s.id;
  $("svc-title").textContent = t("Сервисы через «{name}»", { name: s.name });
  $("dlg-svc").showModal();
  runSvc();
}
$("btn-svc-again").onclick = runSvc;
$("btn-svc-close").onclick = () => $("dlg-svc").close();
$("dlg-svc").addEventListener("close", () => { svcRun++; });

// ---------- на телефон ----------
$("btn-phone").onclick = async () => {
  $("phone-mode").textContent = { bypassru: t("«Обход РФ»"), blocked: t("«Только блок.»"), global: t("«Всё через VPN»") }[V.settings.route] || "";
  $("phone-qr").replaceChildren();
  try {
    const r = await call("phone_routing");
    $("phone-long").classList.toggle("hidden", !!r.qr);
    if (r.qr) {
      // SVG собран нашим Rust (qrcode) из нашей же ссылки — чужого текста в нём нет.
      const doc = new DOMParser().parseFromString(r.qr, "image/svg+xml");
      $("phone-qr").append(document.importNode(doc.documentElement, true));
    }
    $("dlg-phone").showModal();
  } catch {}
};
$("btn-phone-copy").onclick = async () => {
  try { await call("phone_routing_copy"); toast(t("Ссылка скопирована — отправь её себе на телефон")); } catch {}
};
$("btn-phone-close").onclick = () => $("dlg-phone").close();

// ---------- профили по сети ----------
const NET_ROUTE = [["", tk("режим не менять")], ["bypassru", tk("Обход РФ")], ["blocked", tk("Только блок.")], ["global", tk("Всё через VPN")]];
const NET_VPN = [["keep", tk("VPN не трогать")], ["on", tk("включать VPN")], ["off", tk("выключать VPN")]];
let netTrusted = [], netCur = null;
function fillSel(id, opts, val) {
  const sel = $(id);
  sel.replaceChildren(...opts.map(([v, lbl]) => { const o = el("option", "", t(lbl)); o.value = v; return o; }));
  sel.value = val ?? "";
}
function renderNetList() {
  const list = $("net-list");
  list.replaceChildren();
  if (!netTrusted.length) list.append(el("p", "hint", t("Своих сетей пока нет.")));
  netTrusted.forEach((nt, i) => {
    const row = el("div", "nav-row ss-row");
    const del = el("button", "ghost small", "✕");
    del.type = "button";
    del.title = t("Убрать из своих");
    del.onclick = () => { netTrusted.splice(i, 1); renderNetList(); };
    row.append(el("span", "", nt.ssid), el("span", "nav-meta", nt.bssid), del);
    list.append(row);
  });
  const same = netCur && netTrusted.some((nt) => nt.ssid === netCur[0] && nt.bssid === netCur[1]);
  $("btn-net-trust").disabled = !netCur || same;
}
$("btn-net").onclick = async () => {
  const s = V.settings;
  $("net-on").checked = !!s.net_profiles;
  netTrusted = (s.trusted_nets || []).map((nt) => ({ ...nt }));
  fillSel("net-home-route", NET_ROUTE, s.home?.route ?? "");
  fillSel("net-home-vpn", NET_VPN, s.home?.vpn ?? "keep");
  fillSel("net-away-route", NET_ROUTE, s.away?.route ?? "");
  fillSel("net-away-vpn", NET_VPN, s.away?.vpn ?? "keep");
  netCur = null;
  renderNetList();
  $("net-now").textContent = t("Смотрю, где ты…");
  $("dlg-net").showModal();
  try {
    const n = await invoke("net_now");
    netCur = n.wifi;
    $("net-now").textContent = !n.online ? t("Сейчас: нет сети.")
      : n.wifi ? (n.trusted ? t("Сейчас: Wi-Fi «{ssid}» (точка {bssid}) — своя.", { ssid: n.wifi[0], bssid: n.wifi[1] })
        : t("Сейчас: Wi-Fi «{ssid}» (точка {bssid}) — чужая.", { ssid: n.wifi[0], bssid: n.wifi[1] }))
      : t("Сейчас: не Wi-Fi (кабель, телефон) или Windows не даёт имя сети — считается «остальной».");
  } catch {}
  renderNetList();
};
$("btn-net-trust").onclick = () => {
  if (!netCur) return;
  netTrusted.push({ ssid: netCur[0], bssid: netCur[1] });
  renderNetList();
};
$("btn-net-cancel").onclick = () => $("dlg-net").close();
$("form-net").onsubmit = async (e) => {
  e.preventDefault();
  const act = (r, v) => ({ route: $(r).value || null, vpn: $(v).value });
  try {
    V = await call("save_settings", { settings: { ...V.settings, net_profiles: $("net-on").checked, trusted_nets: netTrusted,
      home: act("net-home-route", "net-home-vpn"), away: act("net-away-route", "net-away-vpn") } });
    $("dlg-net").close();
    render();
    toast(t("Сохранено"));
  } catch {}
};

// ---------- подобрать обход ----------
function tweakLabel(tw) {
  const p = [];
  if (tw.fragment) p.push(t("нарезка {fragment}", { fragment: tw.fragment }));
  if (tw.fp) p.push(tw.fp);
  if (tw.noise) p.push(t("шум UDP"));
  return p.length ? p.join(" + ") : t("без обхода");
}
let tweakId = null, tweakRun = 0;
async function runTweak() {
  const id = tweakId, my = ++tweakRun;
  $("tweak-list").replaceChildren(el("li", "wait", t("пробую варианты — до 15 секунд…")));
  $("tweak-verdict").classList.add("hidden");
  $("btn-tweak-reset").classList.add("hidden");
  try {
    const r = await invoke("pick_tweak", { id });
    if (my !== tweakRun) return;
    V = r.view;
    render();
    $("tweak-list").replaceChildren(...r.results.map((x) => {
      const li = el("li", x.ms != null ? "ok" : "bad");
      li.append(el("span", "mark", x.ms != null ? "✓" : "✗"), el("span", "name", x.label),
        el("span", "", x.ms != null ? t("{ms} мс", { ms: x.ms }) : (x.error || t("не прошёл"))), el("span"));
      return li;
    }));
    const v = $("tweak-verdict");
    v.classList.remove("hidden", "good", "bad");
    v.classList.add(r.chosen ? "good" : "bad");
    $("tweak-res").textContent = r.chosen
      ? t("Работает: {chosen}. Запомнил для этого сервера.", { chosen: r.chosen })
      : t("Ни один вариант не прошёл: сервер лежит или закрыт по IP — тут поможет только другой сервер.");
  } catch (e) {
    if (my !== tweakRun) return;
    $("tweak-list").replaceChildren(el("li", "bad", String(e)));
  }
  $("btn-tweak-reset").classList.toggle("hidden", !(V.settings.node_tweaks || {})[id]);
}
function openTweak(s) {
  tweakId = s.id;
  $("tweak-title").textContent = t("Обход для «{name}»", { name: s.name });
  $("dlg-tweak").showModal();
  runTweak();
}
$("btn-tweak-close").onclick = () => $("dlg-tweak").close();
$("dlg-tweak").addEventListener("close", () => { tweakRun++; });
$("btn-tweak-reset").onclick = async () => {
  const tw = { ...(V.settings.node_tweaks || {}) };
  delete tw[tweakId];
  try {
    V = await call("save_settings", { settings: { ...V.settings, node_tweaks: tw } });
    render();
    $("btn-tweak-reset").classList.add("hidden");
    toast(t("Сброшено: сервер снова с общими настройками анти-DPI"));
  } catch {}
};

// ---------- что нового ----------
$("btn-wn-hide").onclick = () => { store("wn-0.15", "1"); render(); };
for (const b of document.querySelectorAll(".wn-row")) {
  b.onclick = () => {
    const [page, btn] = b.dataset.go.split(":");
    document.querySelector(`#tabs [data-page="${page}"]`)?.click();
    if (btn) $(btn).click();
  };
}
$("btn-warp-info").onclick = () => {
  document.querySelector('#tabs [data-page="servers"]')?.click();
  toast(t("WARP добавляется у сервера: «⋯» → «WARP поверх»"));
};

// ---------- гибрид: сервисы и свои сайты ----------
document.querySelectorAll(".hyb-svc input").forEach((c) => {
  c.onchange = () => {
    const keys = [...document.querySelectorAll(".hyb-svc input")].filter((x) => x.checked).map((x) => x.dataset.svc);
    saveSettingsPatch({ hybrid_services: keys }, V.settings.zapret_hybrid ? null : t("Сохранено. Включится вместе с «Включено»"));
  };
});
$("btn-hyb-sites").onclick = () => {
  $("hyb-sites").value = (V.settings.hybrid_sites || []).join("\n");
  $("dlg-hyb").showModal();
};
$("btn-hyb-cancel").onclick = () => $("dlg-hyb").close();
$("form-hyb").onsubmit = async (e) => {
  e.preventDefault();
  try {
    V = await call("save_settings", { settings: { ...V.settings, hybrid_sites: lines($("hyb-sites").value) } });
    $("dlg-hyb").close();
    render();
    toast(V.connected && V.settings.zapret_hybrid ? t("Сохранено, переподключился") : t("Сохранено"));
  } catch {}
};

// ---------- Tor ----------
function torRows() { $("tor-sites-row").classList.toggle("hidden", $("tor-mode").value !== "sites"); }
$("tor-mode").onchange = torRows;
$("btn-tor").onclick = () => {
  $("tor-mode").value = V.settings.tor_mode || "off";
  $("tor-sites").value = (V.settings.tor_sites || []).join("\n");
  $("tor-isolate").checked = V.settings.tor_isolate !== false;
  $("tor-status").textContent = V.tor ? V.tor[1] : V.connected ? "" : t("Заработает, когда подключишься к VPN.");
  torRows();
  $("dlg-tor").showModal();
};
$("btn-tor-cancel").onclick = () => $("dlg-tor").close();
$("form-tor").onsubmit = async (e) => {
  e.preventDefault();
  const settings = { ...V.settings, tor_mode: $("tor-mode").value, tor_sites: lines($("tor-sites").value), tor_isolate: $("tor-isolate").checked };
  try {
    V = await call("save_settings", { settings });
    $("dlg-tor").close();
    render();
    toast(V.connected ? t("Сохранено, переподключился") : t("Сохранено"));
  } catch {}
};

// ---------- белые списки ----------
$("btn-wl").onclick = () => {
  const cur = V.settings.wl_server || "";
  fillServerSelect(cur && !serverName(cur) ? "gone" : cur, "wl-server", true);
  $("wl-auto").checked = V.settings.wl_auto !== false;
  $("wl-status").textContent = V.wl_switched ? t("Сейчас похоже на белые списки — rxvpn на этом сервере и вернётся сам.") : "";
  $("dlg-wl").showModal();
};
$("btn-wl-cancel").onclick = () => $("dlg-wl").close();
$("btn-wl-check").onclick = async () => {
  const b = $("btn-wl-check");
  b.disabled = true;
  $("wl-status").textContent = t("Проверяю напрямую, ~10 секунд…");
  try { $("wl-status").textContent = await call("wl_check", {}); }
  catch { $("wl-status").textContent = ""; }
  finally { b.disabled = false; }
};
$("form-wl").onsubmit = async (e) => {
  e.preventDefault();
  const settings = { ...V.settings, wl_server: $("wl-server").value, wl_server_sub: "", wl_auto: $("wl-auto").checked };
  try {
    V = await call("save_settings", { settings });
    $("dlg-wl").close();
    render();
    toast(t("Сохранено"));
  } catch {}
};

// ---------- сайт → свой сервер ----------
let ssEdit = null, svcInfo = null;
/** Язык окна сменился (переключатель или Windows): сбросить то, что строится один раз. */
function langChanged() {
  svcInfo = null; // названия сервисов приходят из Rust уже переведёнными
  const pre = $("ss-preset");
  while (pre.options.length > 1) pre.lastElementChild.remove();
  fillPresets();
}
async function servicesInfo() {
  if (!svcInfo) svcInfo = await invoke("services_list");
  return svcInfo;
}
function renderSs() {
  const list = $("ss-list");
  const rules = V.settings.site_servers || [];
  list.replaceChildren();
  if (!rules.length) list.append(el("p", "hint", t("Пока нет правил. Начни с «+ Для сервиса…» или кнопки «Сервисы» у сервера.")));
  rules.forEach((r, i) => {
    const row = el("button", "ghost nav-row ss-row");
    row.type = "button";
    const name = ruleServer(r)?.name, spare = ruleBackup(r)?.name;
    const n = r.sites.filter((l) => l.trim() && !l.trim().startsWith("#")).length;
    const meta = name ? `→ ${name}` + (spare ? t(", запасной {spare}", { spare }) : "") + t(" · сайтов: {n}", { n })
      : spare ? t("основного нет → запасной {spare} · сайтов: {n}", { spare, n }) : t("сервера нет — эти сайты закрыты");
    row.append(el("span", "", r.name || t("Без названия")), el("span", "nav-meta" + (name ? "" : " warn"), meta));
    row.onclick = () => editSs(i);
    list.append(row);
  });
}
function fillServerSelect(cur, selId = "ss-server", none = false) {
  const sel = $(selId);
  sel.replaceChildren();
  if (none) {
    const o = el("option", "", t("— нет —"));
    o.value = "";
    sel.append(o);
  }
  if (cur && !serverName(cur)) {
    const o = el("option", "", t("— сервер удалён, выбери другой —"));
    o.value = "";
    sel.append(o);
  }
  // Одинаковые имена (бывает в подписках) различаем по адресу.
  const seen = {};
  for (const s of V.servers) seen[s.name] = (seen[s.name] || 0) + 1;
  for (const s of V.servers) {
    const o = el("option", "", seen[s.name] > 1 ? `${s.name} · ${s.address}:${s.port}` : s.name);
    o.value = s.id;
    sel.append(o);
  }
  sel.value = cur && serverName(cur) ? cur : sel.options[0]?.value ?? "";
}
async function openWarp(s) {
  $("warp-title").textContent = t("WARP поверх «{name}»", { name: s.name });
  $("warp-direct").checked = false;
  $("dlg-warp").dataset.id = s.id;
  $("dlg-warp").showModal();
}
$("btn-warp-cancel").onclick = () => $("dlg-warp").close();
$("form-warp").onsubmit = async (e) => {
  e.preventDefault();
  const via = $("warp-direct").checked ? "" : $("dlg-warp").dataset.id;
  const b = $("btn-warp-ok");
  b.disabled = true;
  b.textContent = t("Регистрирую…");
  try {
    V = await call("warp_add", { via });
    render();
    $("dlg-warp").close();
    toast(t("Готово: сервер «WARP · …» в папке «WARP». Выбери его или поставь в «Сайт → свой сервер»"));
  } catch {} finally {
    b.disabled = false;
    b.textContent = t("Добавить");
  }
};
function editSs(i, preset) {
  ssEdit = i;
  const r = i >= 0 ? V.settings.site_servers[i]
    : { name: preset?.name ?? "", sites: preset ? [...preset.sites] : [], server: (V.auto ? V.active_id : V.selected) || "" };
  $("ss-name").value = r.name;
  $("ss-sites").value = r.sites.join("\n");
  fillServerSelect(i >= 0 && !ruleServer(r) ? "gone" : r.server);
  fillServerSelect(r.backup && !ruleBackup(r) ? "gone" : r.backup || "", "ss-backup", true);
  $("btn-ss-del").classList.toggle("hidden", i < 0);
  $("form-ss").classList.remove("hidden");
  $("ss-close-row").classList.add("hidden");
  (preset ? $("ss-server") : $("ss-name")).focus();
}
function closeSsEdit() {
  ssEdit = null;
  $("form-ss").classList.add("hidden");
  $("ss-close-row").classList.remove("hidden");
}
async function saveSs(rules) {
  V = await call("save_settings", { settings: { ...V.settings, site_servers: rules } });
  render();
  renderSs();
  closeSsEdit();
  toast(V.connected && !V.settings.zapret ? t("Сохранено, переподключился") : t("Сохранено"));
}
$("btn-sitesrv").onclick = async () => {
  closeSsEdit();
  renderSs();
  $("dlg-sitesrv").showModal();
  const pre = $("ss-preset");
  if (pre.options.length === 1) {
    try {
      for (const x of await servicesInfo()) {
        const o = el("option", "", x.name);
        o.value = x.key;
        pre.append(o);
      }
    } catch {}
  }
};
$("btn-ss-add").onclick = () => {
  if (!V.servers.length) return toast(t("Сначала добавь сервера"), true);
  editSs(-1);
};
$("ss-preset").onchange = async (e) => {
  const key = e.target.value;
  e.target.value = "";
  const x = (await servicesInfo()).find((s) => s.key === key);
  if (!x) return;
  if (!V.servers.length) return toast(t("Сначала добавь сервера"), true);
  const i = (V.settings.site_servers || []).findIndex((r) => r.name === x.name);
  if (i >= 0) editSs(i);
  else editSs(-1, x);
};
$("form-ss").onsubmit = async (e) => {
  e.preventDefault();
  // sub проставит Rust по выбранному серверу.
  const r = { name: $("ss-name").value.trim(), sites: lines($("ss-sites").value), server: $("ss-server").value, sub: "",
    backup: $("ss-backup").value, backup_sub: "" };
  if (!r.server) return toast(t("Выбери сервер"), true);
  if (r.backup === r.server) return toast(t("Запасной сервер должен быть другим"), true);
  if (!r.sites.length) return toast(t("Впиши хотя бы один сайт"), true);
  const rules = [...(V.settings.site_servers || [])];
  if (ssEdit >= 0) rules[ssEdit] = r;
  else rules.push(r);
  try { await saveSs(rules); } catch {}
};
$("btn-ss-del").onclick = async () => {
  if (ssEdit == null || ssEdit < 0) return;
  const rules = V.settings.site_servers.filter((_, i) => i !== ssEdit);
  try { await saveSs(rules); } catch {}
};
$("btn-ss-cancel").onclick = closeSsEdit;
$("btn-ss-close").onclick = () => $("dlg-sitesrv").close();

// ---------- настройки ----------
const form = $("form-settings");
// Язык меняется сразу и отдельной командой (без перезапуска Xray): трей, уведомления, ошибки, лог.
$("set-lang").addEventListener("change", async (e) => {
  try {
    V = await call("set_lang", { lang: e.target.value });
    render();
  } catch {} // ошибку уже показал call()
});
function fillSettings() {
  const s = V.settings;
  $("set-lang").value = s.lang || "";
  form.socks_port.value = s.socks_port;
  form.http_port.value = s.http_port;
  form.system_proxy.checked = s.system_proxy;
  form.allow_lan.checked = s.allow_lan;
  form.kill_switch.checked = !!s.kill_switch;
  form.hotkey.value = s.hotkey ?? "";
  form.connect_apps.value = (s.connect_apps || []).join("\n");
  form.log_level.value = s.log_level;
  form.autostart.checked = s.autostart;
  form.auto_connect.checked = s.auto_connect;
  form.close_to_tray.checked = s.close_to_tray;
  form.run_as_admin.checked = s.run_as_admin && V.admin_ok;
  form.run_as_admin.disabled = !V.admin_ok;
  form.run_as_admin.title = V.admin_ok ? "" : t("Только у установленной версии (в Program Files)");
  form.encrypt_state.checked = !!s.encrypt_state;
  form.encrypt_state.disabled = !V.is_windows;
  form.sub_update_hours.value = s.sub_update_hours;
  form.notifications.checked = s.notifications;
  form.dns_remote.value = s.dns_remote;
  form.dns_direct.value = s.dns_direct;
  form.domain_strategy.value = s.domain_strategy;
  form.dns_ipv6.checked = s.dns_ipv6;
  form.hosts.value = s.hosts.join("\n");
  form.fragment.checked = s.fragment;
  form.fragment_length.value = s.fragment_length;
  form.fragment_delay.value = s.fragment_delay;
  form.udp_noise.checked = s.udp_noise;
  syncFragment();
  $("core-state").textContent = V.core_installed ? t("Установлено") : t("Не скачано");
  $("core-state").className = "core-state " + (V.core_installed ? "ok" : "bad");
  $("sb-state").textContent = V.singbox_installed ? t("Установлено") : t("Не скачано");
  $("sb-state").className = "core-state " + (V.singbox_installed ? "ok" : "");
  $("core-dir").textContent =
    (V.portable ? t("Портативная версия — всё хранится в: ") : t("Данные: ")) + V.data_dir;
}
function syncFragment() {
  const on = form.fragment.checked;
  for (const i of $("fragment-opts").querySelectorAll("input")) i.disabled = !on;
  $("fragment-opts").classList.toggle("dim", !on);
}
form.fragment.onchange = syncFragment;
$("btn-settings").onclick = () => { fillSettings(); $("dlg-settings").showModal(); };
$("btn-settings-cancel").onclick = () => $("dlg-settings").close();
form.onsubmit = async (e) => {
  e.preventDefault();
  const settings = {
    ...V.settings,
    socks_port: Number(form.socks_port.value),
    http_port: Number(form.http_port.value),
    system_proxy: form.system_proxy.checked,
    allow_lan: form.allow_lan.checked,
    kill_switch: form.kill_switch.checked,
    hotkey: form.hotkey.value.trim(),
    connect_apps: form.connect_apps.value.split("\n").map((l) => l.trim()).filter(Boolean),
    log_level: form.log_level.value,
    autostart: form.autostart.checked,
    auto_connect: form.auto_connect.checked,
    close_to_tray: form.close_to_tray.checked,
    run_as_admin: form.run_as_admin.checked,
    encrypt_state: form.encrypt_state.checked,
    sub_update_hours: Math.max(0, Math.min(168, Number(form.sub_update_hours.value) || 0)),
    notifications: form.notifications.checked,
    dns_remote: form.dns_remote.value.trim(),
    dns_direct: form.dns_direct.value.trim(),
    domain_strategy: form.domain_strategy.value,
    dns_ipv6: form.dns_ipv6.checked,
    hosts: lines(form.hosts.value),
    fragment: form.fragment.checked,
    fragment_length: form.fragment_length.value.trim() || "100-200",
    fragment_delay: form.fragment_delay.value.trim() || "10-20",
    udp_noise: form.udp_noise.checked,
  };
  const elevateNow = settings.run_as_admin && !V.settings.run_as_admin && !V.is_admin;
  V = await call("save_settings", { settings });
  $("dlg-settings").close();
  render();
  toast(t("Сохранено"));
  // Включили «с правами администратора», а сейчас без них — предложить сразу.
  if (elevateNow && confirm(t("Перезапустить rxvpn с правами администратора сейчас? Windows спросит «Да/Нет»."))) {
    try { await call("relaunch_admin", { then: "restart" }); } catch {}
  }
};

// ---------- бэкап и v2rayN ----------
async function withBtn(id, fn) {
  const b = $(id);
  if (b.disabled) return;
  b.disabled = true;
  try { await fn(); } catch {} finally { b.disabled = false; }
}
$("btn-backup-save").onclick = () => withBtn("btn-backup-save", async () => {
  const path = await call("export_backup");
  if (path) toast(t("Бэкап сохранён: ") + path);
});
$("btn-backup-load").onclick = () => withBtn("btn-backup-load", async () => {
  const r = await call("import_backup");
  if (!r) return;
  V = r.view;
  render();
  fillSettings();
  toast([t("Восстановлено из бэкапа"), ...r.notes].join("\n"));
});
$("btn-v2rayn").onclick = () => withBtn("btn-v2rayn", async () => {
  const r = await call("import_v2rayn");
  if (!r) return;
  showImport(r);
  await refresh();
});

async function downloadCore(btn) {
  const label = [...btn.childNodes]; // исходные узлы — их язык потом меняет i18n.js
  btn.disabled = true; btn.textContent = t("Качаю…");
  try {
    V = await call("download_core");
    render(); fillSettings();
    toast(t("Ядро Xray установлено"));
  } finally { btn.disabled = false; btn.replaceChildren(...label); }
}
$("btn-core-dl").onclick = (e) => downloadCore(e.currentTarget);
$("btn-core-banner").onclick = (e) => downloadCore(e.currentTarget);
$("btn-core-dir").onclick = () => call("open_core_dir");
$("btn-sb-dl").onclick = async (e) => {
  const btn = e.currentTarget, label = [...btn.childNodes];
  btn.disabled = true; btn.textContent = t("Качаю…");
  try {
    V = await call("download_singbox");
    render(); fillSettings();
    toast(t("sing-box установлен — серверы TUIC работают"));
  } catch {} finally { btn.disabled = false; btn.replaceChildren(...label); }
};
$("btn-notify-test").onclick = () => call("test_notification");
$("btn-config-close").onclick = () => $("dlg-config").close();

// ---------- Сообщить о проблеме ----------
async function openReport(error) {
  const pre = $("report-text");
  pre.textContent = t("Собираю…");
  $("btn-report-copy").disabled = $("btn-report-save").disabled = $("btn-report-gh").disabled = true;
  if (!$("dlg-report").open) $("dlg-report").showModal();
  try {
    pre.textContent = await call("problem_report", { error: error || null });
    $("btn-report-copy").disabled = $("btn-report-save").disabled = $("btn-report-gh").disabled = false;
  } catch (e) { pre.textContent = t("Отчёт не собрался: ") + e; }
}
$("btn-report").onclick = () => openReport(null);
$("toast-report").onclick = () => {
  $("toast").classList.remove("show");
  // Окно поверх ошибки закрываем: отчёт — отдельным окном.
  for (const d of document.querySelectorAll("dialog[open]")) d.close();
  openReport(lastError);
};
$("btn-report-copy").onclick = async () => {
  try { await call("problem_report_copy"); toast(t("Отчёт скопирован — вставь в чат или issue")); } catch {}
};
$("btn-report-save").onclick = async () => {
  try { if (await call("problem_report_save")) toast(t("Отчёт сохранён")); } catch {}
};
$("btn-report-gh").onclick = async () => {
  try { await call("problem_report_github"); toast(t("Отчёт скопирован — в открывшейся форме на GitHub вставь его (Ctrl+V)")); } catch {}
};
$("btn-report-close").onclick = () => $("dlg-report").close();

// ---------- лог ----------
const logEl = $("log");
const MAX_LOG = 500;
function addLog(line) {
  const err = /error|failed|rejected|did not connect|не прошла|не подключился/i.test(line); // i18n-skip — лог на любом языке
  // Новые строки — сверху. Читаешь старое ниже — новая строка не сдвигает то, что читаешь.
  const top = logEl.scrollTop < 40;
  const before = logEl.scrollHeight;
  const d = el("div", err ? "err" : line.startsWith("[rxvpn]") ? "me" : "", line);
  logEl.prepend(d);
  while (logEl.childElementCount > MAX_LOG) logEl.lastChild.remove();
  if (top || page !== "home") logEl.scrollTop = 0;
  else logEl.scrollTop += logEl.scrollHeight - before;
  // Ошибка, пока смотришь другую вкладку, — красная точка на «Главной» (лог там).
  if (err && page !== "home") document.querySelector('#tabs button[data-page="home"]').classList.add("alert");
}
$("btn-log-clear").onclick = () => logEl.replaceChildren();
$("btn-log-copy").onclick = async () => {
  try {
    // На экране новые сверху, в буфер — по порядку времени (так лог читают и присылают).
    await navigator.clipboard.writeText([...logEl.children].reverse().map((d) => d.textContent).join("\n"));
    toast(t("Лог скопирован. В нём адреса серверов — в открытые чаты не выкладывай"));
  } catch { toast(t("Не скопировалось — выдели текст мышкой"), true); }
};

// ---------- события из Rust ----------
// Сначала подписываемся, потом забираем то, что было до загрузки окна
// (например, ошибка автоподключения). Пришедшее в промежутке не дублируем.
let logEarly = [], logReady = false;
listen("log", (e) => (logReady ? addLog(e.payload) : logEarly.push(e.payload))).then(async () => {
  const buf = (await call("get_log").catch(() => [])) || [];
  buf.forEach(addLog);
  const endsWith = (n) => n <= buf.length && logEarly.slice(0, n).every((l, i) => buf[buf.length - n + i] === l);
  let n = logEarly.length;
  while (n > 0 && !endsWith(n)) n--;
  logEarly.slice(n).forEach(addLog);
  logReady = true;
  // Строка лога — на языке Rust в момент записи: ищем обе (i18n-skip-begin)
  const FAIL = ["[rxvpn] не подключился: ", "[rxvpn] did not connect: "];
  const fail = buf.findLast((l) => FAIL.some((f) => l.startsWith(f))); // i18n-skip-end
  if (fail && !V?.connected) toast(t("Не подключился: {e}", { e: fail.slice(FAIL.find((f) => fail.startsWith(f)).length) }), true);
});
listen("test-result", (e) => { pings[e.payload.id] = e.payload; renderList(); });
listen("speed-all-result", (e) => {
  const x = e.payload;
  speeds[x.id] = x;
  if (!x.skipped) pings[x.id] = { id: x.id, ms: x.ms, error: x.ms == null ? x.error : null };
  if (speedRun) speedRun.done++;
  render();
});
listen("state-changed", () => refresh());
listen("auto-status", (e) => {
  autoDelays = Object.fromEntries(e.payload.delays);
  if (V && e.payload.active_id !== V.active_id) { refresh(); return; }
  renderList();
});
listen("need-admin", async () => {
  await refresh();
  openAdmin(V.settings.zapret ? "zapret" : V.settings.zapret_hybrid ? "hybrid" : "tun");
});
listen("error-toast", (e) => toast(e.payload, true));
listen("core-exit", async (e) => {
  toast(e.payload, true);
  await refresh();
});

refresh().then(async () => {
  // Перезапустились от администратора ради подбора zapret — продолжаем.
  const act = await invoke("take_startup_action").catch(() => null);
  if (act === "zapret-test") { await openZapret(); runZapretTest(); }
});

// ---------- zapret ----------
let Z = null;          // ZapretView из Rust
let zTesting = false;
const dlgZ = $("dlg-zapret");

async function openZapret() {
  if (!dlgZ.open) dlgZ.showModal();
  try { Z = await call("zapret_get"); } catch { return; }
  $("z-targets").value = Z.targets.join("\n");
  renderZapret();
}

function zBest(results) {
  const base = results.find((r) => r.name === "");
  let best = null;
  for (const r of results) {
    if (!r.name || r.error || r.ok <= (base?.ok ?? 0)) continue;
    if (!best || r.ok > best.ok || (r.ok === best.ok && r.ms < best.ms)) best = r;
  }
  return best?.name ?? null;
}

function zTitle(r) {
  if (r.error) return r.error;
  // Проверок на сайт — 2 (TLS 1.3 со страницей целиком и TLS 1.2).
  const bad = r.targets.filter((x) => !x.full || x.ok < 2).map((x) => `${x.name}: ${x.ok}/2${x.stalled ? t(", обрыв на первых КБ") : ""}`);
  return bad.length ? t("Не прошло:\n") + bad.join("\n") : t("Все сайты открылись");
}

function renderZapret() {
  if (!Z) return;
  const testing = zTesting || Z.testing;
  const src = Z.source;
  $("z-src-title").textContent = Z.builtin ? t("Стратегии Flowseal {n}", { n: src?.version ?? Z.builtin_version }) : t("Своя папка");
  $("z-dir").textContent = !Z.builtin ? Z.dir
    : src?.from_github ? t("обновлены с GitHub {n}", { n: ago(src.installed_at) }) : t("встроены в rxvpn");
  $("z-dir").classList.toggle("mono", !Z.builtin);
  $("btn-z-update").classList.toggle("hidden", !Z.builtin);
  $("btn-z-builtin").classList.toggle("hidden", Z.builtin);
  $("btn-z-folder").textContent = Z.builtin ? t("Своя папка…") : t("Другая…");
  $("z-engine").textContent = Z.windows ? Z.engine : t("Zapret работает только в Windows");
  $("z-warn").textContent = Z.engine_warn || "";
  $("z-warn").classList.toggle("hidden", !Z.engine_warn);
  $("z-game").checked = Z.game_filter;
  $("z-auto").checked = !!V?.settings.zapret_autocheck;
  $("z-game").disabled = testing;
  $("btn-z-folder").disabled = $("btn-z-update").disabled = $("btn-z-builtin").disabled = testing;
  const tb = $("btn-z-test");
  tb.disabled = testing || !Z.strategies.length;
  tb.textContent = testing ? t("Подбираю…") : t("Подобрать лучшую");
  $("z-progress").classList.toggle("hidden", !testing);

  const byName = Object.fromEntries(Z.results.filter((r) => r.name).map((r) => [r.name, r]));
  const base = Z.results.find((r) => r.name === "");
  $("z-base").classList.toggle("hidden", !base);
  if (base) $("z-base").textContent = t("Без zapret: {ok} из {total} проверок", { ok: base.ok, total: base.total });
  const best = zBest(Z.results);

  const list = $("z-list");
  const scroll = list.scrollTop;
  list.replaceChildren();
  if (Z.scan_error) list.append(el("p", "hint bad", Z.scan_error));
  else if (!Z.strategies.length) list.append(el("p", "hint", t("Стратегий нет")));
  for (const s of Z.strategies) {
    const r = el("div", "srv" + (s.name === Z.selected ? " sel" : "") + (s.name === best ? " best" : "") + (s.name === Z.running ? " current" : ""));
    r.append(el("span", "radio"));
    const info = el("div");
    info.append(el("div", "srv-name", s.name));
    const meta = s.name === Z.running ? t("● работает") : s.file;
    info.append(el("div", "srv-meta", s.notes.length ? t("{meta} · вырезано опций: {length}", { meta, length: s.notes.length }) : meta));
    if (s.notes.length) info.title = s.notes.join("\n");
    r.append(info);
    const pg = el("span", "srv-ping");
    const x = byName[s.name];
    if (x) {
      pg.textContent = x.error ? "×" : `${x.ok}/${x.total}`;
      pg.classList.add(x.error ? "bad" : x.ok === x.total ? "ok" : x.ok > (base?.ok ?? 0) ? "mid" : "bad");
      pg.title = zTitle(x);
    }
    r.append(pg, el("div"));
    r.onclick = async () => {
      if (s.name === Z.selected || zTesting || Z.testing) return;
      try {
        Z = await call("zapret_select", { name: s.name });
        renderZapret();
        await refresh();
        toast(V.zapret_active ? t("Zapret: переключился на «{name}»", { name: s.name }) : t("Выбрана «{name}»", { name: s.name }));
      } catch {}
    };
    list.append(r);
  }
  list.scrollTop = scroll;
  $("z-skipped").textContent = Z.skipped.length
    ? t("Пропущено ({count}): {list}{more}", { count: Z.skipped.length, list: Z.skipped.slice(0, 3).join("; "), more: Z.skipped.length > 3 ? "…" : "" }) : "";
}

/** Сохранить свои сайты и игровой фильтр, если поменялись. false — ошибка (тост уже показан). */
async function saveZapretPrefs() {
  const targets = lines($("z-targets").value);
  const game = $("z-game").checked;
  if (JSON.stringify(targets) === JSON.stringify(V.settings.zapret_targets) && game === V.settings.zapret_game_filter) return true;
  try {
    V = await call("save_settings", { settings: { ...V.settings, zapret_targets: targets, zapret_game_filter: game } });
    render();
    return true;
  } catch { return false; }
}

async function runZapretTest() {
  if (zTesting) return;
  // Для гибрида подбор идёт рядом с VPN; для «Без VPN» VPN на это время выключается.
  const hybrid = V?.settings.zapret_hybrid && !V?.settings.zapret;
  if (V?.connected && !hybrid &&
      !confirm(t("Подбор выключит VPN: стратегии проверяются напрямую, с твоего настоящего IP (несколько минут). ") +
               t("Найдётся рабочая — rxvpn останется в режиме «Без VPN», не найдётся — VPN включится обратно. Продолжить?"))) return;
  if (!(await saveZapretPrefs())) return;
  zTesting = true;
  if (Z) Z.results = [];
  $("z-bar").value = 0;
  $("z-prog-text").textContent = t("Готовлю движок…");
  renderZapret();
  adminKind = "zapret-test";
  try {
    const r = await call("zapret_test");
    Z = r.view;
    toast(r.message, !r.fine);
  } catch {
  } finally {
    zTesting = false;
    try { Z = await invoke("zapret_get"); } catch {}
    renderZapret();
    await refresh();
  }
}

listen("zapret-progress", (e) => {
  const p = e.payload, sc = p.score;
  $("z-bar").value = p.done / p.total;
  const who = sc.name ? `«${sc.name}»` : t("без zapret");
  $("z-prog-text").textContent = t("{done} из {total} · {who}: {res}", { done: p.done, total: p.total, who, res: sc.error ? t("не запустилась") : `${sc.ok}/${sc.total}` });
  if (Z) {
    Z.results = Z.results.filter((r) => r.name !== sc.name).concat([sc]);
    renderZapret();
  }
});

$("btn-zapret").onclick = openZapret;
$("btn-current").onclick = () => {
  if (V?.settings.zapret) return openZapret();
  showPage("servers");
  if (!V?.servers.length) $("import-text").focus();
};
$("chk-hybrid").onchange = async (e) => {
  const on = e.target.checked;
  adminKind = "hybrid";
  setBusy(V.connected);
  try {
    V = await call("save_settings", { settings: { ...V.settings, zapret_hybrid: on } });
    toast(on
      ? (V.hybrid_active ? t("Выбранные сайты — через zapret, остальное через VPN") : V.settings.zapret_strategy ? t("Включится вместе с VPN") : t("Подбери стратегию zapret"))
      : t("Сайты «мимо VPN» — снова через VPN"));
  } catch { await refresh(); }
  finally { setBusy(false); }
  if (on && !V.settings.zapret_strategy) openZapret();
};
$("btn-z-test").onclick = runZapretTest;
$("btn-z-stop").onclick = async () => {
  await call("zapret_cancel").catch(() => {});
  $("z-prog-text").textContent = t("Останавливаю после текущей стратегии…");
};
$("btn-z-folder").onclick = () => withBtn("btn-z-folder", async () => {
  const z = await call("zapret_pick_folder");
  if (!z) return;
  Z = z;
  renderZapret();
  await refresh();
  toast(t("Стратегий в папке: {length}. Нажми «Подобрать лучшую»", { length: Z.strategies.length }));
});
$("btn-z-update").onclick = () => withBtn("btn-z-update", async () => {
  $("btn-z-update").textContent = t("Качаю…");
  try {
    Z = await call("zapret_update");
    renderZapret();
    await refresh();
    toast(t("Стратегии Flowseal {n} — готово. Стоит заново нажать «Подобрать лучшую»", { n: Z.source?.version ?? "" }));
  } finally { $("btn-z-update").textContent = t("Обновить"); }
});
$("btn-z-builtin").onclick = () => withBtn("btn-z-builtin", async () => {
  Z = await call("zapret_use_builtin");
  renderZapret();
  await refresh();
  toast(t("Снова встроенные стратегии Flowseal"));
});
$("z-auto").onchange = async (e) => {
  try { V = await call("save_settings", { settings: { ...V.settings, zapret_autocheck: e.target.checked } }); }
  catch { e.target.checked = !e.target.checked; }
};
$("z-game").onchange = async () => {
  if (await saveZapretPrefs()) { try { Z = await call("zapret_get"); } catch {} }
  else $("z-game").checked = V.settings.zapret_game_filter;
  renderZapret();
};
$("btn-z-close").onclick = async () => {
  if (zTesting) { dlgZ.close(); return; } // подбор идёт дальше, прогресс — в логе
  if (await saveZapretPrefs()) dlgZ.close();
};
dlgZ.addEventListener("cancel", (e) => { e.preventDefault(); $("btn-z-close").click(); });

// ---------- программы ----------
const appsDraft = { mode: "except", except: "", only: "" };
let procs = [];

function appsLines() { return lines($("apps-text").value); }
function renderApps() {
  document.querySelectorAll("#seg-apps button").forEach((b) => b.classList.toggle("active", b.dataset.mode === appsDraft.mode));
  $("apps-hint").textContent = appsDraft.mode === "only"
    ? t("Через VPN пойдут только эти программы, всё остальное — напрямую. Удобно: Telegram и Discord через VPN, игры — нет.")
    : t("Эти программы пойдут мимо VPN, всё остальное — как обычно. Например, игры и Steam, чтобы не рос пинг.");
  renderProcs();
}
function renderProcs() {
  const list = $("proc-list");
  list.replaceChildren();
  const q = $("proc-filter").value.trim().toLowerCase();
  const have = new Set(appsLines().map((l) => l.toLowerCase().replace(/\.exe$/, "")));
  const shown = procs.filter((p) => !q || p.toLowerCase().includes(q));
  if (!shown.length) { list.append(el("div", "proc", procs.length ? t("ничего не нашлось") : t("загружаю…"))); return; }
  for (const p of shown) {
    const added = have.has(p.toLowerCase().replace(/\.exe$/, ""));
    const r = el("div", "proc" + (added ? " added" : ""));
    r.append(el("span", "", p));
    const b = el("button", "ghost small", added ? t("добавлена") : t("+ добавить"));
    b.disabled = added;
    b.onclick = () => {
      const ta = $("apps-text");
      ta.value = (ta.value.trim() ? ta.value.trim() + "\n" : "") + p;
      renderProcs();
    };
    r.append(b);
    list.append(r);
  }
}
async function loadProcs() {
  procs = [];
  renderProcs();
  try { procs = await call("list_processes"); } catch {}
  renderProcs();
}
$("btn-apps").onclick = () => {
  appsDraft.mode = V.settings.apps_mode;
  appsDraft.except = V.settings.apps_direct.join("\n");
  appsDraft.only = V.settings.apps_proxy.join("\n");
  $("apps-text").value = appsDraft[appsDraft.mode];
  $("proc-filter").value = "";
  renderApps();
  $("dlg-apps").showModal();
  loadProcs();
};
document.querySelectorAll("#seg-apps button").forEach((b) => {
  b.onclick = () => {
    appsDraft[appsDraft.mode] = $("apps-text").value;
    appsDraft.mode = b.dataset.mode;
    $("apps-text").value = appsDraft[appsDraft.mode];
    renderApps();
  };
});
$("apps-text").addEventListener("input", renderProcs);
$("proc-filter").addEventListener("input", renderProcs);
$("btn-proc-refresh").onclick = loadProcs;
$("btn-apps-cancel").onclick = () => $("dlg-apps").close();
$("btn-apps-save").onclick = async () => {
  appsDraft[appsDraft.mode] = $("apps-text").value;
  try {
    V = await call("save_settings", { settings: {
      ...V.settings, apps_mode: appsDraft.mode,
      apps_direct: lines(appsDraft.except), apps_proxy: lines(appsDraft.only),
    } });
  } catch { return; }
  $("dlg-apps").close();
  render();
  toast(V.connected ? t("Сохранено, переподключился") : t("Сохранено"));
};

// ---------- правила ----------
const PRESETS = [
  { name: tk("Торренты — напрямую"), protocols: ["bittorrent"], action: "direct",
    tip: tk("Многие VPN банят за торренты. Трафик торрент-клиентов пойдёт мимо VPN.") },
  { name: tk("Блокировать QUIC (UDP 443)"), network: "udp", ports: "443", action: "block",
    tip: tk("YouTube и Google перейдут на обычный TCP — через VPN это часто быстрее и стабильнее.") },
  { name: tk("YouTube и Google — через VPN"), sites: ["geosite:youtube", "geosite:google"], action: "proxy" },
  { name: tk("Telegram — через VPN"), sites: ["geosite:telegram", "geoip:telegram"], action: "proxy" },
  { name: tk("Discord — через VPN (с голосом)"), apps: ["Discord.exe"], action: "proxy",
    tip: tk("Правило по программе — голосовые идут на разные IP. Лучше работает в режиме TUN.") },
  { name: tk("ChatGPT и Claude — через VPN"), sites: ["geosite:openai", "geosite:anthropic"], action: "proxy" },
  { name: tk("Steam — напрямую"), sites: ["geosite:steam"], action: "direct" },
  { name: tk("Игровые сервисы — напрямую"), sites: ["geosite:category-games"], action: "direct" },
  { name: tk("Локальная сеть дома — напрямую"), sites: ["192.168.0.0/16", "10.0.0.0/8"], action: "direct" },
];
const ACT_LABEL = { proxy: tk("через VPN"), direct: tk("напрямую"), block: tk("блок") };
let draftRules = [];
let openRule = -1;

function newRule(p = {}) {
  return { enabled: true, name: p.name ? t(p.name) : t("Новое правило"), sites: p.sites || [], apps: p.apps || [],
    ports: p.ports || "", network: p.network || "", protocols: p.protocols || [], action: p.action || "proxy" };
}
function ruleSummary(r) {
  const parts = [];
  if (r.sites.length) parts.push(r.sites.slice(0, 3).join(", ") + (r.sites.length > 3 ? ` +${r.sites.length - 3}` : ""));
  if (r.apps.length) parts.push(t("программы: ") + r.apps.join(", "));
  if (r.protocols.length) parts.push(r.protocols.join(", "));
  if (r.network) parts.push(r.network.toUpperCase());
  if (r.ports) parts.push(t("порты ") + r.ports);
  return parts.join(" · ") || t("нет условий");
}
function renderRules() {
  const list = $("rules-list");
  list.replaceChildren();
  if (!draftRules.length) {
    list.append(el("div", "rules-empty", t("Правил пока нет. Добавь своё или возьми шаблон — например, «Торренты — напрямую».")));
  }
  draftRules.forEach((r, i) => list.append(ruleCard(r, i)));
  const L = V.lists;
  $("lists-state").textContent = V.lists_busy ? t("Качаю…")
    : L ? t("{n} сайтов, {n2} подсетей · {n3}", { n: L.domains.toLocaleString(i18n.lang()), n2: L.ips.toLocaleString(i18n.lang()), n3: ago(L.updated_at) })
    : t("Не скачаны");
  $("lists-state").className = "core-state " + (L ? "ok" : "bad");
  $("btn-lists-update").disabled = V.lists_busy;
}
function ruleCard(r, i) {
  const c = el("div", "rule" + (r.enabled ? "" : " off"));
  const h = el("div", "rule-head");
  const on = el("input");
  on.type = "checkbox"; on.checked = r.enabled; on.title = t("Включено");
  on.onchange = () => { r.enabled = on.checked; renderRules(); };
  const mid = el("div");
  mid.append(el("div", "rule-title", r.name || t("Без названия")), el("div", "rule-sum", ruleSummary(r)));
  const act = el("span", "rule-act " + r.action, t(ACT_LABEL[r.action]));
  const btns = el("div", "rule-btns");
  const mk = (lbl, title, fn, dis) => { const b = el("button", "", lbl); b.title = title; b.disabled = !!dis; b.onclick = fn; btns.append(b); };
  mk("↑", t("Выше"), () => { [draftRules[i - 1], draftRules[i]] = [draftRules[i], draftRules[i - 1]]; openRule = -1; renderRules(); }, i === 0);
  mk("↓", t("Ниже"), () => { [draftRules[i + 1], draftRules[i]] = [draftRules[i], draftRules[i + 1]]; openRule = -1; renderRules(); }, i === draftRules.length - 1);
  mk("✎", t("Изменить"), () => { openRule = openRule === i ? -1 : i; renderRules(); });
  mk("✕", t("Удалить"), () => { draftRules.splice(i, 1); openRule = -1; renderRules(); });
  h.append(on, mid, act, btns);
  c.append(h);
  if (openRule === i) c.append(ruleEditor(r));
  return c;
}
function ruleEditor(r) {
  const b = el("div", "rule-body");
  const field = (label, node, wide) => { const l = el("label", wide ? "wide" : "", label); l.append(node); b.append(l); return node; };
  const name = field(t("Название"), Object.assign(el("input"), { type: "text", value: r.name }), true);
  name.oninput = () => { r.name = name.value; b.parentElement.querySelector(".rule-title").textContent = r.name || t("Без названия"); };
  const sites = field(t("Сайты, IP, geosite:/geoip: — по строке"), Object.assign(el("textarea"), { rows: 4, value: r.sites.join("\n"), spellcheck: false }));
  sites.placeholder = "youtube.com\ngeosite:telegram\n95.163.0.0/16";
  sites.oninput = () => { r.sites = lines(sites.value); };
  const apps = field(t("Программы — по строке"), Object.assign(el("textarea"), { rows: 4, value: r.apps.join("\n"), spellcheck: false }));
  apps.placeholder = "Telegram.exe\nD:\\Games\\";
  apps.oninput = () => { r.apps = lines(apps.value); };
  const ports = field(t("Порты"), Object.assign(el("input"), { type: "text", value: r.ports, placeholder: t("443 или 80,443 или 1000-2000") }));
  ports.oninput = () => { r.ports = ports.value.trim(); };
  const net = field(t("Сеть"), el("select"));
  for (const [v, lbl] of [["", t("любая")], ["tcp", "TCP"], ["udp", "UDP"]]) net.append(Object.assign(el("option", "", lbl), { value: v }));
  net.value = r.network;
  net.onchange = () => { r.network = net.value; };
  const protos = el("div", "rule-protos");
  for (const [v, lbl] of [["bittorrent", "BitTorrent"], ["quic", "QUIC"], ["tls", "TLS"], ["http", "HTTP"]]) {
    const l = el("label");
    const cb = Object.assign(el("input"), { type: "checkbox", checked: r.protocols.includes(v) });
    cb.onchange = () => { r.protocols = cb.checked ? [...r.protocols, v] : r.protocols.filter((x) => x !== v); };
    l.append(cb, lbl);
    protos.append(l);
  }
  field(t("Протокол (распознаётся по трафику)"), protos, true);
  const seg = el("div", "seg seg3");
  for (const v of ["proxy", "direct", "block"]) {
    const btn = el("button", r.action === v ? "active" : "", { proxy: t("Через VPN"), direct: t("Напрямую"), block: t("Блокировать") }[v]);
    btn.onclick = () => { r.action = v; renderRules(); };
    seg.append(btn);
  }
  field(t("Действие"), seg, true);
  return b;
}
const presetSel = $("rule-preset");
function fillPresets() {
  presetSel.replaceChildren(Object.assign(el("option", "", t("+ Из шаблона…")), { value: "" }));
  PRESETS.forEach((p, i) => presetSel.append(Object.assign(el("option", "", t(p.name)), { value: String(i), title: p.tip ? t(p.tip) : "" })));
}
fillPresets();
presetSel.onchange = () => {
  const p = PRESETS[Number(presetSel.value)];
  presetSel.value = "";
  if (!p) return;
  draftRules.push(newRule(p));
  openRule = -1;
  renderRules();
  if (p.tip) toast(t(p.tip));
};
$("btn-rule-add").onclick = () => { draftRules.push(newRule()); openRule = draftRules.length - 1; renderRules(); };
$("btn-rules").onclick = () => {
  draftRules = structuredClone(V.settings.rules);
  openRule = -1;
  $("lists-days").value = V.settings.lists_update_days;
  renderRules();
  $("dlg-rules").showModal();
};
$("btn-rules-cancel").onclick = () => $("dlg-rules").close();
$("btn-rules-save").onclick = async () => {
  try {
    V = await call("save_settings", { settings: {
      ...V.settings, rules: draftRules,
      lists_update_days: Math.max(0, Math.min(60, Number($("lists-days").value) || 0)),
    } });
  } catch { return; } // ошибка правила — тостом, окно остаётся, можно поправить
  $("dlg-rules").close();
  render();
  toast(V.connected ? t("Правила сохранены, переподключился") : t("Правила сохранены"));
};
$("btn-lists-update").onclick = async () => {
  V.lists_busy = true; renderRules();
  try {
    V = await call("update_lists");
    toast(t("Списки обновлены: {n} сайтов", { n: V.lists.domains.toLocaleString(i18n.lang()) }));
  } catch { await refresh(); }
  renderRules();
};

// ---------- свой сервер (VPS) ----------
function fmtBytes(n) {
  if (!n) return "0";
  const u = [t("Б"), t("КБ"), t("МБ"), t("ГБ"), t("ТБ")];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + " " + u[i];
}

function renderVps() {
  const box = $("vps-list");
  if (!box) return;
  const list = V.vps || [];
  box.replaceChildren(...list.map((v) => {
    const b = el("button", "vps-card");
    const left = el("div");
    left.append(el("div", "", v.name), el("div", "meta", `${v.host} · Xray ${v.xray_version} · ${v.friends.length ? t("друзей: ") + v.friends.length : t("без друзей")}`));
    b.append(left, el("span", "meta", t("управлять ›")));
    b.onclick = () => openVpsMan(v.id);
    return b;
  }));
  if (!list.length) box.append(el("p", "hint", t("Есть свой VPS? rxvpn сам поставит на него VPN — кнопка «+ Свой сервер».")));
  if (vmId && $("dlg-vpsman").open) fillVpsMan();
}

// Установка: шаг 1 — адрес и вход, шаг 2 — отпечаток «это твой сервер?», потом установка.
let vpsFp = null, vpsBusy = false;
function vpsReset() {
  vpsFp = null;
  $("vps-step1").classList.remove("hidden");
  $("vps-step2").classList.add("hidden");
  $("vps-trust").checked = false;
  $("btn-vps-next").textContent = t("Дальше");
  $("vps-status").textContent = "";
}
function vpsWipe() {
  // Пароль и ключ не держим в окне дольше нужного.
  $("vps-pass").value = $("vps-key").value = $("vps-keypass").value = "";
}
$("btn-vps-new").onclick = () => { vpsReset(); vpsWipe(); $("dlg-vps").showModal(); };
$("btn-vps-cancel").onclick = () => { if (!vpsBusy) { vpsWipe(); $("dlg-vps").close(); } };
$("dlg-vps").addEventListener("cancel", (e) => { if (vpsBusy) e.preventDefault(); else vpsWipe(); });
$("form-vps").onsubmit = async (e) => {
  e.preventDefault();
  if (vpsBusy) return;
  const host = $("vps-host").value.trim(), port = Number($("vps-port").value) || 22;
  if (!host) { $("vps-status").textContent = t("Впиши IP сервера"); return; }
  vpsBusy = true;
  $("btn-vps-next").disabled = $("btn-vps-cancel").disabled = true;
  try {
    if (!vpsFp) {
      $("vps-status").textContent = t("Подключаюсь, узнаю ключ сервера…");
      vpsFp = await call("vps_probe", { host, sshPort: port });
      $("vps-fp").textContent = vpsFp;
      $("vps-step1").classList.add("hidden");
      $("vps-step2").classList.remove("hidden");
      $("btn-vps-next").textContent = t("Установить");
      $("vps-status").textContent = "";
      return;
    }
    if (!$("vps-trust").checked) { $("vps-status").textContent = t("Сверь отпечаток и отметь «Это мой сервер»"); return; }
    $("vps-status").textContent = t("Ставлю… 2–5 минут. Шаги — в логе на главной.");
    const key = $("vps-key").value;
    V = await call("vps_install", {
      host, sshPort: port, name: $("vps-name").value,
      password: key.trim() ? null : $("vps-pass").value,
      key: key.trim() ? key : null, keyPass: $("vps-keypass").value || null,
      fingerprint: vpsFp,
    });
    vpsWipe();
    $("dlg-vps").close();
    render();
    toast(t("Свой сервер готов (папка «Мои сервера»). Сохрани ключ SSH — кнопка в окне сервера"));
    const v = V.vps[V.vps.length - 1];
    if (v) openVpsMan(v.id);
  } catch (err) {
    $("vps-status").textContent = String(err);
    if (!vpsFp) vpsReset();
  } finally {
    vpsBusy = false;
    $("btn-vps-next").disabled = $("btn-vps-cancel").disabled = false;
  }
};

// Управление.
let vmId = null, vmTraffic = {};
function vmCur() { return (V.vps || []).find((v) => v.id === vmId); }
function openVpsMan(id) {
  vmId = id; vmTraffic = {};
  $("vm-status").textContent = "";
  fillVpsMan();
  if (!$("dlg-vpsman").open) $("dlg-vpsman").showModal();
}
function fillVpsMan() {
  const v = vmCur();
  if (!v) { $("dlg-vpsman").close(); return; }
  $("vm-title").textContent = v.name;
  const info = $("vm-info");
  const rows = [
    [t("Адрес"), `${v.host}:${v.port} (SSH ${v.ssh_port})`],
    [t("Система"), `${v.os}, ${v.arch}`],
    ["Xray", v.xray_version],
    [t("Маскировка"), v.sni],
    [t("Вход по паролю"), v.password_off ? t("выключен, только ключ rxvpn") : t("включён (выключить не вышло — смотри лог)")],
    [t("Ключ сервера"), v.host_key],
  ];
  if (vmTraffic.owner) rows.push([t("Твой трафик"), `↑ ${fmtBytes(vmTraffic.owner[0])} ↓ ${fmtBytes(vmTraffic.owner[1])}`]);
  if (v.exit_name) rows.push([t("Мост"), t("выход через «{name}»", { name: v.exit_name })]);
  info.replaceChildren(...rows.flatMap(([k, val]) => [el("span", "", k), el("span", "", val)]));
  // Выходной сервер моста: любой из списка, кроме самого моста.
  const ex = $("vm-exit");
  if (document.activeElement !== ex) {
    const none = el("option", "", t("Без моста — выход прямо с этого сервера"));
    none.value = "";
    const opts = (V.servers || []).filter((n) => n.id !== v.node_id).map((n) => { const o = el("option", "", n.name); o.value = n.id; return o; });
    if (v.exit_name && !v.exit_id) { const o = el("option", "", v.exit_name); o.value = "?"; opts.unshift(o); }
    ex.replaceChildren(none, ...opts);
    ex.value = v.exit_id || (v.exit_name ? "?" : "");
  }
  const fl = $("vm-friends");
  fl.replaceChildren(...v.friends.map((f) => {
    const r = el("div", "friend-row" + (f.enabled ? "" : " off"));
    const tr = vmTraffic[f.id];
    const tog = el("button", "ghost small", f.enabled ? t("Отключить") : t("Включить"));
    tog.onclick = () => vmDo("vps_friend_set", { id: v.id, fid: f.id, enabled: !f.enabled, delete: false });
    const qr = el("button", "ghost small", "QR");
    qr.onclick = () => openQr(`${v.name} · ${f.name}`, "vps_qr", { id: v.id, fid: f.id }, t("Пусть друг отсканирует в Happ / v2rayNG / v2RayTun."));
    const cp = el("button", "ghost small", t("Ссылка"));
    cp.onclick = async () => { try { await call("vps_copy", { id: v.id, fid: f.id }); toast(t("Ссылка друга скопирована")); } catch {} };
    const lim = el("button", "ghost small" + (f.limit_gb || f.expires ? " on" : ""), t("Лимит"));
    lim.title = t("Лимит трафика и срок доступа — сервер сам отключит друга");
    lim.onclick = () => { vmLimitOpen = vmLimitOpen === f.id ? null : f.id; fillVpsMan(); };
    const del = el("button", "ghost small danger", "✕");
    del.title = t("Удалить друга");
    del.onclick = () => { if (confirm(t("Удалить «{name}»? Его ссылка перестанет работать.", { name: f.name }))) vmDo("vps_friend_set", { id: v.id, fid: f.id, enabled: null, delete: true }); };
    const who = el("div", "who");
    who.append(el("span", "name", f.name));
    const used = tr ? tr[0] + tr[1] : null;
    const parts = [];
    if (used != null) parts.push(f.limit_gb ? t("{used} из {limit} ГБ", { used: fmtBytes(used), limit: f.limit_gb }) : `↑ ${fmtBytes(tr[0])} ↓ ${fmtBytes(tr[1])}`);
    else if (f.limit_gb) parts.push(t("лимит {limit} ГБ", { limit: f.limit_gb }));
    if (f.expires) parts.push(t("до {date}", { date: new Date(f.expires * 1000).toLocaleDateString() }));
    if (parts.length) who.append(el("span", "traffic", parts.join(" · ")));
    const expired = f.expires && f.expires * 1000 <= Date.now();
    if (f.enabled && (expired || (tr && tr[2])))
      who.append(el("span", "traffic warn", expired ? t("отключён сервером: срок вышел") : t("отключён сервером: кончился трафик")));
    r.append(who, tog, lim, qr, cp, del);
    if (vmLimitOpen !== f.id) return r;
    // Мини-форма лимита — прямо под другом.
    const box = el("div", "friend-limit");
    const gb = el("input"); gb.type = "number"; gb.min = "0"; gb.max = "100000"; gb.value = f.limit_gb || ""; gb.placeholder = t("без лимита");
    const days = el("input"); days.type = "number"; days.min = "0"; days.max = "3650";
    days.value = f.expires ? Math.max(1, Math.ceil((f.expires * 1000 - Date.now()) / 86400000)) : ""; days.placeholder = t("бессрочно");
    const l1 = el("label", "", t("ГБ")); l1.prepend(gb);
    const l2 = el("label", "", t("дней")); l2.prepend(days);
    const save = el("button", "primary small", t("Сохранить"));
    save.onclick = () => vmDo("vps_friend_limits", { id: v.id, fid: f.id, limitGb: Number(gb.value) || 0, days: Number(days.value) || 0 },
      t("Лимит «{name}» сохранён — сервер сам следит за ним", { name: f.name })).then(() => { vmLimitOpen = null; fillVpsMan(); });
    const reset = el("button", "ghost small", t("Обнулить трафик"));
    reset.title = t("Новый месяц: счётчик с нуля, отключённый по лимиту — снова работает");
    reset.onclick = () => vmDo("vps_friend_reset", { id: v.id, fid: f.id }, t("Трафик «{name}» обнулён", { name: f.name })).then(() => { if (vmTraffic[f.id]) vmTraffic[f.id] = [0, 0, false]; fillVpsMan(); });
    box.append(l1, l2, save, reset, el("p", "hint", t("Пусто — без лимита и бессрочно. Сервер проверяет раз в 2 минуты, даже когда этот комп выключен.")));
    const wrap = el("div", "friend-wrap");
    wrap.append(r, box);
    return wrap;
  }));
  if (!v.friends.length) fl.append(el("p", "hint", t("Пока никого.")));
}
let vmBusy = false;
let vmLimitOpen = null; // у какого друга раскрыта форма лимита
async function vmDo(cmd, args, okText) {
  if (vmBusy) return;
  vmBusy = true;
  $("vm-status").textContent = t("Подключаюсь к серверу…");
  try {
    V = await call(cmd, args);
    render();
    $("vm-status").textContent = okText || t("Готово");
  } catch (e) {
    $("vm-status").textContent = String(e);
  } finally {
    vmBusy = false;
  }
}
$("btn-vm-close").onclick = () => $("dlg-vpsman").close();
$("btn-vm-exit").onclick = () => {
  const exit = $("vm-exit").value;
  if (exit === "?") return; // выходной не из списка — оставить как есть
  vmDo("vps_set_exit", { id: vmId, exit },
    exit ? t("Мост готов: трафик идёт через выходной сервер. При белых списках rxvpn переключится на него сам") : t("Мост выключен — выход прямо с этого сервера"));
};
$("btn-vm-key").onclick = async () => {
  try {
    const p = await call("vps_export_key", { id: vmId });
    if (p) $("vm-status").textContent = t("Ключ сохранён: ") + p + t(". Храни его как пароль: он открывает сервер.");
  } catch {}
};
$("btn-vm-qr").onclick = () => { const v = vmCur(); if (v) openQr(v.name, "vps_qr", { id: v.id, fid: null }, t("Открой на телефоне Happ / v2rayNG / v2RayTun → «+» → сканировать QR.")); };
$("btn-vm-copy").onclick = async () => { try { await call("vps_copy", { id: vmId, fid: null }); toast(t("Ссылка скопирована")); } catch {} };
$("btn-vm-update").onclick = () => vmDo("vps_update", { id: vmId }, t("Xray обновлён"));
$("btn-vm-restart").onclick = () => vmDo("vps_restart", { id: vmId }, t("Xray перезапущен"));
$("btn-vm-traffic").onclick = async () => {
  if (vmBusy) return;
  vmBusy = true;
  $("vm-status").textContent = t("Спрашиваю сервер…");
  try {
    vmTraffic = (await call("vps_traffic", { id: vmId })).by;
    fillVpsMan();
    $("vm-status").textContent = t("Трафик — за всё время (или с последнего «Обнулить трафик»)");
  } catch (e) { $("vm-status").textContent = String(e); } finally { vmBusy = false; }
};
$("form-friend").onsubmit = (e) => {
  e.preventDefault();
  const name = $("friend-name").value.trim();
  if (!name) return;
  vmDo("vps_friend_add", { id: vmId, name }, t("«{name}» добавлен — дай ему QR или ссылку", { name })).then(() => { $("friend-name").value = ""; });
};
$("btn-vm-remove").onclick = () => {
  const v = vmCur();
  if (v && confirm(t("Удалить VPN с сервера «{name}»? Xray и служба удалятся, сервер пропадёт из списка, вход по паролю root снова включится. ufw и fail2ban останутся.", { name: v.name })))
    vmDo("vps_uninstall", { id: v.id, onlyList: false }, t("Удалено"));
};
$("btn-vm-forget").onclick = () => {
  const v = vmCur();
  if (v && confirm(t("Убрать «{name}» из rxvpn, не трогая сервер? Вход по паролю на нём выключен — ключ rxvpn пропадёт вместе с записью, войти сможешь только через консоль хостера.", { name: v.name })))
    vmDo("vps_uninstall", { id: v.id, onlyList: true }, t("Убран из списка"));
};

// ---------- защита и обновление на главной ----------
function renderShield() {
  const box = $("shield"), list = V.shield || [];
  box.classList.toggle("hidden", !list.length);
  box.replaceChildren(...list.map((x) => {
    const s = el("span", "shield-item " + x.level, x.text);
    s.title = x.hint;
    return s;
  }));
  const u = V.update;
  $("btn-upd-home").classList.toggle("hidden", !u);
  if (u) {
    $("upd-home-name").textContent = t("Есть rxvpn {version} — обновить", { version: u.version });
    $("upd-home-meta").textContent = u.notes || t("Нажми — скачаю, проверю подпись и перезапущусь");
  }
}
$("btn-upd-home").onclick = () => $("btn-upd-apply").onclick();

// ---------- всё ли в порядке ----------
function renderHealth() {
  renderShield();
  const box = $("health"), btn = $("health-btn");
  const list = V.health || [];
  const top = list[0];
  box.className = "health " + (top ? top.level : "ok");
  $("health-text").textContent = top ? top.text + (list.length > 1 ? t(" (и ещё {n})", { n: list.length - 1 }) : "") : t("✓ Всё в порядке");
  box.title = list.map((x) => x.text).join("\n");
  btn.classList.toggle("hidden", !top);
  if (top) { btn.textContent = top.button; btn.dataset.action = top.action; }
}
$("health-btn").onclick = () => {
  const go = (page) => document.querySelector(`#tabs [data-page="${page}"]`)?.click();
  switch ($("health-btn").dataset.action) {
    case "core": call("download_core").then((v) => { V = v; render(); toast(t("Ядро обновлено")); }).catch(() => {}); break;
    case "lists": call("update_lists").then((v) => { V = v; render(); toast(t("Списки обновлены")); }).catch(() => {}); break;
    case "zapret": go("bypass"); break;
    case "servers": case "subs": go("servers"); break;
    case "dns": $("ht-ip").click(); break;
    case "sitesrv": go("routes"); $("btn-sitesrv").click(); break;
    case "dnsfix":
      adminKind = "dns";
      call("doh_restore").then((v) => { V = v; render(); toast(t("DNS Windows вернул как было")); }).catch(() => {});
      break;
  }
};

// ---------- обновления ----------
function showUpd(u) {
  if (!u.configured) {
    $("upd-state").textContent = t("{current} · обновления в этой сборке не настроены", { current: u.current });
    $("btn-upd-check").disabled = true;
    return;
  }
  $("upd-state").textContent = u.version ? t("{current} → есть {version}", { current: u.current, version: u.version }) : t("{current} · последняя", { current: u.current });
  $("btn-upd-apply").classList.toggle("hidden", !u.version);
  if (u.notes) $("upd-hint").textContent = t("Что нового: ") + u.notes;
}
$("btn-upd-check").onclick = async () => {
  $("upd-state").textContent = t("Проверяю…");
  try { showUpd(await call("update_check")); } catch (e) { $("upd-state").textContent = t("Не проверилось: ") + String(e); }
};
$("btn-upd-apply").onclick = async () => {
  if (!confirm(t("Скачать и поставить новую версию? rxvpn перезапустится сам."))) return;
  $("upd-state").textContent = t("Качаю и проверяю…");
  $("upd-home-meta").textContent = t("Качаю и проверяю…");
  try { await call("update_apply"); } catch (e) {
    $("upd-state").textContent = t("Не обновилось: ") + String(e);
    $("upd-home-meta").textContent = t("Не обновилось: ") + String(e);
  }
};
$("btn-settings").addEventListener("click", () => { call("update_check").then(showUpd).catch(() => {}); });

// ---------- трафик по программам (Ещё → «Трафик по программам») ----------
// Подсчёт идёт, пока окно открыто: закрыли — сессия ETW останавливается (app_traffic_stop).
let atTimer = null;
async function atRefresh() {
  let list;
  try { list = await invoke("app_traffic"); }
  catch (e) {
    $("at-status").textContent = String(e);
    $("at-list").replaceChildren();
    clearInterval(atTimer); atTimer = null;
    return;
  }
  const max = Math.max(1, ...list.map((a) => a.up + a.down));
  $("at-list").replaceChildren(...list.slice(0, 30).map((a) => {
    const row = el("div", "at-row");
    const bar = el("span", "at-bar");
    bar.style.width = Math.max(2, Math.round(((a.up + a.down) / max) * 100)) + "%";
    row.append(el("span", "at-name", a.name), el("span", "at-val", `↓ ${fmtBytes(a.down)}  ↑ ${fmtBytes(a.up)}`), bar);
    return row;
  }));
  $("at-status").textContent = list.length ? t("Обновляется каждые 2 секунды") : t("Пока тихо — открой сайт или запусти загрузку");
}
$("btn-apps-traffic").onclick = () => {
  $("dlg-apps-traffic").showModal();
  $("at-status").textContent = t("Включаю подсчёт…");
  atRefresh();
  clearInterval(atTimer);
  atTimer = setInterval(atRefresh, 2000);
};
$("btn-at-reset").onclick = async () => { await invoke("app_traffic_stop").catch(() => {}); atRefresh(); };
$("btn-at-close").onclick = () => $("dlg-apps-traffic").close();
$("dlg-apps-traffic").addEventListener("close", () => {
  clearInterval(atTimer); atTimer = null;
  invoke("app_traffic_stop").catch(() => {});
});
