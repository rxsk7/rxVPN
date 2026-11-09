// Мини-окно из трея. Логика подключения — та же, что в большом окне: команды connect/disconnect в Rust.
const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const $ = (id) => document.getElementById(id);

let V = null;          // состояние из Rust (View)
let busy = false;      // ждём ответа на «Подключить / Отключить»
let connecting = false; // именно подключаемся (для GIF-лавины)
let connSince = null;
let ping = null;

const isOn = () => !!V && (V.connected || V.zapret_active);

function fmtSpeed(n) {
  const u = [t("Б/с"), t("КБ/с"), t("МБ/с"), t("ГБ/с")];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : Math.round(n)) + " " + u[i];
}
function clock(ms) {
  const s = Math.max(0, Math.floor(ms / 1000)), p = (x) => String(x).padStart(2, "0");
  return `${p(Math.floor(s / 3600))}:${p(Math.floor(s / 60) % 60)}:${p(s % 60)}`;
}

// GIF с лавиной — только пока подключаемся; каждый раз с первого кадра.
let gifShown = false;
function renderAvalanche() {
  const want = busy && connecting && !matchMedia("(prefers-reduced-motion: reduce)").matches;
  $("btn-connect").classList.toggle("connecting", want);
  if (want === gifShown) return;
  gifShown = want;
  const img = document.querySelector("#btn-connect .k2-anim");
  if (want) { img.removeAttribute("src"); img.src = "img/avalanche-k2.gif"; }
  else setTimeout(() => { if (!gifShown) img.removeAttribute("src"); }, 400);
}

function render() {
  if (!V) return;
  if (V.lang) i18n.set(V.lang);
  const on = isOn() && !busy;
  if (on && !connSince) connSince = Date.now();
  if (!isOn()) connSince = null;
  const b = $("btn-connect");
  b.classList.toggle("on", on);
  b.classList.toggle("busy", busy);
  b.setAttribute("aria-label", isOn() ? t("Отключить") : t("Подключить"));
  renderAvalanche();

  const st = $("m-state");
  st.classList.toggle("on", on);
  st.classList.toggle("busy", busy);
  st.textContent = busy ? (connecting ? t("Подключаюсь…") : t("Подождите…"))
    : V.zapret_active ? t("Zapret работает")
    : V.connected ? t("Подключено")
    : V.kill_on ? t("VPN упал")
    : V.paused ? t("Пауза")
    : t("Не подключено");

  const sel = V.servers.find((s) => s.id === V.selected);
  const name = V.settings.zapret ? t("Zapret · без VPN") : V.auto ? t("⚡ Авто") : sel ? sel.name : t("Сервер не выбран");
  $("m-name").textContent = V.connected && V.active_name ? V.active_name : name;
  $("m-meta").textContent = V.settings.zapret ? "" : sel && !V.auto ? sel.summary : "";

  let sub;
  if (busy) sub = t("Подождите немного");
  else if (V.connected || V.zapret_active) sub = (ping ? t("{ms} мс", { ms: ping }) + " · " : "") + clock(Date.now() - connSince);
  else if (V.kill_on) sub = t("Kill switch: интернет закрыт, пока VPN не вернётся");
  else if (V.paused) sub = V.pause_until ? t("VPN включится сам в {time}", { time: hhmm(V.pause_until) }) : t("VPN выключен, пока не нажмёшь на гору");
  else sub = V.servers.length || V.settings.zapret ? t("Нажми на гору, чтобы подключиться") : t("Добавь сервер в большом окне");
  $("m-sub").textContent = sub;
  $("m-speed").classList.toggle("idle", !V.connected);
  $("m-pause").classList.toggle("hidden", !on);
}
function hhmm(unix) {
  const d = new Date(unix * 1000), p = (x) => String(x).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}
$("m-pause").onclick = async () => {
  if (busy) return;
  try { V = await invoke("pause_vpn", { minutes: 15 }); } catch { await refresh(); }
  render();
};

async function refresh() {
  try { V = await invoke("get_view"); } catch { return; }
  render();
}

$("btn-connect").onclick = async () => {
  if (busy || !V) return;
  if (!isOn() && !V.servers.length && !V.settings.zapret) return invoke("show_main_window");
  connecting = !isOn();
  busy = true;
  render();
  try { V = await invoke(isOn() ? "disconnect" : "connect"); }
  catch { await refresh(); invoke("show_main_window"); } // ошибку и подробности покажет большое окно
  finally { busy = false; connecting = false; render(); }
};
$("m-open").onclick = () => invoke("show_main_window");
$("m-server").onclick = () => invoke("show_main_window");

listen("state-changed", () => refresh());
listen("stats", (e) => {
  const s = e.payload;
  $("m-down").textContent = fmtSpeed(s.down_speed || 0);
  $("m-up").textContent = fmtSpeed(s.up_speed || 0);
  ping = s.ping ?? null;
});
// Окно показали снова — свежее состояние (пока было скрыто, подключение могли поменять из трея).
document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
setInterval(() => { if (V && connSince && !document.hidden) render(); }, 1000);
refresh();
