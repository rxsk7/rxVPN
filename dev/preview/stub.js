// Заглушка window.__TAURI__ для превью окна в браузере (dev/preview/serve.py).
// Состояние — из ?state=empty|off|on (по умолчанию off). В сборку не попадает.
(() => {
  const q = new URLSearchParams(location.search);
  const mode = q.get("state") || "off";
  const settings = window.__RX_SETTINGS;
  const srv = (id, name, summary, sub, group, mbps, stab) => ({
    id, name, summary, address: "203.0.113." + id.length, port: 443, sub_id: sub, group,
    stab: stab == null ? null : { pct: stab, weak: false, n: 40 }, mbps, hidden: null,
  });
  const servers = mode === "empty" ? [] : [
    srv("a1", "🇳🇱 Нидерланды", "VLESS · Reality · nl1.example.com", "s1", null, 184.2, 99),
    srv("a2", "🇩🇪 Германия", "VLESS · xHTTP · de.example.com", "s1", null, 96.4, 97),
    srv("a3", "🇫🇮 Финляндия", "Trojan · TLS · fi.example.com", "s1", null, 61.0, 88),
    srv("a4", "🇺🇸 США", "Hysteria2 · us.example.com", "s1", null, null, null),
    srv("b1", "Мой VPS", "VLESS · Reality · 198.51.100.7", null, "Свои", 240.5, 100),
  ];
  const on = mode === "on";
  const view = {
    servers, list_filter: { hide_dead: false, dedup: false }, lang: q.get("lang") || "ru",
    subscriptions: mode === "empty" ? [] : [{ id: "s1", name: "Мой VPN-сервис", url: "https://example.com/sub", nodes: 4, updated: 0, usage: { upload: 1e9, download: 21e9, total: 100e9, expire: Date.now() / 1000 + 86400 * 23 } }],
    settings, selected: mode === "empty" ? null : "a1", auto: false, connected: on, active_id: on ? "a1" : null,
    active_name: on ? "🇳🇱 Нидерланды" : null, tun_active: false, is_admin: false, testing: false, speed_all: false,
    lists: null, lists_busy: false, core_installed: mode !== "empty", core_dir: "C:\\rxvpn\\data\\core",
    data_dir: "C:\\rxvpn\\data", portable: true, admin_ok: true, zapret_active: false, zapret_name: null,
    zapret_testing: false,
    tg: { running: false, port: 1443, link: "", active: 0, total: 0, web: 0, cloudflare: 0, direct: 0, failed: 0, last_error: "" },
    doh: { running: false, label: "", queries: 0, cached: 0, failed: 0, last_error: "" },
    vps: q.get("vps") ? [{ id: "v1", name: "Мой VPS", host: "198.51.100.7", ssh_port: 22, port: 443, sni: "www.apple.com",
      xray_version: "26.10.21", os: "Ubuntu 24.04", arch: "amd64", host_key: "SHA256:abc", key_fp: "SHA256:def", password_off: true, node_id: "b1",
      friends: [{ id: "aaaaaaaaaa", name: "Саша", enabled: true, limit_gb: 50, expires: Math.floor(Date.now() / 1000) + 86400 * 23 },
                { id: "bbbbbbbbbb", name: "Дима", enabled: true, limit_gb: 10, expires: 0 }] }] : [], tor: null, wl_switched: false, health: [], hybrid_active: false, is_windows: true,
    // ?shield=tun|proxy|bad — строка «что защищено»; ?upd=1 — плашка обновления.
    shield: !on ? [] : ({
      tun: [{ level: "ok", text: "Всё через VPN", hint: "" }, { level: "ok", text: "Kill switch включён", hint: "" }, { level: "ok", text: "DNS через VPN", hint: "" }],
      bad: [{ level: "ok", text: "Всё через VPN", hint: "" }, { level: "bad", text: "Kill switch снят", hint: "" }, { level: "bad", text: "DNS идёт мимо VPN", hint: "" }],
    })[q.get("shield")] || [{ level: "warn", text: "Через VPN — только браузер", hint: "" }],
    // ?upd=1 — короткое «что нового», ?upd=long — длинное, как в настоящем манифесте (до 300 знаков).
    update: q.get("upd") ? { version: "0.18.0", notes: q.get("upd") === "long" ? "Серверы из подписок с маскировкой sudoku и header-custom теперь подключаются (после обновления нажми «Обновить подписки»). На главной кнопка «Обновления» — проверить новую версию сейчас; сам rxvpn проверяет её каждые 3 часа." : "Состояние защиты на главной, kill switch переживает падение rxvpn" } : null,
  };
  const handlers = {};
  const log = [
    "[rxvpn] запуск 0.12.0",
    on ? "[rxvpn] подключено: 🇳🇱 Нидерланды (VLESS · Reality)" : "[rxvpn] отключено",
  ];
  const answers = {
    get_view: () => view,
    get_log: () => log,
    take_startup_action: () => null,
    connect: () => new Promise((r) => setTimeout(() => { view.connected = true; view.active_id = view.selected; r(view); }, 4000)), // как настоящий: несколько секунд
    disconnect: () => { view.connected = false; view.paused = false; view.pause_until = null; return view; },
    pause_vpn: ({ minutes }) => { view.connected = false; view.paused = true; view.pause_until = minutes ? Math.floor(Date.now() / 1000) + minutes * 60 : null; return view; },
    vps_traffic: () => ({ by: { owner: [1e9, 9e9, false], aaaaaaaaaa: [2.1e9, 17.3e9, false], bbbbbbbbbb: [1.2e9, 9.6e9, true] } }),
    app_traffic: () => { const k = (Date.now() / 1000) % 1e4; return [["firefox.exe", 2.1e6, 48e6 + k * 9e4], ["Telegram.exe", 0.9e6, 12e6], ["steam.exe", 0.2e6, 3.4e6], ["svchost.exe", 0.1e6, 0.4e6]].map(([name, up, down]) => ({ name, up, down })); },
    // Мастер первого запуска (?state=empty → «Вставить из буфера»); ?wiz=dead — серверы не отвечают.
    read_clipboard: () => "vless://example",
    import_text: () => { view.servers = [srv("a1", "🇳🇱 Нидерланды", "VLESS · Reality · nl1.example.com", null, null, null, null), srv("a2", "🇩🇪 Германия", "VLESS · xHTTP · de.example.com", null, null, null, null)]; view.selected = "a1"; return { added: 2, updated: 0, errors: [] }; },
    download_core: () => new Promise((r) => setTimeout(() => { view.core_installed = true; r(view); }, 2000)),
    test_all: () => new Promise((r) => setTimeout(() => r(view.servers.map((s, i) => ({ id: s.id, ms: q.get("wiz") === "dead" ? null : 48 + i * 30 }))), 2000)),
    select_server: ({ id }) => { view.selected = id; view.active_name = view.servers.find((s) => s.id === id)?.name; return view; },
    update_check: () => ({ configured: true, current: "0.12.0", version: null, notes: null }),
  };
  window.__TAURI__ = {
    core: {
      invoke: async (cmd, args) => {
        console.debug("invoke", cmd, args);
        const f = answers[cmd];
        if (f) return structuredClone(await f(args));
        return null;
      },
    },
    event: {
      listen: async (name, cb) => { (handlers[name] ||= []).push(cb); return () => {}; },
    },
  };
  // Живой график скорости для состояния «on».
  if (on) {
    let t = 0;
    setInterval(() => {
      t++;
      const down = Math.round(2.5e6 + Math.sin(t / 3) * 1.4e6 + Math.random() * 6e5);
      for (const cb of handlers.stats || []) cb({ payload: { up_speed: Math.round(down / 9), down_speed: down, up_total: 31e6 + t * 3e5, down_total: 412e6 + t * down, ping: 42 } });
    }, 1000);
  }
})();
