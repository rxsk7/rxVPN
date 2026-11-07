// Перевод окна (этап 6). Исходный язык — русский: ключ = русский текст, перевод — ui/locales/en.js.
// t("… {x} …", {x}) — строка на текущем языке; tk("…") — только пометка ключа (константы верхнего
// уровня: переводятся позже через t(константа), чтобы смена языка без перезапуска их тоже меняла).
// Статичный текст index.html (текстовые узлы и title/placeholder/aria-label) собирается один раз при
// загрузке — данные пользователя (имена серверов, подписок) в перевод не попадают никогда.
"use strict";
(() => {
  // Без прототипа: t("constructor") и т.п. не достанут Object.prototype.
  const EN = Object.assign(Object.create(null), window.RX_EN);
  const ATTRS = ["title", "placeholder", "aria-label"];
  const norm = (s) => s.replace(/\s+/g, " ").trim();
  let lang = "ru";
  try { if (localStorage.getItem("rxvpn.lang") === "en") lang = "en"; } catch {}

  function t(s, vars) {
    let r = lang === "en" && typeof EN[s] === "string" && EN[s] ? EN[s] : String(s ?? "");
    if (vars && typeof vars === "object") r = r.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k] ?? "") : m));
    return r;
  }
  const tk = (s) => s;

  // translate="no" (стандартный атрибут HTML) — не переводить элемент и всё внутри.
  const keep = (e) => !!e?.closest('[translate="no"]');
  // Статичные места: {node, attr, key, pre, post, shown}. shown — что мы туда поставили последним:
  // если app.js с тех пор переписал текст сам, узел больше не наш.
  const statics = [];
  function collect() {
    const w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = w.nextNode(); n; n = w.nextNode()) {
      const tag = n.parentElement?.tagName;
      if (tag === "SCRIPT" || tag === "STYLE" || keep(n.parentElement)) continue;
      const key = norm(n.data);
      if (!key || !(key in EN)) continue;
      const m = /^(\s*)[\s\S]*?(\s*)$/.exec(n.data);
      statics.push({ node: n, attr: null, key, pre: m[1], post: m[2], shown: n.data });
    }
    for (const e of document.body.querySelectorAll("[title],[placeholder],[aria-label]")) {
      if (keep(e)) continue;
      for (const a of ATTRS) {
        const v = e.getAttribute(a);
        if (v === null) continue;
        const key = norm(v);
        if (key && key in EN) statics.push({ node: e, attr: a, key, pre: "", post: "", shown: v });
      }
    }
  }
  function apply() {
    document.documentElement.lang = lang;
    for (const s of statics) {
      const cur = s.attr ? s.node.getAttribute(s.attr) : s.node.data;
      if (cur !== s.shown) continue;
      const v = s.pre + t(s.key) + s.post;
      if (v === cur) continue;
      if (s.attr) s.node.setAttribute(s.attr, v);
      else s.node.data = v;
      s.shown = v;
    }
  }
  /** Сменить язык окна без перезапуска. true — если поменялся. */
  function set(l) {
    l = l === "en" ? "en" : "ru";
    if (l === lang) return false;
    lang = l;
    try { localStorage.setItem("rxvpn.lang", l); } catch {}
    apply();
    return true;
  }

  collect();
  apply();
  window.t = t;
  window.tk = tk;
  window.i18n = Object.freeze({ lang: () => lang, set });
})();
