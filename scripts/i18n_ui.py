#!/usr/bin/env python3
"""Проверка перевода окна rxvpn (этап 6, часть 2). Вызывается из scripts/i18n_check.py.

Исходный язык — русский: ключ = русский текст.
  ui/*.js      — t("…", {x}) / tk("…") (tk — только пометка ключа: строка переводится позже через t(var));
  ui/index.html — текстовые узлы и атрибуты title/placeholder/aria-label (пробелы схлопнуты, края обрезаны),
                  кроме элементов с translate="no" и всего внутри них;
  перевод — ui/locales/en.js: `window.RX_EN = {…JSON…};`

Ошибка, если:
  - кириллический литерал в JS стоит не первым аргументом t(/tk( (кроме комментариев,
    строк с `// i18n-skip` и блоков `i18n-skip-begin … i18n-skip-end`);
  - в t(/tk( шаблонная строка с ${…} (нужно t("… {x}", {x}));
  - нет перевода / пустой / кириллица / другие подстановки / лишний ключ (check_table из i18n_check.py).

  python3 scripts/i18n_ui.py            — проверка только окна
  python3 scripts/i18n_ui.py --add      — дописать в en.js недостающие ключи (пустыми) и убрать лишние
  python3 scripts/i18n_ui.py --list F   — все кириллические литералы JS (строка, вид, текст) — для правки
"""
import json
import os
import re
import sys
from html.parser import HTMLParser

CYR = re.compile(r'[А-Яа-яЁё]')
UI_JS = ['ui/app.js', 'ui/i18n.js']
UI_HTML = 'ui/index.html'
EN_UI = 'ui/locales/en.js'
EN_PREFIX = 'window.RX_EN = '
HTML_ATTRS = ('title', 'placeholder', 'aria-label')

# После этих токенов «/» начинает регэксп, а не деление.
_RE_PREV = set('(,=:[!&|?{};+-*%<>~^')
_RE_KW = ('return', 'typeof', 'case', 'do', 'else', 'in', 'of', 'new', 'delete', 'void', 'throw', 'instanceof', 'yield', 'await')


def lex_js(src):
    """Токены JS: ('comment'|'str'|'tpl'|'regex', начало, конец). У 'tpl' — список вложенных ${…}.
    Возвращает плоский список, включая строки внутри ${…} шаблонов."""
    toks = []
    n = len(src)

    def prev_sig(i):
        j = i - 1
        while j >= 0 and src[j] in ' \t\r\n':
            j -= 1
        if j < 0:
            return '', j
        if src[j].isalnum() or src[j] in '_$':
            k = j
            while k >= 0 and (src[k].isalnum() or src[k] in '_$'):
                k -= 1
            return src[k + 1:j + 1], j
        return src[j], j

    def scan(i, stop_brace):
        depth = 0
        while i < n:
            c = src[i]
            if src.startswith('//', i):
                j = src.find('\n', i)
                j = n if j < 0 else j
                toks.append(('comment', i, j, None)); i = j; continue
            if src.startswith('/*', i):
                j = src.find('*/', i + 2)
                j = n if j < 0 else j + 2
                toks.append(('comment', i, j, None)); i = j; continue
            if c in '"\'':
                j = i + 1
                while j < n and src[j] != c:
                    if src[j] == '\n':
                        raise SyntaxError(f'незакрытая строка с позиции {i}')
                    j += 2 if src[j] == '\\' else 1
                toks.append(('str', i, j + 1, None)); i = j + 1; continue
            if c == '`':
                j = i + 1
                holes = []
                while j < n and src[j] != '`':
                    if src[j] == '\\':
                        j += 2; continue
                    if src.startswith('${', j):
                        a = j
                        j = scan(j + 2, True)
                        holes.append((a, j))
                        continue
                    j += 1
                toks.append(('tpl', i, j + 1, holes)); i = j + 1; continue
            if c == '/':
                p, _ = prev_sig(i)
                if p == '' or p in _RE_PREV or p in _RE_KW:
                    j = i + 1
                    cls = False
                    while j < n:
                        if src[j] == '\\':
                            j += 2; continue
                        if src[j] == '[':
                            cls = True
                        elif src[j] == ']':
                            cls = False
                        elif src[j] == '/' and not cls:
                            break
                        elif src[j] == '\n':
                            raise SyntaxError(f'незакрытый регэксп с позиции {i}')
                        j += 1
                    j += 1
                    while j < n and src[j].isalpha():
                        j += 1
                    toks.append(('regex', i, j, None)); i = j; continue
            if stop_brace:
                if c == '{':
                    depth += 1
                elif c == '}':
                    if depth == 0:
                        return i + 1
                    depth -= 1
            i += 1
        return i

    scan(0, False)
    toks.sort(key=lambda x: x[1])
    return toks


def js_unescape(body):
    """Значение JS-строки без кавычек (только простые экранирования, как в нашем коде)."""
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c == '\\' and i + 1 < len(body):
            d = body[i + 1]
            if d == 'n': out.append('\n')
            elif d == 't': out.append('\t')
            elif d == 'u' and body[i + 2:i + 3] == '{':
                j = body.index('}', i)
                out.append(chr(int(body[i + 3:j], 16))); i = j + 1; continue
            elif d == 'u':
                out.append(chr(int(body[i + 2:i + 6], 16))); i += 6; continue
            elif d == '\n': pass
            else: out.append(d)
            i += 2; continue
        out.append(c); i += 1
    return ''.join(out)


def _skip_ranges(src):
    """Строки с `i18n-skip` и блоки i18n-skip-begin … i18n-skip-end (номера строк)."""
    lines = src.split('\n')
    skip, inside = set(), False
    for k, ln in enumerate(lines, 1):
        if 'i18n-skip-begin' in ln:
            inside = True
        if inside or 'i18n-skip' in ln:
            skip.add(k)
        if 'i18n-skip-end' in ln:
            inside = False
    return skip


def js_scan(path, rel):
    """→ (ключи {текст: где}, ошибки, литералы для --list)."""
    src = open(path, encoding='utf-8').read()
    keys, errs, lits = {}, [], []
    skip = _skip_ranges(src)
    for kind, a, b, holes in lex_js(src):
        if kind == 'comment':
            continue
        text = src[a:b]
        if not CYR.search(text):
            continue
        line = src.count('\n', 0, a) + 1
        where = f'{rel}:{line}'
        if kind == 'tpl' and holes:
            # Кириллица только в ${…} (строки там — свои токены) не считается.
            parts, last = [], a + 1
            for ha, hb in holes:
                parts.append(src[last:ha]); last = hb
            parts.append(src[last:b - 1])
            if not CYR.search(''.join(parts)):
                continue
        lits.append((line, kind, text))
        if line in skip:
            continue
        before = src[max(0, a - 4):a]
        m = re.search(r'(?<![\w$.])(t|tk)\(\s*$', src[max(0, a - 12):a])
        if kind == 'regex':
            errs.append(f'{where}: кириллица в регэкспе (пометь // i18n-skip, если это сравнение с русским текстом)')
            continue
        if not m:
            errs.append(f'{where}: кириллица вне t()/tk(): {text[:70]}')
            continue
        if kind == 'tpl' and holes:
            errs.append(f'{where}: шаблон ${{…}} внутри t() — нужно t("… {{x}}", {{x}}): {text[:70]}')
            continue
        val = js_unescape(text[1:-1])
        keys.setdefault(val, where)
        del before
    return keys, errs, lits


def norm(s):
    return re.sub(r'\s+', ' ', s).strip()


class _Html(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.keys = {}
        self.stack = []  # (тег, translate="no")

    def _no(self):
        return any(no for _, no in self.stack)

    def _add(self, s):
        if self._no():
            return
        k = norm(s)
        if k and CYR.search(k):
            self.keys.setdefault(k, f'{UI_HTML}:{self.getpos()[0]}')

    def handle_starttag(self, tag, attrs):
        no = dict(attrs).get('translate') == 'no'
        if tag not in ('br', 'input', 'img', 'meta', 'link', 'hr', 'source', 'path', 'rect', 'stop'):
            self.stack.append((tag, no))
        if no:
            return
        for k, v in attrs:
            if k in HTML_ATTRS and v:
                self._add(v)

    def handle_startendtag(self, tag, attrs):
        if dict(attrs).get('translate') == 'no':
            return
        for k, v in attrs:
            if k in HTML_ATTRS and v:
                self._add(v)

    def handle_endtag(self, tag):
        while self.stack:
            if self.stack.pop()[0] == tag:
                break

    def handle_data(self, data):
        if self.stack and self.stack[-1][0] in ('script', 'style'):
            return
        self._add(data)


def html_scan(path):
    p = _Html()
    p.feed(open(path, encoding='utf-8').read())
    return p.keys


def load_en(root):
    path = os.path.join(root, EN_UI)
    if not os.path.exists(path):
        return {}
    s = '\n'.join(ln for ln in open(path, encoding='utf-8').read().split('\n')
                  if not ln.startswith('//')).strip()
    if not s.startswith(EN_PREFIX) or not s.endswith(';'):
        raise ValueError(f'{EN_UI}: ожидается `{EN_PREFIX}{{…}};`')
    return json.loads(s[len(EN_PREFIX):-1])


def save_en(root, table):
    path = os.path.join(root, EN_UI)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write('// Перевод окна. Ключ — русский текст из ui/index.html и t()/tk() в ui/*.js.\n')
        f.write('// Проверка и заготовки: python3 scripts/i18n_ui.py [--add]\n')
        f.write(EN_PREFIX + json.dumps(dict(sorted(table.items())), ensure_ascii=False, indent=1) + ';\n')


def collect(root):
    keys, errs = {}, []
    for rel in UI_JS:
        path = os.path.join(root, rel)
        if os.path.exists(path):
            k, e, _ = js_scan(path, rel)
            errs += e
            for x, w in k.items():
                keys.setdefault(x, w)
    for x, w in html_scan(os.path.join(root, UI_HTML)).items():
        keys.setdefault(x, w)
    return keys, errs


def check(root, check_table):
    keys, errs = collect(root)
    try:
        table = load_en(root)
    except (ValueError, json.JSONDecodeError) as e:
        return errs + [str(e)]
    errs += check_table(EN_UI, keys, table)
    print(f'i18n окно: ключей {len(keys)}')
    return errs


def main(argv):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if '--list' in argv:
        out = argv[argv.index('--list') + 1]
        with open(out, 'w', encoding='utf-8') as f:
            for rel in UI_JS:
                path = os.path.join(root, rel)
                if os.path.exists(path):
                    for line, kind, text in js_scan(path, rel)[2]:
                        f.write(f'{rel}:{line}\t{kind}\t{text}\n')
        return 0
    if '--add' in argv:
        keys, errs = collect(root)
        table = load_en(root)
        new = {k: table.get(k, '') for k in keys}
        save_en(root, new)
        for e in errs:
            print(e)
        print(f'{EN_UI}: ключей {len(new)}, без перевода {sum(1 for v in new.values() if not v.strip())}')
        return 0
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from i18n_check import check_table
    errs = check(root, check_table)
    for e in errs:
        print(e)
    return 1 if errs else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
