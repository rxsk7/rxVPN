#!/usr/bin/env python3
"""Проверка переводов rxvpn (этап 6).

Исходный язык — русский: ключ перевода = русский текст как в коде.
  Rust:  tr!("…") / trs!("…") / trc!("…")  →  locales/en.json
  Окно:  t("…") в ui/*.js и текст ui/index.html  →  ui/locales/en.js (когда появится ui/i18n.js)

Падает (код 1), если:
  - кириллический литерал Rust стоит вне tr!/trs!/trc!, тестов, комментариев, отладочных
    макросов (expect/panic!/assert!…) и пометок `// i18n-skip` / `i18n-skip-begin … i18n-skip-end`;
  - у ключа нет перевода, перевод пустой, в нём кириллица или другой набор подстановок {…};
  - в файле перевода есть лишний ключ (строку из кода убрали).

  python3 scripts/i18n_check.py              — проверка
  python3 scripts/i18n_check.py --add        — дописать недостающие ключи с пустым переводом, убрать лишние
  python3 scripts/i18n_check.py --missing F  — недостающие/пустые ключи в JSON-файл F (для перевода)
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CYR = re.compile(r'[А-Яа-яЁё]')
RUST_DIRS = ['core/src', 'src-tauri/src']
EN_RUST = os.path.join(ROOT, 'locales', 'en.json')


# ---------- Rust ----------

def lex(src):
    toks = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith('//', i):
            j = src.find('\n', i)
            j = n if j < 0 else j
            toks.append(('comment', i, j)); i = j; continue
        if src.startswith('/*', i):
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith('/*', j): depth += 1; j += 2
                elif src.startswith('*/', j): depth -= 1; j += 2
                else: j += 1
            toks.append(('comment', i, j)); i = j; continue
        m = re.match(r'(b?)r(#*)"', src[i:i + 300])
        if m and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == '_')):
            hashes = m.group(2)
            end = src.find('"' + hashes, i + len(m.group(0)))
            j = end + 1 + len(hashes)
            toks.append(('bytestr' if m.group(1) else 'rawstr', i, j)); i = j; continue
        if c == '"' or (c == 'b' and src.startswith('b"', i) and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == '_'))):
            j = i + (2 if c == 'b' else 1)
            while j < n and src[j] != '"':
                j += 2 if src[j] == '\\' else 1
            toks.append(('bytestr' if c == 'b' else 'str', i, j + 1)); i = j + 1; continue
        if c == "'":
            if src.startswith('\\', i + 1):
                j = src.find("'", i + 2)
                toks.append(('char', i, j + 1)); i = j + 1; continue
            if i + 2 < n and src[i + 2] == "'":
                toks.append(('char', i, i + 3)); i += 3; continue
            i += 1; continue
        i += 1
    return toks


def _blank(src, toks):
    mask = list(src)
    for _, a, b in toks:
        for x in range(a, b):
            if mask[x] != '\n':
                mask[x] = ' '
    return ''.join(mask)


def _block_end(clean, j):
    depth = 1
    while j < len(clean) and depth:
        if clean[j] == '{': depth += 1
        elif clean[j] == '}': depth -= 1
        j += 1
    return j


def test_ranges(src, toks):
    clean = _blank(src, toks)
    out = []
    for m in re.finditer(r'#\[cfg\(test\)\]\s*(pub(\([^)]*\))?\s+)?mod\s+\w+\s*\{', clean):
        out.append((m.start(), _block_end(clean, m.end())))
    for m in re.finditer(r'#\[cfg\(test\)\]\s*(pub(\(crate\))?\s+)?fn\s', clean):
        j = clean.find('{', m.end())
        out.append((m.start(), _block_end(clean, j + 1)))
    return out


def skip_ranges(src):
    out = []
    for m in re.finditer(r'i18n-skip-begin', src):
        e = src.find('i18n-skip-end', m.end())
        out.append((m.start(), len(src) if e < 0 else e))
    for m in re.finditer(r'i18n-skip(?!-)', src):
        ls = src.rfind('\n', 0, m.start()) + 1
        le = src.find('\n', m.end())
        le = len(src) if le < 0 else le
        if src[ls:m.start()].strip().replace('//', '').strip():
            out.append((ls, le))  # пометка в конце строки кода — только эта строка
        else:
            le2 = src.find('\n', le + 1)
            out.append((ls, len(src) if le2 < 0 else le2))  # на своей строке — и следующая
    return out


def unescape(lit):
    if lit.startswith('r'):
        h = len(lit) - len(lit[1:].lstrip('#')) - 1
        return lit[2 + h:len(lit) - 1 - h]
    body = lit[1:-1]
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c != '\\':
            out.append(c); i += 1; continue
        d = body[i + 1]
        if d == 'n': out.append('\n'); i += 2
        elif d == 'r': out.append('\r'); i += 2
        elif d == 't': out.append('\t'); i += 2
        elif d == '0': out.append('\0'); i += 2
        elif d in '\\"\'': out.append(d); i += 2
        elif d == 'x': out.append(chr(int(body[i + 2:i + 4], 16))); i += 4
        elif d == 'u':
            e = body.index('}', i)
            out.append(chr(int(body[i + 3:e].replace('_', ''), 16))); i = e + 1
        elif d in '\n\r':
            i += 2
            while i < len(body) and body[i] in ' \t\r\n': i += 1
        else:
            raise ValueError(lit)
    return ''.join(out)


DEV_CTX = re.compile(r'(expect|panic!|unreachable!|todo!|unimplemented!|assert!|assert_eq!|assert_ne!|'
                     r'debug_assert!|debug_assert_eq!)\s*\(\s*$')
TR_CTX = re.compile(r'(?<![\w!])(tr|trs|trc)!\s*\(\s*$')


def rust_scan():
    keys, bad = {}, []
    for d in RUST_DIRS:
        for dp, _, fs in os.walk(os.path.join(ROOT, d)):
            for f in sorted(fs):
                if not f.endswith('.rs'):
                    continue
                path = os.path.join(dp, f)
                rel = os.path.relpath(path, ROOT)
                src = open(path, encoding='utf-8').read()
                toks = lex(src)
                tr_, sk = test_ranges(src, toks), skip_ranges(src)
                for k, a, b in toks:
                    if k not in ('str', 'rawstr'):
                        continue
                    lit = src[a:b]
                    if not CYR.search(lit):
                        continue
                    before = src[max(0, a - 120):a]
                    line = src.count('\n', 0, a) + 1
                    in_test = any(x <= a < y for x, y in tr_)
                    if any(x <= a < y for x, y in sk) or (in_test and not TR_CTX.search(before)):
                        continue
                    if TR_CTX.search(before):
                        keys.setdefault(unescape(lit), f'{rel}:{line}')
                    elif DEV_CTX.search(before):
                        continue
                    else:
                        bad.append(f'{rel}:{line}: строка без tr!/trs!: {unescape(lit)[:80]!r}')
    return keys, bad


# ---------- общее ----------

PH = re.compile(r'\{\{|\}\}|\{([^{}]*)\}')


def placeholders(s):
    """Подстановки format!/t(): {x}, {}, {:.1}, {x:>3}. {{ }} — не подстановки."""
    out = []
    for m in PH.finditer(s):
        if m.group(0) in ('{{', '}}'):
            continue
        out.append(m.group(1))
    return sorted(out)


def check_table(name, keys, table):
    errs = []
    for k, where in sorted(keys.items(), key=lambda x: x[1]):
        v = table.get(k)
        if v is None:
            errs.append(f'{where}: нет перевода в {name}: {k[:80]!r}')
        elif not v.strip():
            errs.append(f'{where}: пустой перевод в {name}: {k[:80]!r}')
        else:
            if CYR.search(v):
                errs.append(f'{name}: в переводе кириллица: {k[:60]!r} → {v[:60]!r}')
            # Позиционные {} в Rust идут по порядку — их порядок важен, именованные — нет.
            if placeholders(k) != placeholders(v) or [p for p in placeholders_seq(k) if p == '' or p.startswith(':')] != \
                    [p for p in placeholders_seq(v) if p == '' or p.startswith(':')]:
                errs.append(f'{name}: подстановки не совпадают: {k[:60]!r} {placeholders(k)} → {placeholders(v)}')
    for k in sorted(set(table) - set(keys)):
        errs.append(f'{name}: лишний ключ (в коде такой строки нет): {k[:80]!r}')
    return errs


def placeholders_seq(s):
    return [m.group(1) for m in PH.finditer(s) if m.group(0) not in ('{{', '}}')]


def load_json(path):
    if not os.path.exists(path):
        return {}
    return json.load(open(path, encoding='utf-8'))


def save_json(path, table):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(dict(sorted(table.items())), f, ensure_ascii=False, indent=1)
        f.write('\n')


def main(argv):
    keys, bad = rust_scan()
    table = load_json(EN_RUST)
    if '--add' in argv:
        new = {k: table.get(k, '') for k in keys}
        save_json(EN_RUST, new)
        print(f'locales/en.json: ключей {len(new)}, без перевода {sum(1 for v in new.values() if not v.strip())}')
        return 0
    if '--missing' in argv:
        out = argv[argv.index('--missing') + 1]
        miss = {k: '' for k in keys if not table.get(k, '').strip()}
        json.dump(miss, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
        print(f'{len(miss)} ключей без перевода → {out}')
        return 0
    errs = bad + check_table('locales/en.json', keys, table)
    ui = os.path.join(ROOT, 'ui', 'i18n.js')
    if os.path.exists(ui):
        sys.path.insert(0, os.path.join(ROOT, 'scripts'))
        import i18n_ui  # noqa: E402 — проверка окна (ui/*.js, ui/index.html)
        errs += i18n_ui.check(ROOT, check_table)
    for e in errs:
        print(e)
    print(f'i18n: Rust-ключей {len(keys)}, ошибок {len(errs)}')
    return 1 if errs else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
