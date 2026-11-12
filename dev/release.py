"""Выпуск rxvpn одной командой: тесты → сборка → архив → подписанный manifest.json → проверка.

    python dev/release.py "что нового одной строкой" [--prev 0.17.2] [--skip-tests]

После сборки exe запускается сам (--smoke) на пустой временной папке данных: настоящее окно
должно получить ответ get_view и нарисовать главную. Не ответило за SMOKE_WAIT секунд —
выпуск останавливается до упаковки и подписи.

Что должно быть готово заранее:
  * версия поднята в core/Cargo.toml, src-tauri/Cargo.toml, i18n-macros/Cargo.toml,
    src-tauri/tauri.conf.json (и Cargo.lock);
  * в dist/rxvpn/README.txt сверху «rxvpn X.Y.Z» и «Что нового в X.Y.Z»;
  * в блоке «Что нового» окна (ui/index.html, #whatsnew) есть строки про X.Y;
  * всё закоммичено (exe собирается ровно из коммита).
Ключ подписи — вне репозитория: RXVPN_KEY_DIR (по умолчанию ../rxvpn-keys) с файлами
rxvpn-update.key и pubkey.txt. Репозиторий обновлений — RXVPN_UPDATE_REPO (rxsk7/rxVPN).

Ничего не публикует: в конце — три файла в dist и их SHA-256. Релиз на GitHub — руками.
"""
import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DIST = os.path.join(ROOT, "dist")
REPO = os.environ.get("RXVPN_UPDATE_REPO", "rxsk7/rxVPN")
KEYS = os.environ.get("RXVPN_KEY_DIR", os.path.normpath(os.path.join(ROOT, "..", "rxvpn-keys")))


# Сколько ждать ответа окна: холодный старт WebView2 на новом профиле — секунд 5–15.
SMOKE_WAIT = 90


def die(msg):
    print("СТОП:", msg)
    sys.exit(1)


def run(cmd, cwd=ROOT, env=None, capture=False):
    print("→", " ".join(cmd))
    r = subprocess.run(cmd, cwd=cwd, env=env, text=True, encoding="utf-8", errors="replace",
                       stdout=subprocess.PIPE if capture else None)
    if r.returncode != 0:
        die(f"команда завершилась с кодом {r.returncode}")
    return r.stdout if capture else ""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def toml_version(path):
    for line in open(os.path.join(ROOT, path), encoding="utf-8"):
        if line.startswith("version = "):
            return line.split('"')[1]
    die(f"нет версии в {path}")


def whatsnew_has(html, ver):
    """Есть ли в блоке «Что нового» окна (#whatsnew) номер версии x.y (0.19.1 → «0.19»)."""
    m = re.search(r'id="whatsnew".*?(?=<div class="group">)', html, re.S)
    xy = ".".join(ver.split(".")[:2])
    return bool(m and re.search(r"(?<![\d.])" + re.escape(xy) + r"(?!\d)", m.group(0)))


def smoke(built, ver):
    """Запустить собранный exe на пустой папке данных и дождаться, что настоящее окно ответило.

    Копия exe + пустая data рядом (портативный режим) во временной папке, запуск с --smoke:
    rxvpn в этом режиме не берёт замок второго запуска и не трогает систему, окно зовёт
    настоящий get_view, рисует главную и вызывает smoke_ready — программа пишет
    data\\smoke.json и выходит. Работающий rxvpn не затрагивается.

    С правами администратора --smoke не работает (и не должен), поэтому из консоли с правами
    exe запускается без них: runas /trustlevel:0x20000.
    """
    tmp = tempfile.mkdtemp(prefix="rxvpn-smoke-")
    exe = os.path.join(tmp, "rxvpn.exe")
    mark = os.path.join(tmp, "data", "smoke.json")

    def alive():
        # Наш exe — единственный с таким путём: работающий rxvpn сюда не попадёт.
        r = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "@(Get-CimInstance Win32_Process -Filter \"Name='rxvpn.exe'\" | Where-Object { $_.ExecutablePath -eq $env:RXVPN_SMOKE_EXE }).ProcessId"],
                           env=dict(os.environ, RXVPN_SMOKE_EXE=exe), text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return [int(x) for x in r.stdout.split() if x.isdigit()]

    try:
        shutil.copyfile(built, exe)
        os.mkdir(os.path.join(tmp, "data"))
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        print(f"→ автопроверка окна: {exe} --smoke (жду до {SMOKE_WAIT} с{', запуск без прав администратора' if admin else ''})")
        if admin:
            subprocess.run(["runas", "/trustlevel:0x20000", f'"{exe}" --smoke'], cwd=tmp, stdout=subprocess.DEVNULL)
        else:
            subprocess.Popen([exe, "--smoke"], cwd=tmp)
        started = time.monotonic()
        seen = False  # процесс хоть раз видели — иначе «вышел сразу» не отличить от «ещё не запустился»
        while not os.path.isfile(mark):
            waited = time.monotonic() - started
            pids = alive()
            seen = seen or bool(pids)
            if waited > SMOKE_WAIT:
                for pid in pids:
                    subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                die(f"окно не ответило на get_view за {SMOKE_WAIT} с — exe не пакую и не подписываю")
            if not pids and (seen or waited > 15) and not os.path.isfile(mark):
                die("rxvpn --smoke вышел, не дождавшись окна (нет smoke.json) — exe не пакую и не подписываю")
            time.sleep(0.5)
        got = None
        for _ in range(10):  # файл пишется одним вызовом, но не читаем его на полуслове
            try:
                got = json.load(open(mark, encoding="utf-8"))
                break
            except ValueError:
                time.sleep(0.2)
        if not got or got.get("version") != ver:
            die(f"автопроверка: окно ответило версией {got and got.get('version')}, а выпускается {ver}")
        if not got.get("keys") or got.get("welcome") is not True:
            die(f"автопроверка: окно ответило, но главная не та (пустая папка данных → мастер первого запуска): {got}")
        print(f"  окно ответило за {time.monotonic() - started:.0f} с: версия {got['version']}, полей в get_view — {got['keys']}, мастер первого запуска показан")
    finally:
        for _ in range(20):  # WebView2 отпускает профиль не сразу
            shutil.rmtree(tmp, ignore_errors=True)
            if not os.path.exists(tmp):
                break
            time.sleep(0.5)


def main():
    flags = sys.argv[1:]
    # Значение после --prev — не «что нового».
    skip = {flags.index("--prev") + 1} if "--prev" in flags else set()
    args = [a for i, a in enumerate(flags) if not a.startswith("--") and i not in skip]
    if len(args) != 1 or not args[0].strip():
        die('нужна строка «что нового»: python dev/release.py "…"')
    notes = args[0].strip()
    if len(notes) > 500:
        die("«что нового» длиннее 500 знаков — в окне обновления обрежется")

    # 1. Версия везде одна.
    ver = json.load(open(os.path.join(ROOT, "src-tauri", "tauri.conf.json"), encoding="utf-8"))["version"]
    for p in ["core/Cargo.toml", "src-tauri/Cargo.toml", "i18n-macros/Cargo.toml"]:
        if toml_version(p) != ver:
            die(f"{p}: версия {toml_version(p)}, а в tauri.conf.json — {ver}")
    readme = os.path.join(DIST, "rxvpn", "README.txt")
    text = open(readme, encoding="utf-8-sig").read()
    if not text.startswith(f"rxvpn {ver} ") or f"Что нового в {ver}" not in text:
        die(f"dist/rxvpn/README.txt: сверху должно быть «rxvpn {ver}» и «Что нового в {ver}»")
    xy = ".".join(ver.split(".")[:2])
    if not whatsnew_has(open(os.path.join(ROOT, "ui", "index.html"), encoding="utf-8").read(), ver):
        die(f"ui/index.html: в блоке «Что нового» (#whatsnew) нет ни слова про {xy} — допиши строки и перевод в ui/locales/en.js")
    if os.name != "nt":
        die("выпуск — только в Windows (автопроверка окна запускает rxvpn.exe)")

    # 2. Прошлая версия — для проверки манифеста «как у пользователя».
    prev = None
    if "--prev" in flags:
        prev = flags[flags.index("--prev") + 1]
    else:
        old = os.path.join(DIST, "manifest.json")
        if os.path.exists(old):
            prev = json.load(open(old, encoding="utf-8"))["version"]
    if not prev or prev == ver:
        die(f"не знаю прошлую версию (в dist/manifest.json — {prev}); укажи --prev X.Y.Z")

    # 3. Чистое дерево: exe должен собираться из коммита.
    if run(["git", "status", "--porcelain"], capture=True).strip():
        die("есть незакоммиченные изменения — закоммить или убери")
    commit = run(["git", "rev-parse", "--short", "HEAD"], capture=True).strip()

    # 4. Ключи.
    key = os.path.join(KEYS, "rxvpn-update.key")
    pub_file = os.path.join(KEYS, "pubkey.txt")
    if not os.path.isfile(key) or not os.path.isfile(pub_file):
        die(f"нет ключа подписи в {KEYS} (rxvpn-update.key, pubkey.txt)")
    pub = open(pub_file, encoding="utf-8").read().strip().split("=")[-1]
    if len(pub) != 64:
        die("pubkey.txt: нужен ключ из 64 hex-символов")

    # 5. Тесты, переводы, известные уязвимости.
    if "--skip-tests" not in flags:
        run(["cargo", "test", "-p", "rxvpn-core"])
        py_env = dict(os.environ, PYTHONIOENCODING="utf-8")
        run([sys.executable, "scripts/i18n_check.py"], env=py_env)
        if shutil.which("cargo-audit"):
            # Не останавливает выпуск: список известного — в .cargo/audit.toml, посмотри глазами.
            subprocess.run(["cargo", "audit", "-q"], cwd=ROOT)

    # 6. Сборка с вшитыми репозиторием и ключом обновлений.
    env = dict(os.environ, RXVPN_UPDATE_REPO=REPO, RXVPN_UPDATE_PUBKEY=pub)
    run(["cargo", "tauri", "build", "--no-bundle"], cwd=os.path.join(ROOT, "src-tauri"), env=env)
    built = os.path.join(ROOT, "target", "release", "rxvpn.exe")
    data = open(built, "rb").read()
    for must in (REPO.encode(), pub.encode(), f"rxvpn/{ver}".encode()):
        if must not in data:
            die(f"в собранном exe нет {must.decode()} — не та сборка")
    # 6½. Настоящее окно собранного exe отвечает — только потом пакуем и подписываем.
    smoke(built, ver)
    exe = os.path.join(DIST, "rxvpn", "rxvpn.exe")
    shutil.copyfile(built, exe)
    shutil.copyfile(readme, os.path.join(DIST, "README.txt"))

    # 7. Архив.
    zip_path = os.path.join(DIST, f"rxvpn-portable-{ver}.zip")
    run([sys.executable, "dev/pack.py", "dist/rxvpn", zip_path], env=dict(os.environ, PYTHONIOENCODING="utf-8"))

    # 8. Манифест: подписать и проверить тем же кодом, что в rxvpn.
    url = f"https://github.com/{REPO}/releases/download/v{ver}/rxvpn.exe"
    out = run(["cargo", "run", "-q", "-p", "rxvpn-core", "--example", "sign", "--", "sign", key, exe, ver, url, notes], capture=True)
    manifest = json.loads(out)
    if manifest["notes"] != notes:
        die("«что нового» в манифесте исказилось (кодировка консоли?)")
    man_path = os.path.join(DIST, "manifest.json")
    with open(man_path + ".tmp", "w", encoding="utf-8", newline="\n") as f:
        f.write(out)
    check = ["cargo", "run", "-q", "-p", "rxvpn-core", "--example", "verify_manifest", "--", man_path + ".tmp", exe, REPO, pub]
    ok = run(check + [prev], capture=True)
    if "OK" not in ok or "совпадает: true; размер совпадает: true" not in ok:
        die(f"манифест не прошёл проверку с версии {prev}:\n{ok}")
    back = subprocess.run(check + [ver], cwd=ROOT, text=True, encoding="utf-8", errors="replace", stdout=subprocess.PIPE).stdout
    if "не новее" not in back:
        die(f"манифест принят на ту же версию {ver} — откат не запрещён:\n{back}")
    os.replace(man_path + ".tmp", man_path)

    print(f"\nrxvpn {ver} (коммит {commit}) — готово. Обновление с {prev} принимается, на {ver} — отклоняется.\n")
    for name, path in [(f"rxvpn-portable-{ver}.zip", zip_path), ("rxvpn\\rxvpn.exe", exe), ("manifest.json", man_path)]:
        print(f"  {sha256(path)}  dist\\{name}")
    print(f"\nДальше: запушь main, создай релиз v{ver} на https://github.com/{REPO}/releases/new, прикрепи три файла.")
    print("После релиза: sh dev/trim-target.sh")


if __name__ == "__main__":
    main()
