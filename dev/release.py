"""Выпуск rxvpn одной командой: тесты → сборка → архив → подписанный manifest.json → проверка.

    python dev/release.py "что нового одной строкой" [--prev 0.17.2] [--skip-tests]

Что должно быть готово заранее:
  * версия поднята в core/Cargo.toml, src-tauri/Cargo.toml, i18n-macros/Cargo.toml,
    src-tauri/tauri.conf.json (и Cargo.lock);
  * в dist/rxvpn/README.txt сверху «rxvpn X.Y.Z» и «Что нового в X.Y.Z»;
  * всё закоммичено (exe собирается ровно из коммита).
Ключ подписи — вне репозитория: RXVPN_KEY_DIR (по умолчанию ../rxvpn-keys) с файлами
rxvpn-update.key и pubkey.txt. Репозиторий обновлений — RXVPN_UPDATE_REPO (rxsk7/rxVPN).

Ничего не публикует: в конце — три файла в dist и их SHA-256. Релиз на GitHub — руками.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DIST = os.path.join(ROOT, "dist")
REPO = os.environ.get("RXVPN_UPDATE_REPO", "rxsk7/rxVPN")
KEYS = os.environ.get("RXVPN_KEY_DIR", os.path.normpath(os.path.join(ROOT, "..", "rxvpn-keys")))


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


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = sys.argv[1:]
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
