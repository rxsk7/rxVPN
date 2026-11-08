"""Упаковать портативную версию в zip с правильными путями (через «/», как требует формат zip).

    python dev/pack.py dist/rxvpn dist/rxvpn-portable-X.Y.Z.zip

PowerShell 5.1 (Compress-Archive) пишет пути через «\\» — Проводник такой zip открывает,
а macOS, Linux и часть распаковщиков делают из «rxvpn\\data\\core\\xray.exe» имя файла.
"""
import os
import sys
import zipfile

src, out = sys.argv[1], sys.argv[2]
base = os.path.dirname(os.path.abspath(src))
tmp = out + ".tmp"
with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for root, dirs, files in os.walk(src):
        dirs.sort()
        rel_dir = os.path.relpath(root, base).replace(os.sep, "/")
        if not files and not dirs:
            z.writestr(rel_dir + "/", "")
        for f in sorted(files):
            p = os.path.join(root, f)
            z.write(p, rel_dir + "/" + f)
os.replace(tmp, out)
with zipfile.ZipFile(out) as z:
    names = z.namelist()
    assert all("\\" not in n for n in names), "в путях есть обратный слеш"
    assert z.testzip() is None, "архив битый"
print(out, len(names), "файлов, пути через /")
