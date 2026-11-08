"""Проверка серверного limits.py (core/src/vps/plan.rs) на поддельном xray:
    python dev/test_limits.py core/src/vps/plan.rs
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time

plan = open(sys.argv[1], encoding="utf-8").read()
script = re.search(r'pub fn limits_script\(\) -> &\'static str \{\s*r#"(.*?)"#', plan, re.S).group(1)
d = tempfile.mkdtemp()
sp = os.path.join(d, "limits.py")
open(sp, "w", encoding="utf-8").write(script)

fake = os.path.join(d, "fake_xray.py")
open(fake, "w", encoding="utf-8").write(r'''
import json, os, sys
d = os.path.dirname(os.path.abspath(__file__))
a = sys.argv[1:]
if a[1] == "statsquery":
    print(open(os.path.join(d, "stats.json")).read())
elif a[1] == "rmu":
    open(os.path.join(d, "removed.txt"), "a").write(a[-2] + "\n")
''')
env = dict(os.environ, RXVPN_XRAY=sys.executable + "|" + fake,
           RXVPN_LIMITS=os.path.join(d, "limits.json"), RXVPN_STATE=os.path.join(d, "state", "usage.json"))
GB = 1 << 30

def stats(pairs):
    s = [{"name": f"user>>>{e}>>>traffic>>>{k}", "value": v} for e, k, v in pairs]
    open(os.path.join(d, "stats.json"), "w").write(json.dumps({"stat": s}))

def run(*extra):
    r = subprocess.run([sys.executable, sp, "--json", *extra], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)

def removed():
    p = os.path.join(d, "removed.txt")
    return open(p).read().split() if os.path.exists(p) else []

json.dump({"f-aaaaaaaaaa@rxvpn": {"limit": 2 * GB, "expires": 0},
           "f-bbbbbbbbbb@rxvpn": {"limit": 0, "expires": int(time.time()) - 10},
           "f-cccccccccc@rxvpn": {"limit": 0, "expires": 0}},
          open(env["RXVPN_LIMITS"], "w"))

stats([("f-aaaaaaaaaa@rxvpn", "uplink", GB // 2), ("f-aaaaaaaaaa@rxvpn", "downlink", GB // 2), ("owner@rxvpn", "downlink", 5 * GB)])
s = run()
assert s["f-aaaaaaaaaa@rxvpn"]["up"] + s["f-aaaaaaaaaa@rxvpn"]["down"] == GB and not s["f-aaaaaaaaaa@rxvpn"]["blocked"], s
assert s["f-bbbbbbbbbb@rxvpn"]["blocked"], "срок вышел — отключён"
assert not s["f-cccccccccc@rxvpn"]["blocked"] and "owner@rxvpn" not in removed()
assert removed() == ["f-bbbbbbbbbb@rxvpn"], removed()
print("1) учёт и просрочка: OK")

stats([("f-aaaaaaaaaa@rxvpn", "downlink", GB)])
s = run()
assert s["f-aaaaaaaaaa@rxvpn"]["down"] == GB // 2 + GB, "копится между запусками (счётчики Xray сбрасываются)"
assert s["f-aaaaaaaaaa@rxvpn"]["blocked"] and "f-aaaaaaaaaa@rxvpn" in removed(), "2 ГБ из 2 — отключён"
print("2) накопление и лимит: OK")

open(os.path.join(d, "stats.json"), "w").write("{}")
s = run("--reset", "f-aaaaaaaaaa@rxvpn")
assert s["f-aaaaaaaaaa@rxvpn"]["up"] + s["f-aaaaaaaaaa@rxvpn"]["down"] == 0 and not s["f-aaaaaaaaaa@rxvpn"]["blocked"]
print("3) сброс счётчика и пустой ответ Xray: OK")

json.dump({}, open(env["RXVPN_LIMITS"], "w"))
s = run()
assert not any(u["blocked"] for u in s.values()), "лимиты сняли — никто не отключён"
print("4) лимиты сняты: OK")
