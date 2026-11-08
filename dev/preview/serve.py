"""Превью окна rxvpn в браузере: отдаёт ui/ и подкладывает заглушку Tauri.

    python dev/preview/serve.py        → http://localhost:8765/?state=off|on|empty

Только для разработки дизайна; в сборку (frontendDist = ../ui) не попадает.
"""
import http.server
import json
import os
import socketserver

ROOT = os.path.dirname(os.path.abspath(__file__))
UI = os.path.normpath(os.path.join(ROOT, "..", "..", "ui"))
PORT = 8765


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=UI, **kw)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html", "/mini.html"):
            page = "mini.html" if path == "/mini.html" else "index.html"
            html = open(os.path.join(UI, page), encoding="utf-8").read()
            settings = open(os.path.join(ROOT, "settings.json"), encoding="utf-8").read()
            inject = (f"<script>window.__RX_SETTINGS={settings};</script>"
                      f"<script src=\"/__dev/stub.js\"></script>\n")
            html = html.replace('<script src="locales/en.js"></script>', inject + '<script src="locales/en.js"></script>', 1)
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/__dev/stub.js":
            body = open(os.path.join(ROOT, "stub.js"), "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", PORT), H) as s:
    print(f"rxvpn preview: http://localhost:{PORT}/?state=off", flush=True)
    s.serve_forever()
