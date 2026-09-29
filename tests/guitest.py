"""Teste de integracao GUI <-> Intercept Web.

Cria um App real (Tkinter) num APPDATA temporario, sem autostart, confere o
padrao "unframe", sobe o proxy e o console pela GUI, le a pagina + /api/state
e exercita as rotas /api/flags e /api/proxy (as mesmas usadas pela pagina).

Uso: python tests/guitest.py
"""
import json
import os
import socket
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

tmp = tempfile.mkdtemp(prefix="intercepta-smoke-")
os.environ["APPDATA"] = tmp
appdir = os.path.join(tmp, "Intercepta")
os.makedirs(appdir, exist_ok=True)
# config antiga (sem a chave "unframe") -> deve herdar o padrao True
with open(os.path.join(appdir, "config.json"), "w", encoding="utf-8") as fh:
    json.dump({"autostart": False, "port": 8080, "in_scope_only": True}, fh)


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


FAILED = []


def check(name, cond, extra=""):
    if not cond:
        FAILED.append(name)
    print("%s %s%s" % ("[ok]  " if cond else "[FAIL]", name, (" - " + str(extra)) if extra else ""))


from intercepta import gui as G  # noqa: E402

app = G.App()
app.root.withdraw()
try:
    check("config antiga ganha unframe=True", app.config.get("unframe") is True,
          app.config.get("unframe"))
    check("motor comeca com unframe ligado", app.engine.unframe is True)
    st = app.web_state()
    check("web_state expoe unframe e last_nav",
          st.get("unframe") is True and "last_nav" in st, sorted(st.keys()))
    check("var da GUI reflete a config", app.unframe_var.get() is True)

    app.port_var.set(str(free_port()))
    app.start_proxy()
    check("proxy subiu pela GUI", app.engine.running is True, app.engine.port)

    ok, msg = app.web.start()
    check("console subiu pela GUI", ok, msg)
    url = app.web.page_url()
    with urllib.request.urlopen(url, timeout=10) as resp:
        page = resp.read()
    check("pagina do console responde 200 com o painel do site",
          resp.status == 200 and b'id="site"' in page, resp.status)
    req = urllib.request.Request(url.split("?")[0] + "api/state")
    req.add_header("X-DerpSec-Token", app.web.token)
    with urllib.request.urlopen(req, timeout=10) as resp:
        state = json.loads(resp.read())
    check("estado do console bate com a GUI",
          state["running"] is True and state["port"] == app.engine.port, state)

    # desligar/ligar "embutir sites" pelo console (mesma rota usada pela pagina)
    body = json.dumps({"unframe": False}).encode()
    req = urllib.request.Request(url.split("?")[0] + "api/flags", data=body, method="POST")
    req.add_header("X-DerpSec-Token", app.web.token)
    req.add_header("Content-Type", "application/json")
    urllib.request.urlopen(req, timeout=10).read()
    deadline = time.time() + 3
    while time.time() < deadline and app.unframe_var.get() is not False:
        app.root.update()
        time.sleep(0.05)
    check("toggle 'embutir sites' chega no motor", app.engine.unframe is False)
    check("toggle 'embutir sites' chega na GUI", app.unframe_var.get() is False)

    # religar pelo console (idem rota usada pela pagina)
    req = urllib.request.Request(
        url.split("?")[0] + "api/flags",
        data=json.dumps({"unframe": True}).encode(), method="POST")
    req.add_header("X-DerpSec-Token", app.web.token)
    req.add_header("Content-Type", "application/json")
    urllib.request.urlopen(req, timeout=10).read()
    deadline = time.time() + 3
    while time.time() < deadline and app.unframe_var.get() is not True:
        app.root.update()
        time.sleep(0.05)
    check("religar 'embutir sites' chega na GUI", app.unframe_var.get() is True)

    # parar/religar o proxy pelo console (precisa bombear a GUI em paralelo)
    import threading

    def call(path, payload):
        req = urllib.request.Request(
            url.split("?")[0] + path,
            data=json.dumps(payload).encode(), method="POST")
        req.add_header("X-DerpSec-Token", app.web.token)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read() or b"{}")

    seen = {}

    def worker():
        try:
            call("api/proxy", {"action": "stop"})
            deadline = time.time() + 5
            while time.time() < deadline and app.engine.running:
                time.sleep(0.05)
            seen["stopped"] = not app.engine.running
            seen["start"] = call("api/proxy", {"action": "start"})
        except Exception as exc:
            seen["erro"] = repr(exc)

    th = threading.Thread(target=worker, daemon=True)
    th.start()
    deadline = time.time() + 25
    while th.is_alive() and time.time() < deadline:
        app.root.update()
        time.sleep(0.05)
    th.join(5)
    check("parar proxy pelo console", seen.get("stopped") is True, seen)
    check("religar proxy pelo console", app.engine.running is True, seen)
finally:
    try:
        app.web.stop()
    except Exception:
        pass
    try:
        app.engine.stop()
    except Exception:
        pass
    try:
        app.root.update()
        app.root.destroy()
    except Exception:
        pass

import shutil  # noqa: E402
shutil.rmtree(tmp, ignore_errors=True)
print("\n%s" % ("guitest ok" if not FAILED else "FALHAS: %s" % ", ".join(FAILED)))
sys.exit(1 if FAILED else 0)
