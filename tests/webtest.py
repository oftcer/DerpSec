"""Teste ponta a ponta do Intercept Web (console web + proxy + API).

Sobe: alvo HTTP local -> proxy DerpSec -> console web.
Valida historico, detalhe, interceptacao (segurar/encaminhar), repeater,
escopo, flags, log e o controle de token/Host.
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from intercepta.certs import CertAuthority          # noqa: E402
from intercepta.engine import ProxyEngine           # noqa: E402
from intercepta.webconsole import WebConsole        # noqa: E402

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print("%s %s%s" % ("[ok]  " if cond else "[FAIL]", name, (" - " + str(extra)) if extra else ""))


# --------------------------------------------------------------- alvo local
class Target(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        body = b"<html><body>alvo-intercepta</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(n)
        body = b"recebi:" + data
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Ctx:
    """Stub do App para o console."""

    def __init__(self, engine):
        self.engine = engine
        self.scope = ""
        self.logs = []

    def web_state(self):
        with self.engine._lock:
            n = len(self.engine.history)
        return {
            "running": bool(self.engine.running), "port": self.engine.port,
            "intercept_requests": bool(self.engine.intercept_requests),
            "intercept_responses": bool(self.engine.intercept_responses),
            "in_scope_only": bool(self.engine.in_scope_only),
            "unframe": bool(getattr(self.engine, "unframe", True)),
            "filter_telemetry": bool(getattr(self.engine, "filter_telemetry", True)),
            "last_nav": getattr(self.engine, "last_nav", None),
            "tx_count": n, "held_count": len(self.engine.held_pending),
            "version": "test",
        }

    def get_scope(self):
        return self.scope

    def set_scope(self, text):
        self.scope = text
        return self.engine.set_scope(text)

    def set_flags(self, data):
        if "intercept_requests" in data:
            self.engine.intercept_requests = bool(data["intercept_requests"])
        if "intercept_responses" in data:
            self.engine.intercept_responses = bool(data["intercept_responses"])
        if "in_scope_only" in data:
            self.engine.in_scope_only = bool(data["in_scope_only"])
        if "unframe" in data:
            self.engine.unframe = bool(data["unframe"])
        if "filter_telemetry" in data:
            self.engine.filter_telemetry = bool(data["filter_telemetry"])

    def web_start_proxy(self):
        if self.engine.running:
            return True, "ja ativo"
        self.engine.start(str(free_port()))
        return (self.engine.running, "iniciado")

    def web_stop_proxy(self):
        self.engine.stop()

    def web_clear_history(self):
        self.engine.clear_history()

    def log_lines(self):
        return list(self.logs)

    def clear_log(self):
        self.logs[:] = []


def req(url, token=None, method="GET", body=None):
    r = urllib.request.Request(url, method=method)
    if token:
        r.add_header("X-DerpSec-Token", token)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, data=data, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main():
    tmp = tempfile.mkdtemp(prefix="derpsec-web-")
    ca = CertAuthority(os.path.join(tmp, "ca"))
    events = []
    engine = ProxyEngine(ca, lambda ev, pl: events.append(ev))

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    target.daemon_threads = True
    tport = target.server_address[1]
    threading.Thread(target=target.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True).start()

    ctx = Ctx(engine)
    console = WebConsole(ctx)
    ok, msg = console.start()
    check("console iniciou", ok, msg)
    if not ok:
        return finish()

    ok, msg = engine.start(str(free_port()))
    check("proxy iniciou", ok, msg)

    tok = console.token
    base = "http://127.0.0.1:%d" % console.port
    host = "127.0.0.1"

    # ------------------------------------------------- token / Host
    st, _ = req(base + "/api/state")
    check("API sem token -> 401", st == 401, st)
    st, _ = req(base + "/api/state?token=" + tok)
    check("API com token na query -> 200", st == 200, st)
    st, page = req(base + "/?token=" + tok)
    check("pagina do console -> 200 HTML", st == 200 and b"Intercept Web" in page, st)
    check("pagina tem painel do site (iframe) + divisor + abas",
          all(m in page for m in (b'id="site"', b'id="gutter"', b'id="tabbar"', b'id="addr"')), st)
    check("pagina tem o lado das funcoes (interceptar/repeater/escopo/log)",
          all(m in page for m in (b'id="view-intercept"', b'id="view-repeater',
                                  b'id="view-scope"', b'id="view-log"')), st)
    check("pagina embute o logo do diretorio icon", b'/assets/logo.png' in page, st)
    st, body = req(base + "/assets/app.js")
    check("JS servido com agrupamento por host",
          st == 200 and b"grphead" in body and b"groupByHost" in body, st)
    check("JS controla a barra de endereco e a navegacao",
          all(m in body for m in (b"btnBack", b"btnFwd", b"btnReload", b"navigate")), st)
    st, body = req(base + "/assets/app.css")
    check("CSS servido", st == 200 and b"--bg" in body, st)
    st, body = req(base + "/assets/logo.png")
    check("logo servido (PNG)", st == 200 and body[:8] == b"\x89PNG\r\n\x1a\n",
          len(body) if body else 0)
    r = urllib.request.Request(base + "/api/state")
    r.add_header("Host", "evil.example.com")
    try:
        urllib.request.urlopen(r, timeout=5)
        check("Host estranho bloqueado (403)", False, "aceitou")
    except urllib.error.HTTPError as exc:
        check("Host estranho bloqueado (403)", exc.code == 403, exc.code)

    # ------------------------------------------------- trafego pelo proxy
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": "http://127.0.0.1:%d" % engine.port}))
    # navegacao de iframe: Sec-Fetch-Dest: iframe (como o Intercept Web faz)
    r = urllib.request.Request("http://%s:%d/pagina" % (host, tport),
                               headers={"Sec-Fetch-Dest": "iframe"})
    with opener.open(r, timeout=10) as resp:
        served = resp.read()
    check("trafego HTTP passou pelo proxy", b"alvo-intercepta" in served)
    check("reporter de navegacao injetado no HTML do iframe",
          b"__derpsec_nav" in served, served[:200])

    time.sleep(0.4)
    st, body = req(base + "/api/history?token=" + tok)
    items = json.loads(body)["items"]
    check("historico registrou a transacao", len(items) >= 1 and items[0]["method"] == "GET",
          len(items))
    txid = items[0]["id"]
    st, body = req(base + "/api/tx?id=%d&token=%s" % (txid, tok))
    tx = json.loads(body)
    check("detalhe traz requisicao e resposta",
          "GET /pagina" in tx["request_pretty"] and "alvo-intercepta" in tx["decoded"])

    st, body = req(base + "/api/state?token=" + tok)
    state = json.loads(body)
    check("estado reporta proxy ativo e contagem", state["running"] is True)
    nav = state.get("last_nav") or {}
    check("estado traz a ultima navegacao HTML (last_nav)",
          nav.get("url", "").endswith("/pagina") and nav.get("id") == txid, nav)

    # ------------------------------------------------- filtro de telemetria
    check("filtro de telemetria ligado por padrao",
          json.loads(body)["filter_telemetry"] is True)
    check("host de telemetria reconhecido", engine._is_noise("edge.microsoft.com"))
    check("host normal nao e telemetria", not engine._is_noise("example.com"))
    req(base + "/api/flags", tok, "POST", {"filter_telemetry": False})
    st, body = req(base + "/api/state?token=" + tok)
    check("filtro de telemetria desligado pela API",
          json.loads(body)["filter_telemetry"] is False)
    req(base + "/api/flags", tok, "POST", {"filter_telemetry": True})

    # ------------------------------------------------- embutir sites (unframe)
    st, body = req(base + "/api/state?token=" + tok)
    check("unframe ligado por padrao", json.loads(body)["unframe"] is True)
    check("X-Frame-Options removido pelo proxy (embutir sites)",
          "X-Frame-Options" not in tx["response_pretty"],
          tx["response_pretty"][:80])
    check("CSP frame-ancestors removida pelo proxy",
          "frame-ancestors" not in tx["response_pretty"] and "default-src" in tx["response_pretty"],
          tx["response_pretty"][:120])

    req(base + "/api/flags", tok, "POST", {"unframe": False})
    with opener.open("http://%s:%d/quadro" % (host, tport), timeout=10) as resp:
        resp.read()
    time.sleep(0.4)
    st, body = req(base + "/api/history?token=" + tok)
    framed = [i for i in json.loads(body)["items"] if i["path"] == "/quadro"][0]
    st, body = req(base + "/api/tx?id=%d&token=%s" % (framed["id"], tok))
    kept = json.loads(body)["response_pretty"]
    check("com 'embutir sites' desligado o cabecalho e preservado",
          "X-Frame-Options" in kept and "frame-ancestors" in kept, kept[:120])
    req(base + "/api/flags", tok, "POST", {"unframe": True})

    # ------------------------------------------------- interceptar
    req(base + "/api/flags", tok, "POST", {"intercept_requests": True})
    st, body = req(base + "/api/state?token=" + tok)
    check("flag de interceptar requisicoes ligou", json.loads(body)["intercept_requests"] is True)

    outcome = {}

    def navigate():
        try:
            with opener.open("http://%s:%d/segura" % (host, tport), timeout=20) as resp:
                outcome["body"] = resp.read()
        except Exception as exc:
            outcome["error"] = str(exc)

    th = threading.Thread(target=navigate, daemon=True)
    th.start()

    held = None
    for _ in range(60):
        time.sleep(0.15)
        st, body = req(base + "/api/held?token=" + tok)
        items = json.loads(body)["items"]
        if items:
            held = items[0]
            break
    check("mensagem foi segurada na fila", held is not None)
    if held:
        check("item segurado e uma requisicao", held["kind"] == "request", held)
        st, body = req(base + "/api/state?token=" + tok)
        check("contador da fila no estado", json.loads(body)["held_count"] >= 1)
        edited = held["raw"].replace("GET /segura", "GET /editado")
        st, body = req(base + "/api/held", tok, "POST",
                       {"id": held["id"], "action": "forward", "raw": edited})
        check("encaminhar pela API", st == 200 and json.loads(body).get("ok"), body[:80])
    th.join(20)
    check("navegacao concluiu com resposta",
          b"alvo-intercepta" in outcome.get("body", b""), outcome.get("error", ""))
    time.sleep(0.3)
    st, body = req(base + "/api/history?token=" + tok)
    paths = [i["path"] for i in json.loads(body)["items"]]
    check("edicao aplicada (caminho /editado no historico)", "/editado" in paths, paths[:5])

    # descartar
    def navigate2():
        try:
            with opener.open("http://%s:%d/descartar" % (host, tport), timeout=20) as resp:
                resp.read()
        except Exception:
            pass

    threading.Thread(target=navigate2, daemon=True).start()
    held = None
    for _ in range(60):
        time.sleep(0.15)
        st, body = req(base + "/api/held?token=" + tok)
        items = json.loads(body)["items"]
        if items:
            held = items[0]
            break
    if held:
        req(base + "/api/held", tok, "POST", {"id": held["id"], "action": "drop"})
    time.sleep(0.4)
    st, body = req(base + "/api/history?token=" + tok)
    dropped = [i for i in json.loads(body)["items"] if i["path"] == "/descartar"]
    check("mensagem descartada marcada como erro",
          bool(dropped) and dropped[0]["error"] != "", dropped[:1])

    req(base + "/api/flags", tok, "POST", {"intercept_requests": False})

    # ------------------------------------------------- repeater
    raw = "POST /eco HTTP/1.1\r\nHost: %s:%d\r\nContent-Length: 5\r\n\r\nping!" % (host, tport)
    st, body = req(base + "/api/repeater", tok, "POST",
                   {"raw": raw, "host": host, "port": str(tport), "scheme": "http"})
    out = json.loads(body)
    check("repeater devolve resposta", "recebi:ping!" in out.get("response", ""), out)

    st, body = req(base + "/api/repeater", tok, "POST", {"raw": "GET / HTTP/1.1\r\nHost: \r\n\r\n"})
    check("repeater trata erro sem host", "error" in json.loads(body), body[:80])

    # ------------------------------------------------- escopo
    st, body = req(base + "/api/scope", tok, "POST", {"scope": "*.exemplo.com\n127.0.0.1"})
    check("escopo salvo (2 padroes)", json.loads(body)["count"] == 2, body)
    st, body = req(base + "/api/scope?token=" + tok)
    check("escopo lido de volta", "127.0.0.1" in json.loads(body)["scope"])

    # ------------------------------------------------- log / limpeza
    ctx.logs.extend(["linha 1", "linha 2"])
    st, body = req(base + "/api/log?token=" + tok)
    check("log listado", json.loads(body)["lines"] == ["linha 1", "linha 2"])
    req(base + "/api/log", tok, "POST")
    st, body = req(base + "/api/log?token=" + tok)
    check("log limpo", json.loads(body)["lines"] == [])

    st, body = req(base + "/api/clear", tok, "POST")
    st, body = req(base + "/api/history?token=" + tok)
    check("historico limpo pela API", json.loads(body)["items"] == [])

    # ------------------------------------------------- proxy start/stop
    req(base + "/api/proxy", tok, "POST", {"action": "stop"})
    struct = ctx.web_state()["running"]
    check("proxy parado pela API", struct is False)

    console.stop()
    target.shutdown()
    return finish()


def finish():
    print("\n%d passaram, %d falharam" % (len(PASS), len(FAIL)))
    if FAIL:
        print("Falhas: %s" % ", ".join(FAIL))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
