"""Teste automatizado do motor (sem GUI).

Cobre: HTTP simples, interceptacao/edicao de requisicao, HTTPS com MITM TLS
usando a CA local e o Repeater. Rode com:  python tests/selftest.py
"""
import os
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests  # noqa: E402
from intercepta.certs import CertAuthority  # noqa: E402
from intercepta.engine import ProxyEngine  # noqa: E402

def free_port():
    """Porta TCP livre de verdade (evita faixas reservadas do Windows)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


PROXY_PORT = free_port()
ORIGIN_PORT = free_port()
ORIGIN_HTTPS_PORT = free_port()
failures = []


def check(name, condition, detail=""):
    status = "OK  " if condition else "FALHA"
    print("[%s] %s %s" % (status, name, detail))
    if not condition:
        failures.append(name)


def start_origin_http():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = ("origem-http:%s" % self.path).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            size = int(self.headers.get("Content-Length") or 0)
            data = self.rfile.read(size)
            body = b"recebido:" + data
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def start_origin_https(ca):
    """Servidor TLS local. Usa um certificado assinado por uma CA propria."""
    import ssl
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    tmp = tempfile.mkdtemp(prefix="derpsec-origin-")
    origin_ca = CertAuthority(tmp)
    ctx = origin_ca.leaf_context("localhost")
    # ssl.SSLContext com o certificado gerado pelo helper local
    cert_dir = origin_ca.host_dir
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(
        os.path.join(cert_dir, "localhost.pem"), os.path.join(cert_dir, "localhost.key")
    )

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"origem-https:" + self.path.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", ORIGIN_HTTPS_PORT), Handler)
    server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    tmp = tempfile.mkdtemp(prefix="derpsec-test-")
    ca = CertAuthority(os.path.join(tmp, "ca"))
    logs = []
    engine = ProxyEngine(ca, lambda ev, payload: logs.append((ev, payload)))

    ok, msg = engine.start(PROXY_PORT)
    check("proxy inicia na porta", ok, msg)
    if not ok:
        return 1

    origin = start_origin_http()
    origin_tls = start_origin_https(ca)

    proxies = {"http": "http://127.0.0.1:%d" % PROXY_PORT,
               "https": "http://127.0.0.1:%d" % PROXY_PORT}

    # ---------------------------------------------------------------- HTTP
    try:
        r = requests.get("http://127.0.0.1:%d/abc" % ORIGIN_PORT, proxies=proxies, timeout=15)
        check("HTTP via proxy", r.status_code == 200 and r.text == "origem-http:/abc", r.text)
    except Exception as exc:
        check("HTTP via proxy", False, str(exc))

    try:
        r = requests.post("http://127.0.0.1:%d/envio" % ORIGIN_PORT, data=b"ola-mundo",
                          proxies=proxies, timeout=15)
        check("HTTP POST mantem corpo", r.text == "recebido:ola-mundo", r.text)
    except Exception as exc:
        check("HTTP POST mantem corpo", False, str(exc))

    # ------------------------------------------------------- HTTPS com MITM
    try:
        r = requests.get("https://127.0.0.1:%d/seguro" % ORIGIN_HTTPS_PORT, proxies=proxies,
                         timeout=15, verify=ca.ca_pem_path)
        check("HTTPS MITM com a CA local", r.status_code == 200 and r.text == "origem-https:/seguro", r.text)
    except Exception as exc:
        check("HTTPS MITM com a CA local", False, str(exc))

    # ------------------------------------------------------------ historico
    check("historico registra transacoes", len(engine.history) >= 3,
          "%d registros" % len(engine.history))
    https_tx = [t for t in engine.history if t.scheme == "https"]
    check("transacao HTTPS decifrada", bool(https_tx) and https_tx[0].status == 200)

    # -------------------------------------------------- interceptar e editar
    engine.intercept_requests = True
    engine.in_scope_only = False
    seen = {}

    def decide_worker():
        limit = time.time() + 20
        while time.time() < limit and not engine.held_pending:
            time.sleep(0.05)
        if engine.held_pending:
            held = engine.held_pending[0]
            raw = held.raw.replace(b"GET /editado", b"GET /editado-pelo-usuario")
            held.raw = raw
            seen["edited"] = raw != held.original
            engine.decide(held, "forward")

    threading.Thread(target=decide_worker, daemon=True).start()
    try:
        r = requests.get("http://127.0.0.1:%d/editado" % ORIGIN_PORT, proxies=proxies, timeout=20)
        check("interceptacao edita requisicao", r.text == "origem-http:/editado-pelo-usuario", r.text)
    except Exception as exc:
        check("interceptacao edita requisicao", False, str(exc))
    engine.intercept_requests = False

    # -------------------------------------------------------- descartar
    def drop_worker():
        limit = time.time() + 20
        while time.time() < limit and not engine.held_pending:
            time.sleep(0.05)
        if engine.held_pending:
            engine.decide(engine.held_pending[0], "drop")

    engine.intercept_requests = True
    threading.Thread(target=drop_worker, daemon=True).start()
    dropped = False
    try:
        requests.get("http://127.0.0.1:%d/descartar" % ORIGIN_PORT, proxies=proxies, timeout=20)
    except Exception:
        dropped = True
    check("descarte derruba a conexao", dropped)
    engine.intercept_requests = False

    # ------------------------------------------------------------- repeater
    raw = b"GET /repeater HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % ORIGIN_PORT
    response, error = engine.send_raw(
        raw, host_override="127.0.0.1", port_override=ORIGIN_PORT, scheme_override="http"
    )
    check("repeater devolve resposta", error is None and b"origem-http:/repeater" in (response or b""),
          error or "")

    # ---------------------------------------------------------------- escopo
    engine.set_scope("exemplo.com\n*.teste.local")
    check("escopo casa curinga", engine.in_scope("a.teste.local") and not engine.in_scope("outro.com"))

    engine.stop()
    origin.shutdown()
    origin_tls.shutdown()

    print("\n%d falha(s)" % len(failures))
    if failures:
        print("Falhas: " + ", ".join(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
