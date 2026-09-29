"""Motor do proxy de interceptacao (HTTP/1.1 + HTTPS com MITM TLS)."""
import fnmatch
import gzip
import socket
import ssl
import threading
import time
import zlib
from datetime import datetime
from urllib.parse import urlsplit

from . import httpmsg as H

CONNECT_TIMEOUT = 30
READ_TIMEOUT = 60
HOLD_TIMEOUT = 1800  # 30 min esperando o usuario decidir

# Hosts de telemetria/ruido de fundo (Windows/Edge/navegador): nunca seguram a
# fila de interceptacao e nao viram "ultima navegacao" do Intercept Web.
# O filtro pode ser desligado na GUI/console (flag filter_telemetry).
NOISE_HOSTS = [
    "*.microsoft.com", "*.smartscreen.microsoft.com", "*.azureedge.net",
    "*.office.com", "*.office.net", "*.office365.com", "*.msn.com",
    "*.bing.com", "*.msedge.net", "*.windowsupdate.com",
    "*.microsoftonline.com", "*.msftauth.net", "*.msftauthwindows.net",
    "*.data.microsoft.com", "*.windows.com", "*.live.com", "*.skype.com",
    "*.doubleclick.net", "*.google-analytics.com", "*.googletagmanager.com",
    "*.gstatic.com", "*.googleadservices.com", "*.scorecardresearch.com",
    "*.facebook.net", "*.fbcdn.net", "*.cloudflareinsights.com",
    "*.hotjar.com", "*.mixpanel.com", "*.segment.io", "*.amplitude.com",
    "*.newrelic.com", "*.sentry.io", "*.criteo.com", "*.taboola.com",
    "*.outbrain.com", "*.adnxs.com", "*.rubiconproject.com", "*.openx.net",
    "*.pubmatic.com", "*.krxd.net", "*.moatads.com", "*.quantserve.com",
    "*.comscore.com", "*.chartbeat.com",
]


NAV_REPORTER = (
    b'<script>(function(){function r(){try{parent.postMessage('
    b'{__derpsec_nav:location.href},"*")}catch(e){}}'
    b'if(window.top!==window.self){r();var h=history.pushState,p=history.replaceState;'
    b'history.pushState=function(){h.apply(this,arguments);r()};'
    b'history.replaceState=function(){p.apply(this,arguments);r()};'
    b'window.addEventListener("popstate",r)}})();</script>'
)


def _strip_framing(headers):
    """Remove cabecalhos que impedem embutir o site num iframe (Intercept Web)."""
    out = H.del_header(headers, "X-Frame-Options")
    for name in ("Content-Security-Policy", "Content-Security-Policy-Report-Only"):
        value = H.get_header(out, name)
        if not value:
            continue
        parts = [p.strip() for p in value.split(";")]
        kept = [p for p in parts if p and not p.lower().startswith("frame-ancestors")]
        if kept:
            out = H.set_header(out, name, "; ".join(kept))
        else:
            out = H.del_header(out, name)
    return out


def _inject_nav_reporter(headers, body):
    """Injeta o script que reporta a navegacao do iframe para o Intercept Web.

    So roda para respostas HTML de navegacao de iframe (Sec-Fetch-Dest: iframe)
    com 'embutir sites' ligado. Descomprime/recomprime gzip e deflate para nao
    corromper o corpo; brotli e ignorado (nao mexe).
    """
    enc = (H.get_header(headers, "Content-Encoding") or "").lower()
    data = body
    if "gzip" in enc:
        try:
            data = gzip.decompress(body)
        except Exception:
            return headers, body
    elif "deflate" in enc:
        try:
            data = zlib.decompress(body)
        except zlib.error:
            try:
                data = zlib.decompress(body, -zlib.MAX_WBITS)
            except Exception:
                return headers, body
    elif "br" in enc:
        return headers, body  # brotli: deixa como esta

    low = data.lower()
    marker = b"</body>"
    if marker in low:
        idx = low.rfind(marker)
        data = data[:idx] + NAV_REPORTER + data[idx:]
    elif b"</html>" in low:
        idx = low.rfind(b"</html>")
        data = data[:idx] + NAV_REPORTER + data[idx:]
    else:
        data = data + NAV_REPORTER

    if "gzip" in enc:
        data = gzip.compress(data)
    elif "deflate" in enc:
        data = zlib.compress(data)
    headers = H.set_header(headers, "Content-Length", str(len(data)))
    return headers, data


class Transaction:
    _counter = 0
    _lock = threading.Lock()

    def __init__(self, scheme, host, port):
        with Transaction._lock:
            Transaction._counter += 1
            self.id = Transaction._counter
        self.scheme = scheme
        self.host = host
        self.port = port
        self.method = "-"
        self.path = "-"
        self.url = ""
        self.request_raw = b""
        self.response_raw = b""
        self.req_headers = []
        self.resp_headers = []
        self.req_body = b""
        self.resp_body = b""
        self.status = 0
        self.reason = ""
        self.mime = ""
        self.length = 0
        self.elapsed = 0.0
        self.started = datetime.now().strftime("%H:%M:%S")
        self.error = ""
        self.edited = False
        self.holding = False      # aguardando decisao do usuario na fila

    # ---------------------------------------------------------------- helpers
    @property
    def title(self):
        return "%s %s%s" % (self.method, self.host, self.path)

    def status_text(self):
        if self.error:
            return "erro"
        if self.holding:
            return "segura"
        if self.status:
            return str(self.status)
        return "..."

    def mime_text(self):
        if not self.mime:
            return ""
        return self.mime.split(";")[0].strip()


class Held:
    """Mensagem parada aguardando decisao do usuario na aba Interceptar."""

    _counter = 0
    _lock = threading.Lock()

    def __init__(self, kind, tx, raw):
        with Held._lock:
            Held._counter += 1
            self.serial = Held._counter   # id estavel (id() pode ser reutilizado)
        self.kind = kind          # "request" | "response"
        self.tx = tx
        self.raw = raw            # bytes editaveis
        self.original = raw
        self.event = threading.Event()
        self.action = None        # "forward" | "drop"

    @property
    def edited(self):
        return self.raw != self.original


class ProxyEngine:
    def __init__(self, ca, emit):
        self.ca = ca
        self.emit = emit                # callable(evento:str, dado)
        self.running = False
        self._server = None
        self._threads = []
        self._lock = threading.Lock()
        self.history = []
        self.held_pending = []
        self.intercept_requests = False
        self.intercept_responses = False
        self.in_scope_only = True
        self.verify_upstream = False
        self.unframe = True          # remove X-Frame-Options/CSP para embutir sites
        self.filter_telemetry = True  # nao segura telemetria de fundo na fila
        self.last_nav = None         # ultima navegacao HTML (para a barra de endereco)
        self.scope = []
        self.port = 8080

    # ------------------------------------------------------------ ciclo de vida
    def start(self, port):
        if self.running:
            return True, "ja em execucao"
        self.port = int(port)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("127.0.0.1", self.port))
        except OSError as exc:
            srv.close()
            return False, "nao foi possivel abrir a porta %s: %s" % (self.port, exc)
        self.port = srv.getsockname()[1]
        srv.listen(200)
        srv.settimeout(1.0)
        self._server = srv
        self.running = True
        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
        self._threads.append(thread)
        self.emit("log", "Proxy escutando em 127.0.0.1:%s" % self.port)
        return True, "ok"

    def stop(self):
        self.running = False
        try:
            if self._server:
                self._server.close()
        except Exception:
            pass
        self._server = None
        self.emit("log", "Proxy parado")
        return True, "ok"

    def clear_history(self):
        with self._lock:
            self.history = []

    # ------------------------------------------------------------------ escopo
    def in_scope(self, host, port=None):
        if not self.scope:
            return True
        host = (host or "").lower()
        candidates = [host]
        if port:
            candidates.append("%s:%s" % (host, port))
        for pattern in self.scope:
            pat = pattern.strip().lower()
            if not pat or pat.startswith("#"):
                continue
            for cand in candidates:
                if fnmatch.fnmatch(cand, pat):
                    return True
            if "/" not in pat and host.endswith("." + pat):
                return True
        return False

    def set_scope(self, text):
        self.scope = [line for line in (text or "").splitlines() if line.strip()]
        return len(self.scope)

    def _is_noise(self, host):
        """True se o host e telemetria/ruido de fundo (nao deve ser segurado)."""
        host = (host or "").lower()
        for pattern in NOISE_HOSTS:
            if fnmatch.fnmatch(host, pattern):
                return True
        return False

    # ------------------------------------------------------------ aceitar conexao
    def _accept_loop(self):
        while self.running:
            try:
                conn, _addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def _handle_client(self, conn):
        try:
            conn.settimeout(READ_TIMEOUT)
            first, headers, leftover = H.recv_head(conn)
            if not first:
                conn.close()
                return
            parts = first.split(" ", 2)
            if len(parts) < 2:
                conn.close()
                return
            method, target = parts[0].upper(), parts[1]

            if method == "CONNECT":
                host, _, port_s = target.partition(":")
                port = int(port_s) if port_s.isdigit() else 443
                conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                try:
                    tls_ctx = self.ca.leaf_context(host)
                    client = tls_ctx.wrap_socket(conn, server_side=True)
                except Exception as exc:
                    self.emit("log", "TLS falhou para %s: %s" % (host, exc))
                    try:
                        conn.close()
                    except Exception:
                        pass
                    return
                client.settimeout(READ_TIMEOUT)
                first, headers, leftover = H.recv_head(client)
                if not first:
                    client.close()
                    return
                parts = first.split(" ", 2)
                method, path = parts[0].upper(), parts[1]
                body = H.read_body(client, headers, leftover)
                self._process(client, "https", host, port, method, path, headers, body)
                return

            if target.lower().startswith("http://") or target.lower().startswith("https://"):
                url = urlsplit(target)
                host = url.hostname or ""
                scheme = url.scheme.lower()
                port = url.port or (443 if scheme == "https" else 80)
                path = url.path or "/"
                if url.query:
                    path += "?" + url.query
            else:
                host_header = H.get_header(headers, "Host") or ""
                host, _, port_s = host_header.partition(":")
                port = int(port_s) if port_s.isdigit() else 80
                scheme = "http"
                path = target
            if not host:
                conn.close()
                return
            body = H.read_body(conn, headers, leftover)
            self._process(conn, scheme, host, port, method, path, headers, body)
        except Exception as exc:
            self.emit("log", "conexao encerrada: %s" % exc)
            try:
                conn.close()
            except Exception:
                pass

    # ------------------------------------------------------------- transacao
    def _process(self, client, scheme, host, port, method, path, headers, body):
        tx = Transaction(scheme, host, port)
        tx.method = method
        tx.path = path
        default_port = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        tx.url = "%s://%s%s%s" % (scheme, host, "" if default_port else ":%d" % port, path)
        tx.req_headers = list(headers)
        tx.req_body = body
        tx.request_raw = H.serialize("%s %s HTTP/1.1" % (method, path), headers, body)

        sec_fetch_dest = (H.get_header(headers, "Sec-Fetch-Dest") or "").lower()
        noise = self.filter_telemetry and self._is_noise(host)
        scoped = self.in_scope(host, port)
        with self._lock:
            self.history.append(tx)
            if len(self.history) > 2000:      # historico limitado em RAM
                del self.history[:len(self.history) - 1500]
        self.emit("new_tx", tx)

        # ------------------------------------------------ interceptar requisicao
        if self.intercept_requests and (scoped or not self.in_scope_only) and not noise:
            held = Held("request", tx, tx.request_raw)
            tx.holding = True
            self.emit("update_tx", tx)
            self._hold(held)
            tx.holding = False
            if held.action != "forward":
                tx.error = "descartada pelo usuario"
                self.emit("update_tx", tx)
                self.emit("log", "#%s requisicao descartada" % tx.id)
                self._safe_close(client)
                return
            if held.edited:
                first, headers, body = H.parse_message(held.raw)
                bits = first.split(" ", 2)
                if len(bits) >= 2:
                    method, path = bits[0], bits[1]
                tx.method, tx.path = method, path
                tx.req_headers, tx.req_body = headers, body
                tx.request_raw = held.raw
                tx.edited = True

        # ----------------------------------------------------- conectar upstream
        try:
            upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except Exception as exc:
            tx.error = "falha ao conectar: %s" % exc
            self.emit("update_tx", tx)
            self._safe_close(client)
            return
        try:
            if scheme == "https":
                ctx = ssl.create_default_context()
                if not self.verify_upstream:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                upstream = ctx.wrap_socket(upstream, server_hostname=host)
            upstream.settimeout(READ_TIMEOUT)

            out_headers = [(k, v) for k, v in tx.req_headers if k.lower() != "proxy-connection"]
            out_headers = H.del_header(out_headers, "connection")
            out_headers = H.set_header(out_headers, "Connection", "close")
            if not H.get_header(out_headers, "Host"):
                out_headers = H.set_header(out_headers, "Host", host)
            if tx.req_body:
                out_headers = H.set_header(out_headers, "Content-Length", str(len(tx.req_body)))
            payload = H.serialize("%s %s HTTP/1.1" % (tx.method, tx.path), out_headers, tx.req_body)

            start = time.time()
            upstream.sendall(payload)
            status, reason, resp_headers, resp_body = H.read_response(upstream, tx.method)
            tx.elapsed = time.time() - start
        except Exception as exc:
            tx.error = str(exc)
            self.emit("update_tx", tx)
            self._safe_close(client)
            self._safe_close(upstream)
            return

        tx.status = status
        tx.reason = reason
        tx.resp_headers = resp_headers
        tx.resp_body = resp_body
        tx.length = len(resp_body)
        tx.mime = H.get_header(resp_headers, "Content-Type") or ""
        if self.unframe:
            resp_headers = _strip_framing(resp_headers)
            tx.resp_headers = resp_headers
        # injeta o reporter de navegacao so nas paginas carregadas no iframe
        # do Intercept Web (Sec-Fetch-Dest: iframe) - nunca em telemetria
        if (self.unframe and sec_fetch_dest == "iframe" and not noise
                and "text/html" in (tx.mime or "").lower() and resp_body):
            resp_headers, resp_body = _inject_nav_reporter(resp_headers, resp_body)
            tx.resp_headers, tx.resp_body = resp_headers, resp_body
            tx.length = len(resp_body)
        tx.response_raw = H.serialize(
            "HTTP/1.1 %d %s" % (status, reason), resp_headers, resp_body
        )
        # a barra de endereco do console segue apenas navegacoes reais do
        # iframe (GET + HTML + Sec-Fetch-Dest: iframe), nunca telemetria
        if (tx.method == "GET" and sec_fetch_dest == "iframe" and not noise
                and "text/html" in (tx.mime or "").lower()):
            with self._lock:
                self.last_nav = {"url": tx.url, "id": tx.id, "ts": time.time()}
        self.emit("update_tx", tx)

        # --------------------------------------------------- interceptar resposta
        if self.intercept_responses and (scoped or not self.in_scope_only) and not noise:
            held = Held("response", tx, tx.response_raw)
            tx.holding = True
            self.emit("update_tx", tx)
            self._hold(held)
            tx.holding = False
            if held.action != "forward":
                self.emit("log", "#%s resposta descartada" % tx.id)
                self._safe_close(client)
                self._safe_close(upstream)
                return
            if held.edited:
                first, resp_headers, resp_body = H.parse_message(held.raw)
                bits = first.split(" ", 2)
                if len(bits) >= 2 and bits[1].isdigit():
                    tx.status = int(bits[1])
                    tx.reason = bits[2] if len(bits) > 2 else ""
                tx.resp_headers, tx.resp_body = resp_headers, resp_body
                tx.length = len(resp_body)
                tx.response_raw = held.raw
                tx.edited = True
                self.emit("update_tx", tx)

        # avisa o cliente que a conexao sera fechada (evita reuso + RST)
        raw = tx.response_raw
        if b"connection:" not in raw[:4096].lower():
            head, sep, rest = raw.partition(b"\r\n")
            raw = head + b"\r\nConnection: close" + sep + rest
        try:
            client.sendall(raw)
        except Exception as exc:
            self.emit("log", "nao foi possivel entregar a resposta: %s" % exc)
        finally:
            self._safe_close(client)
            self._safe_close(upstream)

    # ------------------------------------------------------------------ apoio
    def _hold(self, held):
        self.held_pending.append(held)
        self.emit("held", held)
        held.event.wait(HOLD_TIMEOUT)
        if held in self.held_pending:
            self.held_pending.remove(held)

    @staticmethod
    def _safe_close(sock):
        try:
            sock.close()
        except Exception:
            pass

    def decide(self, held, action):
        held.action = action
        held.event.set()
        self.emit("held_done", held)

    def release_all(self, kind=None):
        """Encaminha todas as mensagens seguradas (opcionalmente so de um tipo).

        Usado ao desligar a interceptacao: nada fica preso na fila para sempre.
        """
        count = 0
        for held in list(self.held_pending):
            if kind and held.kind != kind:
                continue
            self.decide(held, "forward")
            count += 1
        return count

    # ------------------------------------------------ envio manual (Repeater)
    def send_raw(self, raw, host_override=None, port_override=None, scheme_override=None):
        """Envia uma requisicao crua e devolve a resposta crua (bytes, erro)."""
        try:
            first, headers, body = H.parse_message(raw)
            bits = first.split(" ", 2)
            if len(bits) < 2:
                return None, "linha de requisicao invalida"
            method, target = bits[0].upper(), bits[1]
            if target.lower().startswith("http"):
                url = urlsplit(target)
                host = url.hostname or ""
                scheme = url.scheme.lower()
                port = url.port or (443 if scheme == "https" else 80)
                path = url.path or "/"
                if url.query:
                    path += "?" + url.query
            else:
                host_header = host_override or H.get_header(headers, "Host") or ""
                host, _, port_s = host_header.partition(":")
                port = port_override or (int(port_s) if port_s.isdigit() else 80)
                scheme = scheme_override or ("https" if port == 443 else "http")
                path = target
            if not host:
                return None, "host nao informado (defina o cabecalho Host)"

            out_headers = [(k, v) for k, v in headers if k.lower() != "proxy-connection"]
            out_headers = H.del_header(out_headers, "connection")
            out_headers = H.set_header(out_headers, "Connection", "close")
            out_headers = H.set_header(out_headers, "Host", host)
            if body:
                out_headers = H.set_header(out_headers, "Content-Length", str(len(body)))

            upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
            try:
                if scheme == "https":
                    ctx = ssl.create_default_context()
                    if not self.verify_upstream:
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    upstream = ctx.wrap_socket(upstream, server_hostname=host)
                upstream.settimeout(READ_TIMEOUT)
                upstream.sendall(
                    H.serialize("%s %s HTTP/1.1" % (method, path), out_headers, body)
                )
                status, reason, resp_headers, resp_body = H.read_response(upstream, method)
            finally:
                self._safe_close(upstream)
            return H.serialize("HTTP/1.1 %d %s" % (status, reason), resp_headers, resp_body), None
        except Exception as exc:
            return None, str(exc)
