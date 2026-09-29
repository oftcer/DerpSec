"""Teste contra um site HTTPS real (requer internet)."""
import os
import socket
import sys
import tempfile

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


PORT = free_port()


def main():
    tmp = tempfile.mkdtemp(prefix="derpsec-real-")
    ca = CertAuthority(os.path.join(tmp, "ca"))
    engine = ProxyEngine(ca, lambda *a: None)
    ok, msg = engine.start(PORT)
    if not ok:
        print("falha ao iniciar:", msg)
        return 1
    proxies = {"http": "http://127.0.0.1:%d" % PORT, "https": "http://127.0.0.1:%d" % PORT}
    code = 0
    for url in ("https://example.com/", "https://api.github.com/", "http://example.com/"):
        try:
            r = requests.get(url, proxies=proxies, timeout=25, verify=ca.ca_pem_path,
                             headers={"User-Agent": "DerpSec-Test/1.4.0"})
            print("[OK  ] %-30s %s  %d bytes" % (url, r.status_code, len(r.content)))
        except Exception as exc:
            print("[FALHA] %-30s %s" % (url, exc))
            code = 1
    for tx in engine.history:
        print("   #%s %-6s %-28s %s" % (tx.id, tx.method, tx.host, tx.status_text()))
    engine.stop()
    return code


if __name__ == "__main__":
    sys.exit(main())
