"""Navegador virtual do DerpSec.

Abre um Chromium (Edge ou Chrome) num perfil isolado, ja apontando o proxy
para o DerpSec e ignorando os certificados gerados pela CA local. Assim o
"Intercept Web" e um ambiente fechado: tudo que navegar ali passa pelo proxy.

O loopback (127.0.0.1) fica fora do proxy por padrao no Chromium, entao a
propria pagina do console carrega direto da maquina.

IMPORTANTE (por que existe o _kill_stale):
  O Chromium usa o perfil (--user-data-dir) como chave de instancia unica.
  Se ja existe uma instancia viva nesse perfil, o processo que acabamos de
  lancar entrega a URL para a instancia antiga e SAI IMEDIATAMENTE (rc=0).
  O resultado pratico e a janela "abrindo e fechando" e, pior, as flags
  novas (--proxy-server, etc.) e o token novo do console sao ignorados:
  a instancia velha continua apontando para o proxy/token antigos.
  Por isso fechamos qualquer instancia presa no perfil antes de abrir.

  Como o processo lancado pode sair sozinho (hand-off), nao usamos
  proc.poll() para dizer se o navegador esta aberto: consultamos de fato
  quais processos estao usando o nosso diretorio de perfil.
"""
import json
import os
import shutil
import subprocess
import sys
import time
import webbrowser

CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
    r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
]

CHROME_NAMES = ("chrome", "msedge", "brave", "chromium", "edge")

# nomes de executavel considerados "navegador virtual"
PROCESS_NAMES = ("msedge.exe", "chrome.exe", "brave.exe", "chromium.exe", "edge.exe")

_TABLE_TTL = 1.5           # segundos de cache da tabela de processos
_TABLE_CACHE = {"ts": 0.0, "rows": []}
_PROC_TIMEOUT = 25


def find_browser():
    """Devolve o caminho de um navegador Chromium, ou None."""
    for path in CANDIDATES:
        if os.path.isfile(path):
            return path
    for name in CHROME_NAMES:
        found = shutil.which(name)
        if found:
            return found
    return None


def _run_quiet(args, timeout=_PROC_TIMEOUT):
    """subprocess.run que nunca lanca excecao nem abre console no Windows."""
    try:
        kwargs = {"capture_output": True, "text": True, "errors": "replace",
                  "timeout": timeout}
        if sys.platform == "win32":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        return subprocess.run(args, **kwargs)
    except Exception:
        return None


def _uses_profile(cmdline, profile_dir):
    """A linha de comando aponta para este perfil (com fronteira de caminho)?"""
    if not cmdline or not profile_dir:
        return False
    cmd = os.path.normcase(cmdline)
    alvo = os.path.normcase(os.path.abspath(profile_dir))
    start = 0
    while True:
        i = cmd.find(alvo, start)
        if i < 0:
            return False
        nxt = cmd[i + len(alvo):i + len(alvo) + 1]
        if nxt in ("", " ", "\t", '"', "'", "\\", "/", "="):
            return True
        start = i + 1


def _process_table():
    """[(pid, cmdline)] dos navegadores Chromium em execucao (com cache curto)."""
    agora = time.time()
    if agora - _TABLE_CACHE["ts"] < _TABLE_TTL:
        return _TABLE_CACHE["rows"]
    rows = _read_process_table()
    _TABLE_CACHE["ts"] = time.time()
    _TABLE_CACHE["rows"] = rows
    return rows


def _read_process_table():
    if sys.platform == "win32":
        # 1) PowerShell/CIM (presente em qualquer Windows 10/11)
        script = (
            "$ErrorActionPreference='SilentlyContinue'; "
            "Get-CimInstance Win32_Process | "
            "Where-Object { $_.Name -match '^(msedge|chrome|brave|chromium|edge)\\.exe$' } | "
            "Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"
        )
        res = _run_quiet(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])
        rows = _parse_json_rows(res.stdout if res else "")
        if rows:
            return rows
        # 2) wmic (legado; ainda existe em parte dos Windows 10)
        rows = []
        for exe in PROCESS_NAMES:
            res = _run_quiet(["wmic", "process", "where", "name='%s'" % exe,
                              "get", "ProcessId,CommandLine"])
            if not res or not res.stdout:
                continue
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line or line.lower().startswith("commandline"):
                    continue
                partes = line.rsplit(None, 1)
                if len(partes) == 2 and partes[1].isdigit():
                    rows.append((int(partes[1]), partes[0]))
        return rows

    # POSIX (o alvo do app e Windows, mas nao custa funcionar)
    res = _run_quiet(["ps", "-eo", "pid=,args="])
    rows = []
    if res and res.stdout:
        for line in res.stdout.splitlines():
            line = line.strip()
            partes = line.split(None, 1)
            if len(partes) == 2 and partes[0].isdigit():
                rows.append((int(partes[0]), partes[1]))
    return rows


def _parse_json_rows(text):
    text = (text or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except Exception:
        return []
    if isinstance(data, dict):
        data = [data]
    rows = []
    for item in data:
        if not isinstance(item, dict):
            continue
        pid = item.get("ProcessId")
        cmd = item.get("CommandLine")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        rows.append((pid, cmd or ""))
    return rows


def profile_pids(profile_dir):
    """PIDs dos navegadores que estao usando este perfil. Nunca lanca excecao."""
    if not profile_dir:
        return []
    pids = []
    for pid, cmd in _process_table():
        if _uses_profile(cmd, profile_dir):
            pids.append(pid)
    return sorted(set(pids))


def kill_pids(pids):
    """Mata os PIDs informados (com a arvore de filhos). Devolve quantos."""
    matados = 0
    for pid in pids:
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        if pid <= 0:
            continue
        if sys.platform == "win32":
            res = _run_quiet(["taskkill", "/F", "/T", "/PID", str(pid)], timeout=20)
            ok = bool(res) and res.returncode == 0
        else:
            res = _run_quiet(["kill", "-9", str(pid)], timeout=10)
            ok = res is None or res.returncode == 0
        if ok:
            matados += 1
    _TABLE_CACHE["ts"] = 0.0  # invalida o cache depois de matar
    return matados


class VirtualBrowser:
    def __init__(self, profile_dir):
        self.profile_dir = profile_dir
        self.exe = find_browser()
        self._proc = None
        self.last_killed = 0
        self.last_open_confirmed = False

    @property
    def available(self):
        return self.exe is not None

    def _base_args(self, proxy_port, extra_flags=None):
        args = [
            self.exe,
            "--user-data-dir=%s" % self.profile_dir,
            "--proxy-server=127.0.0.1:%d" % int(proxy_port),
            "--ignore-certificate-errors",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-features=Translate,MediaRouter,OptimizationHints",
            "--disable-sync",
            "--disable-breakpad",
            "--window-size=1440,900",
            "--lang=pt-BR",
        ]
        if extra_flags:
            args.extend(extra_flags)
        return args

    # ------------------------------------------------------------ instancias
    def running_pids(self):
        """PIDs das instancias do nosso perfil (vistas agora)."""
        pids = profile_pids(self.profile_dir)
        proc = self._proc
        if proc is not None and proc.poll() is None and proc.pid not in pids:
            pids.append(proc.pid)
        return pids

    def is_running(self):
        return bool(self.running_pids())

    def _kill_stale(self):
        """Fecha instancias presas no perfil (proxy/token antigos).

        Repete algumas vezes porque o Chromium sobe varios processos (GPU,
        renderers, utilitarios) e o perfil so fica livre quando todos saem.
        """
        self.last_killed = 0
        for _ in range(4):
            _TABLE_CACHE["ts"] = 0.0  # tabela fresca a cada rodada
            pids = profile_pids(self.profile_dir)
            if not pids:
                return self.last_killed
            self.last_killed += kill_pids(pids)
            if self._wait_profile_free(2.0):
                return self.last_killed
        return self.last_killed

    def _wait_profile_free(self, timeout):
        end = time.time() + timeout
        while time.time() < end:
            if not profile_pids(self.profile_dir):
                return True
            time.sleep(0.3)
        return False

    # ---------------------------------------------------------------- abrir
    def open_console(self, url, proxy_port, app_mode=False):
        """Abre o console. Em modo app fica sem barras (janela do aplicativo).

        Devolve (proc, mensagem). Antes fecha qualquer instancia presa no
        perfil, senao o processo novo sai na hora e as flags nao valem.
        """
        os.makedirs(self.profile_dir, exist_ok=True)
        if not self.exe:
            webbrowser.open(url)
            return None, "navegador padrao (Chromium nao encontrado)"

        fechadas = self._kill_stale()
        flags = ["--app=%s" % url] if app_mode else ["--new-window", url]
        args = self._base_args(proxy_port, flags)
        try:
            self._proc = subprocess.Popen(
                args, close_fds=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception as exc:
            webbrowser.open(url)
            return None, "falha ao abrir Chromium (%s); abri no navegador padrao" % exc

        note = "navegador virtual aberto"
        if fechadas:
            note += " (fechei %d processo(s) antigo(s) presos no perfil)" % fechadas
        self.last_open_confirmed = self.wait_window(8.0)
        if not self.last_open_confirmed:
            return self._proc, note + " - nao confirmei a janela (verifique o navegador)"
        return self._proc, note

    def wait_window(self, timeout=8.0):
        """Espera a janela realmente subir.

        O processo lancado pode sair sozinho (hand-off do Chromium), por isso
        nao basta olhar proc.poll(): confirmamos se ha processo vivo no perfil.
        """
        end = time.time() + timeout
        while time.time() < end:
            if profile_pids(self.profile_dir):
                return True
            time.sleep(0.4)
        return False

    def open_url(self, url, proxy_port):
        """Abre uma nova aba/janela no mesmo perfil, tambem atraves do proxy."""
        if not self.exe:
            webbrowser.open(url)
            return None
        os.makedirs(self.profile_dir, exist_ok=True)
        args = self._base_args(proxy_port, ["--new-window", url])
        try:
            return subprocess.Popen(
                args, close_fds=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception:
            webbrowser.open(url)
            return None

    # --------------------------------------------------------------- fechar
    def close(self):
        """Fecha de verdade o navegador virtual (todas as instancias do perfil)."""
        pids = self.running_pids()
        proc = self._proc
        self._proc = None
        if proc is not None and proc.poll() is None and proc.pid not in pids:
            pids.append(proc.pid)
        return kill_pids(pids)
