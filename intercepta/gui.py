"""Interface grafica (Tkinter) do DerpSec - tema escuro."""
import json
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from collections import deque
from tkinter import filedialog, messagebox, ttk

from . import httpmsg as H
from .browser import VirtualBrowser
from .certs import CertAuthority
from .engine import ProxyEngine
from .webconsole import WebConsole, resource_path

APP_NAME = "DerpSec"
VERSION = "1.4.0"
MONO = ("Consolas", 9)

# ---------------------------------------------------------------- paleta
BG = "#141518"
BG2 = "#17181b"
PANEL = "#1e2024"
PANEL2 = "#2a2e34"
BORDER = "#2f333a"
FG = "#f4f5f6"
MUTED = "#969ba3"
DIM = "#6d727a"
EDIT_BG = "#0f1012"
EDIT_FG = "#e6e8ea"


def data_dir():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    path = os.path.join(base, APP_NAME)
    os.makedirs(path, exist_ok=True)
    _migrate_legacy(base, path)
    return path


def _migrate_legacy(base, new_dir):
    """Migracao unica: copia config.json e a CA do diretorio antigo (Intercepta).

    Mantem a confianca do navegador na CA ja instalada e as preferencias do
    usuario. Nada e apagado do diretorio antigo.
    """
    old_dir = os.path.join(base, "Intercepta")
    if os.path.abspath(old_dir) == os.path.abspath(new_dir):
        return
    if not os.path.exists(os.path.join(old_dir, "config.json")):
        return
    if os.path.exists(os.path.join(new_dir, "config.json")):
        return  # ja migrado
    try:
        import shutil
        shutil.copy2(os.path.join(old_dir, "config.json"),
                     os.path.join(new_dir, "config.json"))
        old_ca = os.path.join(old_dir, "ca")
        if os.path.isdir(old_ca):
            new_ca = os.path.join(new_dir, "ca")
            os.makedirs(new_ca, exist_ok=True)
            for name in os.listdir(old_ca):
                src = os.path.join(old_ca, name)
                if os.path.isfile(src):
                    dst = os.path.join(
                        new_ca, name.replace("intercepta-ca", "derpsec-ca"))
                    shutil.copy2(src, dst)
    except Exception:
        pass


def load_config(path):
    defaults = {
        "port": 8080,
        "intercept_requests": False,
        "intercept_responses": False,
        "in_scope_only": True,
        "verify_upstream": False,
        "unframe": True,
        "filter_telemetry": True,
        "scope": "",
        "autostart": True,
    }
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        defaults.update({k: v for k, v in data.items() if k in defaults})
    except Exception:
        pass
    # A interceptacao sempre inicia desligada (como o Burp): o estado
    # ligado/desligado e de sessao e nao deve ser persistido.
    defaults["intercept_requests"] = False
    defaults["intercept_responses"] = False
    return defaults


class App:
    def __init__(self):
        self.dir = data_dir()
        self.config_path = os.path.join(self.dir, "config.json")
        self.config = load_config(self.config_path)
        self.ca = CertAuthority(os.path.join(self.dir, "ca"))
        self.events = queue.Queue()
        self.engine = ProxyEngine(self.ca, self._on_event)
        self.engine.in_scope_only = self.config["in_scope_only"]
        self.engine.verify_upstream = self.config["verify_upstream"]
        self.engine.unframe = bool(self.config["unframe"])
        self.engine.filter_telemetry = bool(self.config["filter_telemetry"])
        self.engine.set_scope(self.config["scope"])
        self.rows = {}
        self.held_by_row = {}
        self.current_held = None
        self._logbuf = deque(maxlen=4000)
        self._loglock = threading.Lock()

        # ------------------------------------------------- Intercept Web
        self.web = WebConsole(self)
        self.vbrowser = VirtualBrowser(os.path.join(self.dir, "webprofile"))

        self.root = tk.Tk()
        self.root.title("%s v%s - proxy de interceptacao HTTP/HTTPS" % (APP_NAME, VERSION))
        self.root.geometry("1180x760")
        self.root.minsize(960, 620)
        self._apply_icon()
        self._build_style()
        self._build_menu()
        self._build_toolbar()
        self._build_tabs()
        self._build_statusbar()
        self._apply_dark(self.root)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(150, self._pump)
        self.root.bind("<F5>", self._on_f5)
        self.root.bind("<F6>", self._on_f6)
        self.log("Dados do usuario: %s" % self.dir)
        self.log("CA raiz: %s" % self.ca.ca_pem_path)
        if self.config["autostart"]:
            self.root.after(300, self.start_proxy)

    # ------------------------------------------------------------------ icone
    def _apply_icon(self):
        for rel in ("icon/logo.png", "icon/logo.ico"):
            path = resource_path(rel)
            if os.path.exists(path):
                try:
                    if path.lower().endswith(".png"):
                        self._icon_img = tk.PhotoImage(file=path)
                        self.root.iconphoto(True, self._icon_img)
                    else:
                        self.root.iconbitmap(path)
                    return
                except Exception:
                    continue

    # ------------------------------------------------------------------ estilo
    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        self.root.configure(bg=BG)
        style.configure(".", background=BG, foreground=FG, fieldbackground=EDIT_BG,
                        bordercolor=BORDER, lightcolor=PANEL, darkcolor=BG, focuscolor=PANEL)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG)
        style.configure("Muted.TLabel", background=BG, foreground=DIM, font=("Segoe UI", 9))
        style.configure("TLabelframe", background=BG, foreground=MUTED, bordercolor=BORDER,
                        lightcolor=BORDER, darkcolor=BORDER)
        style.configure("TLabelframe.Label", background=BG, foreground=MUTED,
                        font=("Segoe UI", 9, "bold"))
        style.configure("TButton", background=PANEL, foreground=FG, bordercolor=BORDER,
                        lightcolor=PANEL, darkcolor=PANEL, focuscolor=PANEL, padding=(9, 5))
        style.map("TButton",
                  background=[("pressed", "#43484f"), ("active", "#33373e"), ("disabled", BG2)],
                  foreground=[("disabled", DIM)])
        style.configure("Accent.TButton", background=FG, foreground="#111111",
                        bordercolor=FG, lightcolor=FG, darkcolor=FG, focuscolor=FG,
                        padding=(14, 8), font=("Segoe UI", 10, "bold"))
        style.map("Accent.TButton",
                  background=[("pressed", "#d8dade"), ("active", "#ffffff"), ("disabled", "#5c6169")],
                  foreground=[("disabled", "#2a2d31")])
        style.configure("TEntry", fieldbackground=EDIT_BG, foreground=FG, bordercolor=BORDER,
                        insertcolor=FG, selectbackground="#3a4149")
        style.map("TEntry", fieldbackground=[("disabled", BG2)], foreground=[("disabled", DIM)])
        style.configure("TCombobox", fieldbackground=EDIT_BG, background=PANEL, foreground=FG,
                        arrowcolor=FG, bordercolor=BORDER, lightcolor=PANEL, darkcolor=PANEL)
        style.map("TCombobox",
                  fieldbackground=[("readonly", EDIT_BG)],
                  background=[("readonly", PANEL)],
                  foreground=[("readonly", FG)])
        style.configure("TCheckbutton", background=BG, foreground=FG, focuscolor=BG,
                        indicatorcolor=EDIT_BG, bordercolor=BORDER)
        style.map("TCheckbutton",
                  background=[("active", BG)],
                  foreground=[("disabled", DIM)],
                  indicatorcolor=[("selected", FG), ("pressed", PANEL2)])
        style.configure("TNotebook", background=BG, bordercolor=BORDER, tabmargins=(2, 4, 2, 0))
        style.configure("TNotebook.Tab", background=BG2, foreground=MUTED,
                        padding=(14, 6), bordercolor=BORDER, lightcolor=BG2, darkcolor=BG2)
        style.map("TNotebook.Tab",
                  background=[("selected", PANEL), ("active", PANEL)],
                  foreground=[("selected", FG), ("active", FG)])
        style.configure("Treeview", background=BG2, fieldbackground=BG2, foreground=FG,
                        rowheight=21, font=("Segoe UI", 9), bordercolor=BORDER,
                        lightcolor=BG2, darkcolor=BG2)
        style.configure("Treeview.Heading", background="#1b1d21", foreground=MUTED,
                        font=("Segoe UI", 9, "bold"), relief="flat", bordercolor=BORDER)
        style.map("Treeview.Heading", background=[("active", "#23262b")])
        style.map("Treeview",
                  background=[("selected", "#2c3138")],
                  foreground=[("selected", FG)])
        style.configure("TPanedwindow", background=BG)
        for orient in ("Vertical", "Horizontal"):
            style.configure("%s.TScrollbar" % orient, background=PANEL, troughcolor=BG2,
                            bordercolor=BG2, arrowcolor=MUTED, lightcolor=PANEL, darkcolor=PANEL)
            style.map("%s.TScrollbar" % orient,
                      background=[("active", PANEL2), ("pressed", PANEL2)])
        style.configure("TSeparator", background=BORDER)

    def _apply_dark(self, widget):
        """Ajusta cores de widgets tk classicos (Text, Listbox) recursivamente."""
        for child in widget.winfo_children():
            cls = child.winfo_class()
            try:
                if cls == "Text":
                    child.configure(bg=EDIT_BG, fg=EDIT_FG, insertbackground=FG,
                                    selectbackground="#3a4149", selectforeground=FG,
                                    highlightthickness=0, relief="flat", bd=0)
                elif cls == "Listbox":
                    child.configure(bg=BG2, fg=FG, selectbackground="#3a4149",
                                    selectforeground=FG, highlightthickness=0,
                                    relief="flat", bd=0)
            except Exception:
                pass
            self._apply_dark(child)

    # ------------------------------------------------------------------- menu
    def _menu(self, parent):
        return tk.Menu(parent, tearoff=0, bg=PANEL, fg=FG, activebackground="#33373e",
                       activeforeground=FG, bd=0, relief="flat",
                       activeborderwidth=0, selectcolor=FG)

    def _build_menu(self):
        menubar = tk.Menu(self.root, bg=PANEL, fg=FG, activebackground="#33373e",
                          activeforeground=FG, bd=0, relief="flat")
        arquivo = self._menu(menubar)
        arquivo.add_command(label="Intercept Web (navegador virtual)",
                            command=self.open_intercept_web)
        arquivo.add_separator()
        arquivo.add_command(label="Iniciar proxy", command=self.start_proxy)
        arquivo.add_command(label="Parar proxy", command=self.stop_proxy)
        arquivo.add_separator()
        arquivo.add_command(label="Sair", command=self.on_close)
        menubar.add_cascade(label="Arquivo", menu=arquivo)

        ferramentas = self._menu(menubar)
        ferramentas.add_command(label="Instalar CA no Windows", command=self.install_ca)
        ferramentas.add_command(label="Exportar CA (.pem)", command=self.export_ca)
        menubar.add_cascade(label="Ferramentas", menu=ferramentas)

        ajuda = self._menu(menubar)
        ajuda.add_command(label="Como usar o Intercept Web", command=self.show_help)
        ajuda.add_command(label="Sobre", command=self.show_about)
        menubar.add_cascade(label="Ajuda", menu=ajuda)
        self.root.config(menu=menubar)

    # -------------------------------------------------------------- barra topo
    def _build_toolbar(self):
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=8, pady=(8, 2))
        self.btn_web = ttk.Button(bar, text="Intercept Web", style="Accent.TButton",
                                  command=self.open_intercept_web)
        self.btn_web.pack(side="left")
        self.web_status = tk.StringVar(value="navegador virtual: fechado")
        ttk.Label(bar, textvariable=self.web_status, style="Muted.TLabel").pack(side="right")

    def _build_statusbar(self):
        bar = ttk.Frame(self.root)
        bar.pack(side="bottom", fill="x")
        self.status = tk.StringVar(value="parado")
        ttk.Label(bar, textvariable=self.status, anchor="w").pack(side="left", padx=8, pady=2)
        self.counter = tk.StringVar(value="0 transacoes")
        ttk.Label(bar, textvariable=self.counter, anchor="e").pack(side="right", padx=8, pady=2)

    # -------------------------------------------------------------------- abas
    def _build_tabs(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=6, pady=6)
        self.nb = nb
        self._tab_proxy(nb)
        self._tab_intercept(nb)
        self._tab_repeater(nb)
        self._tab_scope(nb)
        self._tab_ca(nb)
        self._tab_log(nb)

    # ------------------------------------------------------------- aba proxy
    def _tab_proxy(self, nb):
        frame = ttk.Frame(nb)
        nb.add(frame, text="Proxy / Historico")

        top = ttk.Frame(frame)
        top.pack(fill="x", padx=6, pady=6)
        ttk.Label(top, text="Porta:").pack(side="left")
        self.port_var = tk.StringVar(value=str(self.config["port"]))
        ttk.Entry(top, textvariable=self.port_var, width=7).pack(side="left", padx=(4, 10))
        self.btn_start = ttk.Button(top, text="Iniciar", command=self.start_proxy)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(top, text="Parar", command=self.stop_proxy, state="disabled")
        self.btn_stop.pack(side="left", padx=4)

        self.ir_var = tk.BooleanVar(value=self.config["intercept_requests"])
        self.irp_var = tk.BooleanVar(value=self.config["intercept_responses"])
        ttk.Checkbutton(
            top, text="Interceptar requisicoes", variable=self.ir_var,
            command=self.sync_intercept_flags,
        ).pack(side="left", padx=12)
        ttk.Checkbutton(
            top, text="Interceptar respostas", variable=self.irp_var,
            command=self.sync_intercept_flags,
        ).pack(side="left")

        ttk.Button(top, text="Limpar", command=self.clear_history).pack(side="right")
        ttk.Label(top, text="Filtro host/caminho:").pack(side="right", padx=(0, 4))
        self.filter_var = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.filter_var, width=24)
        entry.pack(side="right", padx=(0, 8))
        entry.bind("<KeyRelease>", lambda _e: self.refresh_tree())

        panes = ttk.Panedwindow(frame, orient="vertical")
        panes.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        wrap = ttk.Frame(panes)
        cols = ("id", "metodo", "host", "caminho", "status", "tam", "tipo", "hora")
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="browse")
        widths = {"id": 50, "metodo": 70, "host": 210, "caminho": 350, "status": 60,
                  "tam": 70, "tipo": 130, "hora": 70}
        for col in cols:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=widths[col], anchor="w")
        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.tag_configure("ok", background="#182119", foreground="#cdeed3")
        self.tree.tag_configure("redir", background="#171d28", foreground="#cfdcf5")
        self.tree.tag_configure("warn", background="#241f14", foreground="#f0dcae")
        self.tree.tag_configure("erro", background="#251818", foreground="#f2c9c9")
        self.tree.tag_configure("pend", foreground="#8a8f96")
        self.tree.tag_configure("segura", background="#241f14", foreground="#f0c674")
        self.tree.bind("<Double-1>", self.open_detail)
        self.tree.bind("<Button-3>", self.tree_menu)
        panes.add(wrap, weight=4)

        detail = ttk.Frame(panes)
        self.req_text = self._raw_box(detail, "Requisicao")
        self.resp_text = self._raw_box(detail, "Resposta (corpo decodificado)")
        panes.add(detail, weight=3)

    def _raw_box(self, parent, title):
        holder = ttk.LabelFrame(parent, text=title)
        holder.pack(side="left", fill="both", expand=True, padx=3, pady=3)
        text = tk.Text(holder, font=MONO, wrap="none", undo=True)
        text.pack(side="left", fill="both", expand=True)
        vsb = ttk.Scrollbar(holder, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        return text

    # --------------------------------------------------------- aba intercept
    def _tab_intercept(self, nb):
        frame = ttk.Frame(nb)
        nb.add(frame, text="Interceptar")

        top = ttk.Frame(frame)
        top.pack(fill="x", padx=6, pady=6)
        ttk.Button(top, text="Encaminhar (F5)", command=lambda: self.decide("forward")).pack(side="left")
        ttk.Button(top, text="Descartar (F6)", command=lambda: self.decide("drop")).pack(side="left", padx=4)
        ttk.Button(top, text="Encaminhar tudo", command=self.forward_all).pack(side="left", padx=4)
        self.intercept_only_scope = tk.BooleanVar(value=self.config["in_scope_only"])
        ttk.Checkbutton(
            top, text="Somente no escopo", variable=self.intercept_only_scope,
            command=self.sync_intercept_flags,
        ).pack(side="left", padx=12)
        self.queue_label = ttk.Label(top, text="fila: 0")
        self.queue_label.pack(side="right")

        panes = ttk.Panedwindow(frame, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        left = ttk.Frame(panes)
        cols = ("tipo", "metodo", "caminho")
        self.held_tree = ttk.Treeview(left, columns=cols, show="tree headings",
                                      selectmode="browse")
        self.held_tree.heading("#0", text="Host")
        self.held_tree.column("#0", width=170, anchor="w")
        for col in cols:
            self.held_tree.heading(col, text=col.capitalize())
            self.held_tree.column(col, width=90, anchor="w")
        self.held_tree.column("caminho", width=280, anchor="w")
        self.held_tree.tag_configure("group", background="#1b1d21", foreground=MUTED,
                                     font=("Segoe UI", 9, "bold"))
        self.held_tree.tag_configure("req", foreground="#cdeed3")
        self.held_tree.tag_configure("resp", foreground="#cfdcf5")
        vsb = ttk.Scrollbar(left, orient="vertical", command=self.held_tree.yview)
        self.held_tree.configure(yscrollcommand=vsb.set)
        self.held_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.held_tree.bind("<<TreeviewSelect>>", self.on_held_select)
        panes.add(left, weight=1)

        right = ttk.LabelFrame(panes, text="Edite a mensagem e clique em Encaminhar")
        self.held_text = tk.Text(right, font=MONO, wrap="none", undo=True)
        self.held_text.pack(side="left", fill="both", expand=True)
        vsb = ttk.Scrollbar(right, orient="vertical", command=self.held_text.yview)
        self.held_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        panes.add(right, weight=3)

    # ---------------------------------------------------------- aba repeater
    def _tab_repeater(self, nb):
        frame = ttk.Frame(nb)
        nb.add(frame, text="Repeater")

        top = ttk.Frame(frame)
        top.pack(fill="x", padx=6, pady=6)
        ttk.Label(top, text="Host:").pack(side="left")
        self.rp_host = tk.StringVar()
        ttk.Entry(top, textvariable=self.rp_host, width=34).pack(side="left", padx=4)
        ttk.Label(top, text="Porta:").pack(side="left")
        self.rp_port = tk.StringVar(value="443")
        ttk.Entry(top, textvariable=self.rp_port, width=6).pack(side="left", padx=4)
        self.rp_scheme = tk.StringVar(value="https")
        ttk.Combobox(top, textvariable=self.rp_scheme, values=["http", "https"], width=7,
                     state="readonly").pack(side="left", padx=4)
        ttk.Button(top, text="Enviar (Ctrl+Enter)", command=self.repeater_send).pack(side="left", padx=8)
        ttk.Button(top, text="Do historico", command=self.from_history).pack(side="left")

        panes = ttk.Panedwindow(frame, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        left = ttk.LabelFrame(panes, text="Requisicao")
        self.rp_req = tk.Text(left, font=MONO, wrap="none", undo=True)
        self.rp_req.pack(fill="both", expand=True)
        panes.add(left, weight=1)
        right = ttk.LabelFrame(panes, text="Resposta")
        self.rp_resp = tk.Text(right, font=MONO, wrap="none")
        self.rp_resp.pack(fill="both", expand=True)
        panes.add(right, weight=1)
        self.rp_req.bind("<Control-Return>", lambda _e: self.repeater_send())
        self.rp_req.insert("1.0", "GET / HTTP/1.1\nHost: example.com\n\n")

    # ------------------------------------------------------------- aba escopo
    def _tab_scope(self, nb):
        frame = ttk.Frame(nb)
        nb.add(frame, text="Escopo")
        ttk.Label(
            frame,
            text=("Defina os alvos autorizados (um por linha). Use curingas: *.exemplo.com\n"
                  "Deixe vazio para considerar tudo dentro do escopo."),
            justify="left",
        ).pack(anchor="w", padx=8, pady=8)
        self.scope_text = tk.Text(frame, font=MONO, height=18)
        self.scope_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.scope_text.insert("1.0", self.config["scope"])
        ttk.Button(frame, text="Salvar escopo", command=self.save_scope).pack(anchor="e", padx=8, pady=(0, 8))

    # ---------------------------------------------------------------- aba CA
    def _tab_ca(self, nb):
        frame = ttk.Frame(nb)
        nb.add(frame, text="CA & Config")
        box = ttk.LabelFrame(frame, text="Certificado da autoridade local")
        box.pack(fill="x", padx=8, pady=8)
        ttk.Label(box, text="Arquivo: " + self.ca.ca_pem_path, wraplength=900).pack(anchor="w", padx=8, pady=4)
        ttk.Label(box, text="Fingerprint SHA-256: " + self.ca.ca_fingerprint(), wraplength=900,
                  font=("Consolas", 8)).pack(anchor="w", padx=8, pady=(0, 6))
        row = ttk.Frame(box)
        row.pack(anchor="w", padx=8, pady=(0, 8))
        ttk.Button(row, text="Instalar CA no Windows (usuario)", command=self.install_ca).pack(side="left")
        ttk.Button(row, text="Exportar .pem", command=self.export_ca).pack(side="left", padx=6)
        ttk.Button(row, text="Abrir pasta", command=lambda: self.open_path(self.dir)).pack(side="left", padx=6)
        ttk.Label(
            box,
            text=("O navegador virtual do Intercept Web ja ignora os certificados da CA,\n"
                  "entao nao precisa instalar nada para interceptar por ele."),
            justify="left", style="Muted.TLabel",
        ).pack(anchor="w", padx=8, pady=(0, 8))

        box3 = ttk.LabelFrame(frame, text="Preferencias")
        box3.pack(fill="x", padx=8, pady=8)
        self.verify_var = tk.BooleanVar(value=self.config["verify_upstream"])
        ttk.Checkbutton(box3, text="Validar certificado do servidor de destino (pode quebrar sites com TLS antigo)",
                        variable=self.verify_var, command=self.sync_intercept_flags).pack(anchor="w", padx=8, pady=4)
        self.autostart_var = tk.BooleanVar(value=self.config["autostart"])
        ttk.Checkbutton(box3, text="Iniciar o proxy ao abrir o aplicativo",
                        variable=self.autostart_var, command=self.save_config).pack(anchor="w", padx=8, pady=4)
        self.unframe_var = tk.BooleanVar(value=self.config["unframe"])
        ttk.Checkbutton(box3, text="Embutir sites no Intercept Web (remove X-Frame-Options e frame-ancestors)",
                        variable=self.unframe_var, command=self.sync_intercept_flags).pack(anchor="w", padx=8, pady=4)
        self.filter_tel_var = tk.BooleanVar(value=self.config["filter_telemetry"])
        ttk.Checkbutton(box3, text="Filtrar telemetria (nao segura trafego de fundo do Windows/Edge na fila)",
                        variable=self.filter_tel_var, command=self.sync_intercept_flags).pack(anchor="w", padx=8, pady=(0, 8))

    # ------------------------------------------------------------------ log
    def _tab_log(self, nb):
        frame = ttk.Frame(nb)
        nb.add(frame, text="Log")
        self.log_text = tk.Text(frame, font=MONO, wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)

    # ================================================================ acoes
    def _on_event(self, event, payload):
        self.events.put((event, payload))

    def _pump(self):
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event in ("new_tx", "update_tx"):
                    self.upsert_row(payload)
                elif event == "log":
                    self._render_log(payload)
                elif event in ("held", "held_done"):
                    self.refresh_held_list()
                elif event == "ui":
                    try:
                        payload()
                    except Exception as exc:  # nunca derruba o loop da GUI
                        self._render_log("erro na GUI: %s" % exc)
        except queue.Empty:
            pass
        self.root.after(150, self._pump)

    def _ui(self, fn):
        """Executa fn na thread da GUI.

        O Tk nao aceita root.after() chamado de outra thread
        (RuntimeError: main thread is not in main loop), por isso pedidos
        vindos do console web passam pela fila thread-safe consumida por _pump.
        """
        if threading.current_thread() is threading.main_thread():
            try:
                fn()
            except Exception as exc:
                self._render_log("erro na GUI: %s" % exc)
            return
        self.events.put(("ui", fn))

    def log(self, message):
        """Registra no buffer (thread-safe) e agenda a exibicao na thread da UI."""
        with self._loglock:
            self._logbuf.append(message)
        self.events.put(("log", message))

    def _render_log(self, message):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def log_lines(self):
        with self._loglock:
            return list(self._logbuf)

    def clear_log(self):
        with self._loglock:
            self._logbuf.clear()
        def apply():
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.configure(state="disabled")
        self._ui(apply)

    def _set_intercept_flags(self, req, resp, only_scope, verify, unframe, filter_tel):
        """Aplica as flags e libera mensagens seguradas ao desligar a interceptacao."""
        old_req = self.engine.intercept_requests
        old_resp = self.engine.intercept_responses
        self.engine.intercept_requests = bool(req)
        self.engine.intercept_responses = bool(resp)
        self.engine.in_scope_only = bool(only_scope)
        self.engine.verify_upstream = bool(verify)
        self.engine.unframe = bool(unframe)
        self.engine.filter_telemetry = bool(filter_tel)
        if old_req and not self.engine.intercept_requests:
            n = self.engine.release_all("request")
            if n:
                self.log("interceptacao de requisicoes desligada: %d mensagem(ns) encaminhada(s)" % n)
        if old_resp and not self.engine.intercept_responses:
            n = self.engine.release_all("response")
            if n:
                self.log("interceptacao de respostas desligada: %d mensagem(ns) encaminhada(s)" % n)

    def sync_intercept_flags(self):
        self._set_intercept_flags(
            self.ir_var.get(), self.irp_var.get(),
            self.intercept_only_scope.get(), self.verify_var.get(), self.unframe_var.get(),
            self.filter_tel_var.get(),
        )
        self.save_config()

    def save_config(self):
        self.config.update({
            "port": self.port_var.get(),
            "in_scope_only": bool(self.intercept_only_scope.get()),
            "verify_upstream": bool(self.verify_var.get()),
            "unframe": bool(self.unframe_var.get()),
            "filter_telemetry": bool(self.filter_tel_var.get()),
            "scope": self.scope_text.get("1.0", "end").strip(),
            "autostart": bool(self.autostart_var.get()),
        })
        # nao persiste o estado da interceptacao: sempre inicia desligada
        self.config["intercept_requests"] = False
        self.config["intercept_responses"] = False
        try:
            with open(self.config_path, "w", encoding="utf-8") as fh:
                json.dump(self.config, fh, indent=2)
        except Exception as exc:
            self.log("falha ao salvar configuracao: %s" % exc)

    def start_proxy(self):
        self.sync_intercept_flags()
        ok, message = self.engine.start(self.port_var.get().strip() or "8080")
        if not ok:
            messagebox.showerror(APP_NAME, message)
            return
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.status.set("escutando em 127.0.0.1:%s" % self.engine.port)

    def stop_proxy(self):
        self.engine.stop()
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.status.set("parado")

    def clear_history(self):
        self.engine.clear_history()
        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        self.req_text.delete("1.0", "end")
        self.resp_text.delete("1.0", "end")
        self.counter.set("0 transacoes")

    # ====================================================== bridge do console
    def web_state(self):
        with self.engine._lock:
            count = len(self.engine.history)
        return {
            "running": bool(self.engine.running),
            "port": self.engine.port,
            "intercept_requests": bool(self.engine.intercept_requests),
            "intercept_responses": bool(self.engine.intercept_responses),
            "in_scope_only": bool(self.engine.in_scope_only),
            "unframe": bool(getattr(self.engine, "unframe", True)),
            "filter_telemetry": bool(getattr(self.engine, "filter_telemetry", True)),
            "last_nav": getattr(self.engine, "last_nav", None),
            "tx_count": count,
            "held_count": len(self.engine.held_pending),
            "version": VERSION,
        }

    def get_scope(self):
        return self.scope_text.get("1.0", "end").strip()

    def set_scope(self, text):
        count = self.engine.set_scope(text)

        def apply():
            self.scope_text.delete("1.0", "end")
            self.scope_text.insert("1.0", text)
            self.save_config()
        self._ui(apply)
        self.log("escopo atualizado pelo Intercept Web (%d padrao(oes))" % count)
        return count

    def set_flags(self, data):
        def apply():
            if "intercept_requests" in data:
                self.ir_var.set(bool(data["intercept_requests"]))
            if "intercept_responses" in data:
                self.irp_var.set(bool(data["intercept_responses"]))
            if "in_scope_only" in data:
                self.intercept_only_scope.set(bool(data["in_scope_only"]))
            if "unframe" in data:
                self.unframe_var.set(bool(data["unframe"]))
            if "filter_telemetry" in data:
                self.filter_tel_var.set(bool(data["filter_telemetry"]))
            self.sync_intercept_flags()
        self._ui(apply)
        self._set_intercept_flags(
            data.get("intercept_requests", self.engine.intercept_requests),
            data.get("intercept_responses", self.engine.intercept_responses),
            data.get("in_scope_only", self.engine.in_scope_only),
            self.engine.verify_upstream,
            data.get("unframe", getattr(self.engine, "unframe", True)),
            data.get("filter_telemetry", getattr(self.engine, "filter_telemetry", True)),
        )

    def web_start_proxy(self):
        if self.engine.running:
            return True, "proxy ja estava ativo"
        self._ui(self.start_proxy)
        for _ in range(60):
            if self.engine.running:
                return True, "proxy iniciado em 127.0.0.1:%s" % self.engine.port
            time.sleep(0.1)
        return False, "nao foi possivel iniciar o proxy (verifique a porta)"

    def web_stop_proxy(self):
        self._ui(self.stop_proxy)

    def web_clear_history(self):
        self._ui(self.clear_history)

    # ============================================================ Intercept Web
    def open_intercept_web(self, default_browser=False):
        if not self.engine.running:
            self.start_proxy()
        if not self.engine.running:
            messagebox.showerror(APP_NAME, "Inicie o proxy antes de abrir o Intercept Web.")
            return
        ok, message = self.web.start()
        if not ok:
            messagebox.showerror(APP_NAME, message)
            return
        self.log("Intercept Web: %s" % message)
        url = self.web.page_url()

        if default_browser:
            import webbrowser
            webbrowser.open(url)
            self.web_status.set("console :%d (navegador padrao)" % self.web.port)
            return

        _proc, note = self.vbrowser.open_console(url, self.engine.port, app_mode=True)
        self.log("navegador virtual: %s -> %s" % (note, self.vbrowser.exe or "navegador padrao"))
        if not self.vbrowser.available:
            self.web_status.set("console :%d (navegador padrao)" % self.web.port)
            messagebox.showwarning(
                APP_NAME,
                "Nao encontrei Edge/Chrome no sistema.\n\n"
                "Abri o console no navegador padrao:\n%s\n\n"
                "Observacao: o navegador padrao precisa estar configurado para usar\n"
                "o proxy 127.0.0.1:%s para que a interceptacao funcione." % (url, self.engine.port),
            )
        elif getattr(self.vbrowser, "last_open_confirmed", False):
            self.web_status.set("navegador virtual: ativo (console :%d)" % self.web.port)
        else:
            self.web_status.set("navegador virtual: nao confirmado (console :%d)" % self.web.port)
            messagebox.showwarning(
                APP_NAME,
                "Pedi para abrir o navegador virtual, mas nao confirmei a janela.\n\n"
                "Se nada apareceu, abra o console manualmente:\n%s\n\n"
                "Detalhe: %s" % (url, note),
            )

    # ------------------------------------------------------------- historico
    def _row_values(self, tx):
        return (
            tx.id, tx.method, "%s:%s" % (tx.host, tx.port), tx.path,
            tx.status_text(), tx.length if tx.length else "", tx.mime_text(), tx.started,
        )

    def _row_tag(self, tx):
        if tx.error:
            return "erro"
        if tx.holding:
            return "segura"
        if not tx.status:
            return "pend"
        if 200 <= tx.status < 300:
            return "ok"
        if 300 <= tx.status < 400:
            return "redir"
        if 400 <= tx.status < 500:
            return "warn"
        return "erro"

    def upsert_row(self, tx):
        item = self.rows.get(tx.id)
        values = self._row_values(tx)
        if item and self.tree.exists(item):
            self.tree.item(item, values=values, tags=(self._row_tag(tx),))
        else:
            item = self.tree.insert("", "end", values=values, tags=(self._row_tag(tx),))
            self.rows[tx.id] = item
            self.tree.see(item)
        self.counter.set("%d transacoes" % len(self.rows))

    def refresh_tree(self):
        needle = self.filter_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        with self.engine._lock:
            history = list(self.engine.history)
        self.rows.clear()
        for tx in history:
            blob = ("%s%s" % (tx.host, tx.path)).lower()
            if needle and needle not in blob:
                continue
            item = self.tree.insert("", "end", values=self._row_values(tx), tags=(self._row_tag(tx),))
            self.rows[tx.id] = item
        self.counter.set("%d transacoes" % len(self.rows))

    def selected_tx(self):
        sel = self.tree.selection()
        if not sel:
            return None
        values = self.tree.item(sel[0], "values")
        if not values:
            return None
        try:
            tx_id = int(values[0])
        except ValueError:
            return None
        with self.engine._lock:
            for tx in self.engine.history:
                if tx.id == tx_id:
                    return tx
        return None

    def open_detail(self, _event=None):
        tx = self.selected_tx()
        if not tx:
            return
        self.req_text.delete("1.0", "end")
        self.req_text.insert("1.0", H.pretty(tx.request_raw).replace("\r\n", "\n"))
        self.resp_text.delete("1.0", "end")
        if tx.error:
            self.resp_text.insert("1.0", "<erro: %s>" % tx.error)
        else:
            self.resp_text.insert("1.0", H.pretty(tx.response_raw).replace("\r\n", "\n"))
            body, ok = H.decode_body(tx.resp_headers, tx.resp_body)
            if body and ("text" in (tx.mime or "") or "json" in (tx.mime or "") or "xml" in (tx.mime or "")
                         or "javascript" in (tx.mime or "") or "form" in (tx.mime or "")):
                self.resp_text.insert("end", "\n\n===== CORPO DECODIFICADO =====\n" + body[:200000])

    def tree_menu(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        menu = self._menu(self.root)
        menu.add_command(label="Ver detalhes", command=self.open_detail)
        menu.add_command(label="Enviar para o Repeater", command=self.from_history)
        menu.add_command(label="Copiar URL", command=self.copy_url)
        menu.add_separator()
        menu.add_command(label="Limpar historico", command=self.clear_history)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def copy_url(self):
        tx = self.selected_tx()
        if tx:
            self.root.clipboard_clear()
            self.root.clipboard_append(tx.url)

    def from_history(self):
        tx = self.selected_tx()
        if not tx:
            messagebox.showinfo(APP_NAME, "Selecione uma transacao no historico.")
            return
        self.rp_host.set(tx.host)
        self.rp_port.set(str(tx.port))
        self.rp_scheme.set(tx.scheme)
        self.rp_req.delete("1.0", "end")
        self.rp_req.insert("1.0", H.pretty(tx.request_raw).replace("\r\n", "\n"))
        self.rp_resp.delete("1.0", "end")
        self.rp_resp.insert("1.0", H.pretty(tx.response_raw).replace("\r\n", "\n"))
        self.nb.select(2)

    # -------------------------------------------------------------- intercept
    def refresh_held_list(self):
        pending = list(self.engine.held_pending)
        tree = self.held_tree
        current = self.current_held
        current_serial = current.serial if current else None
        tree.delete(*tree.get_children())
        self.held_by_row.clear()
        groups = {}
        for held in pending:
            key = "%s:%s" % (held.tx.host, held.tx.port)
            groups.setdefault(key, []).append(held)
        target_iid = None
        for key in sorted(groups):
            items = groups[key]
            parent = tree.insert("", "end", text="%s  (%d)" % (key, len(items)),
                                 open=True, tags=("group",))
            for held in items:
                tx = held.tx
                kind = "REQ" if held.kind == "request" else "RESP"
                iid = tree.insert(parent, "end",
                                  values=(kind, tx.method, tx.path),
                                  tags=("req" if held.kind == "request" else "resp",))
                self.held_by_row[iid] = held
                if current_serial is not None and held.serial == current_serial:
                    target_iid = iid
        self.queue_label.configure(text="fila: %d" % len(pending))
        if target_iid is not None:
            # mantem a mesma mensagem selecionada SEM reescrever o editor:
            # a edicao em andamento do usuario nao e perdida a cada evento
            self._suppress_select = True
            tree.selection_set(target_iid)
            tree.focus(target_iid)
            self._suppress_select = False
            self.current_held = self.held_by_row[target_iid]
        else:
            first = tree.get_children()
            if first:
                child = tree.get_children(first[0])
                if child:
                    tree.selection_set(child[0])
                    self.on_held_select(None)
            else:
                self.current_held = None
                self.held_text.delete("1.0", "end")

    def on_held_select(self, _event):
        if getattr(self, "_suppress_select", False):
            return
        sel = self.held_tree.selection()
        if not sel:
            return
        held = self.held_by_row.get(sel[0])
        if not held:
            return
        self.current_held = held
        self.held_text.delete("1.0", "end")
        self.held_text.insert("1.0", H.pretty(held.raw).replace("\r\n", "\n"))

    def _consume_editor(self):
        if not self.current_held:
            return None
        raw = self.held_text.get("1.0", "end")
        raw = raw.replace("\r\n", "\n").replace("\n", "\r\n")
        self.current_held.raw = raw.encode("latin-1", "replace")
        return self.current_held

    def _on_f5(self, _event=None):
        if self.nb.index(self.nb.select()) == 1:  # aba Interceptar
            self.decide("forward")

    def _on_f6(self, _event=None):
        if self.nb.index(self.nb.select()) == 1:  # aba Interceptar
            self.decide("drop")

    def decide(self, action):
        held = self._consume_editor()
        if not held:
            messagebox.showinfo(APP_NAME, "Nenhuma mensagem selecionada.")
            return
        self.engine.decide(held, action)
        self.current_held = None
        self.held_text.delete("1.0", "end")
        self.refresh_held_list()

    def forward_all(self):
        for held in list(self.engine.held_pending):
            self.engine.decide(held, "forward")
        self.current_held = None
        self.held_text.delete("1.0", "end")
        self.refresh_held_list()

    # --------------------------------------------------------------- repeater
    def repeater_send(self):
        raw = self.rp_req.get("1.0", "end")
        raw = raw.replace("\r\n", "\n").replace("\n", "\r\n").encode("latin-1", "replace")
        host = self.rp_host.get().strip()
        if not host:
            first, headers, _ = H.parse_message(raw)
            host = H.get_header(headers, "Host") or ""
        port = self.rp_port.get().strip()
        scheme = self.rp_scheme.get()
        self.rp_resp.delete("1.0", "end")
        self.rp_resp.insert("1.0", "enviando...")

        def worker():
            response, error = self.engine.send_raw(
                raw,
                host_override=host,
                port_override=int(port) if port.isdigit() else None,
                scheme_override=scheme,
            )

            def apply():
                self.rp_resp.delete("1.0", "end")
                if error:
                    self.rp_resp.insert("1.0", "<erro: %s>" % error)
                else:
                    self.rp_resp.insert("1.0", H.pretty(response).replace("\r\n", "\n"))
            self._ui(apply)

        threading.Thread(target=worker, daemon=True).start()

    # ---------------------------------------------------------------- escopo
    def save_scope(self):
        count = self.engine.set_scope(self.scope_text.get("1.0", "end"))
        self.save_config()
        self.log("escopo salvo (%d padrao(oes) definido(s))" % count)
        messagebox.showinfo(APP_NAME, "Escopo atualizado: %d padrao(oes)." % count)

    # -------------------------------------------------------------------- CA
    def install_ca(self):
        if sys.platform != "win32":
            messagebox.showinfo(APP_NAME, "Instalacao automatica disponivel apenas no Windows.")
            return
        try:
            result = subprocess.run(
                ["certutil", "-user", "-addstore", "Root", self.ca.ca_crt_path],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode == 0:
                self.log("CA instalada no armazenamento do usuario.")
                messagebox.showinfo(APP_NAME, "Certificado da CA instalado com sucesso.")
            else:
                self.log("certutil: %s" % (result.stdout + result.stderr))
                messagebox.showwarning(
                    APP_NAME,
                    "Nao foi possivel instalar automaticamente.\n\n"
                    + (result.stdout + result.stderr)[:600]
                    + "\n\nInstale manualmente o arquivo:\n" + self.ca.ca_crt_path,
                )
        except Exception as exc:
            messagebox.showerror(APP_NAME, "Erro: %s" % exc)

    def export_ca(self):
        target = filedialog.asksaveasfilename(
            defaultextension=".pem", initialfile="derpsec-ca.pem",
            filetypes=[("PEM", "*.pem"), ("Todos", "*.*")],
        )
        if not target:
            return
        with open(target, "w", encoding="ascii") as fh:
            fh.write(self.ca.ca_pem())
        self.log("CA exportada para %s" % target)

    def open_path(self, path):
        try:
            os.startfile(path)
        except Exception as exc:
            self.log("nao foi possivel abrir %s: %s" % (path, exc))

    # ------------------------------------------------------------- ajuda
    def show_help(self):
        messagebox.showinfo(
            APP_NAME,
            "INTERCEPT WEB (navegador virtual)\n"
            "1) Clique em 'Intercept Web' na barra superior.\n"
            "2) O proxy sobe automaticamente e abre um navegador virtual\n"
            "   (Edge/Chrome em perfil isolado) com o console do DerpSec.\n"
            "3) Use a barra de endereco do console: cada site aberto passa\n"
            "   pelo proxy e aparece no Historico.\n"
            "4) Ligue 'Interceptar requisicoes/respostas' no console, edite\n"
            "   a mensagem na aba Interceptar e clique em Encaminhar.\n"
            "5) A aba Repeater reenvia requisicoes cruas quantas vezes quiser.\n\n"
            "Tudo roda na sua maquina, em 127.0.0.1. Nada sai dela.",
        )

    def show_about(self):
        messagebox.showinfo(
            APP_NAME,
            "%s v%s\n\nProxy de interceptacao HTTP/HTTPS local.\n"
            "Intercept Web: navegador virtual + console embutido.\n"
            "Projeto open source (licenca MIT).\n\n"
            "Tudo roda na sua maquina: nenhum dado sai dela." % (APP_NAME, VERSION),
        )

    def on_close(self):
        try:
            self.save_config()
        except Exception:
            pass
        # fecha o navegador virtual: sem isso a janela ficava viva com o
        # proxy antigo (o console morre junto com o app)
        try:
            fechados = self.vbrowser.close()
            if fechados:
                self.log("navegador virtual: %d processo(s) fechado(s)" % fechados)
        except Exception:
            pass
        try:
            self.web.stop()
        except Exception:
            pass
        try:
            self.engine.stop()
        except Exception:
            pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()
