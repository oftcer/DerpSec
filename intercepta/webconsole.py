"""Console web local do DerpSec (Intercept Web).

Sobe um servidor HTTP preso em 127.0.0.1 que serve a interface do
"Intercept Web": de um lado o site (navegador embutido) e do outro as
funcoes de interceptacao, e expoe o motor de proxy via JSON.

Seguranca:
  * bind somente em loopback;
  * valida o cabecalho Host (anti DNS-rebinding);
  * exige token aleatorio de sessao em todas as rotas de pagina e API
    (os assets estaticos - css/js/logo - sao publicos, sem dado sensivel).
"""
import json
import os
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import httpmsg as H

MAX_HISTORY = 800
MAX_LOG = 4000


# --------------------------------------------------------------------- recursos
def resource_path(rel):
    """Caminho de um recurso, funcionando tanto no codigo quanto no .exe."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        cand = os.path.join(base, rel)
        if os.path.exists(cand):
            return cand
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(here, rel)


def _read_logo():
    for rel in ("icon/logo.png", "logo.png"):
        path = resource_path(rel)
        if os.path.exists(path):
            try:
                with open(path, "rb") as fh:
                    return fh.read()
            except Exception:
                continue
    return None


# ------------------------------------------------------------------------- css
CSS = """
:root{
  --black:#000; --bg:#0e0f11; --bg2:#141518; --panel:#1b1d21; --panel2:#25282e;
  --border:#2f333a; --border2:#3c414a;
  --text:#f4f5f6; --muted:#9ba1a9; --dim:#6d727a;
  --ok:#7fd18b; --warn:#e3c07b; --err:#e28a8a; --redir:#8fb0e0;
  --mono:"Cascadia Mono","Consolas","SFMono-Regular",Menlo,monospace;
}
*{box-sizing:border-box}
html,body{height:100%}
body{
  margin:0; background:var(--bg); color:var(--text);
  font:13px/1.45 "Segoe UI",system-ui,sans-serif; overflow:hidden;
}
::-webkit-scrollbar{width:11px;height:11px}
::-webkit-scrollbar-track{background:#0c0d0f}
::-webkit-scrollbar-thumb{background:#31353c;border-radius:6px;border:2px solid #0c0d0f}
::-webkit-scrollbar-thumb:hover{background:#41464e}

/* ------------------------------------------------------------------ layout */
.app{height:100%;display:flex;flex-direction:column;min-height:0}
.work{flex:1 1 auto;min-height:0;display:flex;align-items:stretch}

/* ------------------------------------------------------------------ topbar */
header.top{
  display:flex;align-items:center;gap:12px;padding:8px 12px;flex:0 0 auto;
  background:linear-gradient(180deg,#1d1f24,#131518);border-bottom:1px solid var(--border);
}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.brand img{width:30px;height:30px;object-fit:contain;border-radius:8px;background:#000;
  border:1px solid var(--border2);padding:2px}
.brand .t{display:flex;flex-direction:column;line-height:1.15;min-width:0}
.brand .t b{font-size:15px;letter-spacing:.4px;white-space:nowrap}
.brand .t span{font-size:10.5px;color:var(--dim);letter-spacing:1.1px;text-transform:uppercase;white-space:nowrap}

.pills{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.pill{display:inline-flex;align-items:center;gap:6px;padding:4px 9px;border-radius:999px;
  background:var(--panel);border:1px solid var(--border);font-size:11.5px;color:var(--muted);white-space:nowrap}
.pill.on{color:var(--text);border-color:var(--border2);background:#2a2e34}
.dot{width:7px;height:7px;border-radius:50%;background:#5c6169;flex:0 0 auto}
.dot.live{background:var(--ok);box-shadow:0 0 8px rgba(127,209,139,.65)}
.dot.off{background:#5c6169}
.spacer{flex:1 1 auto}

button{
  background:var(--panel2);color:var(--text);border:1px solid var(--border2);
  border-radius:8px;padding:7px 12px;font-size:12.5px;cursor:pointer;
  transition:background .12s,border-color .12s,transform .04s;white-space:nowrap;
}
button:hover{background:#33373e;border-color:#4a5059}
button:active{transform:translateY(1px)}
button.primary{background:var(--text);color:#0b0b0b;border-color:var(--text);font-weight:600}
button.primary:hover{background:#fff}
button.danger:hover{background:#4a2b2b;border-color:#7d4444;color:#ffd9d9}
button.ghost{background:transparent}
button.icon{padding:6px 9px;font-size:13px;line-height:1;min-width:32px;text-align:center}
button:disabled{opacity:.45;cursor:default;transform:none}
input[type=text],select,textarea{
  background:#0b0c0e;border:1px solid var(--border2);color:var(--text);
  border-radius:7px;padding:7px 9px;font-size:12.5px;outline:none;font-family:inherit;
}
input[type=text]:focus,select:focus,textarea:focus{border-color:#5a616b}
label.chk{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;
  color:var(--muted);cursor:pointer;user-select:none;padding:4px 2px}
label.chk input{accent-color:var(--text);width:15px;height:15px}
label.chk:hover{color:var(--text)}

/* ------------------------------------------------------------- lado esquerdo */
.site{flex:0 0 58%;min-width:280px;display:flex;flex-direction:column;
  background:#0b0c0e;border-right:1px solid var(--border);min-height:0}
.chrome{display:flex;gap:6px;align-items:center;padding:8px 10px;flex-wrap:nowrap;
  background:linear-gradient(180deg,#1a1c20,#141619);border-bottom:1px solid var(--border)}
.chrome .addr{flex:1 1 auto;min-width:90px;font-family:var(--mono);font-size:12px}
.tabbar{display:flex;gap:4px;align-items:center;padding:5px 8px 0;background:#141619;
  border-bottom:1px solid var(--border);overflow-x:auto;flex:0 0 auto}
.btab{display:inline-flex;align-items:center;gap:8px;max-width:210px;padding:5px 9px;
  border:1px solid var(--border);border-bottom:none;border-radius:8px 8px 0 0;
  background:#191b1f;color:var(--muted);font-size:11.5px;cursor:pointer;white-space:nowrap}
.btab.active{background:#0b0c0e;color:var(--text);border-color:var(--border2)}
.btab .nm{overflow:hidden;text-overflow:ellipsis;max-width:140px}
.btab .x{opacity:.6;font-size:11px}
.btab .x:hover{opacity:1;color:#ffb0b0}
.frame{flex:1 1 auto;min-height:0;position:relative;background:#fff}
.frame iframe{position:absolute;inset:0;width:100%;height:100%;border:none;background:#fff}
.statusbar{display:flex;gap:10px;align-items:center;padding:5px 10px;flex:0 0 auto;
  background:#141619;border-top:1px solid var(--border);font-size:11px;color:var(--dim);
  font-family:var(--mono);white-space:nowrap;overflow:hidden}
.statusbar #siteUrl{overflow:hidden;text-overflow:ellipsis}

.gutter{flex:0 0 6px;cursor:col-resize;background:var(--bg2);position:relative;
  touch-action:none;user-select:none;-webkit-user-select:none}
.gutter::after{content:"";position:absolute;left:2px;top:0;bottom:0;width:2px;background:#33373e}
.gutter:hover::after{background:#5a616b}

/* -------------------------------------------------------------- lado direito */
.tools{flex:1 1 auto;min-width:280px;display:flex;flex-direction:column;min-height:0;background:var(--bg2)}
.tabs{display:flex;gap:2px;padding:0 8px;background:#131518;border-bottom:1px solid var(--border);
  flex:0 0 auto;overflow-x:auto}
.tab{padding:9px 14px;font-size:12.5px;color:var(--muted);cursor:pointer;
  border-bottom:2px solid transparent;white-space:nowrap;user-select:none}
.tab:hover{color:var(--text);background:#181a1e}
.tab.active{color:var(--text);border-bottom-color:var(--text);background:#171a1d}
.tab .badge{display:inline-block;margin-left:7px;min-width:18px;padding:0 5px;
  border-radius:999px;background:var(--text);color:#111;font-size:10.5px;font-weight:700;
  text-align:center;line-height:16px;vertical-align:1px}
.tab .badge.hidden{display:none}

main{flex:1 1 auto;min-height:0;position:relative}
section.view{position:absolute;inset:0;display:none;flex-direction:column;min-height:0}
section.view.active{display:flex}

.bar{display:flex;gap:8px;align-items:center;padding:8px 10px;flex-wrap:wrap;
  border-bottom:1px solid var(--border);background:#16181c;flex:0 0 auto}
.bar .grow{flex:1 1 auto}
.bar select{min-width:90px}

/* ------------------------------------------------------------- historico/grp */
.tablewrap{flex:1 1 auto;min-height:80px;overflow:auto;background:#121316}
.grp{border-bottom:1px solid #202226}
.grphead{display:flex;align-items:center;gap:9px;padding:7px 10px;cursor:pointer;
  background:linear-gradient(180deg,#1e2126,#191c20);position:sticky;top:0;z-index:2;
  border-bottom:1px solid var(--border)}
.grphead:hover{background:#22262b}
.caret{color:var(--muted);font-size:11px;width:12px;display:inline-block}
.grphead .ghost{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--text)}
.grphead .gmeta{font-size:11px;color:var(--dim)}
.gdot{width:8px;height:8px;border-radius:50%;flex:0 0 auto;box-shadow:0 0 6px rgba(0,0,0,.5)}
.gdot.ok{background:#3fb950}
.gdot.warn{background:#d29922}
.gdot.err{background:#f85149}
.gdot.hold{background:#f0c674}
.gdot.req{background:#58a6ff}
.gdot.resp{background:#3fb950}
.grp.closed .grpbody{display:none}

table{width:100%;border-collapse:collapse;font-size:12px}
thead th{position:sticky;top:0;background:#1b1d21;color:var(--muted);text-align:left;
  font-weight:600;font-size:10.5px;letter-spacing:.5px;text-transform:uppercase;
  padding:6px 9px;border-bottom:1px solid var(--border);white-space:nowrap;z-index:1}
tbody td{padding:5px 9px;border-bottom:1px solid #1d1f23;white-space:nowrap;
  overflow:hidden;text-overflow:ellipsis;max-width:420px;font-family:var(--mono);font-size:11.5px}
tbody tr{cursor:pointer}
tbody tr:hover{background:#212429}
tbody tr.sel{background:#2b3037}
td.st-2xx{color:var(--ok)} td.st-3xx{color:var(--redir)}
td.st-4xx{color:var(--warn)} td.st-5xx{color:var(--err)} td.st-err{color:var(--err)}
td.st-hold{color:#f0c674}
td.m{color:#e2e6ea;font-weight:600}
td.p{color:var(--muted)}
.empty{padding:26px;text-align:center;color:var(--dim);font-size:12.5px}

.detail{flex:0 0 auto;height:46%;min-height:150px;display:flex;
  border-top:1px solid var(--border);background:#101113}
.detail.hidden{display:none}
.pane{flex:1 1 50%;min-width:0;display:flex;flex-direction:column;border-right:1px solid var(--border)}
.pane:last-child{border-right:none}
.pane h4{margin:0;padding:6px 10px;font-size:10.5px;letter-spacing:.7px;text-transform:uppercase;
  color:var(--muted);background:#17191d;border-bottom:1px solid var(--border);font-weight:600;
  display:flex;align-items:center;gap:8px}
.pane h4 .grow{flex:1 1 auto}
.pane pre{margin:0;padding:9px 11px;overflow:auto;flex:1 1 auto;font-family:var(--mono);
  font-size:11.5px;white-space:pre-wrap;word-break:break-word;color:#dfe3e7}
.paneTabs{display:flex;gap:2px}
.paneTabs span{padding:3px 8px;font-size:11px;color:var(--muted);cursor:pointer;border-radius:6px}
.paneTabs span.active{background:#2a2e34;color:var(--text)}

/* ------------------------------------------------------------- intercept */
.heldwrap{flex:1 1 auto;min-height:0;display:flex}
.heldlist{flex:0 0 320px;min-width:200px;overflow:auto;background:#121316;
  border-right:1px solid var(--border)}
.heldgrp{border-bottom:1px solid #202226}
.heldgrphead{display:flex;align-items:center;gap:8px;padding:7px 10px;cursor:pointer;
  background:linear-gradient(180deg,#1e2126,#191c20);position:sticky;top:0;z-index:2;
  border-bottom:1px solid var(--border)}
.heldgrphead:hover{background:#22262b}
.heldgrphead .ghost{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--text)}
.heldgrphead .gmeta{font-size:11px;color:var(--dim)}
.heldgrp.closed .heldgrpbody{display:none}
.helditem{display:flex;align-items:center;gap:7px;padding:7px 10px 7px 22px;
  border-bottom:1px solid #1d1f23;cursor:pointer;font-size:12px}
.helditem:hover{background:#212429}
.helditem.sel{background:#2b3037;border-left:3px solid var(--text);padding-left:19px}
.helditem .k{display:inline-block;padding:1px 6px;border-radius:5px;font-size:10px;
  font-weight:700;letter-spacing:.5px;background:#3a3f47;color:#fff;flex:0 0 auto}
.helditem .k.req{background:#2f4a33;color:#cdeed3}
.helditem .k.resp{background:#2f3c52;color:#cfdcf5}
.helditem .m{display:inline-block;padding:1px 6px;border-radius:5px;font-size:10px;
  font-weight:700;background:#3a3f47;color:#e2e6ea;flex:0 0 auto}
.helditem .h{color:var(--muted);font-family:var(--mono);font-size:11px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1 1 auto}
.heldedit{flex:1 1 auto;min-width:0;display:flex;flex-direction:column}
.heldedit textarea{flex:1 1 auto;border-radius:0;border:none;border-top:1px solid var(--border);
  padding:11px;font-family:var(--mono);font-size:12px;resize:none;white-space:pre;
  overflow:auto;background:#0b0c0e;color:#e6e8ea}

/* --------------------------------------------------------------- repeater */
.rp{flex:1 1 auto;min-height:0;display:flex}
.rp .pane{flex:1 1 50%}
.rp textarea{flex:1 1 auto;border-radius:0;border:none;padding:11px;font-family:var(--mono);
  font-size:12px;resize:none;white-space:pre;overflow:auto;background:#0b0c0e;color:#e6e8ea}

/* ----------------------------------------------------------------- scope */
.scope{flex:1 1 auto;min-height:0;display:flex;flex-direction:column;padding:12px}
.scope textarea{flex:1 1 auto;font-family:var(--mono);font-size:12.5px;resize:none;
  white-space:pre;background:#0b0c0e;color:#e6e8ea}
.hint{color:var(--muted);font-size:12px;margin:0 0 10px;line-height:1.5}

/* ------------------------------------------------------------------- log */
.logbox{flex:1 1 auto;min-height:0;overflow:auto;margin:0;padding:11px 13px;
  font-family:var(--mono);font-size:11.5px;white-space:pre-wrap;word-break:break-word;
  color:#c9ced4;background:#0b0c0e}
.logbox i{color:var(--dim);font-style:normal}

/* ------------------------------------------------------------------ misc */
.toast{position:fixed;right:16px;bottom:16px;background:var(--text);color:#111;
  padding:10px 15px;border-radius:9px;font-size:12.5px;font-weight:600;opacity:0;
  transform:translateY(8px);transition:.18s;pointer-events:none;z-index:50;
  box-shadow:0 12px 30px rgba(0,0,0,.5)}
.toast.show{opacity:1;transform:translateY(0)}
.toast.err{background:#e28a8a}
"""

# -------------------------------------------------------------------------- js
JS = r"""
(function(){
  "use strict";
  var TOKEN = window.__DERPSEC_TOKEN__;
  var $ = function(s, r){ return (r||document).querySelector(s); };
  var $$ = function(s, r){ return Array.prototype.slice.call((r||document).querySelectorAll(s)); };

  var currentTx = null, heldSel = null, heldData = [], heldEdit = null, heldCollapsed = {};
  var tabCur = "history";
  var histItems = [], histSel = null, collapsed = {}, groupByHost = true;
  var navLock = 0;

  /* ---------------------------------------------------------------- utils */
  function esc(s){
    return String(s == null ? "" : s)
      .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
      .replace(/"/g,"&quot;");
  }
  function toast(msg, isErr){
    var t = $("#toast");
    t.textContent = msg; t.className = "toast show" + (isErr ? " err" : "");
    clearTimeout(t._t); t._t = setTimeout(function(){ t.className = "toast"; }, 2200);
  }
  function api(path, opts){
    opts = opts || {};
    opts.headers = Object.assign({"X-DerpSec-Token": TOKEN}, opts.headers || {});
    if (opts.body && typeof opts.body !== "string") {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    return fetch(path, opts).then(function(r){
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r.json();
    });
  }
  function fmtSize(n){
    if (n == null || n === 0) return "";
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n/1024).toFixed(1) + " KB";
    return (n/1048576).toFixed(2) + " MB";
  }
  function statusClass(tx){
    if (tx.error) return "st-err";
    if (tx.status_text === "segura") return "st-hold";
    var s = tx.status || 0;
    if (s >= 500) return "st-5xx";
    if (s >= 400) return "st-4xx";
    if (s >= 300) return "st-3xx";
    if (s >= 200) return "st-2xx";
    return "";
  }

  /* ============================================================ navegador */
  var tabs = [], tabActive = 0, tabSeq = 1;

  function newTab(url){
    tabs.push({id: tabSeq++, stack: [], idx: -1, url: url || "derpsec:home"});
    tabActive = tabs.length - 1;
    return tabs[tabActive];
  }
  function curTab(){ return tabs[tabActive] || newTab(); }
  function prettyName(u){
    if (!u || u === "derpsec:home") return "Inicio";
    try { var x = new URL(u); return (x.host || u) + (x.pathname !== "/" ? x.pathname : ""); }
    catch(e){ return u; }
  }
  function hostOf(u){
    try { return new URL(u).hostname; } catch(e){ return ""; }
  }
  function renderTabs(){
    var bar = $("#tabbar");
    bar.innerHTML = "";
    tabs.forEach(function(t, i){
      var b = document.createElement("div");
      b.className = "btab" + (i === tabActive ? " active" : "");
      b.title = t.url;
      b.innerHTML = '<span class="nm">' + esc(prettyName(t.url)) + '</span>';
      var x = document.createElement("span");
      x.className = "x"; x.textContent = "x"; x.title = "Fechar aba";
      x.addEventListener("click", function(ev){
        ev.stopPropagation();
        if (tabs.length === 1) { toast("mantenha ao menos uma aba"); return; }
        tabs.splice(i, 1);
        if (tabActive >= tabs.length) tabActive = tabs.length - 1;
        activateTab(tabActive);
      });
      b.appendChild(x);
      b.addEventListener("click", function(){ activateTab(i); });
      bar.appendChild(b);
    });
    var plus = document.createElement("button");
    plus.className = "icon ghost"; plus.textContent = "+"; plus.title = "Nova aba";
    plus.addEventListener("click", function(){ newTab("derpsec:home"); goHome(); });
    bar.appendChild(plus);
  }
  function activateTab(i){
    tabActive = i;
    var t = curTab();
    renderTabs();
    if (t.url === "derpsec:home") goHome(true); else showUrl(t.url);
  }
  function goHome(silent){
    var t = curTab(), f = $("#site");
    f.removeAttribute("src");
    f.srcdoc = $("#homeTpl").innerHTML;
    t.url = "derpsec:home";
    $("#addr").value = "";
    $("#siteUrl").textContent = "derpsec:inicio";
    renderTabs();
    if (!silent) toast("pagina inicial do Intercept Web");
  }
  function normUrl(raw){
    var u = (raw || "").trim();
    if (!u) return null;
    if (u === "derpsec:home" || u === "about:blank") return u;
    if (!/^[a-z][a-z0-9+.\-]*:/i.test(u)) u = "http://" + u;
    return u;
  }
  function pushUrl(t, u){
    if (t.stack[t.idx] === u) return;
    t.stack = t.stack.slice(0, t.idx + 1);
    t.stack.push(u);
    t.idx = t.stack.length - 1;
  }
  function showUrl(u){
    var t = curTab(), f = $("#site");
    if (u === "derpsec:home") { goHome(true); return; }
    navLock = Date.now() + 700;
    f.removeAttribute("srcdoc");
    f.src = u;
    t.url = u;
    $("#addr").value = u;
    $("#siteUrl").textContent = u;
    renderTabs();
  }
  function updateUrl(t, u){
    /* sincroniza barra/aba SEM recarregar o iframe (evita loop de navegacao) */
    if (!u || u === t.url) return;
    t.url = u;
    $("#addr").value = u;
    $("#siteUrl").textContent = u;
    renderTabs();
  }
  function navigate(raw, push){
    var u = normUrl(raw);
    if (!u) return;
    var t = curTab();
    if (push !== false) pushUrl(t, u);
    showUrl(u);
  }
  function historyStep(delta){
    var t = curTab();
    var next = t.idx + delta;
    if (next < 0 || next >= t.stack.length) { toast("sem historico nesta direcao"); return; }
    t.idx = next;
    showUrl(t.stack[t.idx]);
  }

  $("#btnBack").addEventListener("click", function(){ historyStep(-1); });
  $("#btnFwd").addEventListener("click", function(){ historyStep(1); });
  $("#btnReload").addEventListener("click", function(){
    var t = curTab();
    if (t.url === "derpsec:home") goHome(true); else showUrl(t.url);
  });
  $("#btnHome").addEventListener("click", function(){ goHome(); });
  $("#btnGo").addEventListener("click", function(){ navigate($("#addr").value, true); });
  $("#addr").addEventListener("keydown", function(ev){
    if (ev.key === "Enter") { ev.preventDefault(); navigate($("#addr").value, true); }
  });
  $("#btnNewTab").addEventListener("click", function(){ newTab("derpsec:home"); goHome(); });

  /* navegacao real dentro do iframe (reportada pelo script injetado):
     atualiza a barra/aba sem mexer no src do iframe */
  window.addEventListener("message", function(ev){
    var d = ev.data;
    if (!d || typeof d !== "object" || !d.__derpsec_nav) return;
    var u = normUrl(d.__derpsec_nav);
    if (!u) return;
    var t = curTab();
    if (u !== t.url) { pushUrl(t, u); updateUrl(t, u); }
  });

  /* divisor arrastavel entre site e ferramentas.
     Usa Pointer Events + setPointerCapture: o divisor recebe todos os eventos
     do ponteiro mesmo passando por cima do iframe do site. Com mousedown/
     mousemove soltos (versao antiga) o iframe engolia o mouseup e o divisor
     continuava seguindo o mouse para sempre, com o texto travado sem selecao. */
  (function(){
    var gutter = $("#gutter"), site = $("#sitePane");
    var MIN = 22, MAX = 78, drag = false;

    function clamp(v){ return Math.min(MAX, Math.max(MIN, v)); }

    try {
      var saved = parseFloat(localStorage.getItem("derpsec.split"));
      if (isFinite(saved)) site.style.flexBasis = clamp(saved) + "%";
      else localStorage.removeItem("derpsec.split");
    } catch(e){}

    function stop(ev){
      if (!drag) return;
      drag = false;
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
      try { gutter.releasePointerCapture(ev && ev.pointerId); } catch(e){}
      var pct = parseFloat(site.style.flexBasis);
      try {
        if (isFinite(pct)) localStorage.setItem("derpsec.split", String(clamp(pct)));
        else localStorage.removeItem("derpsec.split");
      } catch(e){}
    }

    gutter.addEventListener("pointerdown", function(ev){
      if (ev.button && ev.button !== 0) return;
      drag = true;
      document.body.style.userSelect = "none";
      document.body.style.cursor = "col-resize";
      try { gutter.setPointerCapture(ev.pointerId); } catch(e){}
      ev.preventDefault();
    });

    gutter.addEventListener("pointermove", function(ev){
      if (!drag) return;
      var w = window.innerWidth || 1200;
      if (w > 0) site.style.flexBasis = clamp((ev.clientX / w) * 100) + "%";
      ev.preventDefault();
    });

    /* fim do arrasto: soltar, cancelar, perder a captura ou a janela perder
       o foco (evita o divisor ficar preso ao mouse) */
    gutter.addEventListener("pointerup", stop);
    gutter.addEventListener("pointercancel", stop);
    gutter.addEventListener("lostpointercapture", stop);
    window.addEventListener("blur", function(){ stop(null); });
    document.addEventListener("visibilitychange", function(){
      if (document.hidden) stop(null);
    });
  })();

  /* -------------------------------------------------------------- abas */
  $$(".tab").forEach(function(el){
    el.addEventListener("click", function(){
      $$(".tab").forEach(function(x){ x.classList.remove("active"); });
      $$("section.view").forEach(function(x){ x.classList.remove("active"); });
      el.classList.add("active");
      $("#view-" + el.dataset.view).classList.add("active");
      tabCur = el.dataset.view;
      if (tabCur === "history") loadHistory();
      if (tabCur === "intercept") loadHeld();
      if (tabCur === "log") loadLog();
      if (tabCur === "scope") loadScope();
    });
  });

  /* ------------------------------------------------------------- estado */
  function renderState(s){
    var live = s.running;
    $("#stProxy").className = "pill" + (live ? " on" : "");
    $("#stProxyDot").className = "dot " + (live ? "live" : "off");
    $("#stProxyText").textContent = live ? ("proxy ON :" + s.port) : "proxy OFF";
    $("#stUnframe").className = "pill" + (s.unframe ? " on" : "");
    $("#stUnframeText").textContent = s.unframe ? "embutir sites ON" : "embutir sites OFF";
    $("#irReq").checked = !!s.intercept_requests;
    $("#irResp").checked = !!s.intercept_responses;
    $("#onlyScope").checked = !!s.in_scope_only;
    $("#unframe").checked = !!s.unframe;
    $("#filterTel").checked = !!s.filter_telemetry;
    $("#txCount").textContent = s.tx_count + (s.tx_count === 1 ? " transacao" : " transacoes");
    $("#btnProxy").textContent = live ? "Parar proxy" : "Iniciar proxy";
    var badge = $("#heldBadge"), n = s.held_count;
    badge.textContent = n;
    badge.className = "badge" + (n ? "" : " hidden");
    $("#qlabel").textContent = "fila: " + n;

    /* a barra de endereco so acompanha navegacoes reais reportadas pelo
       script injetado (NAV_REPORTER) via postMessage; telemetria e ruido
       nao movem a barra nem as abas. */
  }
  function refreshState(){ return api("/api/state").then(renderState).catch(function(){}); }

  /* ------------------------------------------------------------ historico */
  function tableHTML(items, withHost){
    var cols = (withHost ? 7 : 6);
    var html = "<table><thead><tr>";
    html += "<th>Metodo</th>" + (withHost ? "<th>Host</th>" : "") +
            "<th>Caminho</th><th>Status</th><th>Tamanho</th><th>Tipo</th><th>Hora</th>";
    html += "</tr></thead><tbody>";
    items.forEach(function(tx){
      html += '<tr data-id="' + tx.id + '" class="' + (tx.id === histSel ? "sel" : "") + '">' +
        '<td class="m">' + esc(tx.method) + "</td>" +
        (withHost ? "<td>" + esc(tx.host + ":" + tx.port) + "</td>" : "") +
        '<td class="p">' + esc(tx.path) + "</td>" +
        '<td class="' + statusClass(tx) + '">' + esc(tx.status_text) + "</td>" +
        "<td>" + esc(fmtSize(tx.length)) + "</td>" +
        "<td>" + esc(tx.mime) + "</td>" +
        "<td>" + esc(tx.started) + "</td>" +
        "</tr>";
    });
    return html + "</tbody></table>";
  }
  function bindRows(root){
    $$("tbody tr[data-id]", root).forEach(function(tr){
      tr.addEventListener("click", function(){
        histSel = parseInt(tr.dataset.id, 10);
        $$("tbody tr", root).forEach(function(x){ x.classList.remove("sel"); });
        tr.classList.add("sel");
        openTx(histSel);
      });
    });
  }
  function loadHistory(){
    var q = ($("#filter").value || "").trim();
    return api("/api/history?q=" + encodeURIComponent(q)).then(function(data){
      histItems = data.items || [];
      renderHistory();
      $("#histCount").textContent = histItems.length +
        (histItems.length === 1 ? " requisicao" : " requisicoes");
    }).catch(function(){});
  }
  function renderHistory(){
    var wrap = $("#histWrap");
    if (!histItems.length) {
      wrap.innerHTML = '<div class="empty">Nenhuma transacao ainda.<br>' +
        'Digite um endereco na barra a esquerda e navegue: as requisicoes passam pelo proxy.</div>';
      return;
    }
    if (!groupByHost) {
      wrap.innerHTML = '<div class="grp">' + tableHTML(histItems, true) + "</div>";
      bindRows(wrap);
      return;
    }
    var groups = {}, order = [];
    histItems.forEach(function(tx){
      var k = tx.host + ":" + tx.port;
      if (!groups[k]) { groups[k] = []; order.push(k); }
      groups[k].push(tx);
    });
    var html = "";
    order.forEach(function(k){
      var g = groups[k], codes = {}, errs = 0;
      g.forEach(function(tx){
        if (tx.error) { errs++; return; }
        var c = tx.status ? (Math.floor(tx.status / 100) + "xx") : "pendente";
        codes[c] = (codes[c] || 0) + 1;
      });
      var meta = [];
      Object.keys(codes).sort().forEach(function(c){ meta.push(codes[c] + " " + c); });
      if (errs) meta.push(errs + (errs === 1 ? " erro" : " erros"));
      var dot = "ok";
      if (errs || codes["5xx"]) dot = "err";
      else if (codes["4xx"]) dot = "warn";
      else if (codes["pendente"]) dot = "hold";
      var open = !collapsed[k];
      html += '<div class="grp' + (open ? "" : " closed") + '" data-k="' + esc(k) + '">' +
        '<div class="grphead"><span class="caret">' + (open ? "\u25BE" : "\u25B8") + "</span>" +
        '<span class="gdot ' + dot + '"></span>' +
        '<span class="ghost">' + esc(k) + "</span>" +
        '<span class="gmeta">' + g.length + (g.length === 1 ? " requisicao" : " requisicoes") +
        (meta.length ? " \u00b7 " + esc(meta.join(" \u00b7 ")) : "") + "</span></div>" +
        '<div class="grpbody">' + tableHTML(g, false) + "</div></div>";
    });
    wrap.innerHTML = html;
    $$(".grphead", wrap).forEach(function(h){
      h.addEventListener("click", function(){
        var grp = h.parentNode, k = grp.dataset.k;
        collapsed[k] = !collapsed[k];
        grp.classList.toggle("closed");
        $(".caret", h).textContent = collapsed[k] ? "\u25B8" : "\u25BE";
      });
    });
    bindRows(wrap);
  }
  function openTx(id){
    api("/api/tx?id=" + id).then(function(tx){
      currentTx = tx;
      $("#detail").classList.remove("hidden");
      $("#detailTitle").textContent = (tx.method || "") + " " + (tx.path || "") +
        "  \u00b7  " + (tx.status_text || "");
      $("#reqPretty").textContent = tx.request_pretty || "";
      $("#respPretty").textContent = tx.response_pretty || "";
      $("#respBody").textContent = tx.decoded || "(sem corpo textual)";
      setPaneTab("resp", "raw");
      $("#btnRepeater").disabled = false;
    }).catch(function(){ toast("nao foi possivel abrir a transacao", true); });
  }
  function setPaneTab(which, mode){
    var wrap = which === "resp" ? $("#respTabs") : $("#reqTabs");
    $$("span", wrap).forEach(function(s){
      s.classList.toggle("active", s.dataset.mode === mode);
    });
    if (which === "resp") {
      $("#respPretty").style.display = (mode === "raw") ? "" : "none";
      $("#respBody").style.display = (mode === "raw") ? "none" : "";
    }
  }
  $$("#respTabs span").forEach(function(s){
    s.addEventListener("click", function(){ setPaneTab("resp", s.dataset.mode); });
  });
  $("#filter").addEventListener("input", function(){ loadHistory(); });
  $("#groupChk").addEventListener("change", function(){
    groupByHost = $("#groupChk").checked; renderHistory();
  });
  $("#btnClear").addEventListener("click", function(){
    api("/api/clear", {method:"POST"}).then(function(){
      histItems = []; histSel = null; currentTx = null;
      $("#detail").classList.add("hidden");
      renderHistory(); refreshState();
    }).catch(function(){});
  });
  $("#btnRepeater").addEventListener("click", function(){
    if (!currentTx) return;
    $("#rpRaw").value = ($("#reqPretty").textContent || "");
    tabOpen("repeater");
  });

  /* ------------------------------------------------------------ intercept */
  function loadHeld(){
    return api("/api/held").then(function(data){
      heldData = data.items || [];
      if (heldSel && !heldData.some(function(h){ return h.id === heldSel; })) heldSel = null;
      renderHeld();
    }).catch(function(){});
  }
  function renderHeld(){
    var list = $("#heldList");
    if (!heldData.length) {
      list.innerHTML = '<div class="empty">Fila vazia.<br>Ligue "Interceptar requisicoes" e navegue.</div>';
      $("#heldEdit").value = "";
      $("#heldActions").style.visibility = "hidden";
      return;
    }
    if (!heldSel) heldSel = heldData[0].id;
    list.innerHTML = "";
    var groups = {}, order = [];
    heldData.forEach(function(h){
      var k = h.host + ":" + (h.port || "");
      if (!groups[k]) { groups[k] = []; order.push(k); }
      groups[k].push(h);
    });
    order.forEach(function(k){
      var g = groups[k];
      var open = !heldCollapsed[k];
      var grp = document.createElement("div");
      grp.className = "heldgrp" + (open ? "" : " closed");
      grp.dataset.k = k;
      var head = document.createElement("div");
      head.className = "heldgrphead";
      var hasReq = g.some(function(h){ return h.kind === "request"; });
      head.innerHTML = '<span class="caret">' + (open ? "\u25BE" : "\u25B8") + "</span>" +
        '<span class="gdot ' + (hasReq ? "req" : "resp") + '"></span>' +
        '<span class="ghost">' + esc(k) + "</span>" +
        '<span class="gmeta">' + g.length + (g.length === 1 ? " mensagem" : " mensagens") + "</span>";
      head.addEventListener("click", function(){
        heldCollapsed[k] = !heldCollapsed[k];
        grp.classList.toggle("closed");
        $(".caret", head).textContent = heldCollapsed[k] ? "\u25B8" : "\u25BE";
      });
      grp.appendChild(head);
      var body = document.createElement("div");
      body.className = "heldgrpbody";
      g.forEach(function(h){
        var d = document.createElement("div");
        d.className = "helditem" + (h.id === heldSel ? " sel" : "");
        d.innerHTML = '<span class="k ' + (h.kind === "request" ? "req" : "resp") + '">' +
          esc(h.kind === "request" ? "REQ" : "RESP") + "</span>" +
          '<span class="m">' + esc(h.method) + "</span>" +
          '<span class="h">' + esc(h.path) + "</span>";
        d.addEventListener("click", function(){ heldSel = h.id; renderHeld(); });
        body.appendChild(d);
      });
      grp.appendChild(body);
      list.appendChild(grp);
    });
    var cur = heldData.filter(function(h){ return h.id === heldSel; })[0];
    if (cur && (heldEdit === null || heldEdit !== heldSel)) {
      $("#heldEdit").value = cur.raw || "";
      heldEdit = heldSel;
    }
    $("#heldActions").style.visibility = "visible";
  }
  function decide(action){
    if (!heldSel) return;
    api("/api/held", {method:"POST", body:{id: heldSel, action: action,
      raw: $("#heldEdit").value}}).then(function(){
      heldEdit = null; heldSel = null;
      toast(action === "drop" ? "mensagem descartada" : "mensagem encaminhada");
      loadHeld(); refreshState(); loadHistory();
    }).catch(function(){ toast("falha ao aplicar a decisao", true); });
  }
  $("#btnForward").addEventListener("click", function(){ decide("forward"); });
  $("#btnDrop").addEventListener("click", function(){ decide("drop"); });
  $("#heldEdit").addEventListener("keydown", function(e){
    if ((e.ctrlKey && e.key === "Enter") || e.key === "F5") {
      e.preventDefault(); decide("forward");
    }
  });
  $("#btnForwardAll").addEventListener("click", function(){
    api("/api/held", {method:"POST", body:{action:"forward_all"}}).then(function(r){
      toast("encaminhadas: " + (r.count || 0)); loadHeld(); refreshState();
    }).catch(function(){});
  });

  /* flags */
  function pushFlags(){
    api("/api/flags", {method:"POST", body:{
      intercept_requests: $("#irReq").checked,
      intercept_responses: $("#irResp").checked,
      in_scope_only: $("#onlyScope").checked,
      unframe: $("#unframe").checked,
      filter_telemetry: $("#filterTel").checked,
    }}).then(function(){ refreshState(); loadHistory(); }).catch(function(){});
  }
  ["irReq", "irResp", "onlyScope", "unframe", "filterTel"].forEach(function(id){
    $("#" + id).addEventListener("change", pushFlags);
  });

  /* -------------------------------------------------------------- repeater */
  $("#btnRpSend").addEventListener("click", function(){
    var raw = $("#rpRaw").value;
    if (!raw.trim()) { toast("escreva a requisicao crua", true); return; }
    $("#rpResp").value = "enviando...";
    api("/api/repeater", {method:"POST", body:{
      raw: raw,
      host: $("#rpHost").value.trim() || null,
      port: $("#rpPort").value.trim() || null,
      scheme: $("#rpScheme").value || null,
    }}).then(function(r){
      $("#rpResp").value = r.error ? ("ERRO: " + r.error) : (r.response || "");
    }).catch(function(e){ $("#rpResp").value = "falha: " + e; });
  });

  /* ----------------------------------------------------------------- scope */
  function loadScope(){
    return api("/api/scope").then(function(d){ $("#scopeText").value = d.scope || ""; })
      .catch(function(){});
  }
  $("#btnScopeSave").addEventListener("click", function(){
    api("/api/scope", {method:"POST", body:{scope: $("#scopeText").value}}).then(function(r){
      toast("escopo salvo (" + (r.count || 0) + " padroes)");
    }).catch(function(){});
  });

  /* ------------------------------------------------------------------- log */
  function loadLog(){
    return api("/api/log").then(function(d){
      var box = $("#logBox");
      var atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 20;
      box.textContent = (d.lines || []).join("\n");
      if (atBottom) box.scrollTop = box.scrollHeight;
    }).catch(function(){});
  }
  $("#btnLogClear").addEventListener("click", function(){
    api("/api/log", {method:"POST"}).then(function(){ loadLog(); }).catch(function(){});
  });

  /* ------------------------------------------------------------ proxy btn */
  $("#btnProxy").addEventListener("click", function(){
    var live = $("#stProxy").classList.contains("on");
    api("/api/proxy", {method:"POST", body:{action: live ? "stop" : "start"}})
      .then(function(r){ toast(r.message || "ok", !r.ok); refreshState(); })
      .catch(function(){ toast("falha ao mudar o proxy", true); });
  });

  /* --------------------------------------------------------------- helpers */
  function tabOpen(name){
    var el = $$(".tab").filter(function(t){ return t.dataset.view === name; })[0];
    if (el) el.click();
  }
  $("#btnOpenLog").addEventListener("click", function(){ tabOpen("log"); });
  $("#btnOpenScope").addEventListener("click", function(){ tabOpen("scope"); });

  /* --------------------------------------------------------------- inicial */
  newTab("derpsec:home");
  renderTabs();
  goHome(true);
  refreshState();
  loadHistory();
  setInterval(refreshState, 1200);
  setInterval(function(){ if (tabCur === "history") loadHistory(); }, 1600);
  setInterval(function(){ if (tabCur === "intercept") loadHeld(); }, 1200);
  setInterval(function(){ if (tabCur === "log") loadLog(); }, 2200);
})();
"""

# ----------------------------------------------------------------------- html
HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>DerpSec - Intercept Web</title>
<link rel="icon" href="/assets/logo.png">
<link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<script>window.__DERPSEC_TOKEN__ = "{{TOKEN}}";</script>

<div class="app">
  <header class="top">
    <div class="brand">
      <img src="/assets/logo.png" alt="DerpSec">
      <div class="t"><b>DerpSec</b><span>Intercept Web</span></div>
    </div>
    <div class="pills">
      <span class="pill" id="stProxy"><span class="dot off" id="stProxyDot"></span>
        <span id="stProxyText">proxy OFF</span></span>
      <span class="pill" id="stUnframe"><span id="stUnframeText">embutir sites ON</span></span>
      <span class="pill" id="txCount">0 transacoes</span>
      <span class="pill on" id="qlabel">fila: 0</span>
    </div>
    <div class="spacer"></div>
    <button id="btnOpenLog" class="ghost">Log</button>
    <button id="btnOpenScope" class="ghost">Escopo</button>
    <button id="btnClear" class="ghost">Limpar historico</button>
    <button id="btnProxy">Iniciar proxy</button>
  </header>

  <div class="work">
    <!-- ------------------------------------------------ lado do site -->
    <section class="site" id="sitePane">
      <div class="chrome">
        <button class="icon" id="btnBack" title="Voltar">&#9664;</button>
        <button class="icon" id="btnFwd" title="Avancar">&#9654;</button>
        <button class="icon" id="btnReload" title="Recarregar">&#10227;</button>
        <button class="icon" id="btnHome" title="Pagina inicial">&#8962;</button>
        <input type="text" class="addr" id="addr" spellcheck="false"
               placeholder="digite um endereco (ex.: https://example.com)">
        <button class="primary" id="btnGo">Ir</button>
        <button class="icon" id="btnNewTab" title="Nova aba">+</button>
      </div>
      <div class="tabbar" id="tabbar"></div>
      <div class="frame"><iframe id="site" title="Site" src="about:blank"
  sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-modals allow-downloads allow-pointer-lock"></iframe></div>
      <div class="statusbar">
        <span id="siteUrl">derpsec:inicio</span>
        <span class="spacer"></span>
        <span id="siteInfo">trafego deste painel passa pelo proxy local</span>
      </div>
    </section>

    <div class="gutter" id="gutter" title="Arraste para redimensionar"></div>

    <!-- ------------------------------------------ lado das funcoes -->
    <aside class="tools">
      <div class="tabs">
        <div class="tab active" data-view="history">Historico</div>
        <div class="tab" data-view="intercept">Interceptar<span class="badge hidden" id="heldBadge">0</span></div>
        <div class="tab" data-view="repeater">Repeater</div>
        <div class="tab" data-view="scope">Escopo</div>
        <div class="tab" data-view="log">Log</div>
      </div>

      <main>
        <!-- --------------------------------------------- historico -->
        <section class="view active" id="view-history">
          <div class="bar">
            <input type="text" id="filter" placeholder="filtrar por host ou caminho" style="flex:1 1 160px">
            <label class="chk"><input type="checkbox" id="groupChk" checked> agrupar por host</label>
            <span class="pill" id="histCount">0 requisicoes</span>
          </div>
          <div class="tablewrap" id="histWrap"></div>
          <div class="detail hidden" id="detail">
            <div class="pane">
              <h4><span class="grow">Requisicao</span><span id="detailTitle" class="p"></span></h4>
              <pre id="reqPretty"></pre>
            </div>
            <div class="pane">
              <h4><span class="grow">Resposta</span>
                <span class="paneTabs" id="respTabs">
                  <span data-mode="raw" class="active">Bruto</span>
                  <span data-mode="body">Corpo</span>
                </span>
                <button class="ghost" id="btnRepeater" disabled>Enviar ao Repeater</button>
              </h4>
              <pre id="respPretty"></pre>
              <pre id="respBody" style="display:none"></pre>
            </div>
          </div>
        </section>

        <!-- -------------------------------------------- interceptar -->
        <section class="view" id="view-intercept">
          <div class="bar">
            <label class="chk"><input type="checkbox" id="irReq"> Interceptar requisicoes</label>
            <label class="chk"><input type="checkbox" id="irResp"> Interceptar respostas</label>
            <label class="chk"><input type="checkbox" id="onlyScope"> Somente no escopo</label>
            <label class="chk"><input type="checkbox" id="unframe"> Embutir sites (remove X-Frame-Options)</label>
            <label class="chk"><input type="checkbox" id="filterTel"> Filtrar telemetria</label>
            <div class="spacer"></div>
            <button id="btnForwardAll">Encaminhar tudo</button>
          </div>
          <div class="heldwrap">
            <div class="heldlist" id="heldList"></div>
            <div class="heldedit">
              <div class="bar" id="heldActions" style="visibility:hidden">
                <span class="grow"></span>
                <button class="primary" id="btnForward">Encaminhar</button>
                <button class="danger" id="btnDrop">Descartar</button>
              </div>
              <textarea id="heldEdit" spellcheck="false"></textarea>
            </div>
          </div>
        </section>

        <!-- ---------------------------------------------- repeater -->
        <section class="view" id="view-repeater">
          <div class="bar">
            <label class="chk">Host <input type="text" id="rpHost" placeholder="deixe vazio = do cabecalho" style="width:190px"></label>
            <label class="chk">Porta <input type="text" id="rpPort" placeholder="auto" style="width:70px"></label>
            <select id="rpScheme">
              <option value="">auto</option><option value="http">http</option><option value="https">https</option>
            </select>
            <div class="spacer"></div>
            <button class="primary" id="btnRpSend">Enviar requisicao</button>
          </div>
          <div class="rp">
            <div class="pane">
              <h4>Requisicao crua</h4>
              <textarea id="rpRaw" spellcheck="false"></textarea>
            </div>
            <div class="pane">
              <h4>Resposta</h4>
              <textarea id="rpResp" spellcheck="false" readonly></textarea>
            </div>
          </div>
        </section>

        <!-- ------------------------------------------------ escopo -->
        <section class="view" id="view-scope">
          <div class="scope">
            <p class="hint">Um padrao por linha (host, dominio ou parte do caminho).
              Serao interceptadas apenas as requisicoes que casarem com o escopo quando
              "Somente no escopo" estiver ligado.</p>
            <textarea id="scopeText" spellcheck="false"></textarea>
            <div class="bar" style="border:none;background:transparent">
              <div class="spacer"></div>
              <button class="primary" id="btnScopeSave">Salvar escopo</button>
            </div>
          </div>
        </section>

        <!-- --------------------------------------------------- log -->
        <section class="view" id="view-log">
          <div class="bar">
            <div class="spacer"></div>
            <button id="btnLogClear">Limpar log</button>
          </div>
          <pre class="logbox" id="logBox"></pre>
        </section>
      </main>
    </aside>
  </div>
</div>

<div class="toast" id="toast"></div>

<!-- -------------------------------------------- pagina inicial (iframe) -->
<template id="homeTpl">
<style>
  :root{color-scheme:dark}
  body{margin:0;min-height:100vh;background:#0b0c0e}
</style>
</template>

<script src="/assets/app.js"></script>
</body>
</html>
"""


# ------------------------------------------------------------------ utilidade
def _jsonable(obj):
    return json.dumps(obj, ensure_ascii=False).encode("utf-8")


class _ConsoleServer(ThreadingHTTPServer):
    """Servidor do console que nao grita quando o navegador fecha a conexao.

    O navegador cancela o keep-alive o tempo todo (troca de aba, iframe
    recarregado, janela fechada). O socketserver interpretava isso como erro e
    jogava um traceback no log do app, parecendo defeito sem ser.
    """

    daemon_threads = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
            return  # cliente desconectou: nada a fazer, o console segue ativo
        super().handle_error(request, client_address)


class WebConsole:
    """Servidor do console web. Inicia/para em thread propria."""

    def __init__(self, ctx, host="127.0.0.1", port=0):
        self.ctx = ctx
        self.host = host
        self.token = secrets.token_urlsafe(24)
        self._httpd = None
        self._thread = None
        self.port = None
        self._logo = _read_logo()

    # --------------------------------------------------------------- ciclo
    @property
    def running(self):
        return self._httpd is not None and self._thread is not None and self._thread.is_alive()

    def page_url(self):
        return "http://%s:%d/?token=%s" % (self.host, self.port, self.token)

    def start(self):
        if self.running:
            return True, "console ja ativo"
        handler = self._make_handler()
        try:
            self._httpd = _ConsoleServer((self.host, self.port or 0), handler)
        except OSError as exc:
            return False, "nao foi possivel abrir o console: %s" % exc
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        kwargs={"poll_interval": 0.3}, daemon=True)
        self._thread.start()
        return True, "console em %s" % self.page_url()

    def stop(self):
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
        self._httpd = None
        self._thread = None

    # ----------------------------------------------------------- handler
    def _make_handler(self):
        console = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "DerpSecConsole/1.3"

            # ------------------------------------------------ utilidades
            def log_message(self, *_a):
                pass

            def _authorized(self, query):
                if self.headers.get("X-DerpSec-Token") == console.token:
                    return True
                return query.get("token", [None])[0] == console.token

            def _host_ok(self):
                host = (self.headers.get("Host") or "").split(":")[0].lower()
                return host in ("127.0.0.1", "localhost", "[::1]", "::1", "")

            def _send(self, code, body, ctype, extra=None):
                if isinstance(body, str):
                    body = body.encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except Exception:
                    pass

            def _json(self, code, obj):
                self._send(code, _jsonable(obj), "application/json; charset=utf-8")

            def _body(self):
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    return {}
                if length <= 0:
                    return {}
                raw = self.rfile.read(length)
                try:
                    return json.loads(raw.decode("utf-8"))
                except Exception:
                    return {}

            # --------------------------------------------------- roteamento
            def do_GET(self):
                self._route("GET")

            def do_POST(self):
                self._route("POST")

            def _route(self, method):
                if not self._host_ok():
                    self._send(403, "forbidden", "text/plain; charset=utf-8")
                    return
                url = urlparse(self.path)
                path = url.path
                query = parse_qs(url.query)

                if path.startswith("/assets/"):
                    self._asset(path, query)
                    return
                if not self._authorized(query):
                    self._send(401, "token invalido", "text/plain; charset=utf-8")
                    return
                if path in ("/", "/index.html"):
                    html = HTML.replace("{{TOKEN}}", console.token)
                    self._send(200, html, "text/html; charset=utf-8", {"X-Frame-Options": "DENY"})
                    return
                if path == "/favicon.ico":
                    self._asset("/assets/logo.png", query)
                    return
                if path.startswith("/api/"):
                    try:
                        self._api(method, path[5:], query)
                    except Exception as exc:  # nunca derruba o console
                        self._json(500, {"error": str(exc)})
                    return
                self._send(404, "nao encontrado", "text/plain; charset=utf-8")

            # ------------------------------------------------------- assets
            def _asset(self, path, query):
                name = path.rsplit("/", 1)[-1]
                if name == "app.css":
                    self._send(200, CSS, "text/css; charset=utf-8")
                elif name == "app.js":
                    self._send(200, JS, "application/javascript; charset=utf-8")
                elif name == "logo.png":
                    logo = console._logo
                    if logo:
                        self._send(200, logo, "image/png")
                    else:
                        self._send(404, "sem logo", "text/plain; charset=utf-8")
                else:
                    self._send(404, "nao encontrado", "text/plain; charset=utf-8")

            # ---------------------------------------------------------- api
            def _api(self, method, route, query):
                ctx = console.ctx
                engine = ctx.engine

                if route == "state" and method == "GET":
                    self._json(200, ctx.web_state())
                    return

                if route == "history" and method == "GET":
                    needle = (query.get("q", [""])[0] or "").lower()
                    with engine._lock:
                        items = list(engine.history)[-MAX_HISTORY:]
                    out = []
                    for tx in reversed(items):
                        blob = ("%s%s" % (tx.host, tx.path)).lower()
                        if needle and needle not in blob:
                            continue
                        out.append({
                            "id": tx.id, "method": tx.method, "host": tx.host,
                            "port": tx.port, "path": tx.path, "url": tx.url,
                            "status": tx.status, "status_text": tx.status_text(),
                            "length": tx.length, "mime": tx.mime_text(),
                            "started": tx.started, "error": tx.error,
                        })
                    self._json(200, {"items": out})
                    return

                if route == "tx" and method == "GET":
                    try:
                        tx_id = int(query.get("id", ["0"])[0])
                    except ValueError:
                        tx_id = 0
                    with engine._lock:
                        tx = next((t for t in engine.history if t.id == tx_id), None)
                    if tx is None:
                        self._json(404, {"error": "transacao nao encontrada"})
                        return
                    decoded = ""
                    if tx.resp_body and ("text" in (tx.mime or "") or "json" in (tx.mime or "")
                                         or "xml" in (tx.mime or "") or "javascript" in (tx.mime or "")
                                         or "form" in (tx.mime or "") or "html" in (tx.mime or "")):
                        decoded, _ok = H.decode_body(tx.resp_headers, tx.resp_body)
                        decoded = decoded[:300000]
                    self._json(200, {
                        "id": tx.id, "method": tx.method, "path": tx.path,
                        "status_text": tx.status_text(), "error": tx.error,
                        "request_pretty": H.pretty(tx.request_raw).replace("\r\n", "\n"),
                        "response_pretty": H.pretty(tx.response_raw).replace("\r\n", "\n"),
                        "decoded": decoded,
                    })
                    return

                if route == "held" and method == "GET":
                    out = []
                    for held in list(engine.held_pending):
                        tx = held.tx
                        out.append({
                            "id": held.serial, "kind": held.kind, "tx_id": tx.id,
                            "method": tx.method, "host": tx.host, "port": tx.port,
                            "path": tx.path,
                            "raw": H.pretty(held.raw).replace("\r\n", "\n"),
                        })
                    self._json(200, {"items": out})
                    return

                if route == "held" and method == "POST":
                    data = self._body()
                    action = data.get("action")
                    if action == "forward_all":
                        count = 0
                        for held in list(engine.held_pending):
                            engine.decide(held, "forward")
                            count += 1
                        self._json(200, {"ok": True, "count": count})
                        return
                    target = None
                    for held in list(engine.held_pending):
                        if str(held.serial) == str(data.get("id")):
                            target = held
                            break
                    if target is None:
                        self._json(404, {"error": "mensagem nao esta mais na fila"})
                        return
                    raw = data.get("raw")
                    if raw:
                        target.raw = raw.replace("\r\n", "\n").replace("\n", "\r\n").encode("latin-1", "replace")
                    engine.decide(target, "drop" if action == "drop" else "forward")
                    self._json(200, {"ok": True})
                    return

                if route == "repeater" and method == "POST":
                    data = self._body()
                    port = data.get("port") or ""
                    response, error = engine.send_raw(
                        (data.get("raw") or "").encode("latin-1", "replace"),
                        host_override=data.get("host") or None,
                        port_override=int(port) if str(port).isdigit() else None,
                        scheme_override=data.get("scheme") or None,
                    )
                    if error:
                        self._json(200, {"error": str(error)})
                    else:
                        self._json(200, {"response": H.pretty(response).replace("\r\n", "\n")})
                    return

                if route == "scope":
                    if method == "GET":
                        self._json(200, {"scope": ctx.get_scope()})
                    else:
                        text = (self._body().get("scope") or "")
                        count = ctx.set_scope(text)
                        self._json(200, {"ok": True, "count": count})
                    return

                if route == "flags" and method == "POST":
                    ctx.set_flags(self._body())
                    self._json(200, {"ok": True})
                    return

                if route == "proxy" and method == "POST":
                    action = self._body().get("action")
                    if action == "start":
                        ok, message = ctx.web_start_proxy()
                    else:
                        ctx.web_stop_proxy()
                        ok, message = True, "proxy parado"
                    self._json(200, {"ok": ok, "message": message})
                    return

                if route == "log":
                    if method == "GET":
                        self._json(200, {"lines": ctx.log_lines()[-MAX_LOG:]})
                    else:
                        ctx.clear_log()
                        self._json(200, {"ok": True})
                    return

                if route == "clear" and method == "POST":
                    ctx.web_clear_history()
                    self._json(200, {"ok": True})
                    return

                self._json(404, {"error": "rota desconhecida"})

        return Handler
