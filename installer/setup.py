"""Instalador do DerpSec (Windows).

Gera um instalador .exe que copia o aplicativo para a pasta do usuario, cria
atalhos, registra a entrada em "Adicionar ou remover programas" (HKCU) e
oferece desinstalacao. Nao precisa de privilegios de administrador.

Uso:
    DerpSecSetup.exe             -> instalacao grafica
    DerpSecSetup.exe --uninstall -> desinstalacao silenciosa
"""
import os
import shutil
import subprocess
import sys
import tempfile
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

APP_NAME = "DerpSec"
VERSION = "1.4.0"
PUBLISHER = "DerpSec (open source)"
APP_EXE = "DerpSec.exe"
UNINST_EXE = "Desinstalar DerpSec.exe"
REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\DerpSec"


def default_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "Programs", APP_NAME)


def payload_path():
    """Caminho do DerpSec.exe embutido no instalador."""
    if getattr(sys, "frozen", False):
        base = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        candidate = os.path.join(base, APP_EXE)
        if os.path.exists(candidate):
            return candidate
    here = os.path.dirname(os.path.abspath(__file__))
    for folder in (os.path.join(here, "..", "dist"), here, os.path.join(here, "..")):
        candidate = os.path.join(folder, APP_EXE)
        if os.path.exists(candidate):
            return os.path.abspath(candidate)
    return None


def run_powershell(script):
    path = os.path.join(tempfile.gettempdir(), "derpsec_setup_%d.ps1" % os.getpid())
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(script)
    try:
        return subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", path],
            capture_output=True, text=True, timeout=90,
        )
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def make_shortcut(lnk_path, target, workdir, icon):
    script = (
        "$ws = New-Object -ComObject WScript.Shell\n"
        "$sc = $ws.CreateShortcut('%s')\n"
        "$sc.TargetPath = '%s'\n"
        "$sc.WorkingDirectory = '%s'\n"
        "$sc.IconLocation = '%s,0'\n"
        "$sc.Description = 'Proxy de interceptacao HTTP/HTTPS'\n"
        "$sc.Save()\n"
    ) % (lnk_path.replace("'", "''"), target.replace("'", "''"),
         workdir.replace("'", "''"), icon.replace("'", "''"))
    return run_powershell(script)


def start_menu_dir():
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "Microsoft", "Windows", "Start Menu", "Programs", APP_NAME)


def desktop_dir():
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        )
        value, _ = winreg.QueryValueEx(key, "Desktop")
        winreg.CloseKey(key)
        return os.path.expandvars(value)
    except Exception:
        return os.path.join(os.path.expanduser("~"), "Desktop")


def register_uninstall(install_dir):
    import winreg
    size = 0
    try:
        size = os.path.getsize(os.path.join(install_dir, APP_EXE)) // 1024
    except OSError:
        pass
    key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
    values = [
        ("DisplayName", "%s - proxy de interceptacao HTTP/HTTPS" % APP_NAME),
        ("DisplayVersion", VERSION),
        ("Publisher", PUBLISHER),
        ("InstallLocation", install_dir),
        ("DisplayIcon", os.path.join(install_dir, APP_EXE)),
        ("UninstallString", '"%s" --uninstall' % os.path.join(install_dir, UNINST_EXE)),
        ("QuietUninstallString", '"%s" --uninstall' % os.path.join(install_dir, UNINST_EXE)),
    ]
    for name, value in values:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)
    winreg.SetValueEx(key, "EstimatedSize", 0, winreg.REG_DWORD, int(size))
    winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
    winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
    winreg.CloseKey(key)


def unregister():
    try:
        import winreg
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, REG_PATH)
    except Exception:
        pass


def do_install(install_dir, desktop, startmenu, run_after, log):
    source = payload_path()
    if not source:
        return False, "Nao encontrei o arquivo %s junto do instalador." % APP_EXE
    os.makedirs(install_dir, exist_ok=True)
    target = os.path.join(install_dir, APP_EXE)
    log("Copiando aplicativo para %s" % target)
    shutil.copy2(source, target)

    # copia o proprio instalador para permitir desinstalar depois
    if getattr(sys, "frozen", False):
        uninstaller = os.path.join(install_dir, UNINST_EXE)
        if os.path.abspath(sys.executable) != os.path.abspath(uninstaller):
            shutil.copy2(sys.executable, uninstaller)

    icon = target
    if desktop:
        lnk = os.path.join(desktop_dir(), "%s.lnk" % APP_NAME)
        log("Criando atalho na area de trabalho")
        make_shortcut(lnk, target, install_dir, icon)
    if startmenu:
        menu = start_menu_dir()
        os.makedirs(menu, exist_ok=True)
        log("Criando atalho no menu Iniciar")
        make_shortcut(os.path.join(menu, "%s.lnk" % APP_NAME), target, install_dir, icon)
        make_shortcut(
            os.path.join(menu, "Desinstalar %s.lnk" % APP_NAME),
            os.path.join(install_dir, UNINST_EXE), install_dir, icon,
        )
    log("Registrando desinstalador")
    register_uninstall(install_dir)
    if run_after:
        log("Iniciando %s" % APP_NAME)
        subprocess.Popen([target], cwd=install_dir, close_fds=True)
    return True, target


def do_uninstall():
    install_dir = default_dir()
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        install_dir, _ = winreg.QueryValueEx(key, "InstallLocation")
        winreg.CloseKey(key)
    except Exception:
        pass
    for lnk in (os.path.join(desktop_dir(), "%s.lnk" % APP_NAME),
                os.path.join(start_menu_dir(), "%s.lnk" % APP_NAME),
                os.path.join(start_menu_dir(), "Desinstalar %s.lnk" % APP_NAME)):
        try:
            os.remove(lnk)
        except OSError:
            pass
    try:
        os.rmdir(start_menu_dir())
    except OSError:
        pass
    unregister()
    # remove a pasta depois que este processo terminar
    script = 'cmd /c ping -n 3 127.0.0.1 >nul & rmdir /s /q "%s"' % install_dir
    subprocess.Popen(script, shell=True, close_fds=True)
    return install_dir


# ------------------------------------------------------------------ interface
class Installer:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Instalador do %s v%s" % (APP_NAME, VERSION))
        self.root.geometry("560x360")
        self.root.resizable(False, False)
        try:
            self.root.iconbitmap(os.path.join(getattr(sys, "_MEIPASS", "."), "derpsec.ico"))
        except Exception:
            pass

        head = tk.Frame(self.root, bg="#111827")
        head.pack(fill="x")
        tk.Label(head, text="  %s  " % APP_NAME, bg="#111827", fg="#10b981",
                 font=("Segoe UI", 18, "bold")).pack(anchor="w", padx=12, pady=(12, 0))
        tk.Label(head, text="  Proxy de interceptacao HTTP/HTTPS - open source (MIT)",
                 bg="#111827", fg="#9ca3af", font=("Segoe UI", 9)).pack(anchor="w", padx=12, pady=(0, 12))

        body = ttk.Frame(self.root)
        body.pack(fill="both", expand=True, padx=14, pady=12)

        ttk.Label(body, text="Pasta de instalacao:").pack(anchor="w")
        row = ttk.Frame(body)
        row.pack(fill="x", pady=(2, 10))
        self.dir_var = tk.StringVar(value=default_dir())
        ttk.Entry(row, textvariable=self.dir_var).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Alterar...", command=self.pick_dir).pack(side="left", padx=(6, 0))

        self.desktop = tk.BooleanVar(value=True)
        self.startmenu = tk.BooleanVar(value=True)
        self.run_after = tk.BooleanVar(value=True)
        ttk.Checkbutton(body, text="Criar atalho na area de trabalho",
                        variable=self.desktop).pack(anchor="w")
        ttk.Checkbutton(body, text="Criar atalhos no menu Iniciar",
                        variable=self.startmenu).pack(anchor="w")
        ttk.Checkbutton(body, text="Executar o %s agora" % APP_NAME,
                        variable=self.run_after).pack(anchor="w")

        ttk.Label(body, text="Progresso:").pack(anchor="w", pady=(10, 0))
        self.log_text = tk.Text(body, height=7, font=("Consolas", 8), state="disabled")
        self.log_text.pack(fill="both", expand=True)

        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=14, pady=(0, 12))
        ttk.Button(bar, text="Cancelar", command=self.root.destroy).pack(side="right")
        self.btn = ttk.Button(bar, text="Instalar", command=self.install)
        self.btn.pack(side="right", padx=6)

    def log(self, message):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
        self.root.update_idletasks()

    def pick_dir(self):
        chosen = filedialog.askdirectory(initialdir=self.dir_var.get(), title="Escolha a pasta")
        if chosen:
            self.dir_var.set(chosen)

    def install(self):
        self.btn.configure(state="disabled")
        target = self.dir_var.get().strip()
        if not target:
            messagebox.showerror(APP_NAME, "Escolha uma pasta de instalacao.")
            self.btn.configure(state="normal")
            return
        try:
            ok, result = do_install(
                target, self.desktop.get(), self.startmenu.get(),
                self.run_after.get(), self.log,
            )
        except Exception as exc:
            messagebox.showerror(APP_NAME, "Falha na instalacao: %s" % exc)
            self.btn.configure(state="normal")
            return
        if not ok:
            messagebox.showerror(APP_NAME, result)
            self.btn.configure(state="normal")
            return
        self.log("Concluido.")
        messagebox.showinfo(
            APP_NAME,
            "Instalacao concluida em:\n%s\n\n"
            "Para remover depois, use 'Desinstalar DerpSec' no menu Iniciar "
            "ou Adicionar/Remover programas." % target,
        )
        self.root.destroy()


def silent_install():
    target = default_dir()
    if "--dir" in sys.argv:
        idx = sys.argv.index("--dir")
        if idx + 1 < len(sys.argv):
            target = sys.argv[idx + 1]
    report = os.path.join(tempfile.gettempdir(), "derpsec_setup.log")
    lines = []
    try:
        ok, result = do_install(target, True, True, False, lines.append)
    except Exception as exc:
        ok, result = False, "%s: %s" % (type(exc).__name__, exc)
        lines.append(result)
    with open(report, "w", encoding="utf-8") as fh:
        fh.write("ok=%s\n%s\n" % (ok, "\n".join(lines)))
    return 0 if ok else 1


def main():
    if "--silent" in sys.argv:
        return silent_install()
    if "--uninstall" in sys.argv:
        removed = do_uninstall()
        if "--quiet" not in sys.argv:
            root = tk.Tk()
            root.withdraw()
            messagebox.showinfo(
                APP_NAME,
                "DerpSec desinstalado.\nPasta removida: %s\n\n"
                "A autoridade certificadora (CA) permanece em %%APPDATA%%\\DerpSec "
                "para nao invalidar certificados ja instalados. Apague manualmente se desejar."
                % removed,
            )
        return 0
    Installer().root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
