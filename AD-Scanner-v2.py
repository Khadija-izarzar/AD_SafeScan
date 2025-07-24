import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from PIL import Image, ImageTk
import subprocess
import socket
import psutil
import getpass
import datetime
import threading
import platform
import ctypes

PASSWORD = "ADSafe@2025"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_resource_path(filename):
    """
    Retourne le chemin absolu vers un fichier dans le dossier Documents/AD-Scanner
    de l'utilisateur actuellement connecté.
    """
    user_documents = os.path.join(os.path.expanduser("~"), "Documents", "AD-Scanner")
    return os.path.join(user_documents, filename)

class ADSafeScanTool:
    def __init__(self):
        self.root = tk.Tk()
        self.root.withdraw()

        if not is_admin():
            messagebox.showwarning(
                "Droits insuffisants",
                "⚠️ Ce programme nécessite des droits administrateur.\n"
                "💡 Clic droit > Exécuter en tant qu’administrateur."
            )

        self.show_password_prompt()

    def show_password_prompt(self):
        self.login_win = tk.Toplevel()
        self.login_win.title("Connexion sécurisée")
        self.login_win.geometry("350x200")
        self.login_win.configure(bg="#2c2c2c")
        self.login_win.resizable(False, False)
        self.login_win.grab_set()
        self.login_win.protocol("WM_DELETE_WINDOW", self.root.quit)

        tk.Label(self.login_win, text="🔐 Authentification requise",
                 font=("Helvetica", 14, "bold"), bg="#2c2c2c", fg="white").pack(pady=(20, 10))

        tk.Label(self.login_win, text="Entrez le mot de passe :",
                 bg="#2c2c2c", fg="white", font=("Helvetica", 11)).pack()

        self.pwd_entry = tk.Entry(self.login_win, show="*", font=("Helvetica", 12), width=25, justify="center")
        self.pwd_entry.pack()
        self.pwd_entry.bind("<Return>", lambda e: self.validate_password())

        tk.Button(self.login_win, text="Valider", command=self.validate_password,
                  bg="#ff8800", fg="white", font=("Helvetica", 11, "bold")).pack(pady=20)

    def validate_password(self):
        if self.pwd_entry.get() == PASSWORD:
            self.login_win.destroy()
            self.root.deiconify()
            self.setup_main_ui()
        else:
            messagebox.showerror("Erreur", "Mot de passe incorrect")
            self.root.quit()

    def setup_main_ui(self):
        try:
            icon_path = get_resource_path("icone.ico")
            self.root.iconbitmap(icon_path)
            self.root.tk.call('wm', 'iconphoto', self.root._w, ImageTk.PhotoImage(Image.open(icon_path)))
        except Exception as e:
            print("Erreur chargement icône:", e)

        self.root.title("AD-SafeScan")
        self.root.geometry("950x750")
        self.root.configure(bg="#444444")

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TLabel", background="#444444", foreground="#f4f4f4", font=("Helvetica", 11))
        self.style.configure("TButton", font=("Helvetica", 11), padding=5)
        self.style.configure("Audit.TButton", font=("Segoe UI", 11, "bold"),
                             background="#ff8800", foreground="white", padding=10)
        self.style.map("Audit.TButton", background=[("active", "#cc6f00")], foreground=[("disabled", "#888888")])
        self.style.configure("TLabelframe", background="#444444", font=("Helvetica", 12, "bold"), foreground="#f4f4f4")
        self.style.configure("TLabelframe.Label", background="#444444", foreground="#ff8800", font=("Helvetica", 13, "bold"))

        self.audit_results = {}
        self.setup_ui()

    def setup_ui(self):
        font_title = ("Helvetica", 40, "bold")
        color_bg = "#444444"
        color_fg = "#f4f4f4"
        color_accent = "#ff8800"

        tk.Frame(self.root, bg=color_fg, height=3).pack(fill=tk.X)
        header_frame = tk.Frame(self.root, bg=color_bg)
        header_frame.pack(fill=tk.X, pady=(10, 10))

        try:
            logo_path = get_resource_path("logo.png")
            img = Image.open(logo_path).resize((100, 100))
            self.logo_img = ImageTk.PhotoImage(img)
            tk.Label(header_frame, image=self.logo_img, bg=color_bg).pack(side=tk.LEFT, padx=(20, 10))
        except Exception as e:
            print(f"Erreur chargement logo : {e}")

        tk.Label(header_frame, text="AD-SafeScan", font=font_title, fg=color_accent, bg=color_bg).pack(side=tk.LEFT, expand=True, fill=tk.X)

        info_frame = ttk.LabelFrame(self.root, text="État du système", style="TLabelframe")
        info_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        self.system_info_label = ttk.Label(info_frame, text="", font=("Helvetica", 11))
        self.system_info_label.pack(padx=10, pady=5)
        self.update_system_info()

        buttons_frame = ttk.LabelFrame(self.root, text="Modules d'audit", style="TLabelframe")
        buttons_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        self.create_audit_buttons(buttons_frame)

        results_frame = ttk.LabelFrame(self.root, text="Résultats", style="TLabelframe")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self.result_text = scrolledtext.ScrolledText(results_frame, font=("Consolas", 10),
                                                     bg="#181818", fg="#f4f4f4", insertbackground="#f4f4f4", height=15)
        self.result_text.pack(fill=tk.BOTH, expand=True)

        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(self.root, variable=self.progress_var, maximum=100).pack(pady=5, padx=10, fill=tk.X)

        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=10)
        ttk.Button(control_frame, text="🗑 Effacer", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="📀 Sauvegarder", command=self.save_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="🔍 Tout auditer", command=self.run_all_audits).pack(side=tk.LEFT, padx=5)

    def update_system_info(self):
        hostname = socket.gethostname()
        user = getpass.getuser()
        os_name = platform.platform()
        self.system_info_label.config(text=f"Machine: {hostname} | Utilisateur: {user} | OS: {os_name}")

    def create_audit_buttons(self, parent):
        data = [
            ("🛡️ Comptes AD", self.audit_ad_accounts),
            ("🌐 Ports ouverts", self.audit_open_ports),
            ("⚙️ Services", self.audit_services),
            ("👥 Comptes locaux", self.audit_local_accounts),
            ("💾 Activité USB", self.audit_usb_activity),
            ("🚨 Logs de sécurité", self.audit_security_logs)
        ]
        for i, (text, cmd) in enumerate(data):
            row, col = divmod(i, 2)
            ttk.Button(parent, text=text, command=cmd, width=35, style="Audit.TButton").grid(row=row, column=col, padx=5, pady=5, sticky="ew")
            parent.grid_columnconfigure(col, weight=1)

    def log_result(self, title, content):
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sep = "=" * 60
        self.result_text.insert(tk.END, f"\n{sep}\n[{ts}] {title}\n{sep}\n{content}\n")
        self.result_text.see(tk.END)
        self.audit_results[title] = content

    def clear_results(self):
        self.result_text.delete(1.0, tk.END)
        self.progress_var.set(0)
        self.audit_results.clear()

    def save_results(self):
        if not self.audit_results:
            messagebox.showwarning("Aucun résultat", "Aucun audit à sauvegarder")
            return
        path = os.path.join(os.path.expanduser("~"), "Desktop", f"AuditResult_{socket.gethostname()}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.result_text.get(1.0, tk.END))
            messagebox.showinfo("Succès", f"Fichier sauvegardé :\n{path}")
        except Exception as e:
            messagebox.showerror("Erreur", str(e))

    def run_all_audits(self):
        audits = [
            self.audit_ad_accounts,
            self.audit_open_ports,
            self.audit_services,
            self.audit_local_accounts,
            self.audit_usb_activity,
            self.audit_security_logs
        ]

        def run():
            self.clear_results()
            for i, func in enumerate(audits):
                try:
                    func()
                    self.progress_var.set((i + 1) / len(audits) * 100)
                    self.root.update_idletasks()
                except Exception as e:
                    self.log_result(func.__name__, f"Erreur: {e}")
            messagebox.showinfo("Audit terminé", "Tous les audits sont terminés")

        threading.Thread(target=run, daemon=True).start()

    def audit_ad_accounts(self):
        try:
            result = subprocess.check_output("net user /domain", shell=True, text=True)
        except:
            result = subprocess.check_output("net user", shell=True, text=True)
        self.log_result("🛡️ Comptes AD", result)

    def audit_open_ports(self):
        try:
            conns = psutil.net_connections(kind='inet')
            ports = [f"Port {c.laddr.port}" for c in conns if c.status == 'LISTEN']
            result = "\n".join(ports) if ports else "Aucun port à l'écoute."
        except Exception as e:
            result = f"Erreur: {e}"
        self.log_result("🌐 Ports ouverts", result)

    def audit_services(self):
        try:
            result = subprocess.check_output("net start", shell=True, text=True)
        except Exception as e:
            result = f"Erreur: {e}"
        self.log_result("⚙️ Services actifs", result)

    def audit_local_accounts(self):
        try:
            result = subprocess.check_output("net user", shell=True, text=True)
        except Exception as e:
            result = f"Erreur: {e}"
        self.log_result("👥 Comptes locaux", result)

    def audit_usb_activity(self):
        try:
            result = subprocess.check_output('wmic logicaldisk where "drivetype=2" get caption,description,size', shell=True, text=True)
            if not result.strip():
                result = "Aucun périphérique USB connecté"
        except Exception as e:
            result = f"Erreur: {e}"
        self.log_result("💾 Activité USB", result)

    def audit_security_logs(self):
        methods = [
            ('wevtutil qe Security /f:text /c:5 /rd:true', "wevtutil"),
            ('powershell "Get-EventLog -LogName Security -Newest 5 | Format-List"', "Get-EventLog"),
            ('powershell "Get-WinEvent -FilterHashTable @{LogName=\'Security\';Level=2} -MaxEvents 5 -ErrorAction SilentlyContinue | Format-List"', "Get-WinEvent")
        ]
        result = ""
        for cmd, name in methods:
            try:
                output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT, timeout=10)
                result = f"[Méthode {name}]\n{output}"
                break
            except Exception as e:
                result += f"\n❌ Échec {name} : {str(e)}"

        if not result.strip() or ("Échec" in result and "[Méthode" not in result):
            result += "\n⚠️ Impossible de récupérer les logs de sécurité.\n💡 Essayez en mode Administrateur."

        self.log_result("🚨 Logs de sécurité", result)

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    ADSafeScanTool().run()
