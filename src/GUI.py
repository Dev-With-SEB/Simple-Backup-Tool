
# -*- coding: utf-8 -*-

import io
import os
import re
import sys
import time
import yaml
import shutil
import win32con
import platform
import threading
import traceback
import subprocess
# import tkinter as tk
# from tkinter import ttk, messagebox, simpledialog, filedialog
import win32serviceutil
import win32service
import pywintypes
from . import utils, smb_ops, cron as cron_module
from .passwords import PasswordManager
from .simpleLogger import get_logger
from .config_loader import ConfigLoader
from .smb_ops import SMBSessionCache, SMBFileOps
from .backup import BackupRunner


# --- Cross-version Tk import block (Py3 / Py2.7) ---
try:
    # Python 2.7
    import Tkinter as tk
    import ttk
    import tkMessageBox as messagebox
    import tkSimpleDialog as simpledialog
    import tkFileDialog as filedialog
except ImportError:
    # Python 3.x
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog, filedialog


# log.logLvl = 3
# ---------- Configuration ----------
CONFIG_FILE = r''
DEFAULT_SERVICE_NAME = "Backup Tool Service"  # e.g., "BackupService"
DEFAULT_RUN_NOW_COMMAND = ""

# ---------- YAML Helpers ----------
# should really sunset this in favor of the conf class and loader
def load_config(path):
    if not os.path.exists(path):
        messagebox.showerror("Missing file", "Config file not found: {}".format(path))
        return {"auth": {"hosts": []}, "computer2Backup": []}
    with open(path, "rb") as f:
        try:
            cfg = yaml.safe_load(f)
        except Exception as e:
            messagebox.showerror("YAML error", "Failed to parse YAML: {}".format(e))
            cfg = {}
    # Ensure basic structure
    if "auth" not in cfg or cfg["auth"] is None:
        cfg["auth"] = {}
    if "hosts" not in cfg["auth"] or cfg["auth"]["hosts"] is None:
        cfg["auth"]["hosts"] = []
    if "computer2Backup" not in cfg or cfg["computer2Backup"] is None:
        cfg["computer2Backup"] = []
    return cfg


def save_config(path, data):
    try:
        with io.open(path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, default_flow_style=False, allow_unicode=True)
    except Exception as e:
        errMsg = "Save error", "Failed to save YAML: {}".format(e)
        messagebox.showerror(errMsg)
        get_logger().error(errMsg)
        get_logger().debug(traceback.format_exc())
    try:
        with open(path, "rb") as f:
            data = yaml.safe_load(f) or {}
        changed = PasswordManager.sanitize_and_persist_config(data, path)
    except Exception as e:
        messagebox.showerror("password error", "Failed to protect password: {}".format(e))
        get_logger().error(traceback.format_exc())
    get_logger().verbose("{}\n{}".format(path, data))
    

# ---------- Mapping Helpers ----------
UNC_IP_RE = re.compile(r"^\\\\{2}(\d{1,3}(?:\.\d{1,3}){3})\\", re.IGNORECASE)

def infer_host_from_paths(paths):
    """
    Try to infer IP/host from UNC path list like \\192.9.200.31\C$\amat
    Returns first matching IP or None.
    """
    if not paths:
        return None
    for p in paths:
        if not isinstance(p, str):
            continue
        m = UNC_IP_RE.match(p.strip())
        if m:
            return m.group(1)
    return None

def find_auth_host(cfg, host_value):
    """
    Find auth.hosts entry by exact 'host' match.
    Returns (index, entry) or (None, None).
    """
    if not host_value:
        return (None, None)
    hosts = cfg.get("auth", {}).get("hosts", [])
    for i, h in enumerate(hosts):
        if str(h.get("host", "")).strip() == str(host_value).strip():
            return (i, h)
    return (None, None)

def upsert_auth_host(cfg, host, username, domain, password):
    """
    Create or update auth.hosts entry for 'host'.
    """
    if not host:
        return
    idx, h = find_auth_host(cfg, host)
    if idx is None:
        cfg["auth"]["hosts"].append({
            "host": host,
            "username": username or "",
            "domain": domain or "",
            "password": password or ""
        })
    else:
        if username is not None:
            h["username"] = username
        if domain is not None:
            h["domain"] = domain
        if password is not None:
            h["password"] = password

def remove_auth_host(cfg, host):
    """
    Remove auth.hosts entry for 'host' if present.
    """
    if not host:
        return
    hosts = cfg.get("auth", {}).get("hosts", [])
    for i, h in enumerate(list(hosts)):
        if str(h.get("host", "")).strip() == str(host).strip():
            del hosts[i]
            break

def find_computer_entry(cfg, computer_name):
    """
    computer2Backup is a list of { name: details } mappings.
    Returns (index, details_dict) or (None, None).
    """
    lst = cfg.get("computer2Backup", [])
    for i, itm in enumerate(lst):
        if computer_name in itm:
            return (i, itm[computer_name])
    return (None, None)


def ask_string(parent, title, prompt, initial=None,
               entry_width=80,            # characters
               window_width_px=640,       # pixels
               icon_path=None):
    """A wider string input dialog that keeps your app icon."""
    win = tk.Toplevel(parent)
    win.title(title)
    # Optional: apply your .ico to the dialog
    try:
        if icon_path:
            win.iconbitmap(icon_path)
    except Exception:
        pass

    # Make the window a bit wider and center it
    win.geometry("%dx%d" % (window_width_px, 160))
    win.resizable(True, False)

    tk.Label(win, text=prompt).pack(padx=12, pady=(12, 6))
    var = tk.StringVar(value=initial or "")
    e = tk.Entry(win, textvariable=var, width=entry_width)
    e.pack(padx=12, pady=(0, 10), fill="x")
    e.focus_set()

    result = {"value": None}
    def ok():
        result["value"] = var.get()
        win.destroy()
    def cancel():
        win.destroy()

    btns = tk.Frame(win); btns.pack(fill="x", padx=12, pady=10)
    tk.Button(btns, text="OK", command=ok).pack(side=tk.RIGHT, padx=6)
    tk.Button(btns, text="Cancel", command=cancel).pack(side=tk.RIGHT, padx=6)

    # Center on parent (after widgets laid out)
    win.update_idletasks()
    try:
        px = parent.winfo_rootx() + (parent.winfo_width() - window_width_px) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - win.winfo_height()) // 2
        win.geometry("+%d+%d" % (max(px, 0), max(py, 0)))
    except Exception:
        pass

    parent.wait_window(win)
    return result["value"]



# this really could maybe be made into a util as its kind of used twice see run_once_console in backupTool
def run_backup_once( *args, **kwargs):
    cfg_File = args[0]
    log = kwargs.get("log",get_logger())
    runEvt = kwargs.get("runEvt")
    smb_cache = None
    loader = ConfigLoader(cfg_File, lambda cfg: None, log)
    cfg = loader.load_now()    
    log.debug("Running once in console")
    log.debug(cfg)
    try:
        smb_cache = SMBSessionCache(log=log)
        file_ops = SMBFileOps(smb_cache, cfg, log)
        runner = BackupRunner(file_ops, log=log, runEvt=runEvt)
        host, share, rel = runner.run_backup(cfg)
        log.debug("Backup uploaded to //{}/{}/{}".format(host, share, rel))
        return 0
    except Exception as e:
        log.warn("Backup FAILED: {}".format(e))
        tb = traceback.format_exc()
        try:
            log.debug(tb)
        except Exception:
            pass
        return 2
    finally:
        try:
            if smb_cache:
                smb_cache.close_all()
        except Exception:
            pass

# ---------- Service Control ----------
class ServiceController(object):
    def __init__(self, service_name):
        self.service_name = service_name
        self.is_installed = False

    # if service_exists(service_name):
    #     installed = True
    # else:
    #     install_service(service_name, display_name, bin_path, start_type, description)
    #     installed = True
    """
    install_service(
        service_name='AppReadiness',
        display_name='App Readiness',
        bin_path=r'C:\Path\To\YourService.exe --run-service',
        start_type='auto',
        description='Ensures application readiness on boot',
        start_after_install=True
    )
    """


    def _open_scm(self, manager_access=win32con.GENERIC_READ):
        """Open Service Control Manager handle."""
        # machine=None -> local (as in your snippet)
        return win32service.OpenSCManager(
            None,            # machine
            None,            # database
            manager_access   # access rights
        ) 


    def check_install(self, service_name):
        """
        Return True if a service is installed, False otherwise.

        This uses win32service.GetServiceKeyName which throws when the service
        doesn't exist. We trap ERROR_SERVICE_DOES_NOT_EXIST.
        """
        hscm = None
        try:
            hscm =self._open_scm(win32service.SC_MANAGER_CONNECT)
            # If name is a display name, this resolves to the real service key
            win32service.GetServiceKeyName(hscm, service_name)
            return True
        except win32service.error as e:
            # e: (hr, func, msg)
            if hasattr(e, 'winerror'):
                code = e.winerror
            else:
                # pywin32 sometimes provides first tuple item as code
                try:
                    code = e[0]
                except Exception:
                    code = None
            # ERROR_SERVICE_DOES_NOT_EXIST = 1060
            if code == 1060:
                return False
            # Unexpected error: re-raise
            raise
        finally:
            if hscm:
                win32service.CloseServiceHandle(hscm)


    def install_service(self, service_name,
                        display_name,
                        bin_path,
                        start_type='auto',
                        description=None):
        """
        Install (create) a Windows service.

        Args:
            service_name (str): Internal service name (key).
            display_name (str): Human-readable name shown in Services.msc.
            bin_path (str): Full path to the service executable, including any args.
            start_type (str): 'auto' | 'manual' | 'disabled'
            description (str): Optional service description.

        Returns:
            None. Raises on failure.
        """
        # Map start types to win32 constants
        start_type_map = {
            'auto': win32service.SERVICE_AUTO_START,
            'manual': win32service.SERVICE_DEMAND_START,
            'disabled': win32service.SERVICE_DISABLED,
        }
        start_const = start_type_map.get(start_type.lower())
        if start_const is None:
            raise ValueError("start_type must be one of: 'auto', 'manual', 'disabled'")

        # Use convenience API from win32serviceutil to create the service
        # NOTE: Most real services require SERVICE_WIN32_OWN_PROCESS type
        svc_type = win32service.SERVICE_WIN32_OWN_PROCESS

        # Default service dependencies: none
        dependencies = None

        # NOTE: startType in InstallService must be one of the win32 constants
        win32serviceutil.InstallService(
            pythonClassString=None,     # not using Python service framework; install raw exe
            serviceName=service_name,
            displayName=display_name,
            exeName=bin_path,
            startType=start_const,
            serviceDeps=dependencies,
            description=description
        )

        # If description wasn’t applied (older pywin32), set explicitly
        try:
            win32serviceutil.SetServiceCustomOption(service_name, "Description", description or "")
            return True, "Service Successfully Installed"
        except Exception as e:
            self.log.error(e)
            self.log.debug(traceback.format_exc())
            return False, "Install of service failed: {}".format(e)




    def is_running(self):
        if not self.service_name:
            return False
        try:
            status = win32serviceutil.QueryServiceStatus(self.service_name)
            # status is a tuple; index 1 is current state
            return status[1] == win32service.SERVICE_RUNNING
        except pywintypes.error:
            return False

    def start(self, timeout_sec=2):
        if not self.service_name:
            return False, "No service name set."
        try:
            if self.is_running():
                return True, "Service '{}' already running.".format(self.service_name)
            win32serviceutil.StartService(self.service_name)
            # Wait until running or timeout
            t0 = time.time()
            while time.time() - t0 < timeout_sec:
                if self.is_running():
                    return True, "Service '{}' started.".format(self.service_name)
                time.sleep(0.5)
            return False, "Start timed out for '{}'.".format(self.service_name)
        except pywintypes.error as e:
            return False, "Start failed for '{}': {}".format(self.service_name, e)

    def stop(self, timeout_sec=2):
        if not self.service_name:
            return False, "No service name set."
        try:
            if not self.is_running():
                return True, "Service '{}' already stopped.".format(self.service_name)
            win32serviceutil.StopService(self.service_name)
            # Wait until stopped or timeout
            t0 = time.time()
            while time.time() - t0 < timeout_sec:
                if not self.is_running():
                    return True, "Service '{}' stopped.".format(self.service_name)
                time.sleep(0.5)
            return False, "Stop timed out for '{}'.".format(self.service_name)
        except pywintypes.error as e:
            return False, "Stop failed for '{}': {}".format(self.service_name, e)

# ---------- Run-Now Controller ----------
class runOnce_Controller(object):
    def __init__(self, runner_func, *args, **kwargs):
        """
        runner_func: a function to call for 'run now'
        *args, **kwargs: arguments to pass to runner_func
        """
        self.log = kwargs.get("log",get_logger())
        self.runEvt = kwargs.get("runEvt",threading.Event())
        self.runner_func = runner_func
        self.args = args
        self.kwargs = dict(kwargs)
        self.kwargs["runEvt"] = self.runEvt
        self._lock = threading.Lock()        
        self._running = threading.Event()
        self._result = None

    def is_running(self):
        # with self._lock:
        if self._running.is_set():
            return True
        else: return False


    def stop(self):     
        self.runEvt.clear()     

        
    def start(self):
        with self._lock:
            if self._running.is_set():
                return False, "A run-now task is already running."
            self._running.set()
            self.runEvt.set() 
        def run_task():
            thread_name = threading.current_thread().name
            self.log.debug("Starting [{}] thread".format(thread_name))     
            try:
                result = self.runner_func(*self.args, **self.kwargs)
                self._result = result
                msg = "Run-now finished: {}".format(result)
                success = True
            except Exception as e:
                self._result = None
                msg = "Failed to run: {}".format(e)
                success = False
            finally:
                with self._lock:
                    self._running.clear()
                self.log.debug("\nStats: {}\nMsg: {}".format(success,msg))
            # Optional: logging could go here

        # Run in a thread so UI doesn't freeze
        t = threading.Thread(target=run_task, name="runOnce_TaskStarter")
        t.start()
        return True, "Run-now started."

    def get_result(self):
        return self._result

# ---------- Reusable Widgets ----------
class EditableTable(tk.Frame):
    """
    Editable list with:
    - Add (manual text)
    - Edit (replace selected)
    - Remove
    - Add File (file dialog)
    - Add Folder (directory dialog)
    """
    def __init__(self, master, items, caption):
        tk.Frame.__init__(self, master, borderwidth=1, relief=tk.GROOVE)
        tk.Label(self, text=caption).pack(anchor="w", padx=6, pady=4)
        list_frame = tk.Frame(self)
        list_frame.pack(fill=tk.BOTH, expand=True)
        self.listbox = tk.Listbox(list_frame, selectmode=tk.SINGLE, width=80)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        for item in items or []:
            self.listbox.insert(tk.END, item)
        btns = tk.Frame(self)
        btns.pack(fill=tk.X, pady=4)
        tk.Button(btns, text="Add", command=self._add_item).pack(side=tk.LEFT, padx=2)
        tk.Button(btns, text="Edit", command=self._edit_item).pack(side=tk.LEFT, padx=2)
        tk.Button(btns, text="Remove", command=self._remove_item).pack(side=tk.LEFT, padx=2)
        if "Servers" != caption :
            tk.Button(btns, text="Add File", command=self._add_file).pack(side=tk.LEFT, padx=2)
            tk.Button(btns, text="Add Folder", command=self._add_folder).pack(side=tk.LEFT, padx=2)


    def _add_item(self):
        val = ask_string(self, "Add", "Enter path/pattern:",
                        entry_width=80, window_width_px=640,
                        icon_path=iconVarClass.icon_path)
        if val:
            self.listbox.insert(tk.END, val)

    def _edit_item(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("Edit", "Select a row to edit.", parent=self)
            return
        current = self.listbox.get(sel[0])
        val = ask_string(self, "Edit", "Update path/pattern:", initial=current,
                        entry_width=80, window_width_px=640,
                        icon_path=iconVarClass.icon_path)
        if val is not None:
            self.listbox.delete(sel[0])
            self.listbox.insert(sel[0], val)



    # def _add_item(self):
    #     val = tk.simpledialog.askstring("Add", "Enter path/pattern:", parent=self)
    #     if val:
    #         self.listbox.insert(tk.END, val)


    # def _edit_item(self):
    #     sel = self.listbox.curselection()
    #     if not sel:
    #         messagebox.showinfo("Edit", "Select a row to edit.", parent=self)
    #         return
    #     current = self.listbox.get(sel[0])
    #     val = simpledialog.askstring("Edit", "Update path/pattern:", initialvalue=current)
    #     if val is not None:
    #         self.listbox.delete(sel[0])
    #         self.listbox.insert(sel[0], val)

    def _remove_item(self):
        sel = self.listbox.curselection()
        if sel:
            self.listbox.delete(sel[0])

    def _add_file(self):
        p = filedialog.askopenfilename(title="Select file")
        if p:
            self.listbox.insert(tk.END, p)

    def _add_folder(self):
        p = filedialog.askdirectory(title="Select folder")
        if p:
            self.listbox.insert(tk.END, p)

    def get_items(self):
        return [self.listbox.get(i) for i in range(self.listbox.size())]


# ---------- Frames: Selection / Add / Edit / Remove ----------
class ComputerSelectionFrame(tk.Frame):
    """
    Lists computers and shows either Delete or Select buttons.
    Includes a Cancel button.
    mode: "delete" or "edit"
    on_pick(name) is called when user chooses an item.
    """
    def __init__(self, master, computers, mode, on_pick, on_cancel):
        tk.Frame.__init__(self, master)
        self.on_pick = on_pick
        header = "Select a computer to {}".format("delete" if mode == "delete" else "edit")
        tk.Label(self, text=header, font=("TkDefaultFont", 10, "bold")).pack(anchor="w", padx=6, pady=6)
        # scrollable list
        canvas = tk.Canvas(self)
        scroll = ttk.Scrollbar(self, orient=tk.VERTICAL, command=canvas.yview)
        inner = tk.Frame(canvas)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        for comp in computers or []:
            if not isinstance(comp, dict):
                continue
            name = list(comp.keys())[0]
            row = tk.Frame(inner, borderwidth=0)
            row.pack(fill=tk.X, padx=6, pady=2)
            tk.Label(row, text=name, width=36, anchor="w").pack(side=tk.LEFT)
            if mode == "delete":
                tk.Button(row, text="Delete", command=lambda n=name: self._delete(n)).pack(side=tk.LEFT)
            else:
                tk.Button(row, text="Select", command=lambda n=name: self._select(n)).pack(side=tk.LEFT)
        # bottom actions
        actions = tk.Frame(self)
        actions.pack(fill=tk.X, pady=8)
        tk.Button(actions, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=6)

    def _delete(self, name):
        if messagebox.askyesno("Confirm", "Are you sure you want to delete '{}'?".format(name)):
            self.on_pick(name)

    def _select(self, name):
        self.on_pick(name)

class ComputerEditFrame(tk.Frame):
    """
    Edit or Add computer.
    Includes Cancel and Save buttons.
    Scrollable, two-column grid layout.
    """
    def __init__(self, master, mode, initial_name, comp_data, auth_data, on_save, on_cancel):
        tk.Frame.__init__(self, master)
        # --- Scrollable canvas setup ---
        canvas = tk.Canvas(self)
        scrollbar = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # --- Form fields ---
        title = "Edit Computer" if mode == "edit" else "Add Computer"
        tk.Label(scrollable_frame, text=title, font=("TkDefaultFont", 10, "bold")).grid(row=0, column=0, columnspan=2, sticky="w", padx=6, pady=6)

        # Name
        tk.Label(scrollable_frame, text="Name:").grid(row=1, column=0, sticky="e", padx=6, pady=2)
        self.name_var = tk.StringVar(value=initial_name or "")
        tk.Entry(scrollable_frame, textvariable=self.name_var, width=28).grid(row=1, column=1, sticky="w", padx=6, pady=2)

        # Host/IP
        tk.Label(scrollable_frame, text="Host/IP:").grid(row=2, column=0, sticky="e", padx=6, pady=2)
        host_prefill = None
        if comp_data and "Host" in comp_data:
            host_prefill = comp_data.get("Host")
        elif comp_data:
            host_prefill = infer_host_from_paths(comp_data.get("Backups", []) or [])
        self.host_var = tk.StringVar(value=host_prefill or "")
        tk.Entry(scrollable_frame, textvariable=self.host_var, width=28).grid(row=2, column=1, sticky="w", padx=6, pady=2)

        # Auth Username
        tk.Label(scrollable_frame, text="Auth Username:").grid(row=1, column=3, sticky="e", padx=6, pady=2)
        self.username_var = tk.StringVar(value=(auth_data.get("username", "") if auth_data else ""))
        tk.Entry(scrollable_frame, textvariable=self.username_var, width=28).grid(row=1, column=4, sticky="w", padx=6, pady=2)

        # Auth Password
        tk.Label(scrollable_frame, text="Auth Password:").grid(row=2, column=3, sticky="e", padx=6, pady=2)
        self.password_var = tk.StringVar(value=(auth_data.get("password", "") if auth_data else ""))
        tk.Entry(scrollable_frame, textvariable=self.password_var, width=28, show="*").grid(row=2, column=4, sticky="w", padx=6, pady=2)

        # Auth Domain
        tk.Label(scrollable_frame, text="Auth Domain:").grid(row=3, column=3, sticky="e", padx=6, pady=2)
        self.domain_var = tk.StringVar(value=(auth_data.get("domain", "") if auth_data else ""))
        tk.Entry(scrollable_frame, textvariable=self.domain_var, width=28).grid(row=3, column=4, sticky="w", padx=6, pady=2)

        tk.Label(scrollable_frame, text="").grid(row=0, column=4, sticky="e", padx=6, pady=2)
        tk.Label(scrollable_frame, text="").grid(row=0, column=5, sticky="e", padx=6, pady=2)
        tk.Label(scrollable_frame, text="").grid(row=4, column=0, sticky="e", padx=6, pady=2)

        # Editable tables
        backups_init = (comp_data.get("Backups", []) if comp_data else [])
        excludes_init = (comp_data.get("Exclude", []) if comp_data else [])
        self.backups_tbl = EditableTable(scrollable_frame, backups_init, "Backups")
        self.backups_tbl.grid(row=5, column=0, columnspan=6, sticky="ew", padx=6, pady=6)
        self.excludes_tbl = EditableTable(scrollable_frame, excludes_init, "Excludes")
        self.excludes_tbl.grid(row=6, column=0, columnspan=6, sticky="ew", padx=6, pady=6)

        # Actions
        actions = tk.Frame(scrollable_frame)
        actions.grid(row=7, column=0, columnspan=2, sticky="ew", pady=8)
        tk.Button(actions, text="Save", command=self._save).pack(side=tk.RIGHT, padx=6)
        tk.Button(actions, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=6)

        # Save callback
        self._on_save = on_save

    def _save(self):
        data = {
            "name": self.name_var.get(),
            "Backups": self.backups_tbl.get_items(),
            "Exclude": self.excludes_tbl.get_items(),
            "Host": self.host_var.get(),
            "auth": {
                "host": self.host_var.get(),
                "username": self.username_var.get(),
                "domain": self.domain_var.get(),
                "password": self.password_var.get()
            }
        }
        self._on_save(data)

class ScheduleFrame(tk.Frame):
    def __init__(self, master, cfg, cfg_File, back_callback, cron_module, *args, **kwargs):
        self.log = kwargs.pop("log", get_logger())
        tk.Frame.__init__(self, master, *args, **kwargs)        
        self.cfg = cfg
        self.cfg_File = cfg_File
        self.cron_module = cron_module
        self.back_callback = back_callback
        self._build_ui()

    def _build_ui(self):
        # Retention count
        retention_count = self.cfg.get("retentionCount", 14)
        tk.Label(self, text="Retention Count:").pack(anchor="w", padx=6, pady=4)
        self.retention_var = tk.IntVar(value=retention_count)
        tk.Entry(self, textvariable=self.retention_var, width=10).pack(anchor="w", padx=20, pady=2)
        tk.Label(self, text="How many backup files to keep on the server (older files will be deleted automatically).",
                 fg="gray").pack(anchor="w", padx=6, pady=2)

        # Cron Builder Section
        builder_frame = tk.Frame(self)
        builder_frame.pack(fill=tk.BOTH, expand=True)
        tk.Label(builder_frame, text="Schedule Builder", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", padx=6, pady=(30, 10))

        # Cron Expression Display
        self.cron_str_var = tk.StringVar()
        self.nextRun_var = tk.StringVar()
        cron_display_frame = tk.Frame(builder_frame)
        cron_display_frame.pack(anchor="w", padx=20, pady=(0, 30))
        tk.Label(cron_display_frame, text="New Cron Expression:").pack(anchor="w", pady=4)
        tk.Label(cron_display_frame, textvariable=self.cron_str_var, fg="blue").pack(anchor="w", padx=10)
        tk.Label(cron_display_frame, textvariable=self.nextRun_var, fg="#228B22").pack(anchor="w", padx=10)

        # Cron controls
        self.min_var = tk.StringVar(value="*")
        self.hr_var  = tk.StringVar(value="*")
        self.dom_var = tk.StringVar(value="*")
        self.mon_var = tk.StringVar(value="*")
        self.dow_var = tk.StringVar(value="*")

        # Minutes
        min_frame = tk.LabelFrame(builder_frame, text="Minutes")
        min_frame.pack(side=tk.LEFT, padx=8, pady=4)
        tk.Radiobutton(min_frame, text="Every Minute",  variable=self.min_var, value="*").pack(anchor="w")
        tk.Radiobutton(min_frame, text="Every 5 Minutes", variable=self.min_var, value="*/5").pack(anchor="w")
        tk.Radiobutton(min_frame, text="Every 15 Minutes", variable=self.min_var, value="*/15").pack(anchor="w")
        tk.Radiobutton(min_frame, text="Every 30 Minutes", variable=self.min_var, value="*/30").pack(anchor="w")
        min_listbox = tk.Listbox(min_frame, selectmode=tk.MULTIPLE, height=6)
        for i in range(0, 60):
            min_listbox.insert(tk.END, str(i))
        min_listbox.pack()
        min_listbox.bind("<<ListboxSelect>>", lambda e: self._update_var_from_listbox(self.min_var, min_listbox))

        # Hours
        hr_frame = tk.LabelFrame(builder_frame, text="Hours")
        hr_frame.pack(side=tk.LEFT, padx=8, pady=4)
        tk.Radiobutton(hr_frame, text="Every Hour", variable=self.hr_var, value="*").pack(anchor="w")
        tk.Radiobutton(hr_frame, text="Every Even Hour", variable=self.hr_var, value="0/2").pack(anchor="w")
        tk.Radiobutton(hr_frame, text="Every 6 Hours", variable=self.hr_var, value="*/6").pack(anchor="w")
        tk.Radiobutton(hr_frame, text="Every 12 Hours", variable=self.hr_var, value="*/12").pack(anchor="w")
        hr_listbox = tk.Listbox(hr_frame, selectmode=tk.MULTIPLE, height=6)
        for i in range(0, 24):
            hr_listbox.insert(tk.END, str(i))
        hr_listbox.pack()
        hr_listbox.bind("<<ListboxSelect>>", lambda e: self._update_var_from_listbox(self.hr_var, hr_listbox))

        # Days of Month
        dom_frame = tk.LabelFrame(builder_frame, text="Days of Month")
        dom_frame.pack(side=tk.LEFT, padx=8, pady=4)
        tk.Radiobutton(dom_frame, text="Every Day", variable=self.dom_var, value="*").pack(anchor="w")
        tk.Radiobutton(dom_frame, text="Every Even Day", variable=self.dom_var, value="2-30/2").pack(anchor="w")
        tk.Radiobutton(dom_frame, text="Every 5 Days", variable=self.dom_var, value="*/5").pack(anchor="w")
        tk.Radiobutton(dom_frame, text="Every 10 Days", variable=self.dom_var, value="*/10").pack(anchor="w")
        dom_listbox = tk.Listbox(dom_frame, selectmode=tk.MULTIPLE, height=6)
        for i in range(1, 32):
            dom_listbox.insert(tk.END, str(i))
        dom_listbox.pack()
        dom_listbox.bind("<<ListboxSelect>>", lambda e: self._update_var_from_listbox(self.dom_var, dom_listbox))

        # Months
        mon_frame = tk.LabelFrame(builder_frame, text="Months")
        mon_frame.pack(side=tk.LEFT, padx=8, pady=4)
        tk.Radiobutton(mon_frame, text="Every Month", variable=self.mon_var, value="*").pack(anchor="w")
        tk.Radiobutton(mon_frame, text="Every Even Months", variable=self.mon_var, value="*/2").pack(anchor="w")
        tk.Radiobutton(mon_frame, text="Every Odd Months", variable=self.mon_var, value="1-11/2").pack(anchor="w")
        tk.Radiobutton(mon_frame, text="Every Half Year", variable=self.mon_var, value="*/6").pack(anchor="w")
        mon_listbox = tk.Listbox(mon_frame, selectmode=tk.MULTIPLE, height=6)
        months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]
        for m in months:
            mon_listbox.insert(tk.END, m)
        mon_listbox.pack()
        mon_listbox.bind("<<ListboxSelect>>", lambda e: self._update_var_from_listbox(self.mon_var, mon_listbox))

        # Days of Week
        dow_frame = tk.LabelFrame(builder_frame, text="Days of Week")
        dow_frame.pack(side=tk.LEFT, padx=8, pady=4)
        tk.Radiobutton(dow_frame, text="Every Day", variable=self.dow_var, value="*").pack(anchor="w")
        tk.Radiobutton(dow_frame, text="Monday-Friday", variable=self.dow_var, value="1-5").pack(anchor="w")
        tk.Radiobutton(dow_frame, text="Weekend Days", variable=self.dow_var, value="0,6").pack(anchor="w")
        tk.Radiobutton(dow_frame, text="Every Other Day", variable=self.dow_var, value="0,2,4,6").pack(anchor="w")
        dow_listbox = tk.Listbox(dow_frame, selectmode=tk.MULTIPLE, height=6)
        days = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]
        for d in days:
            dow_listbox.insert(tk.END, d)
        dow_listbox.pack()
        dow_listbox.bind("<<ListboxSelect>>", lambda e: self._update_var_from_listbox(self.dow_var, dow_listbox))

        # Current Settings
        currentSchg = self.cfg.get("schedule", {}).get("cron", "")
        currentSchgAry = currentSchg.split(' ')

        CurSet_frame = tk.LabelFrame(builder_frame, text="Current Settings")
        CurSet_frame.pack(side=tk.RIGHT, padx=20, pady=10)
        self.currentSchg_nextRun_date = tk.StringVar()
        self.currentSchg_nextRun_header = tk.StringVar()
        tk.Label(CurSet_frame, text=" ").grid(row=0, column=0, sticky="w")
        self.currentSchg_cron = tk.Label(CurSet_frame, text="Cron Exp: {}".format(currentSchg))
        self.currentSchg_cron.grid(row=1, column=0, sticky="w")
        tk.Label(CurSet_frame, textvariable=self.currentSchg_nextRun_header).grid(row=2, column=0, sticky="sw")
        tk.Label(CurSet_frame, textvariable=self.currentSchg_nextRun_date).grid(row=3, column=0, sticky="e")
        CurSet_frameInner = tk.Frame(CurSet_frame)
        CurSet_frameInner.grid(row=4, column=0, sticky="w")
        labels = ["Minutes", "Hours", "Days of Month", "Months", "Days of Week"]
        for i, lbl in enumerate(labels):        
            tk.Label(CurSet_frameInner, text=lbl, width=13, relief="sunken").grid(row=i, column=0, sticky="w")
            lb = tk.Label(CurSet_frameInner, text=(currentSchgAry[i] if len(currentSchgAry) > i else ""), background='white',
                     anchor="center", width=8, borderwidth=1, relief="sunken")
            lb.grid(row=i, column=1, sticky="w")
            setattr(self, "desc_Cons_{}".format(lbl), lb)       

        # Save/Cancel
        actions = tk.Frame(self)
        actions.pack(fill=tk.X, pady=8)
        tk.Button(actions, text="Save", command=self._save).pack(side=tk.RIGHT, padx=6)
        tk.Button(actions, text="Cancel", command=self.back_callback).pack(side=tk.RIGHT, padx=6)

        # Cron update logic
        for var in [self.min_var, self.hr_var, self.dom_var, self.mon_var, self.dow_var]:
            var.trace("w", self._update_cron)
        # self._update_cron()
        self.cron_str_var.set(currentSchg)
        self._update_cron_current_setting()


    def _update_var_from_listbox(self, var, listbox):
        sel = [listbox.get(i) for i in listbox.curselection()]
        if sel:
            var.set(",".join(sel))

    def _update_cron(self, *args):
        cron_str = "{} {} {} {} {}".format(
            self.min_var.get(), self.hr_var.get(), self.dom_var.get(), self.mon_var.get(), self.dow_var.get()
        )
        self.cron_str_var.set(cron_str)
        try:
            sched = self.cron_module.CronSchedule(cron_expr=cron_str, log=self.log)
            next_run = sched.next_run_after(self.cron_module.datetime.datetime.now())
            desc = "Next run: {}".format(next_run)
        except Exception as e:
            desc = "Invalid cron: {}".format(e)
            self.log.debug(traceback.format_exc())
        self.nextRun_var.set(desc)

    def _update_cron_current_setting(self, *args):
        currentSchg = self.cron_str_var.get()
        self.currentSchg_cron['text'] = "Cron Exp: {}".format(currentSchg)
                                  
        try:
            sched = self.cron_module.CronSchedule(cron_expr=currentSchg, log=self.log)
            next_run = sched.next_run_after(self.cron_module.datetime.datetime.now())
            self.currentSchg_nextRun_header.set("Next run would be:")
            self.currentSchg_nextRun_date.set(next_run)
            desc = "Next run: {}".format(next_run)
        except Exception as e:
            self.currentSchg_nextRun_header.set("Invalid cron:")
            self.currentSchg_nextRun_date.set(e)
            self.log.debug(traceback.format_exc())       
            desc = "Invalid cron: {}".format(e) 
        self.nextRun_var.set(desc)

        currentSchgAry = currentSchg.split(' ')        
        labels = ["Minutes", "Hours", "Days of Month", "Months", "Days of Week"]
        for i, lbl in enumerate(labels):
            lb = getattr(self,"desc_Cons_{}".format(lbl), None)
            if lb:
                lb['text'] = (currentSchgAry[i] if len(currentSchgAry) > i else "")


    def _save(self):
        self._update_cron_current_setting()
        self.cfg.setdefault("schedule", {})["cron"] = self.cron_str_var.get()
        self.cfg["retentionCount"] = self.retention_var.get()
        save_config(self.cfg_File, self.cfg)
        messagebox.showinfo("Schedule", "Cron schedule and retention count updated.")
        self.log.debug("Cron schedule and retention count updated.")
        self.back_callback()


class BackupSettingsFrame(tk.Frame):
    """
    Edit global backup settings:
      - backupLocation
      - backupServerIps
      - auth.default (domain, username, [password])
    """
    def __init__(self, master, cfg, cfg_File, back_callback, log=get_logger()):
        self.log = log
        tk.Frame.__init__(self, master)
        self.cfg = cfg
        self.cfg_File = cfg_File
        self.back_callback = back_callback

        # Read current values
        backup_location = self.cfg.get("backupLocation", "")
        backup_servers = self.cfg.get("backupServerIps", []) or []
        auth_default = self.cfg.get("auth", {}).get("default", {}) or {}

        # --- Layout (scrollable like ComputerEditFrame) ---
        canvas = tk.Canvas(self)
        scrollbar = tk.Scrollbar(self, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        tk.Label(inner, text="Backup Settings", font=("TkDefaultFont", 10, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w", padx=6, pady=6
        )

        # backupLocation
        tk.Label(inner, text="Backup Location (share\\subpath):").grid(row=1, column=0, sticky="e", padx=6, pady=2)
        self.backup_loc_var = tk.StringVar(value=backup_location)
        tk.Entry(inner, textvariable=self.backup_loc_var, width=48).grid(row=1, column=1, sticky="w", padx=6, pady=2, columnspan=2)

        # backupServerIps (reuse EditableTable)
        tk.Label(inner, text="Backup Server IPs").grid(row=2, column=0, sticky="w", padx=6, pady=(12, 4))
        self.servers_tbl = EditableTable(inner, backup_servers, "Servers")
        self.servers_tbl.grid(row=3, column=0, columnspan=3, sticky="ew", padx=6, pady=6)

        # auth.default
        tk.Label(inner, text="Auth Default - Domain:").grid(row=4, column=0, sticky="e", padx=6, pady=2)
        self.domain_var = tk.StringVar(value=auth_default.get("domain", ""))
        tk.Entry(inner, textvariable=self.domain_var, width=28).grid(row=4, column=1, sticky="w", padx=6, pady=2)

        tk.Label(inner, text="Auth Default - Username:").grid(row=5, column=0, sticky="e", padx=6, pady=2)
        self.username_var = tk.StringVar(value=auth_default.get("username", ""))
        tk.Entry(inner, textvariable=self.username_var, width=28).grid(row=5, column=1, sticky="w", padx=6, pady=2)

        tk.Label(inner, text="Auth Default - Password:").grid(row=6, column=0, sticky="e", padx=6, pady=2)
        # Leave blank to keep existing encrypted value
        self.password_var = tk.StringVar(value=auth_default.get("password", ""))
        tk.Entry(inner, textvariable=self.password_var, width=28, show="*").grid(row=6, column=1, sticky="w", padx=6, pady=2)

        # Actions
        actions = tk.Frame(inner)
        actions.grid(row=7, column=0, columnspan=3, sticky="ew", pady=10)
        tk.Button(actions, text="Save", command=self._save).pack(side=tk.RIGHT, padx=6)
        tk.Button(actions, text="Cancel", command=self.back_callback).pack(side=tk.RIGHT, padx=6)

    def _save(self):
        # Persist to cfg
        self.cfg["backupLocation"] = (self.backup_loc_var.get() or "").strip()
        self.cfg["backupServerIps"] = self.servers_tbl.get_items() or []

        self.cfg.setdefault("auth", {}).setdefault("default", {})
        self.cfg["auth"]["default"]["domain"] = (self.domain_var.get() or "").strip()
        self.cfg["auth"]["default"]["username"] = (self.username_var.get() or "").strip()

        pw = self.password_var.get()
        # If user left it blank, do NOT overwrite; only set if provided
        if pw:
            self.cfg["auth"]["default"]["password"] = pw

        # Save via existing helper (handles DPAPI/encryption)
        save_config(self.cfg_File, self.cfg)

        messagebox.showinfo("Backup Settings", "Global backup settings updated.")
        # Return to home
        self.back_callback()

class iconVarClass:
    # this was lazy
    pass

# ---------- Main App ----------
class BackupManagerGUI(tk.Tk):
    def __init__(self, cfg_File, serviceName="Backup Tool Service", runningPath=None, log=get_logger()):
        tk.Tk.__init__(self)

        self.log = log
        self.service_name = serviceName
        self.title("Backup Config Manager")
        self.geometry("1000x700")
        try:
            if runningPath:
                self.icon_path="{}/img/GUI_Img.ico".format(runningPath)
                iconVarClass.icon_path = self.icon_path
                self.iconbitmap(self.icon_path)
        except Exception:
            pass  # icon is optional
        self.runningPath = runningPath
        self.installDir = os.path.dirname(cfg_File)

        # State
        self.cfg_File = cfg_File
        self.cfg = load_config(cfg_File)
        self.runEvt = threading.Event()
        self.is_installed = False
        self.service_controller = ServiceController(serviceName)
        self.run_controller = runOnce_Controller(run_backup_once, cfg_File, log=self.log)

        # SMB session cache reused across the UI (like upload paths)
        self._smb_cache = SMBSessionCache()

        # Containers + view registry
        self.main_frame = tk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self._frames = {}                  # name -> frame
        self._subframe_container = None    # container for add/edit/delete subviews
        self._current_subframe = None      # currently shown subframe

        # Build views once and register
        self._build_main()                 # registers 'home'
        self._Build_download_backup()      # registers 'download'
        self._Build_schedule_backup()      # registers 'schedule'
        self._Build_backup_settings()  # registers 'backup_settings'
        self._show_view('home')

        # Status refresh
        self._schedule_status_updates()

    # ---- view registry helpers ----
    def _register_view(self, name, frame):
        self._frames[name] = frame

    def _hide_all(self):
        for f in self._frames.values():
            f.pack_forget()

    def _show_view(self, name):
        self._hide_all()
        self._frames[name].pack(fill=tk.BOTH, expand=True)

    # ---- Main View ----
    def _build_main(self):
        # Build once, then register; do not destroy on navigation
        if hasattr(self, 'home_frame') and self.home_frame.winfo_exists():
            return
        self.home_frame = tk.Frame(self.main_frame)
        self._register_view('home', self.home_frame)

        top = tk.Frame(self.home_frame)
        top.pack(fill=tk.X, padx=8, pady=8)
        tk.Button(top, text="Backup Settings", command=self._show_backup_settings).pack(side=tk.LEFT, padx=4)
        tk.Button(top, text="Add Computer",    command=self._show_add).pack(side=tk.LEFT, padx=4)
        tk.Button(top, text="Edit Computer",   command=self._show_edit_select).pack(side=tk.LEFT, padx=4)
        tk.Button(top, text="Remove Computer", command=self._show_delete_select).pack(side=tk.LEFT, padx=4)
        tk.Button(top, text="Schedule",        command=self._show_schedule).pack(side=tk.LEFT, padx=4)
        tk.Label(top, text="").pack(side=tk.LEFT, expand=True)
        tk.Button(top, text="Download Backup", command=self._show_download_backup).pack(side=tk.RIGHT, padx=4)

        # Separator
        ttk.Separator(self.home_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=8, pady=8)

        # Service controls
        svc = tk.Frame(self.home_frame)
        svc.pack(fill=tk.X, padx=8, pady=6)
        tk.Label(svc, text="Service Status:").pack(side=tk.LEFT)
        self.service_status_label = tk.Label(svc, text="UNKNOWN", fg="blue", bg="white", relief="sunken", width=28)
        self.service_status_label.pack(side=tk.LEFT, padx=4)
        # self.service_name_entry = tk.Entry(svc, width=28)
        # self.service_name_entry.insert(0, self.service_controller.service_name or "")
        # self.service_name_entry.pack(side=tk.LEFT, padx=4)
        # tk.Button(svc, text="Apply",         command=self._apply_service_name).pack(side=tk.LEFT, padx=4)

        self.srvInstallBtn = tk.Button(svc, text="Install Service", command=self._Install_service)
        self.srvInstallBtn.pack(side=tk.LEFT, padx=6)

        self.srvStartBtn = tk.Button(svc, text="Start Service", command=self._start_service)
        self.srvStartBtn.pack(side=tk.LEFT, padx=6)

        self.srvStopBtn = tk.Button(svc, text="Stop Service",  command=self._stop_service)
        self.srvStopBtn.pack(side=tk.LEFT, padx=6)

        tk.Label(svc, text=" \n ").pack(side=tk.LEFT, padx=6)
        # tk.Label(svc, text="Run Now Cmd:").pack(side=tk.LEFT)
        self.run_cmd_entry = tk.Entry(svc, width=40)

        # Status line
        status = tk.Frame(self.home_frame)
        status.pack(fill=tk.X, padx=8, pady=8)        
        self.runBtnUpdate = False
        tk.Label(status, text="Manual back up status:").pack(side=tk.LEFT)
        self.run_cmd_entry = tk.Entry(status, width=40)
        self.run_status_label = tk.Label(status, text="Run: IDLE", fg="gray", bg="white", relief="sunken", width=28)
        self.run_status_label.pack(side=tk.LEFT, padx=6)        
        self.run_btn = tk.Button(status, text="Start Backup", command=self._run_now)
        self.run_btn.pack(side=tk.LEFT, padx=6)     
        self.stop_btn = tk.Button(status, text="Stop Backup", command=self.run_controller.stop)
        self.stop_btn.pack(side=tk.LEFT, padx=6)        

        # Table overview (read-only summary)
        table_frame = tk.Frame(self.home_frame)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        cols = ("Backups", "Excludes", "Host")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        self.tree.heading("Backups", text="Backups")
        self.tree.heading("Excludes", text="Excludes")
        self.tree.heading("Host",    text="Auth Host/IP")
        self.tree.column("Backups", width=460)
        self.tree.column("Excludes", width=360)
        self.tree.column("Host",     width=140)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._refresh_tree()

        # Subframe container (for selection/add/edit/delete flows)
        self._subframe_container = tk.Frame(self.home_frame)
        # Hidden by default; only shown when a sub-view is active
        self._subframe_container.pack_forget()

    def _refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        for item in self.cfg.get("computer2Backup", []):
            if not isinstance(item, dict):
                continue
            name = list(item.keys())[0]
            details = item[name]
            backups = ", ".join(details.get("Backups", []) or [])
            excludes = ", ".join(details.get("Exclude", []) or [])
            host = details.get("Host", "") or infer_host_from_paths(details.get("Backups", []) or []) or ""
            self.tree.insert("", "end", iid=name, values=(backups, excludes, host))

    def _show_download_backup(self):
        self._show_view('download')
        # self.list_download_files(server_var, backup_location)


    def list_download_files(self, server_var, backup_location ):
        self.download_file_listbox.delete(0, tk.END)
        host = server_var.get().strip()
        creds = self._creds_for(host)
        # Parse UNC path: \\server\share\rest -> we use selected server as host, UNC for share+rel
        try:
            # _, share, rel = utils.split_unc(backup_location)
            share, base_sub = utils.parse_backup_location(backup_location)
            remote_dir_rel = "/".join([p for p in [base_sub, self.tool_name] if p])


        except Exception as e:
            messagebox.showerror("UNC Error", "Could not parse backupLocation: {}".format(e))
            return
        try:          
            # SMBFileOps(self._smb_cache, self.cfg)
            file_ops = smb_ops.SMBFileOps(self._smb_cache, type("cfg", (), {"creds_for_host": lambda self_, h: creds})())
            files = file_ops.list_dir(host, share, remote_dir_rel)
            for f in files:
                self.download_file_listbox.insert(tk.END, f.filename)
        except Exception as e:
            errMsg = "Could not list files on //{}/{}:{}\nDomain: {}\nUser: {}\nError: {}".format(
                    host, share, remote_dir_rel, creds.get("domain"), creds.get("username"), e
                )
            get_logger().error(errMsg)
            get_logger().debug(traceback.format_exc())
            messagebox.showerror("SMB Error", errMsg)


    def _creds_for(self, host):
        # Try host-specific creds from auth.hosts; fall back to auth.default
        _, auth_host = find_auth_host(self.cfg, host)
        source = auth_host or self.cfg.get("auth", {}).get("default", {})
        return {
            "username": source.get("username", ""),
            # "password": source.get("password", ""),
            "password": PasswordManager.resolve_password(source),
            "domain":   source.get("domain", "")
        }

    def _Build_download_backup(self):
        downloadFrame = tk.Frame(self.main_frame)
        self._register_view('download', downloadFrame)

        # Read config values
        backup_location = self.cfg.get("backupLocation", "")
        backup_servers  = self.cfg.get("backupServerIps", [])
        auth_default    = self.cfg.get("auth", {}).get("default", {})
        tool_name = utils.hostname() if hasattr(utils, "hostname") else os.environ.get("COMPUTERNAME", "")
        self.tool_name = tool_name

        tk.Label(downloadFrame, text="Download Backup File", font=("TkDefaultFont", 12, "bold")).pack(anchor="w", padx=6, pady=6)
        tk.Label(downloadFrame, text="Backup Location: {}".format(backup_location)).pack(anchor="w", padx=6)
        tk.Label(downloadFrame, text="Backup Servers: {}".format(", ".join(backup_servers))).pack(anchor="w", padx=6)
        tk.Label(downloadFrame, text="Tool Name: {}".format(tool_name)).pack(anchor="w", padx=6)
        tk.Label(downloadFrame, text="Auth Domain: {}".format(auth_default.get("domain", ""))).pack(anchor="w", padx=6)
        tk.Label(downloadFrame, text="Auth Username: {}".format(auth_default.get("username", ""))).pack(anchor="w", padx=6)

        # Server selection
        server_var = tk.StringVar(value=backup_servers[0] if backup_servers else "")
        tk.Label(downloadFrame, text="Select Backup Server:").pack(anchor="w", padx=6)
        server_menu = ttk.Combobox(downloadFrame, textvariable=server_var, values=backup_servers, state="readonly")
        server_menu.pack(anchor="w", padx=6, pady=2)

        
        tk.Label(downloadFrame, text="{}'s avalible backup files".format(tool_name), font=("TkDefaultFont", 10, "bold")).pack(anchor="w", padx=6)

        downloadlistFrame = tk.Frame(downloadFrame)
        downloadlistFrame.pack(anchor="w", padx=6, pady=6)

        # Create Listbox
        self.download_file_listbox = tk.Listbox(
            downloadlistFrame,
            selectmode=tk.SINGLE,
            width=80,
            height=12
        )
        self.download_file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Create Scrollbar
        scroll = tk.Scrollbar(downloadlistFrame, orient=tk.VERTICAL)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        # Link Scrollbar and Listbox
        self.download_file_listbox.config(yscrollcommand=scroll.set)
        scroll.config(command=self.download_file_listbox.yview)


        tk.Button(downloadFrame, text="Load Backup File List", command=lambda: self.list_download_files(server_var, backup_location) ).pack(anchor="w", padx=6, pady=2)

        
        # t = threading.Thread(target=self.list_download_files, args=(server_var, backup_location) , name="list_download_files")
        # # t.daemon = True
        # t.start()

        # Download path selection
        download_path_var = tk.StringVar(value=os.path.expanduser("~"))
        tk.Label(downloadFrame, text="Download to:").pack(anchor="w", padx=6)
        tk.Entry(downloadFrame, textvariable=download_path_var, width=60).pack(anchor="w", padx=6)

        def pick_download_path():
            path = filedialog.askdirectory(title="Select Download Folder", initialdir=os.path.expanduser("~"))
            if path:
                download_path_var.set(path)

        tk.Button(downloadFrame, text="Browse...", command=pick_download_path).pack(anchor="w", padx=6, pady=2)

        # Download button
        def download_selected():
            sel = self.download_file_listbox.curselection()
            if not sel:
                messagebox.showinfo("Download", "Select a file to download.")
                return
            filename = self.download_file_listbox.get(sel[0])
            host = server_var.get().strip()
            creds = self._creds_for(host)
            try:
                # _, share, rel = utils.split_unc(backup_location)
                
                share, base_sub = utils.parse_backup_location(backup_location)
                remote_dir_rel = "/".join([p for p in [base_sub, self.tool_name] if p])

            except Exception as e:
                messagebox.showerror("UNC Error", "Could not parse backupLocation: {}".format(e))
                return
            local_dest = os.path.join(download_path_var.get(), filename)
            try:
                file_ops = smb_ops.SMBFileOps(self._smb_cache, type("cfg", (), {"creds_for_host": lambda self_, h: creds})())
                file_ops.download_file(host, share, os.path.join(remote_dir_rel, filename), local_dest)
                messagebox.showinfo("Download", "Downloaded '{}' to '{}'".format(filename, local_dest))
            except Exception as e:
                messagebox.showerror(
                    "Download Error",
                    "Could not download //{}/{}:{}\nDomain: {}\nUser: {}\nError: {}".format(
                        host, share, os.path.join(remote_dir_rel, filename), creds.get("domain"), creds.get("username"), e
                    )
                )

        tk.Button(downloadFrame, text="Download Selected File", command=download_selected).pack(anchor="w", padx=6, pady=8)
        tk.Button(downloadFrame, text="Cancel", command=self._back_to_main).pack(anchor="w", padx=6, pady=2)
        self.downloadFrame = downloadFrame

    def _show_schedule(self):
        self._show_view('schedule')

    def _Build_schedule_backup(self):
        self.scheduleFrame = ScheduleFrame(
            self.main_frame,
            self.cfg,
            log=self.log,
            cfg_File=self.cfg_File,
            back_callback=self._back_to_main,
            cron_module=cron_module
        )
        self._register_view('schedule', self.scheduleFrame)

    # ---- Selection / Add / Edit / Delete Flows ----
    def _show_edit_select(self):
        self._show_subframe(lambda parent: ComputerSelectionFrame(
            parent, self.cfg.get("computer2Backup", []), "edit", self._start_edit, self._back_to_main
        ))

    def _show_delete_select(self):
        self._show_subframe(lambda parent: ComputerSelectionFrame(
            parent, self.cfg.get("computer2Backup", []), "delete", self._perform_delete, self._back_to_main
        ))

    def _show_add(self):
        # empty add frame
        def build(parent):
            comp_data = {"Backups": [], "Exclude": [], "Host": ""}
            auth_data = {}
            return ComputerEditFrame(parent, "add", "", comp_data, auth_data, self._save_add, self._back_to_main)
        self._show_subframe(build)

    def _show_backup_location(self):
        # empty add frame
        def build(parent):
            comp_data = {"Backups": [], "Exclude": [], "Host": ""}
            auth_data = {}
            return ComputerEditFrame(parent, "add", "", comp_data, auth_data, self._save_add, self._back_to_main)
        self._show_subframe(build)        

    def _start_edit(self, name):
        # Hide selection, show edit frame populated
        idx, comp_data = find_computer_entry(self.cfg, name)
        if idx is None:
            messagebox.showerror("Edit", "Entry not found: {}".format(name))
            return
        host_val = comp_data.get("Host", "") or infer_host_from_paths(comp_data.get("Backups", []) or []) or ""
        _, auth_data = find_auth_host(self.cfg, host_val)

        def build(parent):
            return ComputerEditFrame(parent, "edit", name, comp_data, auth_data or {}, self._save_edit, self._back_to_main)
        self._show_subframe(build)

    def _perform_delete(self, name):
        idx, comp_data = find_computer_entry(self.cfg, name)
        if idx is None:
            messagebox.showerror("Delete", "Entry not found: {}".format(name))
            return
        host = comp_data.get("Host", "") or infer_host_from_paths(comp_data.get("Backups", []) or []) or ""
        del self.cfg["computer2Backup"][idx]
        if host:
            remove_auth_host(self.cfg, host)
        save_config(self.cfg_File, self.cfg)
        messagebox.showinfo("Delete", "Deleted '{}'".format(name))
        self._back_to_main()

    def _save_add(self, data):
        # Add new computer and auth
        name = data.get("name")
        if not name:
            messagebox.showerror("Add", "Computer name is required.")
            return
        # Prevent duplicate names
        idx, _ = find_computer_entry(self.cfg, name)
        if idx is not None:
            messagebox.showerror("Add", "Computer '{}' already exists.".format(name))
            return
        comp_details = {
            "Backups": data.get("Backups", []),
            "Exclude": data.get("Exclude", [])
        }
        host = data.get("Host", "") or infer_host_from_paths(comp_details.get("Backups", []) or []) or ""
        if host:
            comp_details["Host"] = host
        self.cfg["computer2Backup"].append({name: comp_details})
        auth = data.get("auth", {})
        upsert_auth_host(self.cfg, host, auth.get("username"), auth.get("domain"), auth.get("password"))
        save_config(self.cfg_File, self.cfg)
        messagebox.showinfo("Add", "Added '{}'".format(name))
        self._back_to_main()


    def _save_edit(self, data):
        old_name = None
        if hasattr(self, 'tree') and self.tree and self.tree.winfo_exists():
            sel = self.tree.selection()
            if sel:
                old_name = sel[0]
            else:
                sel = []
        # If not using selection, use provided name for lookup
        target_name = old_name or data.get("name")
        idx, comp = find_computer_entry(self.cfg, target_name)
        if idx is None:
            # If the name was changed, try old target via UI field
            idx, comp = find_computer_entry(self.cfg, data.get("name"))
            if idx is None:
                messagebox.showerror("Save", "Entry not found for '{}'".format(target_name))
                return
        old_host = comp.get("Host", "") or infer_host_from_paths(comp.get("Backups", []) or []) or ""
        new_host = data.get("Host", "") or infer_host_from_paths(data.get("Backups", []) or []) or ""

        # Update details (support rename)
        new_name = data.get("name")
        self.cfg["computer2Backup"][idx] = {
            new_name: {
                "Backups": data.get("Backups", []),
                "Exclude": data.get("Exclude", [])
            }
        }
        if new_host:
            self.cfg["computer2Backup"][idx][new_name]["Host"] = new_host

        # Update auth
        auth = data.get("auth", {})
        if old_host and old_host != new_host:
            # Move old auth if host changed
            remove_auth_host(self.cfg, old_host)
            upsert_auth_host(self.cfg, new_host, auth.get("username"), auth.get("domain"), auth.get("password"))
        save_config(self.cfg_File, self.cfg)
        messagebox.showinfo("Save", "Saved changes for '{}'".format(new_name))
        self._back_to_main()


    def _show_backup_settings(self):
        self._show_view('backup_settings')


    def _Build_backup_settings(self):
        frame = BackupSettingsFrame(
            self.main_frame,
            self.cfg,
            cfg_File=self.cfg_File,
            back_callback=self._back_to_main,
            log=self.log,
        )
        self._register_view('backup_settings', frame)


    # ---- Subframe host ----
    def _show_subframe(self, builder):
        # show home, then overlay the subframe container with built content
        self._show_view('home')
        # clear previous subframe without touching other views
        if self._current_subframe and self._current_subframe.winfo_exists():
            self._current_subframe.pack_forget()
            self._current_subframe.destroy()  # destroy only the inner subframe
            self._current_subframe = None
        self._subframe_container.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        frame = builder(self._subframe_container)
        if isinstance(frame, tk.Frame):
            frame.pack(fill=tk.BOTH, expand=True)
            self._current_subframe = frame

    def _back_to_main(self):
        # hide subframe and return to home view (preserving widgets)
        if self._current_subframe and self._current_subframe.winfo_exists():
            self._current_subframe.pack_forget()
            self._current_subframe.destroy()
            self._current_subframe = None
        if self._subframe_container and self._subframe_container.winfo_exists():
            self._subframe_container.pack_forget()
        self._show_view('home')
        self._refresh_tree()


    # ---- Service / Run-now ----
    def _Install_service(self):  
        try: 
            wrapperDir = os.path.join(self.runningPath,"Wrapper")
            files = ["BackupToolWrapper.exe", "BackupToolWrapper.xml"]
            for file in files:
                shutil.copy2(os.path.join(wrapperDir,file), self.installDir)

            self.bin_path = os.path.join(self.installDir,"BackupToolWrapper.exe")
            ok, msg = self.service_controller.install_service(self.service_name,
                            self.service_name,
                            self.bin_path,
                            start_type='auto',
                            description='Backup Tool Service')
            
            if not ok:
                messagebox.showerror("Install Service", msg)
            else:
                messagebox.showinfo("Install Service", msg)
            self._update_status_once()
        except Exception as e:
            self.log.error(e)
            messagebox.showerror("Install Service", e)
            self.log.debug(traceback.format_exc())

    def _start_service(self):
        ok, msg = self.service_controller.start()
        if not ok:
            messagebox.showerror("Start Service", msg)
        else:
            messagebox.showinfo("Start Service", msg)
        self._update_status_once()

    def _stop_service(self):
        ok, msg = self.service_controller.stop()
        if not ok:
            messagebox.showerror("Stop Service", msg)
        else:
            messagebox.showinfo("Stop Service", msg)
        self._update_status_once()

    def _run_now(self):
        if self.run_controller.is_running():
            messagebox.showinfo("Run Now", "A run-now task is already in progress.")
            return
        self.runEvt.set() 
        ok, msg = self.run_controller.start()
        if not ok:
            messagebox.showerror("Run Now", msg)
            return
        self.run_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL) # Will add this at some point.. or I would like to
        self.run_status_label.config(text="Run: IN PROGRESS", fg="#228B22")

        t = threading.Thread(target=self._watch_run, name="runOnce_Task_Watcher")
        t.daemon = True
        t.start()

    def _watch_run(self):
        thread_name = threading.current_thread().name
        self.log.debug("Starting [{}] thread".format(thread_name))             
        try:
            while self.run_controller.is_running():
                time.sleep(1)
        finally:
            self.log.debug("is_running = False")


    # ---- Status refresh ----
    def _update_status_once(self):
        try:          
            # Services check and install if needed   
            if self.is_installed:
                self.srvStartBtn.pack(side=tk.LEFT, padx=6)
                self.srvStopBtn.pack(side=tk.LEFT, padx=6)
                self.srvInstallBtn.pack_forget()
                running = self.service_controller.is_running()
                if running:
                    self.service_status_label.config(text="RUNNING", fg="#228B22")
                else:
                    self.service_status_label.config(text="STOPPED",  fg="red")
            else:
                self.srvStartBtn.pack_forget()
                self.srvStopBtn.pack_forget()
                self.srvInstallBtn.pack(side=tk.LEFT, padx=6)
                self.service_status_label.config(text="Not Installed",  fg="gray")
                self.is_installed = self.service_controller.check_install(self.service_name)
                
            
            # manual run status
            if self.run_controller.is_running():
                self.runBtnUpdate = True
                self.run_status_label.config(text="Run: IN PROGRESS", fg="#228B22")
            elif self.runBtnUpdate:
                self.runBtnUpdate = False
                self.run_btn.config(state=tk.NORMAL)
                # self.stop_btn.config(state=tk.DISABLED)         
                self.run_status_label.config(text="Run: IDLE", fg="gray")
                messagebox.showinfo("Run Now", "Run-now task finished.")
        except Exception as e:
            self.log.error(e)
            self.log.debug(traceback.format_exc())

    def _schedule_status_updates(self):
        self._update_status_once()
        self.after(500, self._schedule_status_updates)

# ---------- Main ----------
def main():
    app = BackupManagerGUI()
    app.mainloop()

if __name__ == "__main__":
    main()
