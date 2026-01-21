# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import threading
import traceback

try:
    import yaml
except Exception:
    yaml = None

from .cron import CronSchedule
from .simpleLogger import get_logger
from .passwords import PasswordManager
from .utils import ensure_dir, normcase_nopath

DEFAULT_RETENTION = 14
DEFAULT_TEMP_SUBDIR = "ToolBackups"
CONFIG_WATCH_INTERVAL_SEC = 5

class Config(object):
    def __init__(self, cfg_dict, path, log=get_logger()):
        self.log = log
        self._raw = cfg_dict or {}
        self.path = path
        self.mtime = self._safe_mtime(path)
        self._normalize()

    @staticmethod
    def _safe_mtime(path):
        try:
            return os.path.getmtime(path)
        except Exception:
            return 0.0

    def _normalize(self):
        d = self._raw or {}

        self.backup_ips = d.get("backupServerIps") or d.get("bakupServerIps") or []
        self.backup_location = d.get("backupLocation") or d.get("backupLaocation") or ""
        self.retention = int(d.get("retentionCount") or DEFAULT_RETENTION)
        
        self.logLvl = d.get("logLvl") or 2
        self.VerNum = d.get("Version") or 2        
        self.temp_root = d.get("tempRoot") or os.path.join(os.environ.get("TEMP", r"C:\Temp"), DEFAULT_TEMP_SUBDIR)
        try:
            ensure_dir(self.temp_root)
        except:
            curretnDir = os.path.dirname(os.path.abspath(self.path))
            self.temp_root = os.path.join(curretnDir,'TempDir')
            ensure_dir(self.temp_root)


        self.auth_default = (d.get("auth") or {}).get("default") or {}
        self.auth_hosts = (d.get("auth") or {}).get("hosts") or []
        self.auth_dpapi_scope = ((d.get("auth") or {}).get("dpapiScope") or "machine").strip().lower()

        sch = d.get("schedule") or {}
        cron = sch.get("cron")
        weekly = sch.get("weekly")
        monthly = sch.get("monthly")
        daily = sch.get("daily")
        interval = sch.get("intervalMinutes")
        self.schedule = CronSchedule(cron_expr=cron, weekly=weekly, monthly=monthly, daily=daily, interval_minutes=interval, log=self.log)
        # self.schedule = CronSchedule(cron_expr=cron, weekly=weekly, monthly=monthly, daily=daily, interval_minutes=interval)

        self.computers = []
        arr = d.get("computer2Backup") or []
        for item in arr:
            if isinstance(item, dict):
                for label, body in item.items():
                    # at some poitn should move the cred stuff here too I think it would make more sense 
                    self.computers.append({
                        "label": (body or {}).get("hostName") or label,
                        "host": (body or {}).get("Host") or None,
                        "backups": (body or {}).get("Backups") or [],
                        "exclude": [normcase_nopath(p) for p in ((body or {}).get("Exclude") or [])],
                    })

    def creds_for_host(self, host):
        for entry in self.auth_hosts:
            if (entry.get("host") or "").lower() == host.lower():
                return entry
        return self.auth_default or {}

    def __repr__(self):
        return "Config(ips=%r, location=%r, retention=%r, temp=%r, comps=%d, logLvl=%d)" % (
            self.backup_ips, self.backup_location, self.retention, self.temp_root, len(self.computers), self.logLvl
        )


class ConfigLoader(threading.Thread):
    daemon = True

    def __init__(self, path, on_change_cb, log=get_logger()):
        threading.Thread.__init__(self, name="ConfigWatcher")
        self.path = path
        self.log = log
        self.on_change_cb = on_change_cb
        self.stop_evt = threading.Event()
        self._last_mtime = 0.0

    def load_now(self):
        if yaml is None:
            raise RuntimeError("PyYAML is not installed.")
        with open(self.path, "rb") as f:
            data = yaml.safe_load(f) or {}
        try:
            if PasswordManager.sanitize_and_persist_config(data, self.path):
                with open(self.path, "rb") as f2:
                    data = yaml.safe_load(f2) or {}
        except Exception as e:
            self.log.error("Config sanitization failed: {}".format( e))
        cfg = Config(data, self.path, self.log)
        self.log.info("Loaded config: {}".format(cfg))
        return cfg

    def run(self):
        thread_name = threading.current_thread().name
        self.log.debug("Starting [{}] thread".format(thread_name))        
        try:
            cfg = self.load_now()
            self._last_mtime = cfg.mtime
            self.on_change_cb(cfg)
        except Exception as e:
            self.log.error("Initial config load failed: {}\{}".format( e, traceback.format_exc()))

        while not self.stop_evt.is_set():
            try:
                mtime = Config._safe_mtime(self.path)
                if mtime > self._last_mtime:
                    cfg = self.load_now()
                    self._last_mtime = mtime
                    self.on_change_cb(cfg)
            except Exception as e:
                self.log.error("Config reload failed: {}".format( e))
            self.stop_evt.wait(timeout=CONFIG_WATCH_INTERVAL_SEC)
        self.log.debug("Stopping [{}] thread...".format(thread_name))  

    def stop(self):
        self.stop_evt.set()
