# -*- coding: utf-8 -*-
from __future__ import print_function

# Compiled in Python27
# https://github.com/winsw/winsw/tree/v2.10.3

import os
import re
import sys
import time
import ctypes
import datetime
import traceback
import threading
try:
    import Queue as queue  # Py2
except Exception:
    import queue  # Py3
# --- Windows service bits ---
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
except Exception:
    win32serviceutil = None  # Running in console-only mode

__version__ = "0.0.7"


# from src.utils import config_path_default
from src.config_loader import ConfigLoader
from src.smb_ops import SMBSessionCache, SMBFileOps
from src.backup import BackupRunner
from src.scheduler_thread import Scheduler
from src.simpleLogger import get_logger, set_logger, logger
from src.GUI import BackupManagerGUI

tmplogLvl = 3
exePath = os.path.dirname(os.path.abspath(__file__))
try:
    # PyInstaller frozen app puts a temp dir in _MEIPASS; exe is sys.executable
    runningPath = sys._MEIPASS
    exePath = os.path.dirname(sys.executable)
except Exception:
    runningPath = exePath
    pass
runningFileName = os.path.splitext(os.path.basename(__file__))[0]
confgFile = os.path.join(exePath, 'backup_config.yaml')
logFile = os.path.join(exePath, '{}.log'.format(runningFileName))
# log = get_logger(name='Main', logFile=logFile, logLvl=3)
log = set_logger('Main',logger(name='Main', logFile=logFile, logLvl=tmplogLvl))


def confPull():    
    loader = ConfigLoader(confgFile, lambda cfg: None, log)
    cfg = loader.load_now()
    return cfg


def startupPrinter(VerNum, log, msg=None):
    starMsg = '\n' + '-' * 126
    starMsg += '\n ---------------------------- --Starting-- ---------------------------- '
    lineCount = 78
    verStrLine = 'Ver: ' + VerNum
    lenNeeded = (lineCount - len(verStrLine)) // 2
    starMsg += '\n' + '-' * lenNeeded + ' ' + verStrLine + ' ' + '-' * lenNeeded
    if msg:
        starMsg += '\n' + msg
    log.info(starMsg, toFile=True, prt=True)


class ToolBackup(object):
    def __init__(self):
        # # confPull()
        self.log = log
        self._cfg = None
        self._lastSch = None
        self._scheduler = None
        self.schedulerReload = False
        self._config_watcher = None
        self._run_now_q = queue.Queue()
        self._cfg_lock = threading.Lock()
        self._stop_evt = threading.Event()
        self._smb_cache = SMBSessionCache(self.log)
        self._smb_ops = SMBFileOps(self._smb_cache, None, self.log)  # cfg set later
        self._runner = BackupRunner(self._smb_ops, self.log)
        # self.log = get_logger(name='Main', logFile=logFile, logLvl=3)  # Lets start in Debug and change or dont once the conf loads
        self.log.info("Tool_backup service \nVer:{} \nConfig:{}\n".format(__version__, confgFile))


    def _on_config_change(self, cfg):
        with self._cfg_lock:
            self._cfg = cfg
            self._smb_ops.cfg = cfg
            if self.log and hasattr(cfg, 'logLvl') and self.log.logLvl != cfg.logLvl:
                self.log.logLvl = cfg.logLvl
            if self._scheduler.next_run is not None and self._lastSch != cfg.schedule:
                self._lastSch = cfg.schedule
                self.schedulerReload = True
                self._scheduler.next_run = None
        self.log.debug("Config updated: {}".format(cfg))


    def _get_cfg(self):
        with self._cfg_lock:
            return self._cfg


    def _start_threads(self, cfg_path):
        self._config_watcher = ConfigLoader(cfg_path, self._on_config_change, self.log)
        self._config_watcher.start()
        self._scheduler = Scheduler(self._get_cfg, self._run_now_q, self._stop_evt, self.schedulerReload, self.log)
        self._scheduler.start()
        t = threading.Thread(target=self._worker_loop, name="BackupWorker")
        # t.daemon = True
        t.setDaemon(True)
        t.start()
        self.log.info('Running')


    def _worker_loop(self):
        msg = None
        thread_name = threading.current_thread().name
        self.log.debug("Starting [{}] thread".format(thread_name))          
        while not self._stop_evt.is_set():
            try:
                try:
                    msg = self._run_now_q.get(timeout=1)
                except Exception:
                    continue
                if msg != "RUN":
                    continue
                self.log.verbose("Found 'RUN' in msg. Will try to run backup")
                cfg = self._get_cfg()
                if not cfg:
                    self.log.warning("No config loaded; skipping run")
                    continue
                try:
                    self._runner.run_backup(cfg)
                except Exception as e:
                    self.log.error("Backup run failed: {}".format(e))
                    self.log.debug(traceback.format_exc())
            except Exception as e:
                self.log.error("Worker error: {}".format(e))
                self.log.debug(traceback.format_exc())
        
        self.log.debug("Stopping [{}] thread...".format(thread_name))  


    def SvcStop(self):
        self.log.info("Service stopping...")
        self._stop_evt.set()
        if self._config_watcher:
            self._config_watcher.stop()
        self._smb_cache.close_all()
        for thread in threading.enumerate():
            if thread is not threading.current_thread() and thread.name not in ['IOPub', 'Heartbeat', 'Control', 'IPythonHistorySavingThread'] and '_log_' not in thread.name:
                target = getattr(thread, '_target',getattr(thread, '_Thread__target','Unknown'))
                match = re.search(r"<function (\w+) at", str(target))
                if match:   
                    target = match.group(1)             
                self.log.debug('Stopping running thread\n  Name: {}\n  Target: {}'.format(thread.name, target))        
                thread.join()


    def SvcDoRun(self):
        # cfg_path = config_path_default()
        self.log.info("Service starting")
        self._start_threads(confgFile)
        try:
            while not self._stop_evt.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.log.info('Terminated using [ctrl + c]/SIGINT, Shutting down!')
            shutDownCode = 130
        except Exception as e:
            shutDownCode = e.args[0]
            faultMsg = 'Exception: \n{}\n\n'.format(traceback.format_exc())
            self.log.critical('\n{}'.format(faultMsg))
        finally:
            self.SvcStop()
            self.log.info("Service stopped.")


# --- Console helpers (dev) ---
# this really could get cleaned up and maybe made a util as its kind of used twice. see run_backup_once in GUI
def run_once_console():        
    cfg = confPull()
    if tmplogLvl != cfg.logLvl:
        log.logLvl=cfg.logLvl

    startupPrinter(cfg.VerNum, log,)
    smb_cache = None
    log.debug("Running once in console")
    try:
        # these imports where for testing to make sure thye were there but 
        try:
            from smb.SMBConnection import SMBConnection as _S  # noqa
        except Exception:
            print("ERROR: pysmb is required. Install: pip install pysmb==1.2.6")
            return 1
        try:
            from win32crypt import CryptProtectData, CryptUnprotectData  # noqa
        except Exception:
            print("ERROR: pywin32 DPAPI not available. Install: pip install pywin32==228")
            return 1

    
        smb_cache = SMBSessionCache(log)
        smb_ops = SMBFileOps(smb_cache, cfg, log)
        runner = BackupRunner(smb_ops, log)

        host, share, rel = runner.run_backup(cfg)
        log.debug("Backup uploaded to //%s/%s/%s" % (host, share, rel))
        return 0
    
    except KeyboardInterrupt:
        log.info('Terminated using [ctrl + c]/SIGINT, Shutting down!')
    except Exception as e:
        log.warn("Backup FAILED: {}".format(e))
        import traceback
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




def protect_config_console():
    # confPull()
    from src.passwords import PasswordManager
    try:
        import yaml
    except Exception:
        print("ERROR: PyYAML is required. Install: pip install PyYAML==5.4.1")
        return 1
    cfg_path = confgFile
    with open(cfg_path, "rb") as f:
        data = yaml.safe_load(f) or {}
    changed = PasswordManager.sanitize_and_persist_config(data, cfg_path)
    print("Config sanitized: %s" % ("YES" if changed else "NO CHANGES"))
    return 0


helpMenu = """. 
Single run:
  Usage: '{0} [option] 
    --run : run a single backup
    --protect : encrypts passwords (DPAPI) and clears plaintext from config
    --service : Run in service mode. uses cron scheduling to auto backup
    --GUI : load GUI to edit Config options, start stop service if applicable Ect.
"""


def printHelpMenu():
    try:
        fname = os.path.split(sys.argv[0])[1]
    except Exception:
        fname = sys.argv[0]
    for line in helpMenu.format(fname).strip().split('\n'):
        print(line)

def runGUI():
    global log
    cfg = confPull()
    if tmplogLvl != cfg.logLvl:
        log = set_logger('Main',logger(name='Main', logFile=logFile, logLvl=cfg.logLvl))    
    if 3 > cfg.logLvl:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    app = BackupManagerGUI(cfg_File=confgFile, serviceName='Backup Tool Service', runningPath=runningPath, log=log)
    app.mainloop()

if __name__ == '__main__':
    # No noisy prints in service mode—keep stdout quiet for pywin32 CLI.
    syaArgCount = int(len(sys.argv))

    if syaArgCount <= 1:
        sys.exit(runGUI())

    # Dev/utility commands
    cmd = sys.argv[1].lower()
    if cmd in ('help', '--help', '/?'):        
        sys.exit(printHelpMenu())
    elif cmd in ('run', '--run'):
        sys.exit(run_once_console())
    elif cmd in ('protect', '--protect'):
        sys.exit(protect_config_console())
    elif cmd in ('GUI', '--GUI'):
        sys.exit(runGUI())

    elif cmd in ('service', '--service'):
        wapperClass = ToolBackup()
        # wapperClass.SvcDoRun()
        sys.exit(wapperClass.SvcDoRun())
    else:
        # log.logLvl = 3
        sys.exit(runGUI())
