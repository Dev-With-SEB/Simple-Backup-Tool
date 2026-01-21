# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import re
import threading
import traceback

# from logging_setup import get_logger
from .simpleLogger import get_logger
# log = simpleLogger.get_logger()
# from concurrent.futures import ThreadPoolExecutor


from .utils import sanitize_for_fs, ensure_dir, yyyymmdd, yyyymmddHHMM, zip_folder, delete_dir_quiet, canonical_for_exclude
from .utils import is_remote_unc, split_unc, isComputerOnline, delete_file, parse_backup_location, normcase_nopath

def regex(regexStr, path, log):
    rx = re.compile(regexStr, re.IGNORECASE)
    if bool(rx.search(path)):
        log.verbose("**Excluded: {}".format(path))
        return True  
    return False  
    # match = re.search(regexStr, path)
    # if match:
    #     log.verbose("**Excluded: {}".format(path))
    #     return True  
    # return False  


class Copier(object):
    def __init__(self, smb_ops, exclude_list, log=get_logger(), runEvt=threading.Event()):
        self.log = log
        self.smb = smb_ops
        self.runEvt = runEvt
        self.exclude = set(exclude_list or [])

    def _excluded_Chk(self, path):
        self.log.verbose("Checking: {}".format(path))
        try:
            for ex in self.exclude:
                # could build this into the confloader and have this part check instance as the conf loader fixes paths it should probly make the reg stuff too ... one thing at a time I guess
                if ex.startswith('regex '):
                    regStr = ex[len('regex '):]
                    self.log.verbose("Using regex: {}".format(regStr)) 
                    # if regex(ex.lstrip('regex '), path, self.log):
                    if regex(regStr, path, self.log):
                        return True
                elif '*' in ex:
                    wildcard_rx = ex.replace('\\','\\\\').replace('$','\$').replace('.','\.').replace('*','.*')
                    # escaped = re.escape(ex)
                    # wildcard_rx = escaped.replace(r'\*', '.*')
                    if regex(wildcard_rx, path, self.log):
                        return True
                elif path.startswith(ex):
                    self.log.verbose("**Excluded: {}".format(path))
                    return True
            self.log.verbose("Copying: {}".format(path))  
            # print("Copying `{}` -> TmpDir".format(path) , end='')      
            return False
        except Exception as e:
            self.log.warning(e)
            self.log.debug(str(traceback.format_exc()))  
            raise
        

    def _excluded_local(self, path_abs):        
        p = normcase_nopath(path_abs)
        return self._excluded_Chk(p)

    def _excluded_remote(self, host, share, rel):
        canon = canonical_for_exclude(host, share, rel)
        return self._excluded_Chk(canon)
        # for ex in self.exclude:
        #     if ex.startswith('regex '):
        #         return regex(ex.lstrip('regex '), canon, self.log)            
        #     elif '*' in ex:
        #         ex = ex.replace('\\','\\\\').replace('$','\$').replace('.','\.').replace('*','.*')
        #         match = re.search(ex, canon)
        #         if match:
        #             self.log.verbose("Excluded: {}".format(canon))
        #             return True
        #     elif canon.startswith(ex):
        #         return True
        # return False

    def copy_src_to(self, src, comp_dir):
        if is_remote_unc(src):
            try:
                copied = self._copy_local_tree(src, comp_dir, _unc_probe=True)
                if copied > 0:
                    self.log.info("UNC copy OK for {} (files={})".format(src, copied))
                    return
                self.log.warning("UNC produced no files for {}; falling back to SMB.".format(src))
            except Exception as e:
                self.log.warning("UNC copy failed for {}; falling back to SMB. ({})".format(src, e))
            host, share, rel = split_unc(src)
            self._copy_remote_tree(host, share, rel, comp_dir)
        else:
            self._copy_local_tree(src, comp_dir, _unc_probe=False)

    def _copy_local_tree(self, src_path, dest_root, _unc_probe=False):
        import shutil
        src_path = os.path.normpath(src_path)

        if not os.path.exists(src_path):
            raise IOError("Path not found or inaccessible: {}".format(src_path))

        if self._excluded_local(src_path):
            self.log.info("Excluded local path: {}".format(src_path))
            return 0

        files_copied = 0
        subname = sanitize_for_fs(src_path)
        target = os.path.join(dest_root, subname)
        ensure_dir(target)

        if os.path.isdir(src_path):
            for root, dirs, files in os.walk(src_path):
                try:
                    if self._excluded_local(root):
                        dirs[:] = []
                        continue
                    rel = os.path.relpath(root, src_path)
                    rel = "" if rel == "." else rel
                    out_dir = os.path.join(target, rel)
                    ensure_dir(out_dir)
                    for f in files:
                        if not self.runEvt.is_set(): return ('runEvt', 'Stopped', 'in computer loop')
                        src_f = os.path.join(root, f)
                        if self._excluded_local(src_f):
                            continue
                        try:
                            shutil.copy2(src_f, os.path.join(out_dir, f))
                            files_copied += 1
                        except Exception as e:
                            self.log.warning("Copy local failed: {} -> {} ({})".format(src_f, out_dir, e))
                except Exception as e:
                    self.log.warning("UNC list failed at {} ({})".format(root, e))
        else:
            try:
                ensure_dir(target)
                shutil.copy2(src_path, os.path.join(target, os.path.basename(src_path)))
                files_copied = 1
            except Exception as e:
                if _unc_probe and is_remote_unc(src_path):
                    raise
                self.log.warning("Copy local file failed: {} ({})".format(src_path, e))

        return files_copied

    def _copy_remote_tree(self, host, share, rel_root, dest_root):
        rel_root = rel_root.replace("\\", "/").lstrip("/")
        subname = sanitize_for_fs(r"\\{}\{}\{}".format(host, share, rel_root))
        target = os.path.join(dest_root, subname)
        ensure_dir(target)        

        try:
            entries = None
            try:
                # true/false = self.smb.path_exists(self, host, share, rel_root)
                entries = self.smb.list_dir(host, share, rel_root)
            except Exception:
                entries = None

            if entries is None:
                if self._excluded_remote(host, share, rel_root):
                    self.log.info("Excluded remote file: \\{}\\{}\\{}".format(host, share, rel_root))
                    return
                out = os.path.join(target, os.path.basename(rel_root))
                try:
                    if not self.smb.dir_exists(host, share, rel_root): return 
                    self.smb.download_file(host, share, rel_root, out)
                except Exception as e:
                    self.log.warning("SMB download failed: \\{}\\{}\\{} -> {} ([{}] {})".format(
                        host, share, rel_root, out, e.__class__.__name__, e))
                    self.log.debug('{}'.format(traceback.format_exc()))
                return

            for is_dir, rel, entry in self.smb.iter_files_recursive(host, share, rel_root):
                if not self.runEvt.is_set(): return ('runEvt', 'Stopped', 'in computer loop')
                if is_dir:
                    if self._excluded_remote(host, share, rel):
                        continue
                    out_dir = os.path.join(target, os.path.relpath(rel, rel_root)) if rel_root else os.path.join(target, rel)
                    ensure_dir(out_dir)
                else:
                    if self._excluded_remote(host, share, rel):
                        continue
                    out_dir = os.path.join(target, os.path.relpath(os.path.dirname(rel), rel_root)) if rel_root else os.path.join(target, os.path.dirname(rel))
                    ensure_dir(out_dir)
                    out_file = os.path.join(out_dir, os.path.basename(rel))
                    try:
                        self.smb.download_file(host, share, rel, out_file)
                    except Exception as e:                        
                        self.log.warning("SMB file download failed: \\{}\\{}\\{} ([{}] {})".format(
                            host, share, rel, e.__class__.__name__, e))
                        self.log.debug('{}'.format(traceback.format_exc()))
        except Exception as e:
            self.log.error("Remote copy error from \\{}\\{}\\{}: {}".format(host, share, rel_root, e))
            self.log.debug('{}'.format(traceback.format_exc()))


class BackupRunner(object):
    def __init__(self, smb_ops, log=get_logger(), runEvt=threading.Event()):
        self.log = log
        self.smb = smb_ops
        self.runEvt = runEvt
        if not self.runEvt.is_set():
            self.runEvt.set()

    def run_backup(self, cfg):
        dt_str = yyyymmdd()
        work_dir = os.path.join(cfg.temp_root, dt_str)        
        delete_dir_quiet(work_dir, self.log) # <- Clean up if we stop without clean up last time
        ensure_dir(work_dir)
        self.log.info("Starting backup, working dir: {}".format(work_dir))

        for comp in cfg.computers:
            if not self.runEvt.is_set(): return ('runEvt', 'Stopped', 'in computer loop')
            label = comp["label"]
            hostToBackup = comp["host"]
            self.log.debug("Backing up {}".format(label))

            if not hostToBackup:
                self.log.warning("Config 'computer2Backup.{}.Host' is None.".format(label))
                self.log.info("To improve performance, add either the computer name or the IP under the 'Host' section.")
            elif not isComputerOnline(hostToBackup):
                self.log.warning("Could not find the '{}' host. Check to see if is online.".format(hostToBackup))
                continue

            comp_dir = os.path.join(work_dir, sanitize_for_fs(label))
            ensure_dir(comp_dir)
            copier = Copier(self.smb, comp.get("exclude") or [], self.log, self.runEvt)
            for src in (comp.get("backups") or []):
                if not self.runEvt.is_set(): return ('runEvt', 'Stopped', 'While moving files')
                try:
                    copier.copy_src_to(src, comp_dir)
                except Exception as e:
                    self.log.error("Copy error for {}: {}".format(src, e))

            # zip_path = os.path.join(cfg.temp_root, zip_name)        
            # zip_folder(work_dir, zip_path)

        self.log.info("Preping to Zip backups")
        from utils import hostname as _hn
        host_name = _hn()        
        zip_name = dt_str + ".zip"
        share, base_sub = parse_backup_location(cfg.backup_location)
        remote_dir_rel = "/".join([p for p in [base_sub, host_name] if p])
        remote_file_rel = "/".join([remote_dir_rel, zip_name]) if remote_dir_rel else zip_name
        self.log.verbose("remote_dir_rel: {}".format(remote_dir_rel))
        self.log.verbose("remote_file_rel: {}".format(remote_file_rel))
        
        
        host = self._pick_backup_host(cfg)

        if remote_dir_rel:
            #  Check and make if needed a Dir
            self.smb.ensure_remote_dir(host, share, remote_dir_rel)        

        # Check if the Zip file is in the Backup Dir already
        if self.smb.file_exists(host, share, remote_file_rel):
            dt_str = yyyymmddHHMM()
            zip_name = dt_str + ".zip"
            remote_file_rel = "/".join([remote_dir_rel, zip_name]) if remote_dir_rel else zip_name
        
        zip_path = os.path.join(cfg.temp_root, zip_name)
        
        delete_file(zip_path)

        if not self.runEvt.is_set(): 
            delete_dir_quiet(work_dir, self.log)
            delete_file(zip_path, self.log)      
            return ('runEvt', 'Stopped', 'PreZipping')
        
        try:
            zip_folder(work_dir, zip_path)
        except Exception as e:
            self.log.error("Zip failed: {}".format(e))            
            delete_file(zip_path, self.log)
            delete_dir_quiet(work_dir, self.log)
            raise
        
        if not self.runEvt.is_set(): 
            delete_dir_quiet(work_dir, self.log)
            delete_file(zip_path, self.log)            
            return ('runEvt', 'Stopped', 'After Zipping')
        
        self.log.info("Moving Zip to backup Dir: {}".format(remote_dir_rel))
        try:
            self.smb.upload_file(host, share, remote_file_rel, zip_path)
        except Exception as e:
            self.log.error("Upload to backup server failed ({}/{}/{}): {}".format(host, share, remote_file_rel, e))
            delete_dir_quiet(work_dir, self.log)
            raise
        delete_dir_quiet(work_dir, self.log)
        delete_file(zip_path, self.log)

        self._enforce_retention_remote(cfg, host, share, remote_dir_rel, cfg.retention)
        self.log.info("Backup complete -> {}:{}/{}".format(host, share, remote_file_rel))
        return (host, share, remote_file_rel)
    

    def _pick_backup_host(self, cfg):
        last_err = None
        for ip in (cfg.backup_ips or []):
            try:
                self.log.debug(ip)
                _ = self.smb._conn_for(ip)
                return ip
            except Exception as e:
                last_err = e
                self.log.warning("Backup host not available yet: {} ({})".format(ip, e))
                continue
        if last_err:
            raise last_err
        raise RuntimeError("No backupServerIps configured")

    def _enforce_retention_remote(self, cfg, host, share, remote_dir_rel, keep_count):
        if not keep_count or keep_count <= 0:
            return
        try:
            entries = self.smb.list_dir(host, share, remote_dir_rel)
        except Exception as e:
            self.log.warning("Retention: could not list remote dir {}/{}/{} ({})".format(host, share, remote_dir_rel, e))
            return
        zips = [e for e in entries if (not e.isDirectory) and e.filename.lower().endswith(".zip")]
        if len(zips) <= keep_count:
            return
        import os as _os
        import datetime as _dt
        def key_fn(e):
            name, _ext = _os.path.splitext(e.filename)
            try:
                dt = _dt.datetime.strptime(name, "%Y%m%d")
            except Exception:
                dt = _dt.datetime.utcfromtimestamp(e.last_write_time or 0)
            return (dt, e.last_write_time or 0)
        zips.sort(key=key_fn)
        to_delete = zips[0:len(zips) - keep_count]
        for e in to_delete:
            try:
                rel = "/".join([remote_dir_rel, e.filename]) if remote_dir_rel else e.filename
                self.smb.delete_file(host, share, rel)
                self.log.info("Retention: deleted {}".format(e.filename))
            except Exception as ex:
                self.log.warning("Retention: failed delete {} ({})".format(e.filename, ex))
