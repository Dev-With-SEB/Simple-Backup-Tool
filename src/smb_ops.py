# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import threading
import socket
import traceback
# from logging_setup import get_logger
from . import simpleLogger

from .utils import hostname
from .passwords import PasswordManager

try:
    from smb.SMBConnection import SMBConnection
except Exception:
    SMBConnection = None


# Optional NetBIOS (bundled with pysmb's nmb). It's okay if missing.
try:
    from nmb.NetBIOS import NetBIOS
except Exception:
    NetBIOS = None


def _resolve_remote_name(ip, timeout=2):
    """
    Resolve a suitable 'remote_name' (server_name) for SMB:
      1) NetBIOS via nmb.NetBIOS (if available)
      2) Reverse DNS PTR via dnspython (if available)
      3) socket.gethostbyaddr
      4) fallback to the IP itself
    """
    log = simpleLogger.get_logger()

    # 1) NetBIOS
    if NetBIOS is not None:
        try:
            bios = NetBIOS()
            try:
                names = bios.queryIPForName(ip, timeout=timeout)
                if names and len(names) > 0:
                    nb = names[0]
                    if isinstance(nb, (list, tuple)):
                        nb = nb[0]
                    rn = (nb or "").strip().rstrip(".")
                    if rn:
                        log.debug("SMB name-resolve: NetBIOS {} -> {}".format(ip, rn))
                        return rn
            finally:
                try:
                    bios.close()
                except Exception:
                    pass
        except Exception as e:
            log.debug("SMB name-resolve: NetBIOS failed for {} ({})".format(ip, e))

    # 2) Reverse DNS via dnspython
    try:
        import dns.reversename as rev
        import dns.resolver as dres
        ptr = rev.from_address(ip)
        try:
            answers = dres.resolve(ptr, 'PTR', lifetime=timeout)  # dnspython >= 2
        except Exception:
            answers = dres.query(ptr, 'PTR', lifetime=timeout)    # dnspython 1.x (Py2)
        for r in answers:
            rn = str(r).strip().rstrip(".")
            if rn:
                log.debug("SMB name-resolve: rDNS {} -> {}".format(ip, rn))
                return rn
    except Exception as e:
        log.debug("SMB name-resolve: rDNS failed for {} ({})".format(ip, e))

    # 3) gethostbyaddr
    try:
        host, _aliases, _ips = socket.gethostbyaddr(ip)
        rn = (host or "").strip().rstrip(".")
        if rn:
            log.debug("SMB name-resolve: gethostbyaddr {} -> {}".format(ip, rn))
            return rn
    except Exception as e:
        log.debug("SMB name-resolve: gethostbyaddr failed for {} ({})".format(ip, e))

    # 4) fallback
    log.debug("SMB name-resolve: fallback to IP for {}".format(ip))
    return ip


class SMBSessionCache(object):
    def __init__(self,log=simpleLogger.get_logger()):
        self._lock = threading.Lock()
        self._conns = {}
        self.log = log 
        self.connInfo = dict()

    def _mk_conn(self, host, username, password, domain):
        if SMBConnection is None:
            raise RuntimeError("pysmb is not installed. `pip install pysmb==1.2.6`")
        
        # We already do this 
        # last_host = self.connInfo.get('host',None)
        # if last_host == host:    
        #     self.log.debug("host nmae matches the last one used trying to use the last connection")        
        #     conn = self.connInfo.get('conn',None)
        #     return conn


        client_name = hostname()
        remote_name = _resolve_remote_name(host, timeout=2)

        for port, is_direct in ((445, True), (139, False)):
            conn = SMBConnection(
                username or "",
                password or "",
                client_name,
                remote_name,
                domain=domain or "",
                use_ntlm_v2=True,
                is_direct_tcp=is_direct
            )        

            try:
                self.log.debug("SMB connect attempt: host={} remote_name={} port={} domain={} user={}".format(
                    host, remote_name, port, domain or "", username or ""))
                ok = conn.connect(host, port, timeout=5)
                if ok:
                    self.log.debug("SMB connect OK: {}:{} as {}\\{} (client={}, remote_name={})".format(
                        host, port, domain or "", username or "", client_name, remote_name))
                    self.connInfo.update({"host":host,"conn":conn})
                    return conn
            except Exception as e:
                self.log.error("SMB connect failed: {}:{} [{}] {}".format(host, port, e.__class__.__name__, e))
                self.log.debug("Traceback:\n{}".format(traceback.format_exc()))
        raise RuntimeError("Could not connect to SMB host {} (tried ports 445,139)".format(host))

    def get(self, host, creds):
        with self._lock:
            conn = self._conns.get(host)
            if conn:
                try:
                    conn.listShares(timeout=5)  # probe
                    return conn
                except Exception as e:
                    self.log.warning("SMB cached connection stale for {} -> dropping. [{}] {}".format(
                        host, e.__class__.__name__, e))
                    try:
                        conn.close()
                    except Exception:
                        pass
                    self._conns.pop(host, None)

            username = creds.get("username") or ""
            domain = creds.get("domain") or ""
            password = PasswordManager.resolve_password(creds)
            self.log.debug("SMB creds selected for {} -> domain={} user={} (pwd={}, encrypted={})".format(
                host, domain or "", username or "",
                "SET" if bool(password) else "EMPTY",
                "YES" if bool(creds.get("encryptedPassword")) else "NO"))

            conn = self._mk_conn(host, username, password, domain)
            self._conns[host] = conn
            return conn

    def close_all(self):
        with self._lock:
            for h, c in list(self._conns.items()):
                try:
                    c.close()
                except Exception:
                    pass
                self._conns.pop(h, None)


class SMBFileOps(object):
    def __init__(self, session_cache, cfg, log = simpleLogger.get_logger()):
        self.log = log
        self.cache = session_cache
        self.cfg = cfg

    def _conn_for(self, host):
        creds = self.cfg.creds_for_host(host)
        return self.cache.get(host, creds)

    def ensure_remote_dir(self, host, share, path_rel):
        conn = self._conn_for(host)
        parts = [p for p in path_rel.replace("\\", "/").split("/") if p]
        cur = ""
        for p in parts:
            cur = (cur + "/" + p).lstrip("/")
            try:
                conn.createDirectory(share, cur)
            except Exception:
                pass

    def pathFixer(self, path):
        # Normalize the provided path to a share-relative absolute path (leading "/")
        rel = (path or "/").replace("\\", "/")
        if not rel.startswith("/"):
            rel = "/" + rel
        # Collapse duplicated slashes (some servers are picky) should add this to the others... someday
        while "//" in rel:
            rel = rel.replace("//", "/")       
        return rel 


    def list_dir(self, host, share, path_rel):
        conn = self._conn_for(host)
        path_rel = path_rel.replace("\\", "/").lstrip("/")
        return [f for f in conn.listPath(share, path_rel or "/", timeout=10)
                if f.filename not in (".", "..")]

    def download_file(self, host, share, path_rel, local_dest):
        conn = self._conn_for(host)
        path_rel = path_rel.replace("\\", "/").lstrip("/")
        from utils import ensure_dir
        d = os.path.dirname(local_dest)
        if d:
            ensure_dir(d)
        with open(local_dest, "wb") as fp:
            conn.retrieveFile(share, "/" + path_rel, fp, timeout=30)

    def upload_file(self, host, share, path_rel, local_src):
        conn = self._conn_for(host)
        path_rel = path_rel.replace("\\", "/").lstrip("/")
        dir_rel = os.path.dirname(path_rel)
        if dir_rel and dir_rel != ".":
            self.ensure_remote_dir(host, share, dir_rel)
        with open(local_src, "rb") as fp:
            conn.storeFile(share, "/" + path_rel, fp, timeout=60)

    def delete_file(self, host, share, path_rel):
        conn = self._conn_for(host)
        path_rel = path_rel.replace("\\", "/").lstrip("/")
        try:
            conn.deleteFiles(share, "/" + path_rel, timeout=10)
        except Exception as e:
            self.log.warning("Failed to delete remote file {}/{}:{} ({})".format(share, path_rel, host, e))

    def path_exists(self, host, share, path_rel):
        try:
            _ = self.list_dir(host, share, path_rel)
            return True
        except Exception:
            return False


    def file_exists(self, host, share, path_rel):
        # Normalize path
        path_rel = path_rel.replace("\\", "/").lstrip("/")
        dir_name = "/".join(path_rel.split("/")[:-1]) or "/"
        file_name = path_rel.split("/")[-1]

        try:
            conn = self._conn_for(host)        
            files =  conn.listPath(share, dir_name or "/", timeout=10)
            
            # self.log.debug('file_exists:{}'.format([f.filename for f in files]))
            return any(f.filename == file_name for f in files)
        except Exception as e:
            self.log.error(e)
            self.log.debug(str(traceback.format_exc()))
            return False


    def iter_files_recursive(self, host, share, root_rel):
        stack = [root_rel.replace("\\", "/").lstrip("/")]
        while stack:
            cur = stack.pop()
            try:
                children = self.list_dir(host, share, cur)
            except Exception as e:
                self.log.warning("list_dir failed on {}/{}/{}: {}".format(host, share, cur, e))
                continue
            for f in children:
                rel = (cur + "/" + f.filename).lstrip("/")
                if f.isDirectory:
                    yield (True, rel, f)
                    stack.append(rel)
                else:
                    yield (False, rel, f)


    # noticing that there are assumptions that the share are theere and more error than we need. adding the share and Dir checks
    def share_exists(self, host, share, timeout=5):
        """
        Return True if the SMB share exists on the remote host, False otherwise.

        Behavior notes:
          - If we lack permission to list shares (ACCESS_DENIED), we attempt a
            minimal listPath("/") probe. If that is ACCESS_DENIED too, we still
            return True (share likely exists but is not accessible).
          - If the server reports STATUS_BAD_NETWORK_NAME/invalid share, we return False.
        """
        conn = self._conn_for(host)

        # Primary: enumerate shares (may be restricted on some servers)
        try:
            shares = conn.listShares(timeout=timeout)
            if any(getattr(s, "name", "").lower() == share.lower() for s in shares):
                return True
        except Exception as e:
            # Not all servers allow share enumeration; continue with fallback probe.
            self.log.warn("share_exists: listShares failed on {} [{}] {}".format(
                host, e.__class__.__name__, e))

        # Fallback: probe the share root
        try:
            # If the share exists but we lack permissions, many servers raise ACCESS_DENIED.
            _ = conn.listPath(share, "/", pattern="*", timeout=timeout)
            return True
        except Exception as e:
            msg = str(e).upper()
            # Typical "bad share" indicators
            if "STATUS_BAD_NETWORK_NAME" in msg or "INVALID SHARE" in msg or "SHARE NOT FOUND" in msg:
                return False
            if "STATUS_ACCESS_DENIED" in msg:
                self.log.warn("STATUS_ACCESS_DENIED")
                # We cannot list, but the share very likely exists.
                # Should probly kick out fals
                return True
            # Any other failure: conservatively report False
            self.log.warn("share_exists: fallback probe failed on {}/{} [{}] {}".format(
                host, share, e.__class__.__name__, e))
            return False



    def dir_exists(self, host, share, path_rel, timeout=5):
        """
        Return True if a directory exists at `path_rel` inside `share`, False otherwise.

        Resolution strategy:
          1) getAttributes on the exact path (fast and precise when supported).
          2) If that fails, list the parent directory and match the final segment by name.

        Notes:
          - Paths are normalized to forward slashes and ensured to be share-relative with a leading "/".
          - If ACCESS_DENIED prevents confirmation, we return False (unknown) to avoid false positives.
        """
        conn = self._conn_for(host)

        if not self.share_exists(host, share):
            return False

        rel = self.pathFixer(path_rel)

        # 1) Fast probe: attributes for the exact path
        try:
            attrs = conn.getAttributes(share, rel, timeout=timeout)
            # Some servers return a SharedFile-like object with isDirectory flag
            is_dir = bool(getattr(attrs, "isDirectory", False))
            return is_dir
        except Exception as e:
            # Fall through to parent listing; only log at DEBUG to keep noise low
            self.log.warn("dir_exists: getAttributes failed on {}/{}:{} [{}] {}".format(
                host, share, rel, e.__class__.__name__, e))

        # 2) Fallback: list the parent directory and look for the entry
        try:
            # Strip trailing "/" so split works reliably
            target = rel.rstrip("/")
            # If the target became empty (was root "/"), treat as existing dir
            if not target:
                return True

            parent, name = target.rsplit("/", 1)
            if not parent:
                parent = "/"

            entries = conn.listPath(share, parent, pattern="*", timeout=timeout)
            for f in entries:
                if f.filename == name:
                    return bool(getattr(f, "isDirectory", False))
            return False
        except Exception as e:
            msg = str(e).upper()
            if "STATUS_ACCESS_DENIED" in msg:
                # Cannot confirm existence due to permissions -> report False to avoid false positives.
                self.log.warn("dir_exists: access denied on {}/{}:{}".format(host, share, rel))
                return False
            self.log.warn("dir_exists: parent listing failed on {}/{}:{} [{}] {}".format(
                host, share, rel, e.__class__.__name__, e))
            return False
