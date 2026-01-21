# -*- coding: utf-8 -*-
from __future__ import print_function
import os
import re
import sys
import stat
import time
import traceback
# import psutil
try:
    import psutil
except ImportError:
    import psutil_3 as psutil
import zipfile
import shutil
import socket
import datetime
import dns.resolver
import dns.reversename
#from simpleLogger import get_logger
from . import simpleLogger
log = simpleLogger.get_logger()

try:
    basestring
except NameError:
    basestring = str


# UNC: \\host\share\rest...
_UNC_RE = re.compile(r'^\\\\(?P<host>[^\\\/]+)\\(?P<share>[^\\\/]+)(?P<rest>.*)$')
# IPv4 quick check
_IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def ping_host(host, port=22, timeout=3):
    e,boolVal=None,None
    try:
        with socket.create_connection((host, port), timeout=timeout):
            boolVal=True
    except Exception as e:
        if 'timed out' == str(e).strip():
            e,boolVal=(None,False)  
        elif '[Errno 11001] getaddrinfo failed' == str(e).strip():
            e,boolVal=None,False  
        elif '[Errno 10061] No connection could be made because the target machine actively refused it' == str(e).strip():
            e,boolVal=None,True
        elif '__exit__' == str(e).strip():
            e,boolVal=None,True
        elif '[Errno 11001] getaddrinfo failed' == str(e).strip():
            e,boolVal=None,False 
    finally:
        if e and boolVal is None: raise e
        else: return boolVal
    

def isComputerOnline(host):
    ports = [139,445]
    for port in ports:
        try:
            if ping_host(host, port=port):
                return True
        except Exception as e:
            raise e
    return False


def toolNameRe(strval):
    return re.search(r'([^.]+)\.gfoundries\.com', strval)


def nslookup_hostname(ip):    
    try:
        rev_name = dns.reversename.from_address(ip)
        answer = dns.resolver.query(rev_name, 'PTR')
        return str(answer[0])
    except Exception as e:
        raise e
        # log.debug(e)
        # log.debug('{}'.format(traceback.format_exc()))
    

def hostname():
    """
        10.100.100.104 -> VEST00231324
        10.11.178.226 -> VEST00231324
        127.0.0.1 -> VEST00231324
    """
    lastErr=None
    ipv4_addresses = []
    for interface, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == socket.AF_INET:
                ipv4_addresses.append(snic.address)

    toolName = None
    # Loop through and resolve hostnames
    for ip in ipv4_addresses:
        try:
            nsName = nslookup_hostname(ip)
            match = toolNameRe(nsName)
            if match:
                toolName = match.group(1)
                break
            else:
                hostname = socket.gethostbyaddr(ip)[0]

            match = toolNameRe(hostname)
            if match:
                toolName = match.group(1)
                # Return host Name
                break
        except socket.herror:
            raise "{} -> Hostname could not be resolved".format(ip)
        except Exception as e:
            lastErr=e

    if not toolName:
        toolName = socket.gethostname()
        

    if toolName:
        toolNameLower = toolName.lower()
        if toolNameLower.startswith('p08'):
            toolName = toolName[3:]
        # if toolNameLower.endswith('eda'):
            # toolName = toolName[:-3]
        return toolName.upper()
    elif lastErr: raise lastErr



def parse_backup_location(loc):
    loc = (loc or "").strip().strip("\\/").replace("\\", "/")
    if not loc:
        raise ValueError("backupLocation is missing")
    parts = loc.split("/")
    share = parts[0]
    base_sub = "/".join(parts[1:]) if len(parts) > 1 else ""
    return share, base_sub


def ensure_dir(path):
    if path and not os.path.isdir(path):
        os.makedirs(path)


def yyyymmdd(dt=None):
    dt = dt or datetime.datetime.now()
    return dt.strftime("%Y%m%d")
    
def yyyymmddHHMM(dt=None):
    dt = dt or datetime.datetime.now()
    return dt.strftime("%Y%m%d_%H%M")


def sanitize_for_fs(name):
    """
    Sanitize a label for filesystem use with special handling for UNC admin shares.

    Rules:
      - Replace reserved chars [: * ? " < > |] with '_'
      - Replace path separators '\' and '/' with '_'
      - Replace spaces with '_'
      - If path starts with UNC using an IP (e.g., '\\10.11.179.57\C$\...'):
          * Drop the leading '\\<IP>\'
          * If the share's second character is '$' (e.g., 'C$'), change it to '_'
      - Collapse multiple underscores and strip leading/trailing underscores.

    Examples:
      '\\\\10.11.179.57\\C$\\amat' -> 'C_amat'
      '\\\\filesrv\\data\\team'     -> 'filesrv_data_team'  (non-IP UNC keeps host)
      'D:/uploadTEst'               -> 'D_uploadTEst'
    """
    if not isinstance(name, basestring):
        name = str(name)

    original = name

    # If UNC, optionally remove \\<IP>\ and fix admin-share '$'
    m = _UNC_RE.match(name)
    if m:
        host = m.group('host')
        share = m.group('share')
        rest  = m.group('rest') or ''

        # If host looks like an IPv4, drop the \\<IP>\ prefix entirely per your request
        if _IPV4_RE.match(host):
            # normalize admin shares: C$ -> C_
            if len(share) >= 2 and share[1] == '$':
                # share = share[0] + '_' + share[2:]
                share = share[0] + share[2:]
            # rebuild without the leading \\<IP>\ prefix
            name = share + rest
        else:
            # Non-IP UNC host is kept; still normalize admin-shares
            if len(share) >= 2 and share[1] == '$':
                # share = share[0] + '_' + share[2:]
                share = share[0] + share[2:]
            name = host + '\\' + share + rest

    # Replace reserved characters
    name = re.sub(r'[*?"<>|]', '_', name)
    # Replace path separators
    name = name.replace('\\', '.').replace('/', '.').replace(':', '')
    # Replace spaces
    name = name.replace(' ', '_')
    # Collapse multiple underscores
    name = re.sub(r'_+', '_', name)
    name = re.sub(r'-+', '-', name)
    # Trim leading/trailing underscores
    name = name.strip('-_')

    return name


# def sanitize_for_fs(name):
#     name = re.sub(r'[:*?"<>|]', "_", name)
#     name = name.replace("\\", "_").replace("/", "_")
#     name = name.replace(" ", "_")
#     return name


def get_app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

# Not using in v5
def config_path_default():
    # Prefer config in the executable directory; fallback to ../config for dev
    path1 = os.path.join(get_app_dir(), "backup_config.yaml")
    if os.path.exists(path1):
        return path1
    return os.path.join(get_app_dir(), "..", "config", "backup_config.yaml")


def normcase_nopath(p):
    try:
        if not p.startswith('regex '):
            return os.path.normcase(os.path.normpath(p))
        else:
            return p
    except Exception:
        return p


def is_remote_unc(path):
    return isinstance(path, basestring) and path.startswith(r"\\")


def split_unc(path):
    # Expects something like \server\share
    p = path.strip("\\")
    parts = p.split("\\")
    if len(parts) < 2:
        raise ValueError("Invalid UNC path: %s" % path)
    server = parts[0]
    share = parts[1]
    rel = "" if len(parts) == 2 else "\\".join(parts[2:])
    return server, share, rel


def admin_share_to_drive(share):
    if len(share) == 2 and share[1] == "$" and share[0].isalpha():
        return share[0].upper() + ":"
    return None


def canonical_for_exclude(server, share, relpath):
    drv = admin_share_to_drive(share)
    if drv:
        base = drv + "\\"
    else:
        base = r"\\{}\{}\ ".strip().format(server, share)
    rel = relpath.replace("/", "\\").lstrip("\\")
    return normcase_nopath(os.path.join(base, rel))


def list_zip_files_local(dir_path):
    res = []
    try:
        for f in os.listdir(dir_path):
            if f.lower().endswith(".zip"):
                res.append(os.path.join(dir_path, f))
    except Exception:
        pass
    return res


def zip_folder(src_folder, zip_file_path, log=None):
    if log is None:
        log=simpleLogger.get_logger()
    try:
        with zipfile.ZipFile(zip_file_path, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for root, dirs, files in os.walk(src_folder):
                for f in files:
                    full = os.path.join(root, f)
                    arc = os.path.relpath(full, src_folder)
                    try:
                        zf.write(full, arc)
                    except Exception:
                        log.warning("Failed to add to zip: {}".format(full))
    except Exception as e:
        log.warning(e)
        log.debug(str(traceback.format_exc()))  
        raise


def delete_file(path, log=None):
    if log is None:
        log=simpleLogger.get_logger()
    if os.path.isfile(path):   
        for _ in range(3):
            try:
                os.remove(path)
                if not os.path.exists(path):
                    return                
            except Exception as e:
                try:
                    log.warning(e)
                    log.debug(str(traceback.format_exc()))
                except: print('PRINT: {}'.format(str(e)))
                time.sleep(1)


def delete_dir_quiet(path, log=None):
    if log is None:
        log=simpleLogger.get_logger()
    #def handle_err(func,path,exc_info):
    if os.path.isdir(path):    
        mode = stat.S_IWRITE
        for root, dirs, files in os.walk(path):
            for name in files:
                os.chmod(os.path.join(root, name), mode)
            for name in dirs:
                os.chmod(os.path.join(root, name), mode)
        for _ in range(3):
            try:
                # shutil.rmtree(path, ignore_errors=True)
                shutil.rmtree(path, ignore_errors=False)
                if not os.path.exists(path):
                    return
            except Exception as e:
                try:
                    log.warning(e)
                    log.debug(str(traceback.format_exc()))
                except: print('PRINT: {}'.format(str(e)))
                time.sleep(1)
