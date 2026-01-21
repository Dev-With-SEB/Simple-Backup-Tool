# -*- coding: utf-8 -*-
from __future__ import print_function
from base64 import b64encode, b64decode
import datetime
import shutil
import io
import os

try:
    from win32crypt import CryptProtectData, CryptUnprotectData
except Exception:
    CryptProtectData = None
    CryptUnprotectData = None

from .utils import delete_file

from .simpleLogger import get_logger



CRYPTPROTECT_LOCAL_MACHINE = 0x4

class PasswordManager(object):
    # DPAPI-based encryption/decryption for config credentials.
    def __init__(self, log=get_logger()):
        self.log = log

    @staticmethod
    def _scope_flag(scope):
        scope = (scope or "machine").strip().lower()
        return CRYPTPROTECT_LOCAL_MACHINE if scope == "machine" else 0

    @staticmethod
    def encrypt(plain_text, scope="machine"):
        if not plain_text:
            return ""
        if CryptProtectData is None:
            raise RuntimeError("DPAPI not available: install pywin32.")
        try:
            unicode
        except NameError:
            unicode = str
        if isinstance(plain_text, unicode):
            data = plain_text.encode("utf-8")
        else:
            data = plain_text
        enc_blob = CryptProtectData(data, None, None, None, None, PasswordManager._scope_flag(scope))
        if isinstance(enc_blob, tuple) and len(enc_blob) >= 1:
            enc_bytes = enc_blob[1]
        else:
            enc_bytes = enc_blob
        return b64encode(enc_bytes)

    @staticmethod
    def decrypt(b64_blob):
        if not b64_blob:
            return ""
        if CryptUnprotectData is None:
            raise RuntimeError("DPAPI not available: install pywin32.")
        enc_bytes = b64decode(b64_blob)
        dec = CryptUnprotectData(enc_bytes, None, None, None, 0)
        if isinstance(dec, tuple) and len(dec) >= 1:
            plain = dec[1]
        else:
            plain = dec
        try:
            return plain.decode("utf-8")
        except Exception:
            return plain

    @staticmethod
    def _sanitize_auth_entry(entry, scope):
        if not isinstance(entry, dict):
            return False
        pwd = entry.get("password") or ""
        changed = False
        if "" != pwd:
            try:
                enc_b64 = PasswordManager.encrypt(pwd, scope=scope)
                entry["encryptedPassword"] = enc_b64
                entry["password"] = ""
                changed = True
            except Exception as e:
                get_logger().error("Failed to encrypt password: {}".format( e))
        return changed

    @staticmethod
    def sanitize_and_persist_config(data, path):
        auth = (data or {}).get("auth") or {}
        scope = (auth.get("dpapiScope") or "machine").strip().lower()
        changed = False

        if "default" in auth:
            if PasswordManager._sanitize_auth_entry(auth["default"], scope):
                changed = True

        for ent in (auth.get("hosts") or []):
            if PasswordManager._sanitize_auth_entry(ent, scope):
                changed = True

        if not changed:
            return False

        stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        backup_pathPreTimeStamp = path + ".bak-"
        backup_path = backup_pathPreTimeStamp + stamp
        tmp_path = path + ".tmp"
        try:
            try:
                shutil.copy2(path, backup_path)
            except Exception as e:
                get_logger().warning("Could not create config backup: {}".format( e))
            with io.open(tmp_path, "w", encoding="utf-8") as f:
                import yaml
                yaml.safe_dump(data, f, default_flow_style=False, allow_unicode=True)
            try:
                os.replace(tmp_path, path)
            except AttributeError:
                try:
                    os.remove(path)
                except Exception:
                    pass
                os.rename(tmp_path, path)
            get_logger().info("Config sanitized: encrypted passwords -> {} (backup saved)".format(backup_path))
            # Clean up Config file backups so we dont has a folder full of them
            try:
                confhBaseName = os.path.basename(path)
                confPathDir = os.path.dirname(os.path.abspath(path))
                fileLst = sorted([f for f in os.listdir(confPathDir) if f.find(confhBaseName + ".bak-" ) != -1])

                while len(fileLst) > 2:
                    filePath = os.path.join(confPathDir,fileLst[0])
                    delete_file(filePath)
                    fileLst.pop(0)                
            except Exception as e:
                get_logger().error("Failed to delete extra bak conf file: {}".format( e)) 

            return True
        except Exception as e:
            get_logger().error("Failed to persist sanitized config: {}".format( e))
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
            return False

    @staticmethod
    def resolve_password(creds_dict):
        if not isinstance(creds_dict, dict):
            return ""
        enc = creds_dict.get("encryptedPassword") or ""
        if enc:
            try:
                return PasswordManager.decrypt(enc)
            except Exception as e:
                get_logger().error("DPAPI decrypt failed: {}".format( e))
        return creds_dict.get("password") or ""
