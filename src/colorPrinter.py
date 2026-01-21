
# -*- coding: utf-8 -*-
"""
adaptive_color_py27.py

Python 2.7-compatible color printing utility:
  - Windows 10+ -> ANSI/VT (native)
  - Windows XP/7/8/8.1 -> Win32 Console API via ctypes (or Colorama if available)
  - Linux/macOS -> ANSI
  - Non-TTY -> no color

Usage:
    from adaptive_color_py27 import Color, ColorPrinter

    cp = ColorPrinter()
    cp.println("OK (green)", Color.GREEN)
    cp.println("WARN (yellow, bold)", Color.YELLOW, bold=True)
    cp.println("ERR (red on white)", Color.RED, bg=Color.WHITE, bold=True)

No third-party dependencies required. If 'colorama' is present, it will be used.
"""

from __future__ import unicode_literals
import os
import sys
import platform

# Avoid third-party imports; use ctypes for legacy Windows coloring
try:
    import ctypes
    import ctypes.wintypes
except Exception:
    ctypes = None


# ---------------------------
# Public API
# ---------------------------

class Color(object):
    """16-color palette compatible with Win32 console attributes."""
    BLACK          = 0
    BLUE           = 1
    GREEN          = 2
    CYAN           = 3
    RED            = 4
    MAGENTA        = 5
    YELLOW         = 6
    WHITE          = 7

    # Bright variants
    BRIGHT_BLACK   = 8   # usually rendered as "dark gray"
    BRIGHT_BLUE    = 9
    BRIGHT_GREEN   = 10
    BRIGHT_CYAN    = 11
    BRIGHT_RED     = 12
    BRIGHT_MAGENTA = 13
    BRIGHT_YELLOW  = 14
    BRIGHT_WHITE   = 15  # usually rendered as "light gray"/white


class ColorPrinter(object):
    """
    Cross-platform color printer with adaptive strategy for Python 2.7.
    """

    # ANSI mappings for foreground/background (16-color)
    _ANSI_FG = {
        Color.BLACK:          "30",
        Color.RED:            "31",
        Color.GREEN:          "32",
        Color.YELLOW:         "33",
        Color.BLUE:           "34",
        Color.MAGENTA:        "35",
        Color.CYAN:           "36",
        Color.WHITE:          "37",
        Color.BRIGHT_BLACK:   "90",
        Color.BRIGHT_RED:     "91",
        Color.BRIGHT_GREEN:   "92",
        Color.BRIGHT_YELLOW:  "93",
        Color.BRIGHT_BLUE:    "94",
        Color.BRIGHT_MAGENTA: "95",
        Color.BRIGHT_CYAN:    "96",
        Color.BRIGHT_WHITE:   "97",
    }

    _ANSI_BG = {
        Color.BLACK:          "40",
        Color.RED:            "41",
        Color.GREEN:          "42",
        Color.YELLOW:         "43",
        Color.BLUE:           "44",
        Color.MAGENTA:        "45",
        Color.CYAN:           "46",
        Color.WHITE:          "47",
        Color.BRIGHT_BLACK:   "100",
        Color.BRIGHT_RED:     "101",
        Color.BRIGHT_GREEN:   "102",
        Color.BRIGHT_YELLOW:  "103",
        Color.BRIGHT_BLUE:    "104",
        Color.BRIGHT_MAGENTA: "105",
        Color.BRIGHT_CYAN:    "106",
        Color.BRIGHT_WHITE:   "107",
    }

    def __init__(self, force_enable=False, force_disable=False):
        # Detect environment
        self._is_windows = (os.name == "nt")
        self._is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        self._ansi_ok = (not self._is_windows)  # ANSI is fine on non-Windows
        self._win_vt_capable = False            # Windows 10+ VT support

        if force_enable:
            self._is_tty = True
            self._ansi_ok = True
        if force_disable:
            self._is_tty = False
            self._ansi_ok = False

        # Optional: Colorama auto-enable if present
        self._colorama_available = False
        if self._is_windows and self._is_tty:
            try:
                import colorama
                try:
                    # colorama >= 0.4.6
                    colorama.just_fix_windows_console()
                except Exception:
                    # older colorama
                    colorama.init()
                self._colorama_available = True
                self._ansi_ok = True  # Colorama bridges ANSI on legacy Windows
            except Exception:
                self._colorama_available = False

        # Try enabling VT (Windows 10+). If successful, ANSI is native.
        if self._is_windows and self._is_tty and ctypes is not None:
            self._enable_vt_processing()  # sets _win_vt_capable if succeeds
            if self._win_vt_capable:
                self._ansi_ok = True

        # Prepare Win32 console fallback for legacy Windows
        self._win_handle = None
        self._win_default_attr = None
        if self._is_windows and not self._ansi_ok and ctypes is not None and self._is_tty:
            self._init_win32_console()

    # -------- public methods --------

    def println(self, text, fg=None, bg=None, bold=False, end=""):
        """
        Print with color to stdout; degrades gracefully when not supported.
        """
        if not self._is_tty:
            sys.stdout.write(text + end)
            sys.stdout.flush()
            return

        if self._ansi_ok:
            sys.stdout.write(self._fmt_ansi(text, fg, bg, bold) + end)
            sys.stdout.flush()
        elif self._is_windows and self._win_handle is not None:
            # Win32 attribute path
            # sys.stdout.write(self._fmt_win32(text, fg, bg, bold) + end)
            
            # # Win32 path: write text + newline within one attribute span
            self._win_write_line(text, fg, bg, bold)
        else:
            sys.stdout.write(text + end)
            sys.stdout.flush()
    

    # -------- ANSI path --------

    def _fmt_ansi(self, text, fg, bg, bold):
        codes = []
        if bold:
            codes.append("1")
        if fg in self._ANSI_FG:
            codes.append(self._ANSI_FG[fg])
        if bg in self._ANSI_BG:
            codes.append(self._ANSI_BG[bg])
        if codes:
            return "\x1b[" + ";".join(codes) + "m" + text + "\x1b[0m"
        return text

    # -------- Win32 path (legacy Windows) --------

    def _init_win32_console(self):
        """
        Initialize Win32 console access for legacy Windows (XP/7/8/8.1).
        """
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

            # Structures
            class COORD(ctypes.Structure):
                _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]

            class SMALL_RECT(ctypes.Structure):
                _fields_ = [("Left", ctypes.c_short), ("Top", ctypes.c_short),
                            ("Right", ctypes.c_short), ("Bottom", ctypes.c_short)]

            class CONSOLE_SCREEN_BUFFER_INFO(ctypes.Structure):
                _fields_ = [
                    ("dwSize", COORD),
                    ("dwCursorPosition", COORD),
                    ("wAttributes", ctypes.wintypes.WORD),
                    ("srWindow", SMALL_RECT),
                    ("dwMaximumWindowSize", COORD),
                ]

            STD_OUTPUT_HANDLE = ctypes.c_uint(-11).value

            GetStdHandle = kernel32.GetStdHandle
            GetStdHandle.argtypes = [ctypes.wintypes.DWORD]
            GetStdHandle.restype = ctypes.wintypes.HANDLE

            GetConsoleScreenBufferInfo = kernel32.GetConsoleScreenBufferInfo
            GetConsoleScreenBufferInfo.argtypes = [ctypes.wintypes.HANDLE,
                                                   ctypes.POINTER(CONSOLE_SCREEN_BUFFER_INFO)]
            GetConsoleScreenBufferInfo.restype = ctypes.wintypes.BOOL

            SetConsoleTextAttribute = kernel32.SetConsoleTextAttribute
            SetConsoleTextAttribute.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.WORD]
            SetConsoleTextAttribute.restype = ctypes.wintypes.BOOL

            self._kernel32 = kernel32
            self._SetConsoleTextAttribute = SetConsoleTextAttribute

            h = GetStdHandle(STD_OUTPUT_HANDLE)
            self._win_handle = h

            csbi = CONSOLE_SCREEN_BUFFER_INFO()
            if GetConsoleScreenBufferInfo(h, ctypes.byref(csbi)):
                self._win_default_attr = csbi.wAttributes
            else:
                # Default to white-on-black
                self._win_default_attr = 0x0007

        except Exception:
            self._win_handle = None
            self._win_default_attr = None

    def _fmt_win32(self, text, fg, bg, bold):
        """
        Apply Win32 attributes, write text, then restore defaults.
        Returns empty string because coloring is done via attribute changes.
        """
        if self._win_handle is None:
            return text

        # Map 0-15 to Win32 attribute bits
        base_map = {
            Color.BLACK: 0x0,
            Color.BLUE: 0x1,
            Color.GREEN: 0x2,
            Color.CYAN: 0x3,
            Color.RED: 0x4,
            Color.MAGENTA: 0x5,
            Color.YELLOW: 0x6,
            Color.WHITE: 0x7,
            Color.BRIGHT_BLACK: 0x8,
            Color.BRIGHT_BLUE: 0x9,
            Color.BRIGHT_GREEN: 0xA,
            Color.BRIGHT_CYAN: 0xB,
            Color.BRIGHT_RED: 0xC,
            Color.BRIGHT_MAGENTA: 0xD,
            Color.BRIGHT_YELLOW: 0xE,
            Color.BRIGHT_WHITE: 0xF,
        }

        attr = self._win_default_attr
        if fg is not None:
            attr = (attr & 0xF0) | base_map.get(fg, 0x7)
        if bg is not None:
            attr = (attr & 0x0F) | (base_map.get(bg, 0x0) << 4)
        if bold:
            # Approximate 'bold' with bright foreground
            attr |= 0x08

        try:
            self._SetConsoleTextAttribute(self._win_handle, attr)
            sys.stdout.write(text)
        finally:
            if self._win_default_attr is not None:
                self._SetConsoleTextAttribute(self._win_handle, self._win_default_attr)

        return ""  # already written

    # -------- Windows 10+ VT enable --------

    def _enable_vt_processing(self):
        """
        Attempt to enable VT/ANSI on Windows 10+ (cmd/conhost).
        Sets self._win_vt_capable = True on success.
        """
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            STD_OUTPUT_HANDLE = ctypes.c_uint(-11).value

            GetStdHandle = kernel32.GetStdHandle
            GetStdHandle.argtypes = [ctypes.wintypes.DWORD]
            GetStdHandle.restype = ctypes.wintypes.HANDLE

            GetConsoleMode = kernel32.GetConsoleMode
            GetConsoleMode.argtypes = [ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.DWORD)]
            GetConsoleMode.restype = ctypes.wintypes.BOOL

            SetConsoleMode = kernel32.SetConsoleMode
            SetConsoleMode.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
            SetConsoleMode.restype = ctypes.wintypes.BOOL

            h = GetStdHandle(STD_OUTPUT_HANDLE)
            mode = ctypes.wintypes.DWORD()
            if GetConsoleMode(h, ctypes.byref(mode)):
                ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
                new_mode = mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                if SetConsoleMode(h, new_mode):
                    self._win_vt_capable = True
        except Exception:
            self._win_vt_capable = False


# ---------------------------
# Demo (optional)
# ---------------------------

if __name__ == "__main__":
    cp = ColorPrinter()
    cp.println("Adaptive color demo (Py27)", Color.BRIGHT_WHITE, bg=Color.BLUE, bold=True, end="\n")
    cp.println("Success", Color.GREEN, end="\n")
    cp.println("Warning", Color.YELLOW, bold=True, end="\n")
    cp.println("Error", Color.RED, bg=Color.BRIGHT_BLACK, end="\n")
    cp.println("Plain (no color when redirected)")
