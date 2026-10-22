"""Anti-Pendrive System.

Monitors for USB devices (storage, phones, dongles, HID injectors) and shows a
full-screen lock until a proctor enters the admin password. Hardened against the
common bypasses: hashed password, device-ID detection, startup check, fail-closed
monitoring, and keyboard-trap while locked.

First-time setup (run once, as administrator):
    python main.py --set-password

Then run normally (no console):
    python main.py
"""

import tkinter as tk
from tkinter import simpledialog
import psutil
import threading
import time
import queue
import os
import sys
import json
import hmac
import hashlib
import getpass
import ctypes
from ctypes import wintypes
import datetime

import win32api
import win32con
import win32gui

try:
    import win32com.client  # WMI access for device-ID detection
    _HAVE_WMI = True
except Exception:
    _HAVE_WMI = False


# --- Paths ---------------------------------------------------------------

def _config_dir():
    base = os.environ.get("ProgramData", r"C:\ProgramData")
    d = os.path.join(base, "AntiPendrive")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        d = os.path.dirname(os.path.abspath(sys.argv[0]))
    return d

CONFIG_DIR = _config_dir()
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
LOG_PATH = os.path.join(CONFIG_DIR, "antipendrive.log")

# Default password hash so a fresh install is still protected. This is a hash of
# "ADMIN2024" — treat that value as burned; run --set-password to replace it.
_DEFAULT_SALT = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
_PBKDF2_ROUNDS = 200_000


def _hash_password(password, salt, rounds=_PBKDF2_ROUNDS):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)


def _default_config():
    return {
        "salt": _DEFAULT_SALT.hex(),
        "rounds": _PBKDF2_ROUNDS,
        "hash": _hash_password("ADMIN2024", _DEFAULT_SALT).hex(),
    }


def log_event(message):
    line = f"{datetime.datetime.now().isoformat(timespec='seconds')} {message}"
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line)


# --- Low-level keyboard hook (installed only while locked) ---------------

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104

VK_LWIN = 0x5B
VK_RWIN = 0x5C
VK_TAB = 0x09
VK_ESCAPE = 0x1B

LowLevelKeyboardProc = ctypes.WINFUNCTYPE(
    ctypes.c_long, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM
)


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong)),
    ]


class KeyboardTrap:
    """Swallow the keys that let a user escape the lock screen.

    Blocks the Windows keys (Start menu, Win+R, Win+Ctrl+D new desktop),
    Alt+Tab / Alt+Esc (task switch) and Ctrl+Esc (Start menu).
    """

    def __init__(self):
        self._hook = None
        self._user32 = ctypes.windll.user32
        self._proc = LowLevelKeyboardProc(self._callback)

    def _callback(self, nCode, wParam, lParam):
        if nCode == 0 and wParam in (WM_KEYDOWN, WM_SYSKEYDOWN):
            kb = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
            vk = kb.vkCode
            alt_down = bool(self._user32.GetAsyncKeyState(win32con.VK_MENU) & 0x8000)
            ctrl_down = bool(self._user32.GetAsyncKeyState(win32con.VK_CONTROL) & 0x8000)
            if vk in (VK_LWIN, VK_RWIN):
                return 1
            if vk == VK_TAB and alt_down:
                return 1
            if vk == VK_ESCAPE and (alt_down or ctrl_down):
                return 1
        return self._user32.CallNextHookEx(self._hook, nCode, wParam, lParam)

    def install(self):
        if self._hook:
            return
        hmod = ctypes.windll.kernel32.GetModuleHandleW(None)
        self._hook = self._user32.SetWindowsHookExW(
            WH_KEYBOARD_LL, self._proc, hmod, 0
        )

    def remove(self):
        if self._hook:
            self._user32.UnhookWindowsHookEx(self._hook)
            self._hook = None


# --- Monitor -------------------------------------------------------------

class AntiCheatMonitor:
    POLL_SECONDS = 0.5
    MAX_FAILED_SCANS = 3  # fail closed after this many consecutive scan errors

    def __init__(self):
        self.monitoring = True
        self.config = self._load_config()
        self.lock_window = None
        self.events = queue.Queue()
        self.keyboard_trap = KeyboardTrap()

        # Device IDs that are allowed. Seeded with whatever is present at launch
        # ONLY if nothing USB-storage-like is present; see run(). The startup
        # check handles the "plug in before launch" bypass.
        self.approved = set()
        self.failed_scans = 0

        # Password lockout.
        self.failed_attempts = 0
        self.lockout_until = 0.0

    # --- config ---
    def _load_config(self):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            # sanity
            bytes.fromhex(cfg["salt"])
            bytes.fromhex(cfg["hash"])
            int(cfg["rounds"])
            return cfg
        except Exception:
            return _default_config()

    def check_password(self, password):
        salt = bytes.fromhex(self.config["salt"])
        rounds = int(self.config["rounds"])
        expected = bytes.fromhex(self.config["hash"])
        candidate = _hash_password(password, salt, rounds)
        return hmac.compare_digest(candidate, expected)

    # --- detection ---
    def get_usb_device_ids(self):
        """Return a set of USB device identifiers currently connected.

        Uses WMI so it catches fixed-type USB disks, phones (MTP), network
        dongles and HID devices — not just 'removable' drive letters.
        """
        ids = set()
        if _HAVE_WMI:
            wmi = win32com.client.GetObject("winmgmts:")
            for ent in wmi.InstancesOf("Win32_PnPEntity"):
                dev_id = getattr(ent, "PNPDeviceID", None)
                if dev_id and str(dev_id).upper().startswith("USB"):
                    ids.add(str(dev_id))
            for disk in wmi.InstancesOf("Win32_DiskDrive"):
                if str(getattr(disk, "InterfaceType", "")).upper() == "USB":
                    pnp = getattr(disk, "PNPDeviceID", None)
                    if pnp:
                        ids.add(str(pnp))
        else:
            # Fallback: removable drive letters only.
            for p in psutil.disk_partitions():
                if "removable" in p.opts:
                    ids.add("DRIVE:" + p.device)
        return ids

    def unapproved_devices(self):
        return self.get_usb_device_ids() - self.approved

    # --- monitor loop (background thread) ---
    def monitor_drives(self):
        while self.monitoring:
            try:
                offending = self.unapproved_devices()
                self.failed_scans = 0
            except Exception as e:
                self.failed_scans += 1
                log_event(f"SCAN ERROR ({self.failed_scans}): {e}")
                # Fail closed: repeated scan failure triggers a lock.
                offending = {"__scan_failure__"} if self.failed_scans >= self.MAX_FAILED_SCANS else set()

            if offending and self.lock_window is None:
                self.events.put(("lock", frozenset(offending)))

            time.sleep(self.POLL_SECONDS)

    def pump_events(self):
        """Drain monitor-thread events on the Tk thread (thread-safe)."""
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "lock":
                    self.create_lock_screen(payload)
        except queue.Empty:
            pass
        if self.monitoring:
            self.root.after(200, self.pump_events)

    # --- geometry ---
    def get_virtual_desktop_bounds(self):
        monitors = win32api.EnumDisplayMonitors()
        left = top = float("inf")
        right = bottom = float("-inf")
        for m in monitors:
            _, _, (mx1, my1, mx2, my2) = m
            left = min(left, mx1)
            top = min(top, my1)
            right = max(right, mx2)
            bottom = max(bottom, my2)
        return int(left), int(top), int(right - left), int(bottom - top)

    def get_primary_monitor_bounds(self):
        i = 0
        while True:
            try:
                device = win32api.EnumDisplayDevices(None, i)
                if device.StateFlags & win32con.DISPLAY_DEVICE_PRIMARY_DEVICE:
                    settings = win32api.EnumDisplaySettings(
                        device.DeviceName, win32con.ENUM_CURRENT_SETTINGS
                    )
                    return (
                        settings.Position_x,
                        settings.Position_y,
                        settings.PelsWidth,
                        settings.PelsHeight,
                    )
                i += 1
            except Exception:
                break
        return 0, 0, 800, 600  # fallback

    # --- lock screen ---
    def create_lock_screen(self, offending):
        if self.lock_window:
            return

        log_event(f"VIOLATION devices={sorted(offending)}")
        self.keyboard_trap.install()

        vx, vy, vw, vh = self.get_virtual_desktop_bounds()
        px, py, pw, ph = self.get_primary_monitor_bounds()

        self.lock_window = tk.Toplevel(self.root)
        self.lock_window.configure(bg="red")
        self.lock_window.geometry(f"{vw}x{vh}+{vx}+{vy}")
        self.lock_window.attributes("-topmost", True)
        self.lock_window.overrideredirect(True)
        self.lock_window.focus_force()

        canvas = tk.Canvas(self.lock_window, bg="red", highlightthickness=0)
        canvas.pack(fill="both", expand=True)

        canvas_center_x = (px - vx) + (pw // 2)
        canvas_center_y = (py - vy) + (ph // 2)

        center_frame = tk.Frame(canvas, bg="red")
        canvas.create_window(
            canvas_center_x, canvas_center_y, window=center_frame, anchor="center"
        )

        tk.Label(
            center_frame,
            text="⚠️ SECURITY VIOLATION DETECTED ⚠️\n\n"
            "Unauthorized device detected!\nEnter password to continue.",
            font=("Arial", 28, "bold"),
            fg="white",
            bg="red",
            justify="center",
        ).pack(pady=30)

        password_entry = tk.Entry(center_frame, show="*", font=("Arial", 20), width=30)
        password_entry.pack(pady=10)
        password_entry.focus()

        status_label = tk.Label(center_frame, text="", font=("Arial", 14), fg="yellow", bg="red")
        status_label.pack()

        approve_var = tk.IntVar(value=0)
        tk.Checkbutton(
            center_frame,
            text="Approve these devices for the rest of this session",
            variable=approve_var,
            font=("Arial", 12),
            fg="white",
            bg="red",
            selectcolor="red",
            activebackground="red",
            activeforeground="white",
        ).pack(pady=6)

        def check_password():
            now = time.time()
            if now < self.lockout_until:
                wait = int(self.lockout_until - now)
                status_label.config(text=f"Too many attempts. Wait {wait}s.")
                return
            if self.check_password(password_entry.get()):
                self.failed_attempts = 0
                if approve_var.get():
                    try:
                        self.approved |= self.get_usb_device_ids()
                        log_event("Devices approved for session")
                    except Exception:
                        pass
                log_event("Unlock OK")
                self.close_lock_screen()
            else:
                self.failed_attempts += 1
                password_entry.delete(0, tk.END)
                if self.failed_attempts >= 5:
                    self.lockout_until = time.time() + 30
                    self.failed_attempts = 0
                    status_label.config(text="Too many attempts. Wait 30s.")
                    log_event("Unlock FAILED x5 - 30s lockout")
                else:
                    status_label.config(text="Incorrect password!")
                    log_event("Unlock FAILED")

        password_entry.bind("<Return>", lambda e: check_password())
        tk.Button(
            center_frame,
            text="Unlock",
            command=check_password,
            font=("Arial", 16),
            bg="white",
            fg="red",
        ).pack(pady=10)

        self.lock_window.protocol("WM_DELETE_WINDOW", lambda: None)
        self._keep_on_top()

    def _keep_on_top(self):
        """Keep the lock window covering everything and holding focus."""
        if not self.lock_window:
            return
        try:
            vx, vy, vw, vh = self.get_virtual_desktop_bounds()
            self.lock_window.geometry(f"{vw}x{vh}+{vx}+{vy}")
            self.lock_window.attributes("-topmost", True)
            self.lock_window.lift()
            hwnd = self.lock_window.winfo_id()
            ctypes.windll.user32.SetForegroundWindow(hwnd)
        except Exception:
            pass
        self.lock_window.after(300, self._keep_on_top)

    def close_lock_screen(self):
        if self.lock_window:
            self.lock_window.destroy()
            self.lock_window = None
        self.keyboard_trap.remove()

    # --- emergency exit (polled global hotkey) ---
    def _poll_hotkey(self):
        # Ctrl+Shift+Alt+Q, only honoured when not locked.
        u = ctypes.windll.user32
        def down(vk):
            return bool(u.GetAsyncKeyState(vk) & 0x8000)
        if (self.lock_window is None
                and down(win32con.VK_CONTROL) and down(win32con.VK_SHIFT)
                and down(win32con.VK_MENU) and down(0x51)):
            pw = simpledialog.askstring("Emergency Exit", "Enter admin password:", show="*")
            if pw is not None and self.check_password(pw):
                log_event("Emergency exit")
                self.monitoring = False
                self.root.quit()
                return
        if self.monitoring:
            self.root.after(250, self._poll_hotkey)

    # --- lifecycle ---
    def hide_console(self):
        try:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        except Exception:
            pass

    def run(self):
        self.hide_console()
        log_event("Started")
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.attributes("-alpha", 0)

        threading.Thread(target=self.monitor_drives, daemon=True).start()
        self.root.after(200, self.pump_events)
        self.root.after(250, self._poll_hotkey)

        # Startup check: if any USB device is already present, lock immediately
        # so a drive plugged in before launch cannot slip through.
        try:
            present = self.get_usb_device_ids()
            if present:
                self.events.put(("lock", frozenset(present)))
        except Exception as e:
            log_event(f"Startup scan error: {e}")

        self.root.mainloop()


# --- CLI -----------------------------------------------------------------

def set_password():
    pw1 = getpass.getpass("New admin password: ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw1 != pw2:
        print("Passwords do not match.")
        return 1
    if len(pw1) < 6:
        print("Password must be at least 6 characters.")
        return 1
    salt = os.urandom(16)
    cfg = {
        "salt": salt.hex(),
        "rounds": _PBKDF2_ROUNDS,
        "hash": _hash_password(pw1, salt).hex(),
    }
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    print(f"Password saved to {CONFIG_PATH}")
    return 0


def main():
    if "--set-password" in sys.argv:
        sys.exit(set_password())

    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Warning: Not running as administrator. Some features may not work properly.")
    except Exception:
        pass
    AntiCheatMonitor().run()


if __name__ == "__main__":
    main()
