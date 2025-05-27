import tkinter as tk
from tkinter import simpledialog
import psutil
import threading
import time
import win32api
import win32con
import win32gui
import os
import ctypes

class AntiCheatMonitor:
    def __init__(self):
        self.monitoring = True
        self.initial_drives = set(self.get_drives())
        self.lock_window = None
        self.password = "ADMIN2024"
        self.violation_triggered = False
        self.violation_resolved = True
        self.ever_detected_drives = set()

    def get_drives(self):
        return [p.device for p in psutil.disk_partitions() if 'removable' in p.opts]

    def get_virtual_desktop_bounds(self):
        monitors = win32api.EnumDisplayMonitors()
        left = top = float('inf')
        right = bottom = float('-inf')
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
                    settings = win32api.EnumDisplaySettings(device.DeviceName, win32con.ENUM_CURRENT_SETTINGS)
                    return (
                        settings.Position_x,
                        settings.Position_y,
                        settings.PelsWidth,
                        settings.PelsHeight
                    )
                i += 1
            except:
                break
        return 0, 0, 800, 600  # fallback

    def create_lock_screen(self):
        if self.lock_window:
            return

        self.violation_triggered = True
        self.violation_resolved = False

        # Get full desktop bounds and primary monitor bounds
        vx, vy, vw, vh = self.get_virtual_desktop_bounds()
        px, py, pw, ph = self.get_primary_monitor_bounds()

        # Create full-screen window
        self.lock_window = tk.Toplevel(self.root)
        self.lock_window.configure(bg='red')
        self.lock_window.geometry(f"{vw}x{vh}+{vx}+{vy}")
        self.lock_window.attributes('-topmost', True)
        self.lock_window.overrideredirect(True)
        self.lock_window.focus_force()

        canvas = tk.Canvas(self.lock_window, bg='red', highlightthickness=0)
        canvas.pack(fill='both', expand=True)

        # This offset ensures center is relative to canvas
        canvas_center_x = (px - vx) + (pw // 2)
        canvas_center_y = (py - vy) + (ph // 2)

        center_frame = tk.Frame(canvas, bg='red')
        canvas.create_window(canvas_center_x, canvas_center_y, window=center_frame, anchor='center')

        tk.Label(center_frame,
                 text="⚠️ SECURITY VIOLATION DETECTED ⚠️\n\nUnauthorized device detected!\nEnter password to continue.",
                 font=('Arial', 28, 'bold'),
                 fg='white', bg='red', justify='center').pack(pady=30)

        password_entry = tk.Entry(center_frame, show='*', font=('Arial', 20), width=30)
        password_entry.pack(pady=10)
        password_entry.focus()

        def check_password():
            if password_entry.get() == self.password:
                self.close_lock_screen()
                self.violation_resolved = True
                print("Password correct - unlocking screen")
            else:
                password_entry.delete(0, tk.END)
                error_label = tk.Label(center_frame, text="Incorrect password!", font=('Arial', 14), fg='yellow', bg='red')
                error_label.pack()
                self.lock_window.after(2000, lambda: error_label.destroy() if error_label.winfo_exists() else None)

        password_entry.bind('<Return>', lambda e: check_password())
        tk.Button(center_frame, text="Unlock", command=check_password,
                  font=('Arial', 16), bg='white', fg='red').pack(pady=10)

        self.lock_window.protocol("WM_DELETE_WINDOW", lambda: None)

    def close_lock_screen(self):
        if self.lock_window:
            self.lock_window.destroy()
            self.lock_window = None

    def monitor_drives(self):
        while self.monitoring:
            current = set(self.get_drives())
            new_or_reinserted = current - self.initial_drives
            if new_or_reinserted:
                self.ever_detected_drives.update(new_or_reinserted)

            reinserted = current & self.ever_detected_drives - self.initial_drives
            violation_drives = new_or_reinserted | reinserted

            if violation_drives and not self.violation_triggered and self.violation_resolved:
                print(f"Violation detected - Drives: {violation_drives}")
                self.root.after(0, self.create_lock_screen)
                self.violation_triggered = True

            if not violation_drives and self.violation_triggered:
                print("All unauthorized drives removed.")
                self.violation_triggered = False
                self.violation_resolved = True

            time.sleep(2)

    def hide_console(self):
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

    def create_hidden_gui(self):
        self.root = tk.Tk()
        self.root.withdraw()
        self.root.attributes('-alpha', 0)

        threading.Thread(target=self.monitor_drives, daemon=True).start()

        def emergency_exit(event=None):
            pw = simpledialog.askstring("Emergency Exit", "Enter admin password:", show='*')
            if pw == self.password:
                self.monitoring = False
                self.root.quit()

        self.root.bind('<Control-Shift-Alt-q>', emergency_exit)
        self.root.mainloop()

    def run(self):
        self.hide_console()
        self.create_hidden_gui()

def main():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Warning: Not running as administrator. Some features may not work properly.")
    except:
        pass
    AntiCheatMonitor().run()

if __name__ == "__main__":
    main()

