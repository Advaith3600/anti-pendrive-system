# Anti Pendrive System

This program monitors for USB device connections — storage drives (including USB
hard drives, SSDs and "fixed-type" flash drives), phones (MTP), network dongles
and HID devices — and immediately displays a full-screen red warning that locks
the machine until a proctor enters the admin password. It's ideal for
competitions, classrooms, or secure workspaces where external device usage is
restricted.

![screenshot](https://github.com/user-attachments/assets/72336e28-2228-4b71-a770-218b31228b04)

## Setting the password

The admin password is **not** stored in the source. It's kept as a salted
PBKDF2-SHA256 hash in `%ProgramData%\AntiPendrive\config.json`.

Set it once (run as administrator):

```bash
python main.py --set-password
```

or, after building the exe:

```bash
svchost.exe --set-password
```

A fresh install ships with the default password `ADMIN2024` so the tool is
protected before you set your own. **Treat `ADMIN2024` as public and change it
immediately** — it was committed to this repo's history in earlier versions.

## Building

See [`scripts`](scripts) for the PyInstaller build commands, the password-setup
command, and how to install it as a Scheduled Task that restarts at logon and
after being killed.

## What this tool does and does not cover

This program is a **deterrent and alarm**. It cannot, on its own, stop a
determined student with physical access. For real protection, combine it with:

- **Group Policy** → *All Removable Storage classes: Deny all access*, so Windows
  itself blocks USB storage.
- **Standard (non-admin) student accounts** — an admin can kill or uninstall
  anything.
- **`DisableTaskMgr`** via Group Policy, so Task Manager can't be used to end it.
- A **BIOS password** with USB boot disabled, so the machine can't be booted from
  a USB stick.

Every violation, unlock and exit is written to
`%ProgramData%\AntiPendrive\antipendrive.log` so a proctor can review what
happened — including whether the tool was killed.

## Emergency exit

Press **Ctrl+Shift+Alt+Q** (when not locked) and enter the admin password to stop
the tool.
