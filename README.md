Here’s the updated README for **LAZY TECH 2** with your 2.0 patches baked in:

---

🛠️ **LAZY TECH 2** – PowerShell Helpdesk Toolkit
**Author:** Kyle Martin
**Version:** 2.0

**Platform:** Windows PowerShell (Run as Admin)

---

## 💡 What Is It?

LAZY TECH 2 is for every tech who's ever said:

> “Why do I need to click through 5 different settings windows just to fix Outlook?”
> “Why can’t there just be a menu for all the usual crap I deal with?”
> “I’m not typing 10 PowerShell commands—I just want to fix it.”

This toolkit is your escape hatch from endless clicking, command memorization, and hunting through the Control Panel. It gives you a clean PowerShell menu to handle the most common and annoying Windows issues in just a few keystrokes.

You run the script, pick a number, fix the issue. Done.

---

## 🚀 Quick Start

```powershell
git clone https://github.com/sudocod3r/LAZY_TECH_2.git  
cd LAZY_TECH_2  
.\LAZY_TECH_2.ps1
```

> ✅ Don’t forget to right‑click → **Run with PowerShell** or launch it in an elevated terminal.

---

## 📋 Menu Breakdown

```
==== LAZY TECH 2 ====

1. Outlook Issues
2. OneDrive Issues
3. Office Activation & Licensing
4. Login / Auth / MFA
5. Teams Issues
6. Network / Connectivity
7. Devices & Printers
8. User Profiles & Accounts
9. Startup & Performance
10. System Recovery Tools
11. System Logs & Events
12. Windows Update Tools
13. Browser & Internet Issues
14. Helpdesk Profile Info
15. Exit
```

Each number opens a sub‑menu of one‑click tools and diagnostics. No typing. No registry diving. No random forum advice.

---

## ✅ What It Can Do

* 📨 **Outlook** – Rebuild profiles, clear cache, reopen clean
* ☁️ **OneDrive** – Fix sync issues, relaunch stuck clients
* 💼 **Office Licensing** – Diagnose, reset, and rearm activations
* 🔐 **MFA / Login** – Triage sign‑in problems with local or M365 accounts
* 📞 **Teams** – Clear cache, restart services, fix basic comms
* 🌐 **Network** – Flush DNS, reset adapters, ping tests, etc.
* 🖨️ **Printers** – Clear spooler, reset print services
* 👤 **Profiles** – Reset temp logins, check user folder issues
* 🚀 **Performance** – Disable startup junk, clean temp files
* 🧰 **Recovery** – One‑click access to restore and repair tools
* 📑 **Logs** – Shortcut to Event Viewer logs and filtering
* 🔄 **Updates** – Kick off stalled updates, reset components
* 🌍 **Browser Issues** – DNS errors, SSL problems, and cache nukes
* 🧾 **Helpdesk Info** – Pull quick system/user info for tickets

---

## 🛠️ What’s New in 2.0?

1. **Line 151** – Force‑kills all Office apps (Outlook, Word, Excel, PowerPoint), plus Skype & legacy Lync before any repair to avoid file locks.
2. **Line 333** – Automates IP stack reset (`ipconfig /release` & `/renew` + full `ipconfig /all`), then checks for APIPA (169.254.x.x) and warns if still using it.
3. **Line 363** – Adds live socket inspection: classic `netstat -ano` for ESTABLISHED connections and a PowerShell native `Get‑NetTCPConnection` view.
4. **Line 771** – Runs `gpupdate /force` to immediately apply any pending Group Policy changes.
5. **Line 823** – Schedules a Safe Mode reboot with a clear warning, a 5‑second delay (allowing cancellation), and a forced restart.
6. **Line 882** – Backs up Chrome & Edge bookmarks to the Desktop, auto‑detecting Windows 10 vs. 11 to name the backup files accordingly.

---

## ⚙️ How to Use It

1. **Clone** or download the script
2. Right‑click → **Run with PowerShell** (or launch from an Admin terminal)
3. Select your issue from the menu
4. Fix it without thinking

You don’t need to memorize syntax or dig through Control Panel—the script does the boring stuff for you.

---

## 🧪 Requirements

* Windows 10 or 11
* PowerShell 5.1+
* Must be run **as Administrator**
* Internet connection for update/license fixes

---

## 📖 License

MIT License – Free to use, fork, and modify. Not for resale.

---

🧠 Made By
**Kyle Martin – Squid Tech Services**
🔗 [https://sudocod3r.github.io/](https://sudocod3r.github.io/)

> “\$i11y U53R, T0015 AR3 4 ADM1N5.”
