# LAZY TECH 2 – PowerShell GUI Helpdesk Toolkit

## About

**LAZY TECH 2** is a modular Windows PowerShell toolkit designed for Microsoft 365 environments and general IT troubleshooting.  
All classic text-menu scripts have been modernized with easy, clickable GUIs for actual helpdesk, techs, and end users.

**Author:** Cypher Playfair  
**Contributors:** Kingworm, OpenAI ChatGPT

---

## Features

- **Clickable GUI for Every Module**  
  All core helpdesk scripts (Outlook, OneDrive, Teams, Printers, Windows Update, Network, Browsers, and more) are now fully interactive. No more typing numbers—just click the button and get feedback.

- **Error Handling & Status Feedback**  
  Every critical operation is wrapped in try/catch. Status labels and output windows show you exactly what happened, success or failure.

- **User Data Safety & Migration**
  - Outlook: Migrate signatures, fix send/receive, create & set new profiles.
  - Edge/Chrome: One-click bookmark backup and profile reset with warnings.

- **Common Troubleshooting, One Click Away**
  - Outlook: Safe mode, clear temp, repair.
  - OneDrive: Reset, restart, open logs.
  - Teams: Full cache clear, kill/restart, error logs.
  - Printers: Restart spooler, list printers, clear jobs. TBD
  - Network: Release/renew, traceroute/ping/arp/DNS, test ports, see progress. TBD
  - Windows Update: Scan, view, clear cache.
  - Browsers: Backup/restore, full profile reset.

- **Modern PowerShell Compatibility**
  - Removed deprecated syntax (ternaries, old color props, etc.).
  - Works with modern Windows 10/11 PowerShell and does not hang the GUI.
  - All actions display progress and handle errors visually.

---

## How To Use

1. **Download or copy the .ps1 files** for the modules you want.
2. **Open PowerShell as Administrator** (recommended for most modules).
3. **Import or run the module** (e.g., `Show-OutlookMenu-GUI`).
4. **Click buttons for each troubleshooting action**—output and errors will appear live in the GUI.
5. **To extend:** Copy-paste any included module template and swap code for new tools.

---

## Collaboration & Credits

- **Original scripts & design:** Cypher Playfair (Playfair/Cypher/Jalena)
- **GUI refactor, debugging:** Playfair + Kingworm
- **Realtime co-dev:** Discord, ChatGPT, message.txt

---

## Future Plans

- Package as a single main launcher (all modules in one window)
- Add more progress bars & logs
- Auto-backup user data before destructive changes
- Optional: Compile to EXE for deployment

---

> LAZY TECH 2 makes Windows troubleshooting actually usable for techs, power users, and regular folks alike.
>
> Have ideas, bugs, or want to collab?  
> Ping **Playfair** (Cypher Playfair) on Discord!

---

