
# Microsoft 365 Helpdesk Toolkit - PowerShell CLI Edition
# Author: Kyle Martin
# Version: 1.0

function Show-OutlookMenu {
    Clear-Host
    Write-Host "=== Outlook Troubleshooting ===" -ForegroundColor Yellow
    Write-Host "1. Launch Outlook in Safe Mode"
    Write-Host "2. Open Mail Control Panel"
    Write-Host "3. Clear Outlook Temp Files"
    Write-Host "4. Back"
    $choice = Read-Host "Select an action (1-4)"
    switch ($choice) {
        1 {
            $outlookPaths = @(
                "$env:ProgramFiles\Microsoft Office\root\Office16\OUTLOOK.EXE",
                "$env:ProgramFiles(x86)\Microsoft Office\Office16\OUTLOOK.EXE",
                "$env:ProgramFiles\Microsoft Office\Office16\OUTLOOK.EXE",
                "$env:LOCALAPPDATA\Microsoft\WindowsApps\outlook.exe"
            )
            $outlookExe = $outlookPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

            if ($outlookExe) {
                Start-Process $outlookExe "/safe"
            } else {
                Write-Host "Outlook.exe not found in known locations. Please verify installation." -ForegroundColor Red
            }
        }
        2 {
    $cplPaths = @(
        "$env:ProgramFiles(x86)\Microsoft Office\root\Office16\mlcfg32.cpl",
        "$env:ProgramFiles\Microsoft Office\root\Office16\mlcfg32.cpl",
        "$env:ProgramFiles(x86)\Microsoft Office\Office16\mlcfg32.cpl",
        "$env:ProgramFiles\Microsoft Office\Office16\mlcfg32.cpl"
    )
    
    $mailCpl = $cplPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($mailCpl) {
        Start-Process "control.exe" $mailCpl
    } else {
        Write-Host "Mail Control Panel (mlcfg32.cpl) not found in standard Office paths." -ForegroundColor Red
    }
}
        3 {
            $pathsToClean = @(
                "$env:TEMP\Outlook Logging\*",
                "$env:TEMP\*.dat",
                "$env:LOCALAPPDATA\Microsoft\Outlook\*",
                "$env:APPDATA\Microsoft\Outlook\*",
                "$env:USERPROFILE\AppData\Local\Temp\*.tmp",
                "$env:USERPROFILE\AppData\Local\Microsoft\Outlook\*"
            )

            $found = $false
            foreach ($path in $pathsToClean) {
                if (Test-Path $path) {
                    try {
                        Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Host "Cleared: $path" -ForegroundColor Green
                        $found = $true
                    } catch {
                        Write-Host "Failed to clean: $path" -ForegroundColor Red
                    }
                }
            }

            if (-not $found) {
                Write-Host "No Outlook temp/log files found in common locations." -ForegroundColor Yellow
            }
        }

        4 {
            Show-MainMenu
        }

        default {
            Show-OutlookMenu
        }
    }
}

function Show-OneDriveMenu {
    Clear-Host
    Write-Host "=== OneDrive Troubleshooting ===" -ForegroundColor Blue
    Write-Host "1. Reset OneDrive"
    Write-Host "2. Restart OneDrive"
    Write-Host "3. Open OneDrive Logs Folder"
    Write-Host "4. Back"
    $choice = Read-Host "Select an action (1-4)"
    switch ($choice) {
        1 {
            $pathsToCheck = @(
                "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
                "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
                "$env:ProgramFiles(x86)\Microsoft OneDrive\OneDrive.exe"
            )

            $exePath = $pathsToCheck | Where-Object { Test-Path $_ } | Select-Object -First 1

            if ($exePath) {
                Start-Process $exePath "/reset"
            } else {
                Write-Host "OneDrive.exe not found in standard locations." -ForegroundColor Red
            }
        }

        2 {
            $pathsToCheck = @(
                "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
                "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
                "$env:ProgramFiles(x86)\Microsoft OneDrive\OneDrive.exe"
            )

            $exePath = $pathsToCheck | Where-Object { Test-Path $_ } | Select-Object -First 1

            # Fallback: use Start Menu shortcut to resolve actual target
            if (-not $exePath) {
                $shortcut = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
                if (Test-Path $shortcut) {
                    $exePath = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcut).TargetPath
                }
            }

            if ($exePath -and (Test-Path $exePath)) {
                Start-Process $exePath
            } else {
                Write-Host "OneDrive.exe not found in standard locations." -ForegroundColor Red
            }
        }

        3 {
            $logPath = "$env:LOCALAPPDATA\Microsoft\OneDrive\logs"
            if (Test-Path $logPath) {
                Start-Process "explorer.exe" $logPath
            } else {
                Write-Host "OneDrive logs folder not found." -ForegroundColor Yellow
            }
        }

        4 {
            Show-MainMenu
        }

        default {
            Show-OneDriveMenu
        }
    }
}
# Line 151 - Force stop all Office apps including legacy LYNC
Stop-Process -Name OUTLOOK, WINWORD, EXCEL, POWERPNT, SKYPE, LYNC -Force -ErrorAction SilentlyContinue


function Show-OfficeActivationMenu {
    Clear-Host
    Write-Host "=== Office Activation ===" -ForegroundColor Green
    Write-Host "1. View Activation Status"
    Write-Host "2. Run Online Repair"
    Write-Host "3. Back"
    $choice = Read-Host "Select an action (1-3)"
    switch ($choice) {
        1 {
            $osppPaths = @(
                "$env:ProgramFiles\Microsoft Office\Office16\ospp.vbs",
                "$env:ProgramFiles(x86)\Microsoft Office\Office16\ospp.vbs",
                "$env:ProgramFiles\Microsoft Office\root\Office16\ospp.vbs",
                "$env:ProgramFiles(x86)\Microsoft Office\root\Office16\ospp.vbs"
            )

            $ospp = $osppPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

            if ($ospp) {
                Write-Host "`nRunning Office activation status check..." -ForegroundColor Cyan
                Start-Process "cmd.exe" "/c cscript //Nologo `"$ospp`" /dstatus" -Wait
                Pause
            } else {
                Write-Host "`nospp.vbs not found. Office may be installed from Microsoft Store or missing." -ForegroundColor Red
                Pause
            }
        }

        2 {
            Write-Host "`nOpening Programs and Features..." -ForegroundColor Cyan
            Write-Host "To repair Office: Find 'Microsoft 365' in the list, right-click > Change > Online Repair." -ForegroundColor Gray
            Start-Process "appwiz.cpl" -Wait
            Pause
        }

        3 {
            Show-MainMenu
        }

        default {
            Show-OfficeActivationMenu
        }
    }
}

function Show-LoginAuthMenu {
    Clear-Host
    Write-Host "=== Login / MFA & Identity Management ===" -ForegroundColor Magenta
    Write-Host "1. Open Azure MFA Reset Portal"
    Write-Host "2. Open Microsoft Entra Admin Center"
    Write-Host "3. Open Entra Permissions Management"
    Write-Host "4. Open Microsoft Entra ID Overview"
    Write-Host "5. Open MySignins Portal (Sign-in History)"
    Write-Host "6. Back"
    $choice = Read-Host "Select an action (1-6)"
    switch ($choice) {
        1 {
            Write-Host "Opening Azure MFA reset portal..." -ForegroundColor Cyan
            Start-Process "https://account.activedirectory.windowsazure.com/usermanagement/multifactorverification.aspx"
            Pause
        }

        2 {
            Write-Host "Opening Microsoft Entra Admin Center..." -ForegroundColor Cyan
            Start-Process "https://entra.microsoft.com"
            Pause
        }

        3 {
            Write-Host "Opening Entra Permissions Management..." -ForegroundColor Cyan
            Start-Process "https://portal.cloudknox.io"
            Pause
        }

        4 {
            Write-Host "Opening Microsoft Entra ID Overview..." -ForegroundColor Cyan
            Start-Process "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Overview"
            Pause
        }

        5 {
            Write-Host "Opening MySignins Portal..." -ForegroundColor Cyan
            Start-Process "https://mysignins.microsoft.com"
            Pause
        }

        6 {
            Show-MainMenu
        }

        default {
            Show-LoginAuthMenu
        }
    }
}

function Show-TeamsMenu {
    Clear-Host
    Write-Host "=== Microsoft Teams Troubleshooting ===" -ForegroundColor Red
    Write-Host "1. Clear Teams Cache"
    Write-Host "2. Restart Teams"
    Write-Host "3. Back"
    $choice = Read-Host "Select an action (1-3)"
    switch ($choice) {
        1 {
    Write-Host "Stopping all Teams processes..." -ForegroundColor Cyan
    Stop-Process -Name Teams -Force -ErrorAction SilentlyContinue
    Stop-Process -Name TeamsUpdater -Force -ErrorAction SilentlyContinue
    Stop-Process -Name Update -Force -ErrorAction SilentlyContinue

    Write-Host "Clearing Teams cache and logs..." -ForegroundColor Cyan
    $teamsCachePaths = @(
        "$env:APPDATA\Microsoft\Teams\Application Cache\Cache\*",
        "$env:APPDATA\Microsoft\Teams\blob_storage\*",
        "$env:APPDATA\Microsoft\Teams\Cache\*",
        "$env:APPDATA\Microsoft\Teams\databases\*",
        "$env:APPDATA\Microsoft\Teams\GPUCache\*",
        "$env:APPDATA\Microsoft\Teams\IndexedDB\*",
        "$env:APPDATA\Microsoft\Teams\Local Storage\*",
        "$env:APPDATA\Microsoft\Teams\tmp\*",
        "$env:APPDATA\Microsoft\Teams\Logs\*",
        "$env:LOCALAPPDATA\Microsoft\Teams\*",
        "$env:LOCALAPPDATA\SquirrelTemp\*",
        "$env:TEMP\*.tmp",
        "$env:TEMP\Teams\*"
    )

    foreach ($path in $teamsCachePaths) {
        if (Test-Path $path) {
            Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "Cleared: $path" -ForegroundColor Green
        }
    }

    Write-Host "Teams cache cleared successfully." -ForegroundColor Yellow
    Pause
}

        2 {
    Write-Host "Attempting to restart Microsoft Teams..." -ForegroundColor Cyan

    $teamsExecutables = @(
        @{ Path = "$env:LOCALAPPDATA\Microsoft\Teams\Update.exe"; Args = "--processStart Teams.exe" },
        @{ Path = "$env:LOCALAPPDATA\Microsoft\Teams\current\Teams.exe"; Args = "" },
        @{ Path = "$env:ProgramFiles\Microsoft\Teams\current\Teams.exe"; Args = "" },
        @{ Path = "$env:ProgramFiles(x86)\Microsoft\Teams\current\Teams.exe"; Args = "" },
        @{ Path = "$env:LOCALAPPDATA\Microsoft\WindowsApps\Teams.exe"; Args = "" }
    )

    $launched = $false
    foreach ($entry in $teamsExecutables) {
        if (Test-Path $entry.Path) {
            Start-Process $entry.Path $entry.Args
            Write-Host "✅ Launched Teams from path: $($entry.Path)" -ForegroundColor Green
            $launched = $true
            break
        }
    }

    if (-not $launched) {
        Write-Host "⚠️ Teams EXE not found in standard locations. Attempting protocol launch..." -ForegroundColor Yellow
        try {
            Start-Process "explorer.exe" "ms-teams:"
            Write-Host "✅ Launched Teams using 'ms-teams:' URI protocol." -ForegroundColor Green
        } catch {
            Write-Host "❌ Failed to launch Teams via URI protocol. Teams may not be installed." -ForegroundColor Red
        }
    }

    Pause
}

        3 {
            Show-MainMenu
        }

        default {
            Show-TeamsMenu
        }
    }
}
# Line 333 - Renew IP and check for APIPA
ipconfig /release
ipconfig /renew
ipconfig /all | Out-Host

# Validate non-APIPA address
$ipValid = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notmatch '^169\.254\.' -and $_.IPAddress -ne '127.0.0.1'
}).IPAddress

if (-not $ipValid) {
    Write-Host "⚠️ Warning: IP address is still APIPA. Network issue may persist." -ForegroundColor Yellow
}


function Show-NetworkMenu {
    while ($true) {
        Clear-Host
        Write-Host "=== Network Troubleshooting ===" -ForegroundColor Cyan
        Write-Host "1. Flush DNS"
        Write-Host "2. View IP Configuration"
        Write-Host "3. Restart Network Adapter"
        Write-Host "4. Ping Test"
        Write-Host "5. Run Traceroute"
        Write-Host "6. Check Public IP Address"
        Write-Host "7. Test DNS Resolution"
        Write-Host "8. Basic Port Scan"
        Write-Host "9. Back"
        $choice = Read-Host "Select an action (1-9)"
        switch ($choice) {

            1 {
                Write-Host "⚠️  Flushing DNS will clear cached domain name lookups." -ForegroundColor Yellow
                ipconfig /flushdns
                Write-Host "✅ DNS cache flushed." -ForegroundColor Green
                Pause
            }

            2 {
                ipconfig /all | Out-Host
                Pause
            }

            3 {
# Line 363 - Network connections
netstat -ano | Select-String "ESTABLISHED"
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' } | Format-Table -AutoSize

                Write-Host "⚠️  Restarting your network adapter may interrupt connectivity or remote sessions." -ForegroundColor Red
                $confirm = Read-Host "Are you sure you want to restart the adapter? (Y/N)"
                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
                    if ($adapter) {
                        Disable-NetAdapter -Name $adapter.Name -Confirm:$false
                        Start-Sleep -Seconds 3
                        Enable-NetAdapter -Name $adapter.Name -Confirm:$false
                        Write-Host "✅ Restarted adapter: $($adapter.Name)" -ForegroundColor Green
                    } else {
                        Write-Host "❌ No active network adapter found." -ForegroundColor Red
                    }
                } else {
                    Write-Host "❌ Cancelled. Adapter not restarted." -ForegroundColor DarkGray
                }
                Pause
            }

            4 {
                $target = Read-Host "Enter hostname or IP to ping"
                Test-Connection -ComputerName $target -Count 4 | Format-Table
                Pause
            }

            5 {
                $target = Read-Host "Enter hostname or IP for traceroute"
                tracert $target | Out-Host
                Pause
            }

            6 {
                try {
                    $publicIP = Invoke-RestMethod "https://api.ipify.org?format=json"
                    Write-Host "🌐 Public IP Address: $($publicIP.ip)" -ForegroundColor Green
                } catch {
                    Write-Host "❌ Unable to retrieve public IP address." -ForegroundColor Red
                }
                Pause
            }

            7 {
                $domain = Read-Host "Enter domain to resolve (e.g. google.com)"
                try {
                    $dnsResult = Resolve-DnsName $domain
                    $dnsResult | Format-Table
                } catch {
                    Write-Host "❌ DNS resolution failed for $domain" -ForegroundColor Red
                }
                Pause
            }

            8 {
                Write-Host "⚠️  Port scans may be flagged by firewalls or antivirus tools." -ForegroundColor Yellow
                $targetHost = Read-Host "Enter host/IP to scan"
                $ports = @(21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389)

                foreach ($port in $ports) {
                    try {
                        $tcp = New-Object System.Net.Sockets.TcpClient
                        $tcp.Connect($targetHost, $port)
                        Write-Host "✅ Port $port open" -ForegroundColor Green
                        $tcp.Close()
                    } catch {
                        Write-Host "❌ Port $port closed or filtered" -ForegroundColor DarkGray
                    }
                }
                Pause
            }

            9 {
                return
            }

            default {
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
                Pause
            }
        }
    }
}

function Show-DevicesPrintersMenu {
    while ($true) {
        Clear-Host
        Write-Host "=== Devices & Printers ===" -ForegroundColor White
        Write-Host "1. Restart Print Spooler"
        Write-Host "2. List Installed Printers"
        Write-Host "3. Open Devices and Printers"
        Write-Host "4. Clear Stuck Print Jobs"
        Write-Host "5. Back"
        $choice = Read-Host "Select an action (1-5)"

        switch ($choice) {
            1 {
                try {
                    Restart-Service -Name Spooler -Force -ErrorAction Stop
                    Write-Host "`nPrint Spooler restarted successfully." -ForegroundColor Green
                } catch {
                    Write-Host "`nFailed to restart Print Spooler: $_" -ForegroundColor Red
                }
                Pause
            }
            2 {
                try {
                    Get-Printer | Format-Table Name, DriverName, PortName
                } catch {
                    Write-Host "`nFailed to list printers: $_" -ForegroundColor Red
                }
                Pause
            }
            3 {
                Write-Host "`nAttempting to open Devices and Printers..." -ForegroundColor Cyan
                $opened = $false
                try {
                    Start-Process "rundll32.exe" "shell32.dll,Control_RunDLL printers"
                    $opened = $true
                } catch {}

                if (-not $opened) {
                    try {
                        Start-Process "explorer.exe" "shell:::{A8A91A66-3A7D-4424-8D24-04E180695C7A}"
                        $opened = $true
                    } catch {}
                }

                if (-not $opened) {
                    try {
                        Start-Process "ms-settings:printers"
                        $opened = $true
                    } catch {}
                }

                if (-not $opened) {
                    Write-Host "❌ Failed to open Devices and Printers in any known way." -ForegroundColor Red
                }
                Pause
            }
            4 {
                try {
                    Stop-Service spooler -Force
                    Remove-Item "$env:SystemRoot\System32\spool\PRINTERS\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Start-Service spooler
                    Write-Host "`nStuck print jobs cleared." -ForegroundColor Green
                } catch {
                    Write-Host "`nFailed to clear print jobs: $_" -ForegroundColor Red
                }
                Pause
            }
            5 {
                return  # Go back to Main Menu
            }
            default {
                Write-Host "`nInvalid selection. Try again." -ForegroundColor Red
                Pause
            }
        }
    }
}

function Show-UserProfilesMenu {
    while ($true) {
        Clear-Host
        Write-Host "=== User Profiles & Accounts ===" -ForegroundColor White
        Write-Host "1. Create New Local Admin User"
        Write-Host "2. Reset Local User Password"
        Write-Host "3. Clear Local Profile Registry Keys (use with caution)"
        Write-Host "4. Back"

        $choice = Read-Host "Select an action (1-4)"
        switch ($choice) {
            1 {
                try {
                    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
                        Write-Host "`n⚠️ You must run this tool as Administrator to create new users." -ForegroundColor Yellow
                        Pause
                        continue
                    }

                    $username = Read-Host "Enter new username"
                    if ([string]::IsNullOrWhiteSpace($username)) {
                        Write-Host "Invalid username." -ForegroundColor Red
                        Pause
                        continue
                    }

                    $password = Read-Host "Enter password" -AsSecureString

                    New-LocalUser -Name $username -Password $password -FullName $username -Description "Created by Helpdesk Toolkit"
                    Add-LocalGroupMember -Group "Administrators" -Member $username
                    Write-Host "`n✅ Local admin user '$username' created successfully." -ForegroundColor Green
                } catch {
                    Write-Host "`n❌ Failed to create user: $_" -ForegroundColor Red
                }
                Pause
            }
            2 {
                try {
                    $username = Read-Host "Enter username to reset password for"
                    $password = Read-Host "Enter new password" -AsSecureString

                    Set-LocalUser -Name $username -Password $password
                    Write-Host "`n✅ Password for '$username' updated." -ForegroundColor Green
                } catch {
                    Write-Host "`n❌ Failed to reset password: $_" -ForegroundColor Red
                }
                Pause
            }
            3 {
                Write-Host "`n⚠️ This will remove all user profile registry keys from the current user hive."
                Write-Host "This is typically only used after removing local user profiles manually." -ForegroundColor Yellow
                $confirm = Read-Host "Are you sure? Type YES to continue"

                if ($confirm -eq "YES") {
                    try {
                        Remove-Item -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList" -Recurse -Force -ErrorAction Stop
                        Write-Host "`n✅ Registry keys cleared." -ForegroundColor Green
                    } catch {
                        Write-Host "`n❌ Failed to clear registry keys: $_" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Cancelled." -ForegroundColor Cyan
                }
                Pause
            }
            4 {
                return  # Back to Main Menu
            }
            default {
                Write-Host "Invalid selection." -ForegroundColor Red
                Pause
            }
        }
    }
}

function Show-StartupPerformanceMenu {
    while ($true) {
        Clear-Host
        Write-Host "=== Startup & Performance ===" -ForegroundColor Green
        Write-Host "1. Launch Task Manager"
        Write-Host "2. Launch Autoruns (if installed)"
        Write-Host "3. Clear Temp and Prefetch"
        Write-Host "4. View Top Resource Consumers"
        Write-Host "5. Back"

        $choice = Read-Host "Select an action (1-5)"
        switch ($choice) {
            1 {
                Start-Process "taskmgr.exe"
                Pause
            }
            2 {
                $autorunsPaths = @(
                    "$env:USERPROFILE\Desktop\Autoruns.exe",
                    "$env:ProgramFiles\Autoruns\Autoruns.exe",
                    "$env:ProgramFiles(x86)\Autoruns\Autoruns.exe"
                )

                $found = $false
                foreach ($path in $autorunsPaths) {
                    if (Test-Path $path) {
                        Start-Process $path
                        $found = $true
                        break
                    }
                }

                if (-not $found) {
                    Write-Host "`n⚠️ Autoruns.exe not found. Please install it and try again." -ForegroundColor Yellow
                }
                Pause
            }
            3 {
                try {
                    Remove-Item "$env:TEMP\*" -Recurse -Force -ErrorAction Stop
                    Remove-Item "C:\Windows\Prefetch\*" -Recurse -Force -ErrorAction Stop
                    Write-Host "`n✅ Temp and Prefetch files cleared." -ForegroundColor Green
                } catch {
                    Write-Host "`n❌ Failed to clear some files. Try running as Administrator." -ForegroundColor Red
                }
                Pause
            }
            4 {
                Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Format-Table Name, CPU
                Pause
            }
            5 { return }
            default {
                Write-Host "Invalid option." -ForegroundColor Red
                Pause
            }
        }
    }
}

function Show-SystemRecoveryMenu {
    while ($true) {
        Clear-Host
        Write-Host "=== System Recovery Tools ===" -ForegroundColor Cyan
        Write-Host "1. Launch System Restore"
        Write-Host "2. Create Restore Point"
        Write-Host "3. Boot into Safe Mode (Next Reboot)"
        Write-Host "4. Back"

        $choice = Read-Host "Select an action (1-4)"
        switch ($choice) {
            1 {
                try {
                    Start-Process "rstrui.exe"
                } catch {
                    Write-Host "`n❌ Failed to launch System Restore: $_" -ForegroundColor Red
                }
                Pause
            }
            2 {
                try {
                    Enable-ComputerRestore -Drive "C:\"
                    Checkpoint-Computer -Description "Manual restore point by Helpdesk Toolkit" -RestorePointType "MODIFY_SETTINGS"
                    Write-Host "`n✅ Restore point created successfully." -ForegroundColor Green
                } catch {
                    Write-Host "`n❌ Could not create restore point: $_" -ForegroundColor Red
                }
                Pause
            }
            3 {
                try {
                    bcdedit /set {current} safeboot minimal
                    Write-Host "`n✅ Safe Mode enabled. Will apply on next reboot." -ForegroundColor Green

                    $rebootChoice = Read-Host "Would you like to reboot now? (Y/N)"
                    if ($rebootChoice -match '^[Yy]$') {
                        Write-Host "Rebooting..." -ForegroundColor Cyan
                        Restart-Computer
                    } else {
                        Write-Host "You can reboot manually when ready." -ForegroundColor Yellow
                        Pause
                    }
                } catch {
                    Write-Host "`n❌ Failed to configure Safe Mode: $_" -ForegroundColor Red
                    Pause
                }
            }
            4 { return }
            default {
                Write-Host "Invalid option." -ForegroundColor Red
                Pause
            }
        }
    }
}

function Show-SystemLogsMenu {
    while ($true) {
        Clear-Host
        Write-Host "=== System Logs & Events ===" -ForegroundColor White
        Write-Host "1. View Application Log"
        Write-Host "2. View System Log"
        Write-Host "3. Export Last 50 System Errors to CSV"
        Write-Host "4. Back"

        $choice = Read-Host "Select an action (1-4)"
        switch ($choice) {
            1 {
                try {
                    Write-Host "`n📄 Viewing latest 50 Application log entries..." -ForegroundColor Cyan
                    Write-Host "👉 Press Q to exit log view, SPACE for next page, ENTER for next line" -ForegroundColor Yellow
                    Pause
                    $logs = Get-EventLog -LogName Application -Newest 50 |
                        Select-Object TimeGenerated, EntryType, Source, Message
                    $logs | Format-Table -Wrap | Out-String | more
                } catch {
                    Write-Host "`n❌ Error reading Application log: $_" -ForegroundColor Red
                    Pause
                }
            }
            2 {
                try {
                    Write-Host "`n📄 Viewing latest 50 System log entries..." -ForegroundColor Cyan
                    Write-Host "👉 Press Q to exit log view, SPACE for next page, ENTER for next line" -ForegroundColor Yellow
                    Pause
                    $logs = Get-EventLog -LogName System -Newest 50 |
                        Select-Object TimeGenerated, EntryType, Source, Message
                    $logs | Format-Table -Wrap | Out-String | more
                } catch {
                    Write-Host "`n❌ Error reading System log: $_" -ForegroundColor Red
                    Pause
                }
            }
            3 {
                try {
                    $exportPath = "$env:USERPROFILE\Desktop\SystemErrors.csv"
                    Get-EventLog -LogName System -EntryType Error -Newest 50 |
                        Select-Object TimeGenerated, Source, EventID, Message |
                        Export-Csv $exportPath -NoTypeInformation
                    Write-Host "`n✅ Exported to: $exportPath" -ForegroundColor Green
                } catch {
                    Write-Host "`n❌ Failed to export logs: $_" -ForegroundColor Red
                }
                Pause
            }
            4 { return }
            default {
                Write-Host "Invalid option. Try again." -ForegroundColor Red
                Pause
            }
        }
    }
}
# Line 771 - gpupdate
gpupdate /force


function Show-WindowsUpdateMenu {
    while ($true) {
        Clear-Host
        Write-Host "=== Windows Update Tools ===" -ForegroundColor Blue
        Write-Host "1. Force Update Scan"
        Write-Host "2. View Installed Update History"
        Write-Host "3. Clear Windows Update Cache"
        Write-Host "4. Back"

        $choice = Read-Host "Select an action (1-4)"
        switch ($choice) {
            1 {
                try {
                    Write-Host "`n🔄 Forcing Windows Update Scan..." -ForegroundColor Cyan
                    Start-Process "UsoClient.exe" "StartScan"
                    Write-Host "✅ Update scan triggered."
                } catch {
                    Write-Host "❌ Failed to trigger update scan: $_" -ForegroundColor Red
                }
                Pause
            }

            2 {
                try {
                    Write-Host "`n📋 Installed Updates:" -ForegroundColor Cyan
                    Get-HotFix | Format-Table -AutoSize
                } catch {
                    Write-Host "❌ Failed to retrieve update history: $_" -ForegroundColor Red
                }
                Pause
            }

            3 {
                Write-Host "`n⚠️ This will stop the update service and clear cache files." -ForegroundColor Yellow
                Write-Host "You may need to run this as Administrator."
                Pause
                try {
                    net stop wuauserv | Out-Null
                    Remove-Item "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
                    net start wuauserv | Out-Null
                    Write-Host "`n✅ Windows Update cache cleared and service restarted." -ForegroundColor Green
                } catch {
                    Write-Host "❌ Failed to clear update cache: $_" -ForegroundColor Red
                }
                Pause
            }

            4 { return }

            default {
                Write-Host "Invalid option. Please try again." -ForegroundColor Red
# Line 823 - Safe Mode reboot with delay warning
Write-Host "⚠️ Safe Mode has been scheduled. System will reboot immediately!" -ForegroundColor Yellow
Start-Sleep -Seconds 5
shutdown /r /t 0 /f

                Pause
            }
        }
    }
}

function Show-BrowserInternetMenu {
    while ($true) {
        Clear-Host
        Write-Host "=== Browser & Internet Issues ===" -ForegroundColor DarkYellow
        Write-Host "1. Flush DNS Cache"
        Write-Host "2. Reset WinHTTP Proxy Settings"
        Write-Host "3. Reset Microsoft Edge Settings"
        Write-Host "4. Reset Google Chrome Settings"
        Write-Host "5. Back"

        $choice = Read-Host "Select an action (1-5)"
        switch ($choice) {
            1 {
                try {
                    Write-Host "`n🔄 Flushing DNS cache..." -ForegroundColor Cyan
                    ipconfig /flushdns | Out-Null
                    Write-Host "✅ DNS cache flushed successfully." -ForegroundColor Green
                } catch {
                    Write-Host "❌ Failed to flush DNS: $_" -ForegroundColor Red
                }
                Pause
            }

            2 {
                try {
                    Write-Host "`n🔄 Resetting WinHTTP proxy settings..." -ForegroundColor Cyan
                    netsh winhttp reset proxy | Out-Null
                    Write-Host "✅ Proxy settings reset." -ForegroundColor Green
                } catch {
                    Write-Host "❌ Failed to reset proxy: $_" -ForegroundColor Red
                }
                Pause
            }

            3 {
                Write-Host "`n⚠️ This will delete your Edge browser profile, including bookmarks, history, and settings." -ForegroundColor Yellow
                $confirm = Read-Host "Are you sure you want to continue? (Y/N)"
                if ($confirm -match '^[Yy]$') {
                    try {
                        Stop-Process -Name "msedge" -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 1
                        Remove-Item "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default" -Recurse -Force -ErrorAction Stop
                        Write-Host "✅ Edge profile reset." -ForegroundColor Green
                    } catch {
                        Write-Host "❌ Failed to reset Edge: $_" -ForegroundColor Red
                    }
                } else {
                    Write-Host "❌ Operation cancelled." -ForegroundColor DarkGray
                }
                Pause
            }

            4 {
# Line 882 - Bookmark backup with Windows version check
$osVersion = (Get-CimInstance Win32_OperatingSystem).Version
$isWin11 = ($osVersion -like "10.0.22*")

if ($isWin11) {
    Copy-Item "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Bookmarks" "$env:USERPROFILE\Desktop\EdgeBookmarksBackup_Win11.json" -Force -ErrorAction SilentlyContinue
    Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks" "$env:USERPROFILE\Desktop\ChromeBookmarksBackup_Win11.json" -Force -ErrorAction SilentlyContinue
} else {
    Copy-Item "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Bookmarks" "$env:USERPROFILE\Desktop\EdgeBookmarksBackup_Win10.json" -Force -ErrorAction SilentlyContinue
    Copy-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks" "$env:USERPROFILE\Desktop\ChromeBookmarksBackup_Win10.json" -Force -ErrorAction SilentlyContinue
}

                Write-Host "`n⚠️ This will delete your Chrome browser profile, including bookmarks, history, and settings." -ForegroundColor Yellow
                $confirm = Read-Host "Are you sure you want to continue? (Y/N)"
                if ($confirm -match '^[Yy]$') {
                    try {
                        Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 1
                        Remove-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default" -Recurse -Force -ErrorAction Stop
                        Write-Host "✅ Chrome profile reset." -ForegroundColor Green
                    } catch {
                        Write-Host "❌ Failed to reset Chrome: $_" -ForegroundColor Red
                    }
                } else {
                    Write-Host "❌ Operation cancelled." -ForegroundColor DarkGray
                }
                Pause
            }

            5 { return }

            default {
                Write-Host "Invalid option. Try again." -ForegroundColor Red
                Pause
            }
        }
    }
}


function Show-HelpdeskProfileInfo {
    Clear-Host
    Write-Host "=== Helpdesk Profile Info ===" -ForegroundColor Cyan

    $hostname = $env:COMPUTERNAME
    $user = $env:USERNAME
    $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike '169.*' -and $_.IPAddress -ne "127.0.0.1"} | Select-Object -First 1).IPAddress
    $os = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
    $uptimeFormatted = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    $uptimeHours = [math]::Round(((Get-Date) - $uptimeFormatted).TotalHours, 1)

    # Check if script is running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdmin) {
        try {
            $lastLogon = (Get-EventLog -LogName Security -InstanceId 4624 -Newest 1).TimeGenerated
        } catch {
            $lastLogon = "Could not retrieve logon time"
        }
    } else {
        $lastLogon = "Run as Administrator to view last logon"
    }

    Write-Host "`nComputer Name: $hostname"
    Write-Host "Username: $user"
    Write-Host "IP Address: $ip"
    Write-Host "OS Version: $os"
    Write-Host "System Uptime: $uptimeHours hours"
    Write-Host "Last Logon: $lastLogon"

    Pause
    Show-MainMenu
}

function Show-MainMenu {
    while ($true) {
        Clear-Host
        Write-Host "==== LAZY TECH 2 ====" -ForegroundColor Cyan
        Write-Host "1. Outlook Issues"
        Write-Host "2. OneDrive Issues"
        Write-Host "3. Office Activation & Licensing"
        Write-Host "4. Login / Auth / MFA"
        Write-Host "5. Teams Issues"
        Write-Host "6. Network / Connectivity"
        Write-Host "7. Devices & Printers"
        Write-Host "8. User Profiles & Accounts"
        Write-Host "9. Startup & Performance"
        Write-Host "10. System Recovery Tools"
        Write-Host "11. System Logs & Events"
        Write-Host "12. Windows Update Tools"
        Write-Host "13. Browser & Internet Issues"
        Write-Host "14. Helpdesk Profile Info"
        Write-Host "15. Exit"
        $choice = Read-Host "Select a category (1-15)"
        switch ($choice) {
            1 { Show-OutlookMenu }
            2 { Show-OneDriveMenu }
            3 { Show-OfficeActivationMenu }
            4 { Show-LoginAuthMenu }
            5 { Show-TeamsMenu }
            6 { Show-NetworkMenu }
            7 { Show-DevicesPrintersMenu }
            8 { Show-UserProfilesMenu }
            9 { Show-StartupPerformanceMenu }
            10 { Show-SystemRecoveryMenu }
            11 { Show-SystemLogsMenu }
            12 { Show-WindowsUpdateMenu }
            13 { Show-BrowserInternetMenu }
            14 { Show-HelpdeskProfileInfo }
            15 { exit }
            default {
                Write-Host "Invalid option. Try again." -ForegroundColor Red
                Pause
            }
        }
    }
}
Show-MainMenu
