# LAZY TECH 2 - Modular CLI Launcher
# Author: Cypher Playfair

# Import all function modules from current folder (or specify a folder)
$modules = @(
    "OutlookMenu.ps1",
    "OneDriveMenu.ps1",
    "OfficeActivationMenu.ps1",
    "LoginAuthMenu.ps1",
    "TeamsMenu.ps1",
    "NetworkMenu.ps1",
    "DevicesPrintersMenu.ps1",
    "UserProfilesMenu.ps1",
    "StartupPerformanceMenu.ps1",
    "SystemRecoveryMenu.ps1",
    "SystemLogsMenu.ps1",
    "WindowsUpdateMenu.ps1",
    "BrowserInternetMenu.ps1",
    "HelpdeskProfileInfo.ps1"
)

foreach ($mod in $modules) {
    $path = Join-Path -Path $PSScriptRoot -ChildPath $mod
    if (Test-Path $path) {
        . $path
    } else {
        Write-Host "Missing module: $mod" -ForegroundColor Yellow
    }
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

function Pause { Write-Host ''; Read-Host 'Press ENTER to continue...' | Out-Null }

Show-MainMenu
