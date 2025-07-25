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
