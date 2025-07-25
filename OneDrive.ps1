Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-OneDriveMenu-GUI {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'OneDrive Troubleshooting'
    $form.Size = New-Object System.Drawing.Size(420,255)
    $form.StartPosition = 'CenterScreen'

    # Status label
    $statusLabel = New-Object System.Windows.Forms.Label
    $statusLabel.Size = New-Object System.Drawing.Size(380,30)
    $statusLabel.Location = New-Object System.Drawing.Point(20, 160)
    $statusLabel.Text = "Ready"
    $form.Controls.Add($statusLabel)

    function Show-Status($msg, $color='Black') {
        $statusLabel.ForeColor = [System.Drawing.Color]::$color
        $statusLabel.Text = $msg
    }

    # Button 1: Reset OneDrive
    $btn1 = New-Object System.Windows.Forms.Button
    $btn1.Text = 'Reset OneDrive'
    $btn1.Size = New-Object System.Drawing.Size(360,32)
    $btn1.Location = New-Object System.Drawing.Point(20,20)
    $btn1.Add_Click({
        try {
            $pathsToCheck = @(
                "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
                "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
                "$env:ProgramFiles(x86)\Microsoft OneDrive\OneDrive.exe"
            )
            $exePath = $pathsToCheck | Where-Object { Test-Path $_ } | Select-Object -First 1
            if ($exePath) {
                Start-Process $exePath "/reset"
                Show-Status "OneDrive reset command issued." 'Green'
            } else {
                Show-Status "OneDrive.exe not found in standard locations." 'Red'
            }
        } catch {
            Show-Status "Error: $_" 'Red'
        }
    })
    $form.Controls.Add($btn1)

    # Button 2: Restart OneDrive
    $btn2 = New-Object System.Windows.Forms.Button
    $btn2.Text = 'Restart OneDrive'
    $btn2.Size = New-Object System.Drawing.Size(360,32)
    $btn2.Location = New-Object System.Drawing.Point(20,60)
    $btn2.Add_Click({
        try {
            $pathsToCheck = @(
                "$env:LOCALAPPDATA\Microsoft\OneDrive\OneDrive.exe",
                "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe",
                "$env:ProgramFiles(x86)\Microsoft OneDrive\OneDrive.exe"
            )
            $exePath = $pathsToCheck | Where-Object { Test-Path $_ } | Select-Object -First 1
            # Fallback: use Start Menu shortcut
            if (-not $exePath) {
                $shortcut = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
                if (Test-Path $shortcut) {
                    $exePath = (New-Object -ComObject WScript.Shell).CreateShortcut($shortcut).TargetPath
                }
            }
            if ($exePath -and (Test-Path $exePath)) {
                Start-Process $exePath
                Show-Status "OneDrive started." 'Green'
            } else {
                Show-Status "OneDrive.exe not found in standard locations." 'Red'
            }
        } catch {
            Show-Status "Error: $_" 'Red'
        }
    })
    $form.Controls.Add($btn2)

    # Button 3: Open OneDrive Logs Folder
    $btn3 = New-Object System.Windows.Forms.Button
    $btn3.Text = 'Open OneDrive Logs Folder'
    $btn3.Size = New-Object System.Drawing.Size(360,32)
    $btn3.Location = New-Object System.Drawing.Point(20,100)
    $btn3.Add_Click({
        try {
            $logPath = "$env:LOCALAPPDATA\Microsoft\OneDrive\logs"
            if (Test-Path $logPath) {
                Start-Process "explorer.exe" $logPath
                Show-Status "Opened logs folder." 'Green'
            } else {
                Show-Status "OneDrive logs folder not found." 'Orange'
            }
        } catch {
            Show-Status "Error: $_" 'Red'
        }
    })
    $form.Controls.Add($btn3)

    # Button 4: Close
    $btn4 = New-Object System.Windows.Forms.Button
    $btn4.Text = 'Close'
    $btn4.Size = New-Object System.Drawing.Size(360,32)
    $btn4.Location = New-Object System.Drawing.Point(20,140)
    $btn4.Add_Click({ $form.Close() })
    $form.Controls.Add($btn4)

    [void]$form.ShowDialog()
}

# To launch the GUI:
Show-OneDriveMenu-GUI
