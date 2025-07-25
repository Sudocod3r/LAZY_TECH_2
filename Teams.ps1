Add-Type -AssemblyName System.Windows.Forms

function Clear-TeamsCache {
    $log = ""
    $processes = 'Teams','TeamsUpdater','Update'
    foreach ($proc in $processes) {
        try {
            Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
            $log += "Stopped: $proc`n"
        } catch {
            $log += "Could not stop: $proc`n"
        }
    }

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
            try {
                Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
                $log += "Cleared: $path`n"
            } catch {
                $log += "Failed to clear: $path`n"
            }
        }
    }
    if ($log -eq "") { $log = "No Teams cache files found to clear." }
    return $log
}

function Restart-Teams {
    $log = ""
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
            try {
                Start-Process $entry.Path $entry.Args
                $log += "✅ Launched Teams from path: $($entry.Path)`n"
                $launched = $true
                break
            } catch {
                $log += "❌ Failed to launch: $($entry.Path)`n"
            }
        }
    }

    if (-not $launched) {
        $log += "⚠️ Teams EXE not found in standard locations. Trying protocol...`n"
        try {
            Start-Process "explorer.exe" "ms-teams:"
            $log += "✅ Launched Teams using ms-teams: protocol.`n"
        } catch {
            $log += "❌ Failed to launch Teams via protocol. Teams may not be installed.`n"
        }
    }
    return $log
}

function Show-TeamsMenu-GUI {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Microsoft Teams Troubleshooting"
    $form.Size = New-Object System.Drawing.Size(560,380)
    $form.StartPosition = "CenterScreen"

    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = "Teams Troubleshooting"
    $lblTitle.Font = 'Segoe UI,14,style=Bold'
    $lblTitle.ForeColor = 'Red'
    $lblTitle.Location = New-Object System.Drawing.Point(15,15)
    $lblTitle.Size = New-Object System.Drawing.Size(340,28)
    $form.Controls.Add($lblTitle)

    $txtLog = New-Object System.Windows.Forms.TextBox
    $txtLog.Multiline = $true
    $txtLog.ReadOnly = $true
    $txtLog.ScrollBars = "Vertical"
    $txtLog.Size = New-Object System.Drawing.Size(520,170)
    $txtLog.Location = New-Object System.Drawing.Point(15,55)
    $txtLog.Font = 'Consolas, 10pt'
    $form.Controls.Add($txtLog)

    $btnClearCache = New-Object System.Windows.Forms.Button
    $btnClearCache.Text = "Clear Teams Cache"
    $btnClearCache.Size = New-Object System.Drawing.Size(160,40)
    $btnClearCache.Location = New-Object System.Drawing.Point(15,240)
    $btnClearCache.Add_Click({
        $txtLog.Text = Clear-TeamsCache
    })
    $form.Controls.Add($btnClearCache)

    $btnRestartTeams = New-Object System.Windows.Forms.Button
    $btnRestartTeams.Text = "Restart Teams"
    $btnRestartTeams.Size = New-Object System.Drawing.Size(160,40)
    $btnRestartTeams.Location = New-Object System.Drawing.Point(185,240)
    $btnRestartTeams.Add_Click({
        $txtLog.Text = Restart-Teams
    })
    $form.Controls.Add($btnRestartTeams)

    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Text = "Exit"
    $btnExit.Size = New-Object System.Drawing.Size(160,40)
    $btnExit.Location = New-Object System.Drawing.Point(355,240)
    $btnExit.Add_Click({ $form.Close() })
    $form.Controls.Add($btnExit)

    $form.ShowDialog()
}

Show-TeamsMenu-GUI
