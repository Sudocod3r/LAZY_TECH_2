Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-BrowserBookmarkBackupGUI {
    $form                = New-Object System.Windows.Forms.Form
    $form.Text           = "Browser Bookmarks Backup & Chrome Reset"
    $form.Size           = New-Object System.Drawing.Size(540, 340)
    $form.StartPosition  = "CenterScreen"
    $form.FormBorderStyle= "FixedDialog"
    $form.MaximizeBox    = $false

    $outputBox                 = New-Object System.Windows.Forms.TextBox
    $outputBox.Multiline       = $true
    $outputBox.ScrollBars      = "Vertical"
    $outputBox.ReadOnly        = $true
    $outputBox.Size            = New-Object System.Drawing.Size(500,140)
    $outputBox.Location        = New-Object System.Drawing.Point(10,10)
    $outputBox.Font            = 'Consolas, 10'
    $form.Controls.Add($outputBox)

    function Add-Output($msg) {
        $outputBox.AppendText($msg + "`r`n")
        $outputBox.SelectionStart = $outputBox.Text.Length
        $outputBox.ScrollToCaret()
    }

    $btnBackup = New-Object System.Windows.Forms.Button
    $btnBackup.Text = "Backup Edge/Chrome Bookmarks"
    $btnBackup.Size = New-Object System.Drawing.Size(500,35)
    $btnBackup.Location = New-Object System.Drawing.Point(10,165)
    $btnBackup.Add_Click({
        $outputBox.Clear()
        $osVersion = (Get-CimInstance Win32_OperatingSystem).Version
        $isWin11   = $false
        if ($osVersion -like "10.0.22*") { $isWin11 = $true }
        if ($isWin11) { $suffix = "Win11" } else { $suffix = "Win10" }

        $edgeSource  = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Bookmarks"
        $chromeSource= "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Bookmarks"

        $edgeDest    = "$env:USERPROFILE\Desktop\EdgeBookmarksBackup_$suffix.json"
        $chromeDest  = "$env:USERPROFILE\Desktop\ChromeBookmarksBackup_$suffix.json"

        try {
            if (Test-Path $edgeSource) {
                Copy-Item $edgeSource $edgeDest -Force
                Add-Output "✅ Edge bookmarks backed up to: $edgeDest"
            } else {
                Add-Output "⚠️ Edge bookmarks file not found."
            }
        } catch {
            Add-Output "❌ Failed to backup Edge bookmarks: $($_.Exception.Message)"
        }

        try {
            if (Test-Path $chromeSource) {
                Copy-Item $chromeSource $chromeDest -Force
                Add-Output "✅ Chrome bookmarks backed up to: $chromeDest"
            } else {
                Add-Output "⚠️ Chrome bookmarks file not found."
            }
        } catch {
            Add-Output "❌ Failed to backup Chrome bookmarks: $($_.Exception.Message)"
        }
    })
    $form.Controls.Add($btnBackup)

    $btnChromeReset = New-Object System.Windows.Forms.Button
    $btnChromeReset.Text = "Reset Chrome Profile (Danger!)"
    $btnChromeReset.Size = New-Object System.Drawing.Size(500,35)
    $btnChromeReset.Location = New-Object System.Drawing.Point(10,205)
    $btnChromeReset.Add_Click({
        $outputBox.Clear()
        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "This will DELETE your Chrome profile (history, bookmarks, extensions, etc.). Are you sure?",
            "Confirm Chrome Profile Reset",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
            try {
                Stop-Process -Name "chrome" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
                Remove-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default" -Recurse -Force -ErrorAction Stop
                Add-Output "✅ Chrome profile reset."
            } catch {
                Add-Output "❌ Failed to reset Chrome: $($_.Exception.Message)"
            }
        } else {
            Add-Output "❌ Operation cancelled."
        }
    })
    $form.Controls.Add($btnChromeReset)

    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Text = "Back"
    $btnExit.Size = New-Object System.Drawing.Size(500,35)
    $btnExit.Location = New-Object System.Drawing.Point(10,245)
    $btnExit.Add_Click({ $form.Close() })
    $form.Controls.Add($btnExit)

    [void]$form.ShowDialog()
}

Show-BrowserBookmarkBackupGUI
