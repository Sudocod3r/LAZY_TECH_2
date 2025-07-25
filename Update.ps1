Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Show-WindowsUpdateMenuGUI {
    $form                = New-Object System.Windows.Forms.Form
    $form.Text           = "Windows Update Tools"
    $form.Size           = New-Object System.Drawing.Size(540, 340)
    $form.StartPosition  = "CenterScreen"
    $form.FormBorderStyle= "FixedDialog"
    $form.MaximizeBox    = $false

    $outputBox                 = New-Object System.Windows.Forms.TextBox
    $outputBox.Multiline       = $true
    $outputBox.ScrollBars      = "Vertical"
    $outputBox.ReadOnly        = $true
    $outputBox.Size            = New-Object System.Drawing.Size(500,130)
    $outputBox.Location        = New-Object System.Drawing.Point(10,10)
    $outputBox.Font            = 'Consolas, 10'
    $form.Controls.Add($outputBox)

    function Add-Output($msg) {
        $outputBox.AppendText($msg + "`r`n")
        $outputBox.SelectionStart = $outputBox.Text.Length
        $outputBox.ScrollToCaret()
    }

    $btn1 = New-Object System.Windows.Forms.Button
    $btn1.Text = "Force Update Scan"
    $btn1.Size = New-Object System.Drawing.Size(250,35)
    $btn1.Location = New-Object System.Drawing.Point(10,155)
    $btn1.Add_Click({
        $outputBox.Clear()
        Add-Output "Forcing Windows Update Scan..."
        try {
            Start-Process "UsoClient.exe" "StartScan"
            Add-Output "Update scan triggered."
        } catch {
            Add-Output "Failed to trigger update scan: $($_.Exception.Message)"
        }
    })
    $form.Controls.Add($btn1)

    $btn2 = New-Object System.Windows.Forms.Button
    $btn2.Text = "View Installed Update History"
    $btn2.Size = New-Object System.Drawing.Size(240,35)
    $btn2.Location = New-Object System.Drawing.Point(270,155)
    $btn2.Add_Click({
        $outputBox.Clear()
        Add-Output "Installed Updates:"
        try {
            $updates = Get-HotFix | Format-Table -AutoSize | Out-String
            Add-Output $updates
        } catch {
            Add-Output "Failed to retrieve update history: $($_.Exception.Message)"
        }
    })
    $form.Controls.Add($btn2)

    $btn3 = New-Object System.Windows.Forms.Button
    $btn3.Text = "Clear Windows Update Cache"
    $btn3.Size = New-Object System.Drawing.Size(500,35)
    $btn3.Location = New-Object System.Drawing.Point(10,195)
    $btn3.Add_Click({
        $outputBox.Clear()
        Add-Output "This will stop the update service and clear cache files. You may need to run as Administrator."
        try {
            net stop wuauserv | Out-Null
            Remove-Item "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue
            net start wuauserv | Out-Null
            Add-Output "Windows Update cache cleared and service restarted."
        } catch {
            Add-Output "Failed to clear update cache: $($_.Exception.Message)"
        }
    })
    $form.Controls.Add($btn3)

    $btnGpupdate = New-Object System.Windows.Forms.Button
    $btnGpupdate.Text = "Run GPUpdate (/force)"
    $btnGpupdate.Size = New-Object System.Drawing.Size(500,35)
    $btnGpupdate.Location = New-Object System.Drawing.Point(10,235)
    $btnGpupdate.Add_Click({
        $outputBox.Clear()
        Add-Output "Running: gpupdate /force"
        try {
            $gpResult = gpupdate /force | Out-String
            Add-Output $gpResult
            Add-Output "Group Policy updated."
        } catch {
            Add-Output "Failed to run gpupdate: $($_.Exception.Message)"
        }
    })
    $form.Controls.Add($btnGpupdate)

    $btnExit = New-Object System.Windows.Forms.Button
    $btnExit.Text = "Back"
    $btnExit.Size = New-Object System.Drawing.Size(500,35)
    $btnExit.Location = New-Object System.Drawing.Point(10,275)
    $btnExit.Add_Click({ $form.Close() })
    $form.Controls.Add($btnExit)

    [void]$form.ShowDialog()
}

Show-WindowsUpdateMenuGUI
