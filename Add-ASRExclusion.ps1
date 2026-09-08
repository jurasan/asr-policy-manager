[CmdletBinding(DefaultParameterSetName = 'Add')]
param(
    [Parameter(ParameterSetName = 'Add', Position = 0, ValueFromRemainingArguments = $true)]
    [Alias('Path')]
    [string[]] $ExclusionPath,

    [Parameter(ParameterSetName = 'List', Mandatory = $true)]
    [switch] $List,

    [Parameter(ParameterSetName = 'RecentBlocks', Mandatory = $true)]
    [ValidateRange(1, 100)]
    [int] $RecentBlocks,

    [switch] $SkipManagedPolicyWarning
)

<#!
.SYNOPSIS
    Adds files or folders to Microsoft Defender's global ASR-exclusion list.

.DESCRIPTION
    Adds entries without replacing existing Defender preferences. Run without
    arguments to paste one or more paths, or use:
      .\Add-ASRExclusion.ps1 'C:\Apps\Example\app.exe'
      .\Add-ASRExclusion.ps1 -List
      .\Add-ASRExclusion.ps1 -RecentBlocks 20

    These are global ASR exclusions, so every ASR rule ignores the added path.
    If the computer is managed by Group Policy or Intune, that policy can
    override local PowerShell preferences.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AsrExclusions {
    $preferences = Get-MpPreference -ErrorAction Stop
    return @($preferences.AttackSurfaceReductionOnlyExclusions)
}

function Get-ConfiguredAsrExclusions {
    # Gather both local Defender preferences and the Local/Domain GPO list.
    # A GPO can take precedence over local preferences, so both are relevant
    # when deciding whether an earlier blocked path is excluded now.
    $allExclusions = [System.Collections.Generic.List[string]]::new()

    try {
        foreach ($entry in Get-AsrExclusions) {
            if (-not [string]::IsNullOrWhiteSpace($entry)) {
                $allExclusions.Add($entry)
            }
        }
    }
    catch {
        # Non-elevated sessions can't always read Defender preferences. The
        # Group Policy list below can still be read and is enough for the
        # policy shown in gpedit.
    }

    $gpoExclusionKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ASROnlyExclusions'
    try {
        if (Test-Path -LiteralPath $gpoExclusionKey) {
            foreach ($entry in (Get-Item -LiteralPath $gpoExclusionKey -ErrorAction Stop).Property) {
                if (-not [string]::IsNullOrWhiteSpace($entry)) {
                    $allExclusions.Add($entry)
                }
            }
        }
    }
    catch {
        # The caller can still display events if it lacks registry access.
    }

    return @($allExclusions | Sort-Object -Unique)
}

function Test-AsrPathIsExcluded {
    param(
        [string] $BlockedPath,
        [string[]] $Exclusions
    )

    if ([string]::IsNullOrWhiteSpace($BlockedPath) -or $BlockedPath -eq '<not recorded>') {
        return $false
    }

    $expandedBlockedPath = [Environment]::ExpandEnvironmentVariables($BlockedPath).Trim().Trim('"')
    foreach ($entry in $Exclusions) {
        $expandedEntry = [Environment]::ExpandEnvironmentVariables($entry).Trim().Trim('"').TrimEnd('\\')
        if ([string]::IsNullOrWhiteSpace($expandedEntry)) {
            continue
        }

        # Exact file matches and folder-prefix matches cover normal ASR
        # exclusion entries without guessing from the filename extension.
        if ($expandedBlockedPath -ieq $expandedEntry -or $expandedBlockedPath.StartsWith("$expandedEntry\\", [StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Get-RecentAsrBlocks {
    param(
        [ValidateRange(1, 100)]
        [int] $Maximum = 10
    )

    $logName = 'Microsoft-Windows-Windows Defender/Operational'
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = 1121 } -MaxEvents $Maximum
    }
    catch {
        Write-Warning "Unable to read the Defender event log: $($_.Exception.Message)"
        return @()
    }

    return @(
        foreach ($event in $events) {
            [xml] $xml = $event.ToXml()
            $fields = @{}
            foreach ($field in @($xml.Event.EventData.Data)) {
                $fields[$field.Name] = [string] $field.InnerText
            }

            [pscustomobject]@{
                Time        = $event.TimeCreated
                BlockedPath = if ($fields['Path']) { $fields['Path'] } else { '<not recorded>' }
                Process     = if ($fields['Process Name']) { $fields['Process Name'] } else { '<not recorded>' }
                Rule        = if ($fields['ID']) { $fields['ID'] } else { '<not recorded>' }
            }
        }
    )
}

function Show-RecentAsrBlocks {
    param(
        [ValidateRange(1, 100)]
        [int] $Maximum = 10
    )

    $blocks = Get-RecentAsrBlocks -Maximum $Maximum
    if ($blocks.Count -eq 0) {
        Write-Host 'No recent ASR block events were found.' -ForegroundColor DarkYellow
        return
    }

    $exclusions = Get-ConfiguredAsrExclusions
    Write-Host "Recent ASR blocks (newest first, showing $($blocks.Count)):" -ForegroundColor Cyan
    Write-Host 'Green [OK] means the path is excluded now; red [X] means it is still not excluded.' -ForegroundColor DarkGray
    $index = 0
    foreach ($block in $blocks) {
        $index++
        $isExcludedNow = Test-AsrPathIsExcluded -BlockedPath $block.BlockedPath -Exclusions $exclusions
        $icon = if ($isExcludedNow) { '[OK]' } else { '[X]' }
        $status = if ($isExcludedNow) { 'EXCLUDED NOW' } else { 'BLOCKED' }
        $color = if ($isExcludedNow) { 'Green' } else { 'Red' }
        Write-Host "$icon [$index] $($block.Time.ToString('yyyy-MM-dd HH:mm:ss'))  $status" -ForegroundColor $color
        Write-Host "    Path:    $($block.BlockedPath)" -ForegroundColor $color
        Write-Host "    Process: $($block.Process)"
        Write-Host "    Rule:    $($block.Rule)"
    }
}

function Select-AsrBlockedPaths {
    param(
        [ValidateRange(1, 500)]
        [int] $Maximum = 100
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $exclusions = Get-ConfiguredAsrExclusions
    $rows = @(
        Get-RecentAsrBlocks -Maximum $Maximum |
            Group-Object -Property BlockedPath |
            ForEach-Object {
                $latest = $_.Group | Sort-Object Time -Descending | Select-Object -First 1
                [pscustomobject]@{
                    Time          = $latest.Time
                    BlockedPath   = $latest.BlockedPath
                    Process       = $latest.Process
                    Rule          = $latest.Rule
                    ExcludedNow   = Test-AsrPathIsExcluded -BlockedPath $latest.BlockedPath -Exclusions $exclusions
                    Occurrences   = $_.Count
                }
            } |
            Sort-Object Time -Descending
    )

    if ($rows.Count -eq 0) {
        Write-Host 'No recent ASR block events were found.' -ForegroundColor DarkYellow
        return @()
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Choose ASR exclusions'
    $form.StartPosition = 'CenterScreen'
    $form.Size = New-Object System.Drawing.Size(1320, 720)
    $form.MinimumSize = New-Object System.Drawing.Size(950, 500)

    $instructions = New-Object System.Windows.Forms.Label
    $instructions.Dock = 'Top'
    $instructions.Height = 48
    $instructions.Padding = New-Object System.Windows.Forms.Padding(12, 8, 12, 4)
    $instructions.Text = 'Select one or more red [X] rows to add as global ASR exclusions. Green [OK] rows are already excluded. Hold Ctrl or Shift to select multiple rows.'
    $form.Controls.Add($instructions)

    $grid = New-Object System.Windows.Forms.DataGridView
    $grid.Dock = 'Fill'
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToResizeRows = $false
    $grid.RowHeadersVisible = $false
    $grid.SelectionMode = 'FullRowSelect'
    $grid.MultiSelect = $true
    $grid.AutoGenerateColumns = $false
    $grid.AutoSizeRowsMode = 'AllCells'
    $grid.BackgroundColor = [System.Drawing.SystemColors]::Window

    $statusColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $statusColumn.Name = 'Status'
    $statusColumn.HeaderText = 'Status'
    $statusColumn.Width = 120
    [void] $grid.Columns.Add($statusColumn)

    $timeColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $timeColumn.Name = 'Time'
    $timeColumn.HeaderText = 'Latest block'
    $timeColumn.Width = 145
    [void] $grid.Columns.Add($timeColumn)

    $pathColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $pathColumn.Name = 'Path'
    $pathColumn.HeaderText = 'Blocked path'
    $pathColumn.AutoSizeMode = 'Fill'
    $pathColumn.FillWeight = 180
    [void] $grid.Columns.Add($pathColumn)

    $processColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $processColumn.Name = 'Process'
    $processColumn.HeaderText = 'Initiating process'
    $processColumn.AutoSizeMode = 'Fill'
    $processColumn.FillWeight = 100
    [void] $grid.Columns.Add($processColumn)

    $countColumn = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $countColumn.Name = 'Count'
    $countColumn.HeaderText = 'Blocks'
    $countColumn.Width = 55
    [void] $grid.Columns.Add($countColumn)

    foreach ($item in $rows) {
        $status = if ($item.ExcludedNow) { '[OK] Excluded now' } else { '[X] Blocked' }
        $rowIndex = $grid.Rows.Add($status, $item.Time.ToString('yyyy-MM-dd HH:mm:ss'), $item.BlockedPath, $item.Process, $item.Occurrences)
        $gridRow = $grid.Rows[$rowIndex]
        $gridRow.Tag = $item
        $gridRow.DefaultCellStyle.ForeColor = if ($item.ExcludedNow) { [System.Drawing.Color]::ForestGreen } else { [System.Drawing.Color]::Firebrick }
    }
    $form.Controls.Add($grid)

    $buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttonPanel.Dock = 'Bottom'
    $buttonPanel.Height = 54
    $buttonPanel.FlowDirection = 'RightToLeft'
    $buttonPanel.Padding = New-Object System.Windows.Forms.Padding(8)

    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Text = 'Cancel'
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $cancelButton.AutoSize = $true
    $buttonPanel.Controls.Add($cancelButton)

    $addButton = New-Object System.Windows.Forms.Button
    $addButton.Text = 'Exclude selected blocked path(s)'
    $addButton.AutoSize = $true
    $addButton.Enabled = $false
    $buttonPanel.Controls.Add($addButton)
    $form.AcceptButton = $addButton
    $form.CancelButton = $cancelButton
    $form.Controls.Add($buttonPanel)

    $updateSelection = {
        $selectableCount = @($grid.SelectedRows | Where-Object { -not $_.Tag.ExcludedNow }).Count
        $addButton.Enabled = $selectableCount -gt 0
    }
    $grid.add_SelectionChanged($updateSelection)
    $addButton.add_Click({ $form.DialogResult = [System.Windows.Forms.DialogResult]::OK; $form.Close() })

    $result = $form.ShowDialog()
    if ($result -ne [System.Windows.Forms.DialogResult]::OK) {
        return @()
    }

    return @(
        $grid.SelectedRows |
            ForEach-Object { $_.Tag } |
            Where-Object { -not $_.ExcludedNow -and $_.BlockedPath -ne '<not recorded>' } |
            ForEach-Object { $_.BlockedPath } |
            Sort-Object -Unique
    )
}

function Start-ElevatedCommandPrompt {
    param([string[]] $ScriptArguments = @())

    $powerShellArguments = @('-NoProfile', '-STA', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    foreach ($argument in $ScriptArguments) {
        $powerShellArguments += ('"{0}"' -f $argument.Replace('"', '\"'))
    }

    # CMD stays open after the script exits so a result or error remains visible.
    $command = '/k powershell.exe ' + ($powerShellArguments -join ' ')
    Start-Process -FilePath 'cmd.exe' -Verb RunAs -ArgumentList $command
}

function Start-ElevatedList {
    Start-ElevatedCommandPrompt -ScriptArguments @('-List')
}

function Start-ElevatedRecentBlocks {
    param([int] $Maximum)

    Start-ElevatedCommandPrompt -ScriptArguments @('-RecentBlocks', "$Maximum")
}

function Start-ElevatedInteractive {
    Start-ElevatedCommandPrompt
}

if ($PSCmdlet.ParameterSetName -eq 'RecentBlocks') {
    if (-not (Test-IsAdministrator)) {
        Write-Host 'Requesting administrator permission...' -ForegroundColor Yellow
        Start-ElevatedRecentBlocks -Maximum $RecentBlocks
        exit 0
    }
    Show-RecentAsrBlocks -Maximum $RecentBlocks
    exit 0
}

if ($List) {
    if (-not (Test-IsAdministrator)) {
        Write-Host 'Requesting administrator permission...' -ForegroundColor Yellow
        Start-ElevatedList
        exit 0
    }
    $current = Get-AsrExclusions
    if ($current.Count -eq 0) {
        Write-Host 'No ASR-only exclusions are currently reported by Microsoft Defender.'
    }
    else {
        Write-Host "Current ASR-only exclusions ($($current.Count)):" -ForegroundColor Cyan
        $current | Sort-Object | ForEach-Object { Write-Host "  $_" }
    }
    exit 0
}

if (-not $ExclusionPath -or $ExclusionPath.Count -eq 0) {
    if (-not (Test-IsAdministrator)) {
        Write-Host 'Requesting administrator permission...' -ForegroundColor Yellow
        Start-ElevatedInteractive
        exit 0
    }
    $ExclusionPath = Select-AsrBlockedPaths -Maximum 100
}

$requested = @(
    $ExclusionPath |
        ForEach-Object { $_.Trim().Trim('"') } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
)

if ($requested.Count -eq 0) {
    Write-Host 'No blocked paths were selected. Nothing was changed.'
    exit 0
}

# The Group Policy setting shown in gpedit writes to this policy location.
$asrPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
$gpoPolicyEnabled = $false
if (Test-Path -LiteralPath $asrPolicyKey) {
    $policy = Get-ItemProperty -LiteralPath $asrPolicyKey -ErrorAction SilentlyContinue
    $gpoPolicyEnabled = $null -ne $policy -and $policy.ExploitGuard_ASR_ASROnlyExclusions -eq 1
}

if ($gpoPolicyEnabled -and -not $SkipManagedPolicyWarning) {
    Write-Warning @'
The ASR-exclusions setting is enabled through policy on this computer.
This helper changes local Defender preferences; Group Policy or Intune can overwrite
them. To avoid mixing management methods, add the exclusion in that policy instead.
'@
    $confirmation = Read-Host 'Add it to local Defender preferences anyway? (y/N)'
    if ($confirmation -notmatch '^(y|yes)$') {
        Write-Host 'No changes were made.'
        exit 0
    }
}

if (-not (Test-IsAdministrator)) {
    Write-Host 'Requesting administrator permission...' -ForegroundColor Yellow
    $arguments = @('-ExclusionPath') + $requested
    if ($SkipManagedPolicyWarning) {
        $arguments += '-SkipManagedPolicyWarning'
    }
    Start-ElevatedCommandPrompt -ScriptArguments $arguments
    exit 0
}

$before = Get-AsrExclusions
$newEntries = @($requested | Where-Object { $_ -notin $before })

if ($newEntries.Count -eq 0) {
    Write-Host 'Those paths are already in the current ASR-exclusion list.' -ForegroundColor Green
    exit 0
}

try {
    Add-MpPreference -AttackSurfaceReductionOnlyExclusions $newEntries
}
catch {
    Write-Error "Microsoft Defender did not accept the exclusion(s): $($_.Exception.Message)"
    exit 1
}

$after = Get-AsrExclusions
$confirmed = @($newEntries | Where-Object { $_ -in $after })
$notConfirmed = @($newEntries | Where-Object { $_ -notin $after })

if ($confirmed.Count -gt 0) {
    Write-Host "Added $($confirmed.Count) ASR exclusion(s):" -ForegroundColor Green
    $confirmed | ForEach-Object { Write-Host "  $_" }
}

if ($notConfirmed.Count -gt 0) {
    Write-Warning "The following entries were not reported after the change: $($notConfirmed -join '; '). A managed policy may be overriding local preferences."
    exit 2
}

Write-Host 'Reminder: every ASR rule ignores these paths. Keep exclusions as narrow as possible.' -ForegroundColor Yellow
