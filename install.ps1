<#
.SYNOPSIS
    Makes ASR Policy Manager reachable from anywhere.

.DESCRIPTION
    Creates two launch points that both target the built executable in this
    folder's target\release directory:

      1. %USERPROFILE%\.local\bin\asr.cmd  - type "asr" in any terminal
      2. Start Menu shortcut "ASR Policy Manager" - press Win, type "asr"

    The executable itself stays where cargo builds it. That path already has an
    ASR exclusion for the build output, and copying the binary elsewhere could
    trip the "block untrusted executables" ASR rule again. Rebuilding with
    "cargo build --release" therefore updates both launch points automatically.

    Safe to re-run; existing files are overwritten.
#>
[CmdletBinding()]
param(
    # Name of the command available in terminals.
    [string] $CommandName = 'asr'
)

$ErrorActionPreference = 'Stop'

$projectDir = $PSScriptRoot
$exe = Join-Path $projectDir 'target\release\asr-policy-manager.exe'
if (-not (Test-Path -LiteralPath $exe)) {
    throw "Executable not found: $exe`nBuild it first with: cargo build --release"
}

# 1. Command shim on the user PATH.
$binDir = Join-Path $env:USERPROFILE '.local\bin'
New-Item -ItemType Directory -Path $binDir -Force | Out-Null
$shim = Join-Path $binDir "$CommandName.cmd"
@"
@echo off
rem Launches ASR Policy Manager in its own elevated window (one UAC prompt).
start "" "$exe" %*
"@ | Set-Content -LiteralPath $shim -Encoding ASCII
Write-Host "Command shim : $shim"

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User') -split ';'
if ($userPath -notcontains $binDir) {
    Write-Warning "$binDir is not on your user PATH. Add it, or run: setx Path `"%Path%;$binDir`""
}

# 2. Start Menu shortcut.
$startMenu = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs'
$lnk = Join-Path $startMenu 'ASR Policy Manager.lnk'
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($lnk)
$shortcut.TargetPath = $exe
$shortcut.WorkingDirectory = Split-Path $exe
$shortcut.Description = 'Review Defender ASR blocks and add exclusions'
$shortcut.IconLocation = '%SystemRoot%\System32\imageres.dll,73'
$shortcut.Save()
Write-Host "Start Menu   : $lnk"

Write-Host ''
Write-Host "Done. Open a new terminal and type '$CommandName', or press Win and type 'asr'."
