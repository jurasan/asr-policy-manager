# ASR Policy Manager

A keyboard-driven Windows terminal app for reviewing recent Microsoft Defender
Attack Surface Reduction (ASR) blocks and adding selected paths as global ASR
exclusions.

## Run from anywhere

Run `install.ps1` once (re-run after moving the project). It creates:

- an `asr` command in `%USERPROFILE%\.local\bin`, so typing `asr` in any
  terminal launches the app in its own elevated window;
- a Start Menu shortcut named "ASR Policy Manager", so pressing the Windows key
  and typing `asr` finds it.

Both point at the executable in `target\release`, so rebuilding updates them.

## Run from this folder

Double-click `Run-Add-ASRExclusion.cmd` or `target\release\asr-policy-manager.exe`.

The executable checks whether it is already elevated. If not, it re-launches
itself through the standard UAC prompt and exits, so you approve once and get a
single elevated terminal window with the app in it. There are no intermediate
PowerShell or Command Prompt windows.

You can also start it from an already elevated terminal; in that case no prompt
appears and it runs in the current window.

## Build

```powershell
$env:Path = "$env:USERPROFILE\.cargo\bin;$env:Path"
cargo build --release
```

The binary is written to `target\release\asr-policy-manager.exe`.

## How it works

The app reads ASR block events (ID 1121) from the Defender Operational event
log, groups them by blocked path, and marks each path green when it is already
covered by a local or policy-based ASR-only exclusion. Selected red paths are
added with the supported `Add-MpPreference` command.

When the ASR-exclusions policy is enabled on the computer, Defender ignores the
local preference list. In that case the app asks for confirmation and then writes
the selected paths into the policy list itself (the registry location the gpedit
setting uses) as well as into local preferences. The rows turn green right after
applying. If a domain or Intune policy refresh rewrites that list, entries added
here may be removed again.

Defender is driven through Windows PowerShell. The scripts are sent on standard
input rather than as `-EncodedCommand` or `-ExecutionPolicy Bypass` arguments,
because Defender's suspicious command line heuristic (`CMD_HSTR`) flags those
patterns as threats.

## Keys

- `Up` / `Down` or `j` / `k`: move
- `Space`: select or clear a red blocked path
- `Enter` or `a`: add selected exclusions
- `r`: refresh
- `q` / `Esc`: quit

## Legacy script

`Add-ASRExclusion.ps1` is the earlier PowerShell implementation of the same
task. It still works from an elevated PowerShell session but is no longer used
by the launcher.
