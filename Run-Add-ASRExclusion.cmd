@echo off
rem Launches the ASR Policy Manager terminal app. The executable requests
rem administrator rights itself (one UAC prompt) and opens in its own window.
set "EXE=%~dp0target\release\asr-policy-manager.exe"
if not exist "%EXE%" (
    echo Build the app first:  cargo build --release
    pause
    exit /b 1
)
start "" "%EXE%"
exit /b
