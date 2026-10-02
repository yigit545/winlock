@echo off
chcp 65001 >nul
setlocal

set "PS1=%~dp0recovery_setup.ps1"

:: Is the PS1 in the same folder?
if not exist "%PS1%" (
    echo [ERROR] recovery_setup.ps1 not found.
    echo        Must be in the same folder as this file.
    pause
    exit /b 1
)

:: ── Route 1: Set permanent policy, then run ──────────────────────────────
powershell -NoProfile -Command ^
    "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force" >nul 2>&1

powershell -NoProfile -Command ^
    "if ((Get-ExecutionPolicy -Scope CurrentUser) -in @('RemoteSigned','Unrestricted','Bypass')) { exit 0 } else { exit 1 }" >nul 2>&1

if %ERRORLEVEL% == 0 (
    powershell -NoProfile -File "%PS1%"
    goto :done
)

:: ── Route 2: Permanent policy failed → Bypass for this session ───────────
echo [!] Could not set policy permanently, trying Bypass...
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
if %ERRORLEVEL% == 0 goto :done

:: ── Both routes failed ────────────────────────────────────────────────────
echo.
echo [ERROR] Script could not be launched by any method.
echo        Try right-clicking this .bat file and selecting "Run as administrator".
pause
exit /b 1

:done
endlocal
