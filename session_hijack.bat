@echo off
chcp 65001 >nul
setlocal

set "PS1=%~dp0winlock_setup.ps1"

if not exist "%PS1%" (
    echo [HATA] winlock_setup.ps1 bulunamadi.
    echo        Bu dosya ile ayni klasorde olmali.
    pause
    exit /b 1
)

:: PowerShell politikasini bypass ederek dogrudan calistir
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [HATA] Script calistirilirken bir hata olustu.
    echo        Lutfen dosyaya sag tiklayip "Yonetici olarak calistir" secenegini deneyin.
    pause
)

endlocal
