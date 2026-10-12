@echo off
chcp 65001 >nul
setlocal

set "PS1=%~dp0winwipev6_setup.ps1"

if not exist "%PS1%" (
    echo [HATA] winwipev6_setup.ps1 bulunamadi.
    echo        Bu dosya ile ayni klasorde olmali.
    pause
    exit /b 1
)

:: Tek satir olarak birlestirilmis guvenli PowerShell komutlari
powershell -NoProfile -Command "Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force" >nul 2>&1

powershell -NoProfile -Command "if ((Get-ExecutionPolicy -Scope CurrentUser) -in @('RemoteSigned','Unrestricted','Bypass')) { exit 0 } else { exit 1 }" >nul 2>&1

if %ERRORLEVEL% == 0 (
    powershell -NoProfile -File "%PS1%"
    goto :done
)

echo [!] Policy kalici ayarlanamadi, bypass ile deneniyor...
powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
if %ERRORLEVEL% == 0 goto :done

echo.
echo [HATA] Script hicbir yontemle calistirilamadi.
echo        Bu .bat dosyasina sag tikla > "Yonetici olarak calistir" deneyin.
pause
exit /b 1

:done
endlocal
