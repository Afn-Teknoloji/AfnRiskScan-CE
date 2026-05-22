@echo off
REM ───────────────────────────────────────────────────────────────────
REM  AFN RiskScan CE — PowerShell 7 launcher
REM  Çift tıklayın veya CMD/PowerShell 5'ten çalıştırın.
REM  Otomatik olarak pwsh (PowerShell 7) ile çalıştırır.
REM ───────────────────────────────────────────────────────────────────
setlocal

REM pwsh kurulu mu kontrol et
where pwsh >nul 2>nul
if errorlevel 1 (
    echo.
    echo   X  PowerShell 7 ^(pwsh^) bulunamadi.
    echo.
    echo      Bu script PowerShell 7+ gerektirir.
    echo      Kurulum icin yonetici PowerShell ile:
    echo.
    echo          winget install --id Microsoft.PowerShell
    echo.
    echo      Ya da: https://aka.ms/PSWindows
    echo.
    pause
    exit /b 1
)

REM Script'i bulundugu klasorde, pwsh ile, ExecutionPolicy Bypass ile calistir
pwsh -NoProfile -ExecutionPolicy Bypass -File "%~dp0AfnRiskScan.ps1" %*
set EXITCODE=%ERRORLEVEL%

REM Cift tiklamada konsol kapanmasin
if "%~1"=="" pause
exit /b %EXITCODE%
