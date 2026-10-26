@echo off
setlocal
REM AUTHENTIX / EduVerify-AI (SIH26261) — Windows Command Prompt Launcher
REM Delegates to PowerShell script with ExecutionPolicy Bypass for reliable Python/Node detection and health checks.

where powershell >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Windows PowerShell was not found on PATH.
    exit /b 1
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-windows.ps1" %*
set EXIT_CODE=%ERRORLEVEL%

if %EXIT_CODE% NEQ 0 (
    echo.
    echo [ERROR] AUTHENTIX startup exited with error code %EXIT_CODE%.
    pause
    exit /b %EXIT_CODE%
)

endlocal
