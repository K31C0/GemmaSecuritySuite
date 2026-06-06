@echo off
setlocal enabledelayedexpansion
title GemmaSecuritySuite
cd /d "%~dp0"
set GEMMA_SUITE_HOME=%~dp0

:: ================================================================
::  GemmaSecuritySuite — Single-Click USB Launcher
:: ================================================================
::  Just double-click this file. It finds Python, checks deps,
::  and boots the suite. No installation required.
:: ================================================================

echo.
echo   ===================================================
echo     GemmaSecuritySuite — Starting...
echo   ===================================================
echo.

:: --- Ensure data/logs exists for bootstrap log ---
if not exist "data\logs" mkdir "data\logs"

:: --- Priority 1: Bundled portable Python ---
if exist "runtime\python.exe" (
    set "PYTHON=runtime\python.exe"
    echo   [+] Using bundled Python: runtime\python.exe
    goto :found
)

:: --- Priority 2: Windows Python Launcher ---
where py >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON=py -3"
    echo   [+] Using Python Launcher: py -3
    goto :found
)

:: --- Priority 3: python on PATH ---
where python >nul 2>&1
if %errorlevel% equ 0 (
    :: Verify it's real Python, not the Windows Store alias
    python --version >nul 2>&1
    if %errorlevel% equ 0 (
        set "PYTHON=python"
        echo   [+] Using system Python: python
        goto :found
    )
)

:: --- Priority 4: python3 on PATH ---
where python3 >nul 2>&1
if %errorlevel% equ 0 (
    set "PYTHON=python3"
    echo   [+] Using system Python: python3
    goto :found
)

:: --- No Python found ---
echo.
echo   ===========================================================
echo    ERROR: Python was not found on this machine.
echo   ===========================================================
echo.
echo    To fix this, do ONE of the following:
echo.
echo    Option A (Recommended for USB):
echo      Place the Python Embeddable ZIP in the 'runtime\' folder.
echo      Run 'setup_runtime.ps1' on your build machine first.
echo.
echo    Option B (Install on this machine):
echo      Download Python 3.12+ from https://www.python.org
echo      Check "Add Python to PATH" during installation.
echo.
echo   ===========================================================
echo.
pause
exit /b 1

:found
echo.

:: --- Run bootstrap preflight + main app ---
%PYTHON% bootstrap.py
set EXIT_CODE=%errorlevel%

if %EXIT_CODE% neq 0 (
    echo.
    echo   ===========================================================
    echo    [!] Startup failed (exit code %EXIT_CODE%).
    echo   ===========================================================
    echo.
    if exist "data\logs\bootstrap.log" (
        echo    Opening bootstrap log for details...
        echo.
        notepad "data\logs\bootstrap.log"
    ) else (
        echo    No bootstrap log found.
    )
    echo.
    pause
)

exit /b %EXIT_CODE%
