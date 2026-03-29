:: SPDX-License-Identifier: AGPL-3.0-only
:: Copyright (C) 2026 Selim Şentürk
::
:: This program is free software: you can redistribute it and/or modify
:: it under the terms of the GNU Affero General Public License as published
:: by the Free Software Foundation, version 3.
::
:: This program is distributed in the hope that it will be useful,
:: but WITHOUT ANY WARRANTY; without even the implied warranty of
:: MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
:: GNU Affero General Public License for more details.
@echo off
:: ─────────────────────────────────────────────────────────────────────────────
::  CGTI Lite for OpenClaw — Windows Installer
::  Run as Administrator
:: ─────────────────────────────────────────────────────────────────────────────

setlocal
title CGTI Lite Installer

echo.
echo   ============================================
echo     CGTI Lite for OpenClaw  -  Windows Setup
echo   ============================================
echo.

:: ── Admin check ───────────────────────────────────────────────────────────────
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARN] Administrator privileges required.
    echo        Right-click this file and select "Run as administrator".
    pause
    exit /b 1
)
echo [  OK] Administrator privileges confirmed.

:: ── Python check ──────────────────────────────────────────────────────────────
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [FAIL] Python not found. https://www.python.org/downloads/
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo [  OK] Python %PY_VER% found.

:: ── pip + rich ────────────────────────────────────────────────────────────────
echo [INFO] Installing dependencies...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet --upgrade rich
if %errorlevel% neq 0 (
    echo [FAIL] Dependency installation failed.
    pause
    exit /b 1
)
echo [  OK] rich installation complete.

:: ── Npcap check ───────────────────────────────────────────────────────────────
echo [INFO] Checking for Npcap...
sc query npcap >nul 2>&1
if %errorlevel% equ 0 (
    echo [  OK] Npcap is already installed.
    goto :npcap_done
)
if exist "%SystemRoot%\System32\Npcap\wpcap.dll" (
    echo [  OK] Npcap is already installed.
    goto :npcap_done
)

echo [INFO] Npcap not found. Downloading...
set NPCAP_DEST=%TEMP%\npcap-setup.exe
powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-1.79.exe' -OutFile '%NPCAP_DEST%' -UseBasicParsing"
if not exist "%NPCAP_DEST%" (
    echo [WARN] Npcap could not be downloaded. Install manually: https://npcap.com/#download
    goto :npcap_done
)
echo [INFO] Installing Npcap...
echo [INFO] The Npcap installer window will open. Click "Next" and "Install".
echo [INFO] Return to this window when the installation is complete.
echo.
"%NPCAP_DEST%"
if %errorlevel% equ 0 (
    echo [  OK] Npcap installed.
) else if %errorlevel% equ 3010 (
    echo [  OK] Npcap installed. A system restart is recommended.
) else (
    echo [WARN] Npcap could not be installed. Install manually: https://npcap.com/#download
)
del /f /q "%NPCAP_DEST%" >nul 2>&1

:npcap_done

:: ── Suricata check ────────────────────────────────────────────────────────────
echo [INFO] Checking for Suricata...
if exist "C:\Program Files\Suricata\suricata.exe" (
    echo [  OK] Suricata is installed.
) else (
    echo [WARN] Suricata not found. The cgti install command will install it automatically.
)

:: ── Copy files ────────────────────────────────────────────────────────────────
set INSTALL_DIR=%APPDATA%\cgti-lite
set RULES_SRC=%~dp0rules
if not exist "%INSTALL_DIR%"     mkdir "%INSTALL_DIR%"
if not exist "%INSTALL_DIR%\bin" mkdir "%INSTALL_DIR%\bin"

copy /Y "%~dp0cgti_lite.py" "%INSTALL_DIR%\cgti_lite.py" >nul
echo [  OK] cgti_lite.py copied to: %INSTALL_DIR%

:: ── Copy rules directory ─────────────────────────────────────────────────────
if exist "%RULES_SRC%" (
    if not exist "%INSTALL_DIR%\rules" mkdir "%INSTALL_DIR%\rules"
    xcopy /Y /Q "%RULES_SRC%\*.rules" "%INSTALL_DIR%\rules\" >nul 2>&1
    echo [  OK] Rules directory copied to: %INSTALL_DIR%\rules
) else (
    echo [WARN] rules/ directory not found. It must be in the same directory as install.bat.
)

:: ── Launcher (cgti.cmd) ───────────────────────────────────────────────────────
set SCRIPTS_DIR=%INSTALL_DIR%\bin
(
    echo @echo off
    echo python "%INSTALL_DIR%\cgti_lite.py" %%*
) > "%SCRIPTS_DIR%\cgti.cmd"
echo [  OK] Launcher created: %SCRIPTS_DIR%\cgti.cmd

:: ── Add to PATH (safe — existing PATH is not corrupted) ───────────────────────
echo [INFO] Updating PATH...
powershell -NoProfile -NonInteractive -Command ^
  "$scriptsDir = '%SCRIPTS_DIR%'; " ^
  "$currentPath = [System.Environment]::GetEnvironmentVariable('PATH', 'User'); " ^
  "if ($currentPath -and $currentPath.Split(';') -contains $scriptsDir) { " ^
  "  Write-Host '[  OK] PATH already contains entry.'; exit 0 } " ^
  "else { " ^
  "  $newPath = if ($currentPath) { $currentPath + ';' + $scriptsDir } else { $scriptsDir }; " ^
  "  [System.Environment]::SetEnvironmentVariable('PATH', $newPath, 'User'); " ^
  "  Write-Host '[  OK] PATH updated.' }"
if %errorlevel% neq 0 (
    echo [WARN] PATH could not be updated. Add manually: %SCRIPTS_DIR%
)

echo.
echo   ============================================
echo    Installation complete!
echo   ============================================
echo.
echo   Open a NEW Administrator CMD window:
echo.
echo     cgti install    ^(configure Suricata^)
echo     cgti status     ^(system status^)
echo     cgti --help     ^(all commands^)
echo.
pause
endlocal
