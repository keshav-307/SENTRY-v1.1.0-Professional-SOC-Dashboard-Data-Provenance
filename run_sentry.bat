@echo off
setlocal EnableExtensions
cd /d "%~dp0"

echo ============================================================
echo  SENTRY v1.1.0 - Security Monitoring ^& Threat Detection
echo ============================================================
echo.

rem ------------------------------------------------------------
rem 1. Reuse the existing virtual environment, or create it
rem ------------------------------------------------------------
if not exist ".venv\Scripts\python.exe" (
    call :create_venv
    if errorlevel 1 exit /b 1
)

call ".venv\Scripts\activate.bat"
if errorlevel 1 (
    echo [ERROR] Could not activate .venv.
    echo Delete the .venv folder and run this launcher again.
    echo.
    pause
    exit /b 1
)

set "VENV_PY=.venv\Scripts\python.exe"
set "MARKER=.venv\.sentry-deps.sha256"
set "NEED_INSTALL=0"

rem Missing runtime libraries always force a dependency check.
"%VENV_PY%" -c "import streamlit, scapy" >nul 2>&1
if errorlevel 1 set "NEED_INSTALL=1"

rem Reinstall only when requirements.txt changed.
set "REQ_HASH="
"%VENV_PY%" -c "import hashlib,pathlib;print(hashlib.sha256(pathlib.Path('requirements.txt').read_bytes()).hexdigest())" > ".venv\.sentry-req.tmp"
if exist ".venv\.sentry-req.tmp" set /p REQ_HASH=<".venv\.sentry-req.tmp"
del ".venv\.sentry-req.tmp" >nul 2>&1

if not exist "%MARKER%" set "NEED_INSTALL=1"
set "STORED_HASH="
if exist "%MARKER%" set /p STORED_HASH=<"%MARKER%"
if /I not "%STORED_HASH%"=="%REQ_HASH%" set "NEED_INSTALL=1"

if "%NEED_INSTALL%"=="1" (
    echo [SETUP] Installing dependencies from requirements.txt ...
    echo This happens only on the first run or after requirements change.
    "%VENV_PY%" -m pip install --disable-pip-version-check -r requirements.txt
    if errorlevel 1 (
        echo.
        echo [ERROR] Dependency installation failed.
        echo Check your internet connection, then run this launcher again.
        echo.
        pause
        exit /b 1
    )
    if defined REQ_HASH (
        > "%MARKER%" echo %REQ_HASH%
    )
)

rem ------------------------------------------------------------
rem 2. Final dependency verification
rem ------------------------------------------------------------
"%VENV_PY%" -c "import streamlit, scapy" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Streamlit or Scapy is not available in .venv.
    echo Delete the .venv folder and run this launcher again.
    echo.
    pause
    exit /b 1
)

rem ------------------------------------------------------------
rem 3. Npcap notice (live capture only; synthetic data works without it)
rem ------------------------------------------------------------
set "NPCAP_FOUND=0"
if exist "%SystemRoot%\System32\Npcap\wpcap.dll" set "NPCAP_FOUND=1"
reg query "HKLM\SOFTWARE\WOW6432Node\Npcap" >nul 2>&1 && set "NPCAP_FOUND=1"
reg query "HKLM\SYSTEM\CurrentControlSet\Services\npcap" >nul 2>&1 && set "NPCAP_FOUND=1"

if "%NPCAP_FOUND%"=="0" (
    echo [NOTICE] Npcap was not detected.
    echo Live network monitoring needs Npcap with WinPcap API
    echo compatibility mode from https://npcap.com/
    echo Synthetic event generation and the dashboard work without it.
    echo.
) else (
    echo [OK] Npcap detected - live packet capture is available.
)

rem ------------------------------------------------------------
rem 4. Start SENTRY
rem ------------------------------------------------------------
echo [RUN] Starting SENTRY at http://localhost:8501
echo Press Ctrl+C in this window to stop SENTRY.
echo.
"%VENV_PY%" -m streamlit run app_v3.py
set "EXIT_CODE=%ERRORLEVEL%"
echo.
if not "%EXIT_CODE%"=="0" (
    echo [ERROR] SENTRY stopped with exit code %EXIT_CODE%.
    echo If the port is busy, close the other SENTRY window and retry.
    echo Check the messages above for details.
)
echo SENTRY has stopped. Press any key to close this window.
pause >nul
exit /b %EXIT_CODE%

rem ============================================================
rem Subroutine: locate Python 3.10+ and create .venv
rem ============================================================
:create_venv
set "PY_CMD="

rem The Windows Store "py" stub can exist without an interpreter,
rem so validate the command before trusting it.
where py >nul 2>&1
if errorlevel 1 goto try_python
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 goto try_python
set "PY_CMD=py -3"
goto python_ready

:try_python
where python >nul 2>&1
if errorlevel 1 goto no_python
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if errorlevel 1 goto no_python
set "PY_CMD=python"
goto python_ready

:no_python
echo [ERROR] Python 3.10 or newer was not found.
echo.
echo Install Python from:
echo   https://www.python.org/downloads/windows/
echo During installation tick "Add python.exe to PATH".
echo.
pause
exit /b 1

:python_ready
echo [SETUP] Creating virtual environment in .venv ...
%PY_CMD% -m venv .venv
if errorlevel 1 (
    echo [ERROR] Could not create the virtual environment.
    echo Check that the project folder is writable and try again.
    echo.
    pause
    exit /b 1
)
exit /b 0
