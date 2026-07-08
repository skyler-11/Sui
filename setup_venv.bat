@echo off
:: ===========================================================================
:: Create this slot's ISOLATED virtualenv and install the pinned dependencies.
:: ---------------------------------------------------------------------------
:: Run this ONCE per deployment folder (blue and green each get their own).
:: It touches NOTHING except <this folder>\.venv, so it is safe to run while
:: the live app keeps serving from another folder/port.
::
:: PATH-proof: it finds Python via `python` OR the `py` launcher, so it works
:: even when "Add python.exe to PATH" was NOT ticked at install time. The
:: bootstrap interpreter is only used to CREATE the venv; afterwards everything
:: runs from .venv\Scripts\python.exe and PATH is irrelevant.
::
:: Requires an installed Python 3.10-3.12 (streamlit 1.55 / numpy 2.4 / pandas 2.3).
:: ===========================================================================
setlocal
cd /d "%~dp0"

:: -- Locate a bootstrap Python without depending on PATH --------------------
:: 1) `python` if it's on PATH; 2) the `py` launcher (installed to C:\Windows,
::    reachable even when python.exe was not added to PATH).
set "PYBOOT="
python --version >nul 2>&1 && set "PYBOOT=python"
if not defined PYBOOT (
    py -3 --version >nul 2>&1 && set "PYBOOT=py -3"
)
if not defined PYBOOT (
    echo [ERROR] No Python found via "python" or the "py" launcher.
    echo         Install Python 3.10-3.12, then re-run this script.
    echo         Tip: run  py -0p  to list installed Pythons and their paths.
    pause
    exit /b 1
)

echo [INFO] Bootstrap interpreter: %PYBOOT%
%PYBOOT% --version
for /f "delims=" %%p in ('%PYBOOT% -c "import sys; print(sys.executable)"') do echo        %%p

if not exist ".venv" (
    echo [1/3] Creating virtualenv at .venv ...
    %PYBOOT% -m venv .venv
    if errorlevel 1 ( echo [ERROR] venv creation failed. & pause & exit /b 1 )
) else (
    echo [1/3] Reusing existing .venv
)

echo [2/3] Upgrading pip inside the venv ...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 ( echo [ERROR] pip upgrade failed. & pause & exit /b 1 )

echo [3/3] Installing pinned requirements into the venv ...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 ( echo [ERROR] requirements install failed. & pause & exit /b 1 )

echo.
echo Venv ready. Nothing outside this folder was modified.
echo Start the app with run_streamlit.bat
pause
exit /b 0
