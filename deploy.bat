@echo off
:: ===========================================================================
:: Deploy Manning Simulator to the IIS site folder.
:: ---------------------------------------------------------------------------
:: Mirrors the project to the target folder, EXCLUDING dev/test artifacts that
:: must never reach the production server (agent docs, test suite, test data,
:: IDE/CI folders, build caches, stale PID).
::
:: Runtime-required files that git IGNORES are still copied because this filter
:: is independent of .gitignore: certs\ca.cer, resource\manning_template.xlsx,
:: .streamlit\config.toml, icon\.
::
:: Usage:  deploy.bat "D:\inetpub\manning"
:: ===========================================================================
setlocal

:: Source = this script's folder, with the trailing backslash stripped so
:: robocopy accepts it as a directory.
set "SRC=%~dp0"
if "%SRC:~-1%"=="\" set "SRC=%SRC:~0,-1%"

set "DST=%~1"
if not defined DST goto :usage

:: NOTE: .venv is excluded so re-deploying code into a slot does NOT delete that
:: slot's installed virtualenv (/MIR would otherwise remove it as an "extra").
robocopy "%SRC%" "%DST%" /MIR ^
  /XD .git .github .vscode .idea .claude .ruff_cache .pytest_cache __pycache__ .venv tests test_data docs ^
  /XF *.pyc streamlit.pid CLAUDE.md .gitignore "Manning Context dump.txt"

:: robocopy exit codes 0-7 are success (8+ is a real error).
if %ERRORLEVEL% GEQ 8 goto :failed

echo Deploy complete. Excluded dev/test artifacts.
exit /b 0

:failed
echo [ERROR] robocopy reported errors (exit %ERRORLEVEL%).
exit /b %ERRORLEVEL%

:usage
echo Usage: deploy.bat ^<target-folder^>
exit /b 1
