@echo off
rem Windows wrapper. The real work is done by tools\run_checks.py
rem Messages here are ASCII only so they are readable in any console code page.
rem
rem   tools\run_checks.bat
rem   tools\run_checks.bat --only java
rem   tools\run_checks.bat --strict
setlocal
cd /d "%~dp0.."

where py >nul 2>&1
if %errorlevel%==0 (
  py -3 tools\run_checks.py %*
  exit /b %errorlevel%
)

where python >nul 2>&1
if %errorlevel%==0 (
  python tools\run_checks.py %*
  exit /b %errorlevel%
)

echo Python not found. Install Python 3 and make sure "py" or "python" is on PATH.
echo See docs/70 for details.
exit /b 1
