@echo off
rem Windows wrapper. The real work is done by tools\run_checks.py
rem Messages here are ASCII only so they are readable in any console code page.
rem
rem   tools\run_checks.bat
rem   tools\run_checks.bat --only java
rem   tools\run_checks.bat --strict
rem
rem Note on the goto labels below: a %errorlevel% written inside a parenthesised
rem if-block is expanded when the block is parsed, not when it runs, so it would
rem report the exit code of "where" instead of the exit code of the checks.
rem Keeping each exit on its own line outside a block avoids that.
setlocal
cd /d "%~dp0.."

where py >nul 2>&1
if %errorlevel%==0 goto use_py

where python >nul 2>&1
if %errorlevel%==0 goto use_python

echo Python not found. Install Python 3 and make sure "py" or "python" is on PATH.
echo See docs/저장소/빌드_및_시험_설명서.md for details.
exit /b 1

:use_py
py -3 tools\run_checks.py %*
exit /b %errorlevel%

:use_python
python tools\run_checks.py %*
exit /b %errorlevel%
