@echo off
rem ---------------------------------------------------------------------------
rem  OCSecure keystore keeper - Windows launcher
rem
rem  Messages in this file are in English on purpose. A batch file is read with
rem  the console code page, and this repository stores text as UTF-8, so Korean
rem  text here would be unreadable on a KO16MSWIN949 console. The Java program
rem  itself still prints Korean correctly.
rem
rem  See the installation manual, section 3.12. (development/test) or 7.12. (production)
rem ---------------------------------------------------------------------------
setlocal

if not defined OCS_HOME (
  echo [ERROR] OCS_HOME is not set.
  echo         Open an administrator command prompt and run:
  echo             setx OCS_HOME C:\ocsecure /M
  echo         Then open a NEW window. See the installation manual, section 3.1.1. (development/test) or 7.1.1. (production)
  exit /b 2
)

set "OCS_JAVA=%OCS_HOME%\java"

if not exist "%OCS_JAVA%" (
  echo [ERROR] Folder not found: %OCS_JAVA%
  echo         OCS_HOME points to %OCS_HOME% - is that where the package was unpacked?
  exit /b 2
)

if not exist "%OCS_JAVA%\out\ocsecure\keeper\OcsKeystoreKeeper.class" (
  echo [ERROR] Program not compiled: %OCS_JAVA%\out
  echo         See the installation manual, section 3.11. (development/test) or 7.11. (production)
  exit /b 2
)

if not exist "%OCS_JAVA%\ojdbc8.jar" (
  echo [ERROR] JDBC driver not found: %OCS_JAVA%\ojdbc8.jar
  echo         Copy it from %%ORACLE_HOME%%\jdbc\lib. See the installation manual, section 3.1.3. (development/test) or 7.1.3. (production)
  exit /b 2
)

if not exist "%OCS_JAVA%\keeper.properties" (
  echo [ERROR] Config file not found: %OCS_JAVA%\keeper.properties
  echo         Copy keeper.properties.sample and fill it in.
  echo         See the installation manual, section 3.12.3. (development/test) or 7.12.3. (production)
  exit /b 2
)

cd /d "%OCS_JAVA%" || (
  echo [ERROR] Cannot change directory to %OCS_JAVA%
  exit /b 2
)

if not exist log mkdir log

java -cp out;ojdbc8.jar ocsecure.keeper.OcsKeystoreKeeper keeper.properties %* >> log\keeper.log 2>&1
exit /b %ERRORLEVEL%
