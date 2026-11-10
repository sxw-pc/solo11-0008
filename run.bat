@echo off
setlocal
cd /d "%~dp0"
if "%PYTHON%"=="" set "PYTHON=python"
"%PYTHON%" -m gateway.app
endlocal
