@echo off
setlocal
cd /d "%~dp0"
if "%PYTHON%"=="" set "PYTHON=python"
"%PYTHON%" -m pytest tests -q --cov=gateway --cov-report=term-missing --cov-report=html:htmlcov --cov-fail-under=85
set "RESULT=%ERRORLEVEL%"
endlocal & exit /b %RESULT%
