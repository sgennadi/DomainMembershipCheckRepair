@echo off
setlocal EnableExtensions

echo ============================================================
echo Building DomainMembershipCheckRepair for x86, x64 and ARM64
echo ============================================================
echo.

call "%~dp0Build-x86.bat"
if errorlevel 1 exit /b 1

echo.
call "%~dp0Build-x64.bat"
if errorlevel 1 exit /b 1

echo.
call "%~dp0Build-arm64.bat"
if errorlevel 1 exit /b 1

echo.
echo All builds completed successfully.
exit /b 0
