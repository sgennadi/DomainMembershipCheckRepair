@echo off
setlocal EnableExtensions

echo ============================================================
echo Building DomainMembershipCheckRepair for x86, x64 and ARM64
echo ============================================================
echo.

call "%~dp0Test.bat"
if errorlevel 1 exit /b 1

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
echo Generating SHA-256 checksums...
"%~dp0Tools\bin\Release\DomainMembershipCheckRepair.Tools.exe" hash-dist --directory "%~dp0dist"
if errorlevel 1 exit /b 1

echo.
echo All builds completed successfully.
echo Keep each EXE together with its matching .exe.config file.
echo Checksums: %~dp0dist\SHA256SUMS.txt
exit /b 0
