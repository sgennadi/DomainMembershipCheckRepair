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
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$files = Get-ChildItem -Path '%~dp0dist' -Recurse -File | Where-Object { $_.Name -like 'DomainMembershipCheckRepair-*' -and ($_.Extension -eq '.exe' -or $_.Name -like '*.exe.config') } | Sort-Object FullName; $lines = $files | ForEach-Object { $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(); $relative = $_.FullName.Substring(('%~dp0dist').Length).TrimStart('\'); \"$hash  $relative\" }; $lines | Set-Content -Encoding ascii '%~dp0dist\SHA256SUMS.txt'"
if errorlevel 1 exit /b 1

echo.
echo All builds completed successfully.
echo Keep each EXE together with its matching .exe.config file.
echo Checksums: %~dp0dist\SHA256SUMS.txt
exit /b 0
