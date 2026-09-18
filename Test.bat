@echo off
setlocal EnableExtensions

set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
set "OUTDIR=%~dp0dist\tests"
set "OUT=%OUTDIR%\DomainMembershipCheckRepair.Tests.exe"

if not exist "%CSC%" (
    echo ERROR: .NET Framework C# compiler was not found:
    echo %CSC%
    exit /b 1
)

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

"%CSC%" /nologo /target:exe /platform:anycpu /optimize+ /out:"%OUT%" /reference:System.dll /reference:System.Core.dll "%~dp0Core\DomainValidation.cs" "%~dp0Tests\Program.cs"
if errorlevel 1 (
    echo.
    echo TEST BUILD FAILED.
    exit /b 1
)

"%OUT%"
if errorlevel 1 (
    echo.
    echo TESTS FAILED.
    exit /b 1
)

echo.
echo TESTS PASSED.
exit /b 0
