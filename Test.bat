@echo off
setlocal EnableExtensions

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: Visual Studio 2022 Build Tools or Visual Studio 2022 is required.
    echo Install the .NET desktop development workload and .NET Framework 4.8 targeting pack.
    exit /b 1
)

for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set "MSBUILD=%%I"
if not defined MSBUILD (
    echo ERROR: MSBuild was not found.
    exit /b 1
)

if not exist "%ProgramFiles(x86)%\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8\mscorlib.dll" (
    echo ERROR: .NET Framework 4.8 targeting pack was not found.
    exit /b 1
)

"%MSBUILD%" "%~dp0Tests\DomainMembershipCheckRepair.Tests.csproj" /m /t:Rebuild /p:Configuration=Release /p:Platform=AnyCPU
if errorlevel 1 (
    echo.
    echo TEST BUILD FAILED.
    exit /b 1
)

"%~dp0Tests\bin\Release\DomainMembershipCheckRepair.Tests.exe"
if errorlevel 1 (
    echo.
    echo TESTS FAILED.
    exit /b 1
)

echo.
echo TESTS PASSED.
exit /b 0
