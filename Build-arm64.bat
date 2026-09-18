@echo off
setlocal EnableExtensions

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo ERROR: Visual Studio 2022 Build Tools or Visual Studio 2022 is required for ARM64 build.
    echo Install the .NET desktop development workload and .NET Framework 4.8.1 targeting pack.
    exit /b 1
)

for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set "MSBUILD=%%I"
if not defined MSBUILD (
    echo ERROR: MSBuild was not found.
    exit /b 1
)

if not exist "%ProgramFiles(x86)%\Reference Assemblies\Microsoft\Framework\.NETFramework\v4.8.1\mscorlib.dll" (
    echo ERROR: .NET Framework 4.8.1 targeting pack was not found.
    echo Install the .NET Framework 4.8.1 Developer Pack.
    exit /b 1
)

"%MSBUILD%" "%~dp0DomainMembershipCheckRepair.csproj" /m /t:Rebuild /p:Configuration=Release /p:Platform=ARM64
if errorlevel 1 exit /b 1

if not exist "%~dp0dist\ARM64" mkdir "%~dp0dist\ARM64"
copy /y "%~dp0bin\Release\ARM64\DomainMembershipCheckRepair.exe" "%~dp0dist\ARM64\DomainMembershipCheckRepair-arm64.exe" >nul

echo.
echo BUILD SUCCESSFUL:
echo %~dp0dist\ARM64\DomainMembershipCheckRepair-arm64.exe
exit /b 0
