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
    echo Install the .NET Framework 4.8 Developer Pack.
    exit /b 1
)

"%MSBUILD%" "%~dp0DomainMembershipCheckRepair.csproj" /m /t:Rebuild /p:Configuration=Release /p:Platform=x64
if errorlevel 1 exit /b 1

set "OUTDIR=%~dp0dist\x64"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

copy /y "%~dp0bin\Release\x64\DomainMembershipCheckRepair.exe" "%OUTDIR%\DomainMembershipCheckRepair-x64.exe" >nul
if errorlevel 1 exit /b 1

copy /y "%~dp0bin\Release\x64\DomainMembershipCheckRepair.exe.config" "%OUTDIR%\DomainMembershipCheckRepair-x64.exe.config" >nul
if errorlevel 1 exit /b 1

echo.
echo BUILD SUCCESSFUL:
echo %OUTDIR%\DomainMembershipCheckRepair-x64.exe
echo %OUTDIR%\DomainMembershipCheckRepair-x64.exe.config
exit /b 0
