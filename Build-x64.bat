@echo off
setlocal EnableExtensions

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
set "OUTDIR=%~dp0dist\x64"
set "OUT=%OUTDIR%\DomainMembershipCheckRepair-x64.exe"
set "ICON=%~dp0obj\generated\DomainMembershipCheckRepair.ico"

if not exist "%CSC%" (
    echo ERROR: 64-bit .NET Framework C# compiler was not found:
    echo %CSC%
    exit /b 1
)

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Generate-AppIcon.ps1" -OutputPath "%ICON%"
if errorlevel 1 exit /b 1

"%CSC%" /nologo /target:winexe /platform:x64 /define:ARCH_X64 /optimize+ /win32manifest:"%~dp0app.manifest" /win32icon:"%ICON%" /out:"%OUT%" /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.DirectoryServices.dll /reference:System.IO.Compression.dll /reference:System.IO.Compression.FileSystem.dll "%~dp0AssemblyInfo.cs" "%~dp0VersionInfo.cs" "%~dp0Program.cs" "%~dp0BuildInfo.cs" "%~dp0Core\DomainValidation.cs" "%~dp0Core\DiagnosticsService.cs" "%~dp0Core\AdDirectoryService.cs" "%~dp0CliRunner.cs" "%~dp0MainForm.cs" "%~dp0NativeMethods.cs" "%~dp0Models.cs" "%~dp0Dialogs.cs"

if errorlevel 1 (
    echo.
    echo BUILD FAILED.
    exit /b 1
)

echo.
echo BUILD SUCCESSFUL:
echo %OUT%
exit /b 0
