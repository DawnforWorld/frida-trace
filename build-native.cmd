@echo off
setlocal

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Visual Studio Installer vswhere.exe was not found. 1>&2
  exit /b 1
)

set "MSBUILD="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\amd64\MSBuild.exe`) do set "MSBUILD=%%i"
if not defined MSBUILD (
  echo x64 MSBuild was not found. 1>&2
  exit /b 1
)

"%MSBUILD%" "%~dp0native\veh-dll\veh-dll.vcxproj" /p:Configuration=Release /p:Platform=x64 /m
if errorlevel 1 exit /b %errorlevel%

"%MSBUILD%" "%~dp0native\veh-injector\veh-injector.vcxproj" /p:Configuration=Release /p:Platform=x64 /m
exit /b %errorlevel%
