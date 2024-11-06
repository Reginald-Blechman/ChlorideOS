@echo off
SETLOCAL EnableDelayedExpansion

echo NOTE: This is the same option as the scaling options in the graphics control panel
echo.
echo [1] No Scaling controlled by the program/ operating system (recommended)
echo. 
echo [2] No Scaling controlled by the GPU driver
echo. 
echo [3] Full-Screen
echo. 
echo [4] Aspect ratio
echo.
choice /c:1234 /n > NUL 2>&1
if "!errorlevel!"=="4" set SCALING=4
if "!errorlevel!"=="3" set SCALING=3
if "!errorlevel!"=="2" set SCALING=2
if "!errorlevel!"=="1" set SCALING=1

:SET_SCALING
for %%i in (Scaling) do (
    for /f "tokens=*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /s /f "%%i"^| findstr "HKEY"') do (
		reg add "%%a" /v "Scaling" /t REG_DWORD /d "!SCALING!" /f  > NUL 2>&1
    )
)

pause
exit /b