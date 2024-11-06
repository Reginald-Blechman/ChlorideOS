@echo off
title Runtime Broker Disabler, made by imribiy#0001

echo.	Press [D] to Disable Proxy Support (XOS Default)
echo.	Press [E] to Enable Proxy Support
echo.
set /p c="What is your choice? "
if /i %c% equ D goto :disable
if /i %c% equ E goto :enable

:disable
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f
cls
echo Please reboot.
pause
exit

:enable
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "2" /f
cls
echo Please reboot.
pause
exit