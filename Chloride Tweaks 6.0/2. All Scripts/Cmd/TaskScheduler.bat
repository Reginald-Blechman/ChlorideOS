@echo off
title Task Scheduler Toggle Script, made by imribiy#0001

echo.	Press [D] to Disable Task Scheduler 
echo.	Press [E] to Enable Task Scheduler (XOS Default)
echo.
set /p c="What is your choice? "
if /i %c% equ D goto :disable
if /i %c% equ E goto :enable

:disable
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\Schedule" /v "Start" /t REG_DWORD /d "4" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\timebrokersvc" /v "Start" /t REG_DWORD /d "4" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\tiledatamodelsvc" /v "Start" /t REG_DWORD /d "2" /f
PowerRun.exe /SW:0 Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Services\Schedule" /v "ErrorControl" /f
cls
echo Please reboot your system.
pause
exit

:enable
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v "Start" /t REG_DWORD /d "3" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\schedule" /v "Start" /t REG_DWORD /d "2" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\schedule" /v "errorcontrol" /t REG_DWORD /d "1" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\tiledatamodelsvc" /v "Start" /t REG_DWORD /d "2" /f
cls
echo Please reboot your system.
pause
exit