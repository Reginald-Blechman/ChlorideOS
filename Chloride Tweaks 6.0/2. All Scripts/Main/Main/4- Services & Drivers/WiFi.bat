@echo off
title WiFi Toggle Script

echo.	Press [D] to Disable WiFi (Desktop default)
echo.	Press [E] to Enable WiFi (Laptop default)
echo.
set /p c="What is your choice? "
if /i %c% equ D goto :disable
if /i %c% equ E goto :enable

:disable
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\Wcmsvc" /v "Start" /t REG_DWORD /d "4" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\Ndisuio" /v "Start" /t REG_DWORD /d "4" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\NativeWifiP" /v "Start" /t REG_DWORD /d "4" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\vwifibus" /v "Start" /t REG_DWORD /d "4" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\vwififlt" /v "Start" /t REG_DWORD /d "4" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\wdiwifi" /v "Start" /t REG_DWORD /d "4" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvc" /v "Start" /t REG_DWORD /d "4" /f
cls
echo Please reboot your system.
pause
exit

:enable
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /v "Start" /t REG_DWORD /d "2" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\Wcmsvc" /v "Start" /t REG_DWORD /d "2" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\Ndisuio" /v "Start" /t REG_DWORD /d "3" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\NativeWifiP" /v "Start" /t REG_DWORD /d "3" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\vwifibus" /v "Start" /t REG_DWORD /d "3" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\vwififlt" /v "Start" /t REG_DWORD /d "1" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\wdiwifi" /v "Start" /t REG_DWORD /d "3" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\Netman" /v "Start" /t REG_DWORD /d "3" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\nsi" /v "Start" /t REG_DWORD /d "2" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc" /v "Start" /t REG_DWORD /d "2" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\WlanSvc" /v "Start" /t REG_DWORD /d "2" /f
echo Please reboot your system.
pause
exit