@echo off
title Force PState 0 ON - OFF
color a
mode con: cols=98 lines=20
echo.
:home
cls
echo.
echo ------------------------------
echo - PLEASE READ THIS CAREFULLY -
echo ------------------------------
timeout /t 2 /nobreak >nul
echo Forcing P0 states, is a performance state which generates more heat and higher power consumption. 
echo In theory, this should override NVIDIA's per-application hidden power settings 
echo (such as DWM, Explorer, which are set to adaptive at the factory). 
echo Some users have reported that this can cause much less jitter in games, 
echo as when the GPU is not fully utilized, the clock speed can vary greatly while gaming.
echo.
echo AT THE END OF THE SCRIPT YOUR PC WILL RESTART.
echo.
echo Force Performance State 0 ON - OFF
echo ------------------------------------
echo - 1) Disable DynamicPState On (1)  -
echo - 2) Disable DynamicPState Off (0) -
echo ------------------------------------
set /p q=: 
if %q% EQU 1 goto on
if %q% EQU 2 goto off
goto home

:on  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
shutdown -r -f -t 5 -c "Please wait until your PC restarts..."
timeout /t 2 /nobreak >NUL 2>&1
exit

:off
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDynamicPstate" /t REG_DWORD /d "0" /f
shutdown -r -f -t 5 -c "Please wait until your PC restarts..."
timeout /t 2 /nobreak >NUL 2>&1
exit