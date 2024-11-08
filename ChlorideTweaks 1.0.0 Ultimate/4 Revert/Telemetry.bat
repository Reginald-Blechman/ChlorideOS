@echo off
echo Run the bat as an admin
echo Starting in 5 seconds

timeout /t 5 /nobreak >nul

echo Connected User Experiences and Telemetry: tracking
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 2 /f