:: rebuilding performance counters 


lodctr /r

lodctr /r

echo  Hide Sleep Option
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t REG_DWORD /d "0" /f


echo Disable File Stamps
FSUTIL behavior set disablelastaccess 1
