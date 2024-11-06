@echo off

@echo Network Tweaks
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "Class" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SoftWARE\Policies\Microsoft\Windows\QoS\Fortnite" /v "Local Port" /t REG_SZ /d "*" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SoftWARE\Policies\Microsoft\Windows\QoS\Fortnite" /v "Protocol" /t REG_SZ /d "UDP" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SoftWARE\Policies\Microsoft\Windows\QoS\Fortnite" /v "Remote IP" /t REG_SZ /d "*" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SoftWARE\Policies\Microsoft\Windows\QoS\Fortnite" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SoftWARE\Policies\Microsoft\Windows\QoS\Fortnite" /v "Remote Port" /t REG_SZ /d "*" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SoftWARE\Policies\Microsoft\Windows\QoS\Fortnite" /v "throttle Rate" /t REG_SZ /d "-1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SoftWARE\Policies\Microsoft\Windows\QoS\Fortnite" /v "version" /t REG_SZ /d "1.0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SoftWARE\Policies\Microsoft\Windows\QoS\Fortnite" /v "Application Name" /t REG_SZ /d "fortniteclient-win64-shipping.exe" /f 
Reg.exe add "HKEY_LOCAL_MACHINE\SoftWARE\Policies\Microsoft\Windows\QoS\Fortnite" /v "DSCP value" /t REG_SZ /d "46" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SoftWARE\Policies\Microsoft\Windows\QoS\Fortnite" /v "Local IP" /t REG_SZ /d "*" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SoftWARE\Policies\Microsoft\Windows\QoS\Fortnite" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f

 Pause & Exit
)
cls

pause
