@echo off
title ZSN ULTIMATE (CHECKED BY NAWR)
:: Check if C:\temp exists, if not, create it
if not exist "C:\temp\" mkdir "C:\temp\"
cls
set w=[97m
set p=[95m
set b=[96m

chcp 65001 >nul 2>&1
cls
mode 720,400
echo.                                        ██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗ 
echo.                                        ██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝ 
echo.                                        ██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗
echo.                                        ██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║
echo.                                        ╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝
echo.                                         ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝ 
echo.                                            
echo.                          DO NOT REDISTRIBUTE MY PRODUCT, IT IS NOW HWID LOCKED AND IF YOUR SERIAL IS DUPLICATED ON ANOTHER
echo.                         PC I HAVE THE RIGHT TO PULL YOUR ACCESS TO MY PRODUCT WITH NO REFUND. YOU AGREED TO THIS IN MY TOS.
echo.
echo.
echo.                                                           Press any key to continue...
pause >nul                                                           
:: Execute the VBScript to show the pop-up from C:\temp
cscript //nologo "C:\temp\popup.vbs"

:: Delete the temporary VBScript from C:\temp
del "C:\temp\popup.vbs"

::Disable UAC
Reg.exe ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f > nul

:: Enable ANSI Escape Sequences
Reg.exe add "HKCU\CONSOLE" /v "VirtualTerminalLevel" /t REG_DWORD /d "1" /f  > nul

::Enable Delayed Expansion
setlocal EnableDelayedExpansion > nul
cls 

::Enable Restore points 
Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\SystemRestore" /v "RPSessionInterval" /f  >nul 2>&1
Reg.exe delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\SystemRestore" /v "DisableConfig" /f >nul 2>&1
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d 0 /f  >nul 2>&1
powershell -ExecutionPolicy Unrestricted -NoProfile Enable-ComputerRestore -Drive 'C:\'>nul 2>&1
cls 
:: Creating Restore Point
echo Creating Restore Point
Wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "ZSN ULTIMATE RESTORE POINT", 100, 7

cls
set w=[97m
set p=[95m
set b=[96m

chcp 65001 >nul 2>&1
cls

goto menu

:menu
cls
echo.            
echo.
echo.  
echo.                 ███████╗███████╗███╗   ██╗    ██████╗ ██████╗ ███████╗███╗   ███╗██╗██╗   ██╗███╗   ███╗
echo.                 ╚══███╔╝██╔════╝████╗  ██║    ██╔══██╗██╔══██╗██╔════╝████╗ ████║██║██║   ██║████╗ ████║
echo.                   ███╔╝ ███████╗██╔██╗ ██║    ██████╔╝██████╔╝█████╗  ██╔████╔██║██║██║   ██║██╔████╔██║
echo.                  ███╔╝  ╚════██║██║╚██╗██║    ██╔═══╝ ██╔══██╗██╔══╝  ██║╚██╔╝██║██║██║   ██║██║╚██╔╝██║
echo.                 ███████╗███████║██║ ╚████║    ██║     ██║  ██║███████╗██║ ╚═╝ ██║██║╚██████╔╝██║ ╚═╝ ██║
echo.                 ╚══════╝╚══════╝╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝ ╚═════╝ ╚═╝     ╚═╝
echo.
echo.                                                                   
wmic systemenclosure get serialnumber
echo.                                     
echo                                                                       [92m   VERIFIED USER
echo                                                                    [90m==========================[97m                     
echo.                                               
echo.                             
echo.                                                                                
echo.                                                          Select Your Option by Typing it and Then Hitting Enter.
echo.╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗                                                             
echo.║                                                                              ║                                                                 ║
echo.║                                                                              ║                                                                 ║
echo.║                                                                              ║                                                                 ║
echo.║══════════════════════════════════════════════════════════════════════════════║════════════════════════════════════════════════════════════════ ║                                                              ║                                                                 ║
echo.║                                                                              ║                                                                 ║
echo.║                                                                              ║                                                                 ║           
echo.║                                                                              ║                                                                 ║                                                                                                                                                                                      
echo.║  𝓢𝓔𝓛𝓔𝓒𝓣 𝓨𝓞𝓤𝓡 𝓞𝓟𝓣𝓘𝓞𝓝                                                          ║                                                                 ║
echo.╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝ 
echo.                                                                                                                                                 
echo.
echo.
echo.

set /p input=: 
if /i %input% == Z goto FPS BOOST
if /i %input% == S goto ZERO INPUT DELAY
if /i %input% == N goto GPU
if /i %input% == A goto CPU
if /i %input% == W goto BIOS
if /i %input% == R goto CLEANER





) ELSE (
echo Invalid Input & goto MisspellRedirect

:MisspellRedirect
cls
echo Misspell Detected
timeout 2 > nul
goto RedirectMenu


:RedirectMenu
cls
goto :menu

:FPS BOOST
netsh int tcp set global autotuninglevel=normal
netsh int tcp set global ecncapability=enabled
netsh interface teredo set state disabled
netsh interface 6to4 set state disabled
netsh winsock reset
netsh int isatap set state disable
netsh int ip set global taskoffload=disabled
netsh int ip set global neighborcachelimit=4096
netsh int tcp set global timestamps=disabled
netsh int tcp set heuristics disabled
netsh int tcp set global autotuninglevel=disable
netsh int tcp set global ecncapability=disabled
netsh int tcp set global rss=enabled
netsh int tcp set global rsc=disabled
netsh int tcp set global dca=enabled
netsh int tcp set global netdma=enabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set security mpp=disabled
netsh int tcp set security profiles=disabled
netsh int ip set global icmpredirects=disabled
netsh int tcp set security mpp=disabled profiles=disabled
netsh int ip set global multicastforwarding=disabled
PowerShell Disable-NetAdapterLso -Name "*"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue}"
powershell "ForEach($adapter In Get-NetAdapter){Disable-NetAdapterLso -Name $adapter.Name -ErrorAction SilentlyContinue}"
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "8760" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_S
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckFrequency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DelayedAckTicks" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "CongestionAlgorithm" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MultihopSets" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DefaultSendWindow" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "16384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DynamicSendBufferDisable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "IgnorePushBitOnReceives" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "NonBlockingSendSpecialBuffering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "DisableRawSecurity" /t REG_DWORD /d "1" /f
netsh interface tcp set heuristics disabled
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
ipconfig /flushdns
ipconfig /renew
set global rss=enabled autotuninglevel=normal congestionprovider=default ecncapability=enabled timestamps=disabled initialrto=2000 rsc=enabled nonsackrttresiliency=disabled maxsynretransmissions=2 fastopen=enabled fastopenfallback=enabled hystart=enabled prr=enabled pacingprofile=off
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f

dir /b %SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientExtensions-Package~3*.mum >List.txt
dir /b %SystemRoot%\servicing\Packages\Microsoft-Windows-GroupPolicy-ClientTools-Package~3*.mum >>List.txt
for /f %%i in ('findstr /i . List.txt 2^>nul') do dism /online /norestart /add-package:"%SystemRoot%\servicing\Packages\%%i"
vssadmin delete shadows /all /Quiet
sc stop cpuz150
sc stop vgt
sc stop vgrl
sc stop vgk
sc stop vgc
sc delete vgrl
sc delete vgk
sc delete vgc
sc delete vg
taskkill /f /im vgtray.exe
sc delete cpuz150
sc config wuauserv start= disabled
net stop wuauserv
sc config bits start= disabled
net stop bits
sc config dosvc start= disabled
net stop dosvc
sc config UsoSvc start= disabled
net stop UsoSvc
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{FA99DFC7-6AC2-453A-A5E2-5E2AFF4507BD}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F2A1CB5A-E3CC-4A2E-AF9D-505A7009D442}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CAA59E3C-4792-41A5-9909-6A6A8D32490E}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{BCB48336-4DDD-48FF-BB0B-D3190DACB3E2}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{B267E3AD-A825-4A09-82B9-EEC22AA3B847}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{A3D53349-6E61-4557-8FC7-0028EDCEEBF6}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}\Count" /f
reg delete "HKEY_CLASSES_ROOT\riotclient" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\com.epicgames.launcher" /f
reg delete "HKEY_USERS\S-1-5-21-2097722829-2509645790-3642206209-1001\Software\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\WOW6432Node\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\com.epicgames.launcher" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Identifiers" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Hardware Survey" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\HardwareConfig" /f
reg delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control" /v SystemStartOptions /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\com.epicgames.launcher" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Hardware Survey" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Identifiers" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Hardware Survey" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Identifiers" /f
reg delete "HKEY_CLASSES_ROOT\com.epicgames.launcher" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\com.epicgames.launcher" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\EpicGames" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Epic Games" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Epic Games" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\EpicGames" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\Installer\Dependencies" /v MSICache /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Direct3D" /v WHQLClass /f
reg delete "HKEY_CLASSES_ROOT\com.epicgames.launcher" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Epic Games" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\EpicGames" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\Installer\Dependencies" /v MSICache /f
reg delete "HKEY_CURRENT_USER\Software\Classes\com.epicgames.launcher" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Hardware Survey" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Identifiers" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Direct3D" /v WHQLClass /f
reg delete "HKEY_CURRENT_USER\Software\WOW6432Node\Epic Games" /f
reg delete "HKEY_LOCAL_MACHINE\Hardware\Description\System\CentralProcessor\0" /v ProcessorNameString /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\com.epicgames.launcher" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Epic Games" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\EpicGames" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Epic Games" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\EpicGames" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\HardwareConfig" /f
reg delete "HKEY_LOCAL_MACHINE\Software\Epic Games" /f
reg delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control" /v SystemStartOptions /f
reg delete "HKEY_USERS\S-1-5-21-2097722829-2509645790-3642206209-1001\Software\Epic Games" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App\windows.protocol" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App\windows.protocol\ms-gamebarservices" /f
reg delete "HKLM\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications\FortniteClient-Win64-Shipping.exe" /f
reg delete "HKLM\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\181\93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\181^App" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\181^App\93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Data\ac" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Data\ad" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplication\3^93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplication\3^93\ac" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplication\4^93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplication\4^93\ad" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Data\180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Data\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Data\182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\4e\180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\4e\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\4e\182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe\182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a80" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a81" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a82" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a83" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a84" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\3\1a80" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\3\1a81" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\3\1a82" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\4\1a83" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\4\1a84" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^180\1a80" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^181\1a81" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^182\1a82" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^180\1a83" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^181\1a84" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x86__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-21-2532382528-581214834-2534474248-1001\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-21-2532382528-581214834-2534474248-1001\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-21-2532382528-581214834-2534474248-1001\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x86__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\5e4eddc4_0" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\5e4eddc4_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\Streams\0" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000205B6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000403D6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000405DE" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000060286" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000009042E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000A03B4" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000A0430" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000B0532" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000B05D6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000C0430" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000C0586" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000E03D2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000E0406" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000100430" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001103EE" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000011041E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000012047E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001303EE" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001304F2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000014041E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001703E6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000170440" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001704FC" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499\87f345c2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\DefaultIcon" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\shell" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\shell\open" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\shell\open\command" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\System\GameConfigStore\Children\03ce6902-ff58-41de-ab92-36fcaf27a580" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\System\GameConfigStore\Parents\fd13f746e7d2d69760b017363f621255c9b49ac8" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499\87f345c2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\DefaultIcon" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\shell" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\shell\open" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\shell\open\command" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe" /f /0
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f /0 
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f /0 
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App" /f /0 
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App\windows.protocol" /f /0
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App\windows.protocol\ms-gamebarservices" /f /0
reg delete "HKLM\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications\FortniteClient-Win64-Shipping.exe" /f
reg delete "HKLM\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\181\93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\181^App" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\181^App\93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Data\ac" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Data\ad" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplication\3^93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplication\3^93\ac" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplication\4^93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplication\4^93\ad" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Data\180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Data\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Data\182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\4e\180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\4e\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\4e\182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe\182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a80" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a81" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a82" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a83" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a84" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\3\1a80" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\3\1a81" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\3\1a82" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\4\1a83" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\4\1a84" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^180\1a80" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^181\1a81" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^182\1a82" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^180\1a83" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^181\1a84" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x86__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-21-2532382528-581214834-2534474248-1001\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-21-2532382528-581214834-2534474248-1001\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-21-2532382528-581214834-2534474248-1001\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x86__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\5e4eddc4_0" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\5e4eddc4_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\Streams\0" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000205B6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000403D6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000405DE" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000060286" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000009042E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000A03B4" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000A0430" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000B0532" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000B05D6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000C0430" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000C0586" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000E03D2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000E0406" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000100430" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001103EE" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000011041E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000012047E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001303EE" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001304F2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000014041E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001703E6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000170440" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001704FC" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499\87f345c2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\DefaultIcon" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\shell" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\shell\open" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\shell\open\command" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\System\GameConfigStore\Children\03ce6902-ff58-41de-ab92-36fcaf27a580" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\System\GameConfigStore\Parents\fd13f746e7d2d69760b017363f621255c9b49ac8" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499\87f345c2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\DefaultIcon" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\shell" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\shell\open" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\shell\open\command" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\Temporary Internet Files"
RMDIR /S /Q "C:\Windows\logs\CBS"
RMDIR /S /Q "C:\Windows\Temp"
RMDIR /S /Q "C:\Windows\System32\config\systemprofile\AppData\Local\ScreenTime"
RMDIR /S /Q "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault\UserProfileRoaming"
RMDIR /S /Q "C:\Windows\System32\config\systemprofile\AppData\Local\D3DSCache"
RMDIR /S /Q "C:\Windows\System32\config\TxR"
RMDIR /S /Q "C:\Windows\System32\WDI\LogFiles\StartpInfo"
RMDIR /S /Q "C:\Windows\System32\WDI\LogFiles"
RMDIR /S /Q "C:\Windows\SoftwareDistribution\"
RMDIR /S /Q "C:\Windows\UserviceProfiles\NetworkService\AppData\Local\Microsoft\Windows\deliveryOptimization\Logs"
RMDIR /S /Q "C:\Windows\UserviceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State"
RMDIR /S /Q "C:\Users\%username%\AppData\Roaming\Microsoft\Protect"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\VirtalStore"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\UnrealEngine"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Temp"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\DeviceSearchCache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\WebCache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\WER"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCookies"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\IEDownloadHistory"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\IECompataCache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\IECompatCache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\Caches"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Terminal Server Client\Cache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Internet Explorer\CacheStorage"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\D3DSCache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\CrashDmps"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\ConnectedDevicesPlatform"
RMDIR /S /Q "C:\ProgramData\NVIDIA Corporation\NV_Cache"
RMDIR /S /Q "C:\ProgramData\NVIDIA Corporation\Drs\nvAppTimestamps"
RMDIR /S /Q "C:\ProgramData\Microsoft\Windows\WER"
RMDIR /S /Q "C:\PerfLogs"
RMDIR /S /Q "C:\Documents and Settings\%username%\AppData\Local\Application Data\Microsoft\Windows\Caches"
RMDIR /S /Q "%localappdata%\Microsoft\Windows\Caches"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\VALORANT"
RMDIR /S /Q "C:\ProgramData\Riot Games\Metadata\Riot Client"
RMDIR /S /Q "C:\ProgramData\Riot Games\Metadata\valorant.live"
RMDIR /S /Q "%systemdrive%\ProgramData\Microsoft\Windows\WER"
RMDIR /S /Q "%systemdrive%\Users\Public\Shared Files"
RMDIR /S /Q "%systemdrive%\System Volume Information\IndexerVolumeGuid"
RMDIR /S /Q "%systemdrive%\Users\Public\Libraries"
RMDIR /S /Q "%systemdrive%\MSOCache"
del /S /Q "C:\ProgramData\Riot Games\machine.cfg"
del "C:\Riot Games\VALORANT\live\Manifest_NonFSFiles_Win64.txt" /f /q
del "C:\Riot Games\VALORANT\live\Engine\Binaries\ThirdParty\CEF3\Win64\icdtl.dat" /f /q
del "C:\Riot Games\Riot Client\X\natives_blob.bin" /f /q
del "C:\Riot Games\Riot Client\X\icdtl.dat" /f /q
del "C:\Riot Games\Riot Client\X\Plgins\plgin-manifest.json" /f /q
del /s /q "C:\Windows\vgkbootstats.dat"
del /s /q /f "%systemdrive%\$Recycle.bin"
del /s /q "D:\System Volume Information\tracking.log"
del /s /q "C:\Windows\win.ini"
del /s /q "C:\Windows\memory.dmp"
del /s /q "C:\Windows\WindowsUpdate.log"
del /s /q "C:\Windows\System32\LogFiles\WMI\Wifi.etl"
del /s /q "C:\Windows\System32\LogFiles\WMI\RadioMgr.etl"
del /s /q "C:\Windows\System32\LogFiles\WMI\NtfsLog.etl"
del /s /q "C:\Windows\System32\LogFiles\WMI\NetCore.etl"
del /s /q "C:\Windows\System32\LogFiles\WMI\Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace.etl"
del /s /q "C:\Windows\System32\LogFiles\WMI\LwtNetLog.etl"
del /s /q "C:\Windows\UserviceProfiles\NetworkService\NTSER.DAT"
del /s /q "C:\Windows\UserviceProfiles\LocalService\AppData\Local\Microsoft\Windows\qwavecache.dat"
del /s /q "C:\Windows\Logs\DISM\dism.log"
del /s /q "C:\Windows\DirectX.log"
del /s /q "C:\Users\%username%\ntser.dat.LOG2"
del /s /q "C:\Users\%username%\ntser.dat.LOG1"
del /s /q "C:\Users\%username%\\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat"
del /s /q "C:\Users\%username%\NTSER.DAT"
del /s /q "C:\Users\%username%\AppData\Local\UnrealEngine\4.23\Saved\Config\WindowsClient\Manifest.ini"
del /s /q "C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat"
del /s /q "C:\Users\%username%\AppData\Local\Microsoft\Vault\UserProfileRoaming\Latest.dat"
del /s /q "C:\Users\%username%\AppData\Local\Microsoft\OneDrive\logs\Common\DeviceHealthSummaryConfigration.ini"
del /s /q "C:\Users\%username%\AppData\Local\IconCache.db"
del /s /q "C:\Users\%username%\AppData\Local\AC\INetCookies\ESE\container.dat"
del /s /q "C:\System Volume Information\tracking.log"
del /s /q "C:\ProgramData\Microsoft\Windows\DeviceMetadataCache\dmrc.idx"
del /s /q "C:\Config.Msi"
del /s /q "C:\Windows\System32\restore\MachineGuid.txt"
del /s /q "%systemdrive%\Users\Public\Libraries\collection.dat"
del /s /q "%systemdrive%\System Volume Information\WPSettings.dat"
del /s /q "%systemdrive%\System Volume Information\tracking.log"
del /s /q "%systemdrive%\Windows\INF\setpapi.dev.log"
del /s /q "%systemdrive%\Windows\INF\setpapi.setp.log"
del /s /q "%systemdrive%\ProgramData\ntser.pol"
del /s /q "%systemdrive%\Users\Defalt\NTSER.DAT"
del /s /q "%systemdrive%\Recovery\ntser.sys"
del /s /q "%systemdrive%\desktop.ini"
rd /q /s %systemdrive%\$Recycle.Bin
rd /q /s d:\$Recycle.Bin
rd /q /s e:\$Recycle.Bin
rd /q /s f:\$Recycle.Bin
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName /v ComputerName /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName /v ComputerName /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SYSTEM\HardwareConfig /v LastConfig /t REG_SZ /d {eac%random%} /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware" "Profiles\0001 /v HwProfileGuid /t REG_SZ /d {%random%-%random%-%random%-%random%-%random%} /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware" "Profiles\0001 /v GUID /t REG_SZ /d {%random%-%random%-%random%-%random%-%random%} /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v BuildGUID /t REG_SZ /d %random%-%random% /f
SET subkey1=%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%
SET subkey1=%subkey1:0=a%
SET subkey1=%subkey1:1=b%
SET subkey1=%subkey1:2=c%
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v BuildGUIDEx /t REG_BINARY /d %subkey1% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOwner /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOrganization /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Cryptography /v GUID /t REG_SZ /d %random%-%random%-%random%-%random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid /t REG_SZ /d %random%-%random%-%random%-%random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v ProductId /t REG_SZ /d %random%-%random%-%random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v InstallDate /t REG_SZ /d %random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation /v ComputerHardwareId /t REG_SZ /d {%random%-%random%-%random%-%random%} /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" /v MachineGuid /t REG_SZ /d %Hex8%-%Hex1%-%Hex0%-%Hex1%-%Hex10% /f>nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v BuildGUID /t REG_SZ /d %Hex8%-%Hex1%-%Hex0%-%Hex1%-%Hex10% /f>nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}\Configuration\Variables\BusDeviceDesc" /v PropertyGuid /t REG_SZ /d {%Hex8%-%Hex1%-%Hex0%-%Hex1%-%Hex10%} /f>nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\Configuration\Variables\DeviceDesc" /v PropertyGuid /t REG_SZ /d {%Hex8%-%Hex1%-%Hex0%-%Hex1%-%Hex10%} /f>nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\Configuration\Variables\Driver" /v PropertyGuid /t REG_SZ /d {%Hex8%-%Hex1%-%Hex0%-%Hex1%-%Hex10%} /f>nul 2>&1W
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemInformation" /v ComputerHardwareId /t REG_SZ /d {%Hex8%-%Hex1%-%Hex0%-%Hex1%-%Hex10%} /f>nul 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v InstallDate /t REG_SZ /d %random% /f
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductId /t REG_SZ /d %random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Cryptography /v GUID /t REG_SZ /d %Hex1%-%Hex8%-%Hex1%-%Hex0%-%Hex10% /f
REG ADD HKLM\SOFTWARE\Microsoft\Cryptography /v GUID /t REG_SZ /d %random%-%random%-%random%-%random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid /t REG_SZ /d %random%-%random%-%random%-%random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v BuildGUID /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v InstallDate /t REG_SZ /d %random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v ProductId /t REG_SZ /d %random%-%random%-%random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOrganization /t REG_SZ /d FS%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOrganization /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOwner /t REG_SZ /d FS%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOwner /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName /v ComputerName /t REG_SZ /d %random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName /v ComputerName /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName /v ComputerName /t REG_SZ /d %random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName /v ComputerName /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware" "Profiles\0001 /v GUID /t REG_SZ /d {%random%-%random%-%random%-%random%-%random%} /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware" "Profiles\0001 /v HwProfileGuid /t REG_SZ /d {%random%-%random%-%random%-%random%-%random%} /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation /v ComputerHardwareId /t REG_SZ /d {%random%-s%random%-%random%-%random%-%random%} /f
REG ADD HKLM\SYSTEM\HardwareConfig /v LastConfig /t REG_SZ /d {eac%random%} /f
REG ADD HKLM\SYSTEM\HardwareConfig /v LastConfig /t REG_SZ /d {fefefee%random%-%random%-%random%-%random%} /f
REG ADD HKLM\Software\Microsoft\Windows NT\CurrentVersion /v InstallDate /t REG_SZ /d %random% /f
REG ADD HKLM\Software\Microsoft\Windows NT\CurrentVersion /v ProductId /t REG_SZ /d %random% /f
REG ADD HKLM\System\CurrentControlSet\Control\SystemInformation /v ComputerHardwareId /t REG_SZ /d %random% /f
REG ADD HKLM\System\CurrentControlSet\Control\WMI\Security /v 671a8285-4edb-4cae-99fe-69a15c48c0bc /t REG_SZ /d %random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" "WindowsUpdate /v SusClientId /t REG_SZ /d {%random%-%random%-%random%-%random%-%random%} /f
netsh winsock reset
netsh advfirewall reset
vssadmin delete shadows /all /Quiet
sc stop cpuz150
sc stop vgt
sc stop vgrl
sc stop vgk
sc stop vgc
sc stop vg
sc delete vgrl
sc delete vgk
sc delete vgc
sc delete vg
taskkill /f /im vgtray.exe
sc delete cpuz150
sc config wuauserv start= disabled
net stop wuauserv
sc config bits start= disabled
net stop bits
sc config dosvc start= disabled
net stop dosvc
sc config UsoSvc start= disabled
net stop UsoSvc
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications\VALORANT-Win64-Shipping.exe" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{FA99DFC7-6AC2-453A-A5E2-5E2AFF4507BD}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{F2A1CB5A-E3CC-4A2E-AF9D-505A7009D442}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CAA59E3C-4792-41A5-9909-6A6A8D32490E}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{BCB48336-4DDD-48FF-BB0B-D3190DACB3E2}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{B267E3AD-A825-4A09-82B9-EEC22AA3B847}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{A3D53349-6E61-4557-8FC7-0028EDCEEBF6}\Count" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}\Count" /f
reg delete "HKEY_CLASSES_ROOT\riotclient" /f
reg delete "HKEY_CURRENT_USER\Software\WOW6432Node\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\com.epicgames.launcher" /f
reg delete "HKEY_USERS\S-1-5-21-2097722829-2509645790-3642206209-1001\Software\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\WOW6432Node\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\com.epicgames.launcher" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Identifiers" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Hardware Survey" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\HardwareConfig" /f
reg delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control" /v SystemStartOptions /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\WOW6432Node\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\com.epicgames.launcher" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Hardware Survey" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Identifiers" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Hardware Survey" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Identifiers" /f
reg delete "HKEY_CLASSES_ROOT\com.epicgames.launcher" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\com.epicgames.launcher" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Epic Games" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\EpicGames" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\EpicGames" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Epic Games" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Epic Games" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\EpicGames" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\Installer\Dependencies" /v MSICache /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Direct3D" /v WHQLClass /f
reg delete "HKEY_CLASSES_ROOT\com.epicgames.launcher" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Epic Games" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\EpicGames" /f
reg delete "HKEY_CURRENT_USER\Software\Classes\Installer\Dependencies" /v MSICache /f
reg delete "HKEY_CURRENT_USER\Software\Classes\com.epicgames.launcher" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Hardware Survey" /f
reg delete "HKEY_CURRENT_USER\Software\Epic Games\Unreal Engine\Identifiers" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Direct3D" /v WHQLClass /f
reg delete "HKEY_CURRENT_USER\Software\WOW6432Node\Epic Games" /f
reg delete "HKEY_LOCAL_MACHINE\Hardware\Description\System\CentralProcessor\0" /v ProcessorNameString /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\com.epicgames.launcher" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Epic Games" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\EpicGames" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Epic Games" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\EpicGames" /f
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\HardwareConfig" /f
reg delete "HKEY_LOCAL_MACHINE\Software\Epic Games" /f
reg delete "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control" /v SystemStartOptions /f
reg delete "HKEY_USERS\S-1-5-21-2097722829-2509645790-3642206209-1001\Software\Epic Games" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App\windows.protocol" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App\windows.protocol\ms-gamebarservices" /f
reg delete "HKLM\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications\FortniteClient-Win64-Shipping.exe" /f
reg delete "HKLM\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\181\93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\181^App" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\181^App\93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Data\ac" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\4e\180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\4e\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\4e\182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe\182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^182\1a82" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^180\1a83" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^181\1a84" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x86__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-21-2532382528-581214834-2534474248-1001\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-21-2532382528-581214834-2534474248-1001\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-21-2532382528-581214834-2534474248-1001\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x86__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\WOW6432Node\EasyAntiCheat" /f
reg delete "HKLM\SYSTEM\ControlSet001\Services\EasyAntiCheat" /f
reg delete "HKLM\SYSTEM\ControlSet001\Services\EasyAntiCheat\Security" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat\Security" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\5e4eddc4_0" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\5e4eddc4_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\Streams\0" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000205B6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000403D6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000405DE" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000060286" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000009042E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000A03B4" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000A0430" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000B0532" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000B05D6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000C0430" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000C0586" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000E03D2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000E0406" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000100430" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001103EE" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000011041E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000012047E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001303EE" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001304F2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000014041E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001703E6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000170440" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001704FC" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499\87f345c2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\DefaultIcon" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\shell" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\shell\open" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\shell\open\command" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\System\GameConfigStore\Children\03ce6902-ff58-41de-ab92-36fcaf27a580" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\System\GameConfigStore\Parents\fd13f746e7d2d69760b017363f621255c9b49ac8" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499\87f345c2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\DefaultIcon" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\shell" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\shell\open" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\shell\open\command" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f

reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App\windows.protocol" /f
reg delete "HKLM\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\PackageRepository\Packages\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\Microsoft.XboxGameOverlay_8wekyb3d8bbwe!App\windows.protocol\ms-gamebarservices" /f
reg delete "HKLM\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications\FortniteClient-Win64-Shipping.exe" /f
reg delete "HKLM\SOFTWARE\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data\93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\Package\181\93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\181^App" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Index\PackageAndPackageRelativeApplicationId\181^App\93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Data\ac" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Data\ad" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplication\3^93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplication\3^93\ac" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplication\4^93" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\ApplicationUser\Index\UserAndApplication\4^93\ad" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Data\180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Data\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Data\182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\4e\180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\4e\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFamily\4e\182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_split.scale-100_8wekyb3d8bbwe\182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Package\Index\PackageFullName\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe\181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a80" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a81" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a82" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a83" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Data\1a84" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\3\1a80" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\3\1a81" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\3\1a82" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\4\1a83" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\User\4\1a84" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^180\1a80" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^181\1a81" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^182" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\3^182\1a82" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^180" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^180\1a83" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^181" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\PackageUser\Index\UserAndPackage\4^181\1a84" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x86__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-21-2532382528-581214834-2534474248-1001\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-21-2532382528-581214834-2534474248-1001\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x64__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\S-1-5-21-2532382528-581214834-2534474248-1001\Microsoft.XboxGameOverlay_1.41.24001.0_neutral_~_8wekyb3d8bbwe\Microsoft.VCLibs.140.00_14.0.27323.0_x86__8wekyb3d8bbwe" /f
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\SecurityManager\CapAuthz\ApplicationsEx\Microsoft.XboxGameOverlay_1.41.24001.0_x64__8wekyb3d8bbwe" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\.DEFAULT\Software\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\.DEFAULT\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\5e4eddc4_0" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore\5e4eddc4_0\{219ED5A0-9CBF-4F3A-B927-37C9E5C5F14F}" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\Streams\0" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000205B6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000403D6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000405DE" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000060286" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000009042E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000A03B4" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000A0430" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000B0532" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000B05D6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000C0430" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000C0586" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000E03D2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000000E0406" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000100430" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001103EE" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000011041E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000012047E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001303EE" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001304F2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:000000000014041E" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001703E6" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:0000000000170440" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\SessionInfo\1\ApplicationViewManagement\W32:00000000001704FC" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499\87f345c2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\DefaultIcon" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\shell" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\shell\open" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\Software\Classes\discord-432980957394370572\shell\open\command" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\System\GameConfigStore\Children\03ce6902-ff58-41de-ab92-36fcaf27a580" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001\System\GameConfigStore\Parents\fd13f746e7d2d69760b017363f621255c9b49ac8" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\Local Settings\MrtCache\C:%5CProgram Files%5CWindowsApps%5CMicrosoft.XboxGamingOverlay_2.26.28001.0_x64__8wekyb3d8bbwe%5Cmicrosoft.system.package.metadata%5CS-1-5-21-2532382528-581214834-2534474248-1001-MergedResources-2.pri\1d50f44cf1a0499\87f345c2" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\DefaultIcon" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\shell" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\shell\open" /f
reg delete "HKU\S-1-5-21-2532382528-581214834-2534474248-1001_Classes\discord-432980957394370572\shell\open\command" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\S-1-5-18\Software\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\Certificates" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CRLs" /f
reg delete "HKU\S-1-5-18\Software\Policies\Microsoft\SystemCertificates\TrustedPublisher\CTLs" /f


RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\Temporary Internet Files"
RMDIR /S /Q "C:\Windows\logs\CBS"
RMDIR /S /Q "C:\Windows\Temp"
RMDIR /S /Q "C:\Windows\System32\config\systemprofile\AppData\Local\ScreenTime"
RMDIR /S /Q "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Vault\UserProfileRoaming"
RMDIR /S /Q "C:\Windows\System32\config\systemprofile\AppData\Local\D3DSCache"
RMDIR /S /Q "C:\Windows\System32\config\TxR"
RMDIR /S /Q "C:\Windows\System32\WDI\LogFiles\StartpInfo"
RMDIR /S /Q "C:\Windows\System32\WDI\LogFiles"
RMDIR /S /Q "C:\Windows\SoftwareDistribution\"
RMDIR /S /Q "C:\Windows\UserviceProfiles\NetworkService\AppData\Local\Microsoft\Windows\deliveryOptimization\Logs"
RMDIR /S /Q "C:\Windows\UserviceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\State"
RMDIR /S /Q "C:\Users\%username%\AppData\Roaming\Microsoft\Protect"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\VirtalStore"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\UnrealEngine"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Temp"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\DeviceSearchCache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\LocalState\ConstraintIndex"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\WebCache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\WER"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCookies"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\IEDownloadHistory"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\IECompataCache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\IECompatCache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Windows\Caches"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Terminal Server Client\Cache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\Microsoft\Internet Explorer\CacheStorage"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\D3DSCache"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\CrashDmps"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\ConnectedDevicesPlatform"
RMDIR /S /Q "C:\ProgramData\NVIDIA Corporation\NV_Cache"
RMDIR /S /Q "C:\ProgramData\NVIDIA Corporation\Drs\nvAppTimestamps"
RMDIR /S /Q "C:\ProgramData\Microsoft\Windows\WER"
RMDIR /S /Q "C:\PerfLogs"
RMDIR /S /Q "C:\Documents and Settings\%username%\AppData\Local\Application Data\Microsoft\Windows\Caches"
RMDIR /S /Q "%localappdata%\Microsoft\Windows\Caches"
RMDIR /S /Q "C:\Users\%username%\AppData\Local\VALORANT"
RMDIR /S /Q "C:\ProgramData\Riot Games\Metadata\Riot Client"
RMDIR /S /Q "C:\ProgramData\Riot Games\Metadata\valorant.live"
RMDIR /S /Q "%systemdrive%\ProgramData\Microsoft\Windows\WER"
RMDIR /S /Q "%systemdrive%\Users\Public\Shared Files"
RMDIR /S /Q "%systemdrive%\System Volume Information\IndexerVolumeGuid"
RMDIR /S /Q "%systemdrive%\Users\Public\Libraries"
RMDIR /S /Q "%systemdrive%\MSOCache"


del /S /Q "C:\ProgramData\Riot Games\machine.cfg"
del "C:\Riot Games\VALORANT\live\Manifest_NonFSFiles_Win64.txt" /f /q
del "C:\Riot Games\VALORANT\live\Engine\Binaries\ThirdParty\CEF3\Win64\icdtl.dat" /f /q
del "C:\Riot Games\Riot Client\X\natives_blob.bin" /f /q
del "C:\Riot Games\Riot Client\X\icdtl.dat" /f /q
del "C:\Riot Games\Riot Client\X\Plgins\plgin-manifest.json" /f /q
del /s /q "C:\Windows\vgkbootstats.dat"
del /s /q /f "%systemdrive%\$Recycle.bin"
del /s /q "D:\System Volume Information\tracking.log"
del /s /q "C:\Windows\win.ini"
del /s /q "C:\Windows\memory.dmp"
del /s /q "C:\Windows\WindowsUpdate.log"
del /s /q "C:\Windows\System32\LogFiles\WMI\Wifi.etl"
del /s /q "C:\Windows\System32\LogFiles\WMI\RadioMgr.etl"
del /s /q "C:\Windows\System32\LogFiles\WMI\NtfsLog.etl"
del /s /q "C:\Windows\System32\LogFiles\WMI\NetCore.etl"
del /s /q "C:\Windows\System32\LogFiles\WMI\Microsoft-Windows-Rdp-Graphics-RdpIdd-Trace.etl"
del /s /q "C:\Windows\System32\LogFiles\WMI\LwtNetLog.etl"
del /s /q "C:\Windows\UserviceProfiles\NetworkService\NTSER.DAT"
del /s /q "C:\Windows\UserviceProfiles\LocalService\AppData\Local\Microsoft\Windows\qwavecache.dat"
del /s /q "C:\Windows\Logs\DISM\dism.log"
del /s /q "C:\Windows\DirectX.log"
del /s /q "C:\Users\%username%\ntser.dat.LOG2"
del /s /q "C:\Users\%username%\ntser.dat.LOG1"
del /s /q "C:\Users\%username%\\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat"
del /s /q "C:\Users\%username%\NTSER.DAT"
del /s /q "C:\Users\%username%\AppData\Local\UnrealEngine\4.23\Saved\Config\WindowsClient\Manifest.ini"
del /s /q "C:\Users\%username%\AppData\Local\Microsoft\Windows\INetCache\IE\container.dat"
del /s /q "C:\Users\%username%\AppData\Local\Microsoft\Vault\UserProfileRoaming\Latest.dat"
del /s /q "C:\Users\%username%\AppData\Local\Microsoft\OneDrive\logs\Common\DeviceHealthSummaryConfigration.ini"
del /s /q "C:\Users\%username%\AppData\Local\IconCache.db"
del /s /q "C:\Users\%username%\AppData\Local\AC\INetCookies\ESE\container.dat"
del /s /q "C:\System Volume Information\tracking.log"
del /s /q "C:\ProgramData\Microsoft\Windows\DeviceMetadataCache\dmrc.idx"
del /s /q "C:\Config.Msi"
del /s /q "C:\Windows\System32\restore\MachineGuid.txt"
del /s /q "%systemdrive%\Users\Public\Libraries\collection.dat"
del /s /q "%systemdrive%\System Volume Information\WPSettings.dat"
del /s /q "%systemdrive%\System Volume Information\tracking.log"
del /s /q "%systemdrive%\Windows\INF\setpapi.dev.log"
del /s /q "%systemdrive%\Windows\INF\setpapi.setp.log"
del /s /q "%systemdrive%\ProgramData\ntser.pol"
del /s /q "%systemdrive%\Users\Defalt\NTSER.DAT"
del /s /q "%systemdrive%\Recovery\ntser.sys"
del /s /q "%systemdrive%\desktop.ini"


rd /q /s %systemdrive%\$Recycle.Bin
rd /q /s d:\$Recycle.Bin
rd /q /s e:\$Recycle.Bin
rd /q /s f:\$Recycle.Bin


REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName /v ComputerName /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName /v ComputerName /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SYSTEM\HardwareConfig /v LastConfig /t REG_SZ /d {eac%random%} /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware" "Profiles\0001 /v HwProfileGuid /t REG_SZ /d {%random%-%random%-%random%-%random%-%random%} /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware" "Profiles\0001 /v GUID /t REG_SZ /d {%random%-%random%-%random%-%random%-%random%} /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v BuildGUID /t REG_SZ /d %random%-%random% /f

SET subkey1=%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%%random%
SET subkey1=%subkey1:0=a%
SET subkey1=%subkey1:1=b%
SET subkey1=%subkey1:2=c%

REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v BuildGUIDEx /t REG_BINARY /d %subkey1% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOwner /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOrganization /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Cryptography /v GUID /t REG_SZ /d %random%-%random%-%random%-%random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid /t REG_SZ /d %random%-%random%-%random%-%random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v ProductId /t REG_SZ /d %random%-%random%-%random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v InstallDate /t REG_SZ /d %random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation /v ComputerHardwareId /t REG_SZ /d {%random%-%random%-%random%-%random%} /f




REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography" /v MachineGuid /t REG_SZ /d %Hex8%-%Hex1%-%Hex0%-%Hex1%-%Hex10% /f>nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v BuildGUID /t REG_SZ /d %Hex8%-%Hex1%-%Hex0%-%Hex1%-%Hex10% /f>nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e967-e325-11ce-bfc1-08002be10318}\Configuration\Variables\BusDeviceDesc" /v PropertyGuid /t REG_SZ /d {%Hex8%-%Hex1%-%Hex0%-%Hex1%-%Hex10%} /f>nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\Configuration\Variables\DeviceDesc" /v PropertyGuid /t REG_SZ /d {%Hex8%-%Hex1%-%Hex0%-%Hex1%-%Hex10%} /f>nul 2>&1
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\Configuration\Variables\Driver" /v PropertyGuid /t REG_SZ /d {%Hex8%-%Hex1%-%Hex0%-%Hex1%-%Hex10%} /f>nul 2>&1W
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemInformation" /v ComputerHardwareId /t REG_SZ /d {%Hex8%-%Hex1%-%Hex0%-%Hex1%-%Hex10%} /f>nul 2>&1
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v InstallDate /t REG_SZ /d %random% /f
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductId /t REG_SZ /d %random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Cryptography /v GUID /t REG_SZ /d %Hex1%-%Hex8%-%Hex1%-%Hex0%-%Hex10% /f
REG ADD HKLM\SOFTWARE\Microsoft\Cryptography /v GUID /t REG_SZ /d %random%-%random%-%random%-%random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid /t REG_SZ /d %random%-%random%-%random%-%random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v BuildGUID /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v InstallDate /t REG_SZ /d %random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v ProductId /t REG_SZ /d %random%-%random%-%random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOrganization /t REG_SZ /d FS%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOrganization /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOwner /t REG_SZ /d FS%random% /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows" "NT\CurrentVersion /v RegisteredOwner /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName /v ComputerName /t REG_SZ /d %random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName /v ComputerName /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName /v ComputerName /t REG_SZ /d %random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName /v ComputerName /t REG_SZ /d %random%-%random% /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware" "Profiles\0001 /v GUID /t REG_SZ /d {%random%-%random%-%random%-%random%-%random%} /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware" "Profiles\0001 /v HwProfileGuid /t REG_SZ /d {%random%-%random%-%random%-%random%-%random%} /f
REG ADD HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation /v ComputerHardwareId /t REG_SZ /d {%random%-s%random%-%random%-%random%-%random%} /f
REG ADD HKLM\SYSTEM\HardwareConfig /v LastConfig /t REG_SZ /d {eac%random%} /f
REG ADD HKLM\SYSTEM\HardwareConfig /v LastConfig /t REG_SZ /d {fefefee%random%-%random%-%random%-%random%} /f
REG ADD HKLM\Software\Microsoft\Windows NT\CurrentVersion /v InstallDate /t REG_SZ /d %random% /f
REG ADD HKLM\Software\Microsoft\Windows NT\CurrentVersion /v ProductId /t REG_SZ /d %random% /f
REG ADD HKLM\System\CurrentControlSet\Control\SystemInformation /v ComputerHardwareId /t REG_SZ /d %random% /f
REG ADD HKLM\System\CurrentControlSet\Control\WMI\Security /v 671a8285-4edb-4cae-99fe-69a15c48c0bc /t REG_SZ /d %random% /f


REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion" "WindowsUpdate /v SusClientId /t REG_SZ /d {%random%-%random%-%random%-%random%-%random%} /f
                                                                                                                                                  
                                                                                                                                                                                           

echo.
echo.
echo                                                        Press any key to continue...     
pause >nul
cls
goto :menu



:ZERO INPUT DELAY
bcdedit /set useplatformclock no 
bcdedit /set useplatformtick yes
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f
reg dd "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /v "EnableEventTranscript" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f
PowerShell -Command "Get-AppxPackage *print3d* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *3dviewer* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *zune* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *bing* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *skype* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *solitaire* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *candycrush* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *onenote* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *dolby* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *fitbit* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *feedback* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *yourphone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *ConnectivityStore* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *windowscamera* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *officehub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *getstarted* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *soundrecorder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *xboxapp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxGamingOverlay* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxGameOverlay* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.WebpImageExtension* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.WebMediaExtensions* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.MixedReality.Portal* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.HEIFImageExtension* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxIdentityProvider* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *paint* | Remove-AppxPackage"
fsutil behavior query memoryusage
cls
call :colortext FC "Remove" && echo  3D Builder?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.3DBuilder* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  3D Print?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Print3D* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  3D Viewer?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Alarms App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Bing News?
set /p con=
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Calculator App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsCalculator* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Camera App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsCamera* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Cortana (App only)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.549981C3F5F10* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Feedback Hub?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Get Help?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage" && cls  
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Get Started?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Maps App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsMaps* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Messaging?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Advertising Client?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Advertising.Xaml* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Edge?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftEdge.Stable* | Remove-AppxPackage" && cd %PROGRAMFILES(X86)%\Microsoft\Edge\Application\8*\Installer && setup --uninstall --force-uninstall --system-level && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Office (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage" > nul && PowerShell -Command "Get-AppxPackage *Microsoft.Office.Sway* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.Office.Desktop* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Mail and Calendar?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *microsoft.windowscommunicationsapps* | Remove-AppxPackage"  && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Mixed Reality Portal?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.MixedReality.Portal* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Pay?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Wallet* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft People?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.People* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft OneNote?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Office.OneNote* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Snip and Sketch?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.ScreenSketch* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Solitare Collection?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Sticky Notes App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Store?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsStore* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Store Purchase (breaks MS Store)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.StorePurchaseApp* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Microsoft Zune Video and Music Apps?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.ZuneMusic* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Photos App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.Windows.Photos* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Remote Desktop?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.RemoteDesktop* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Sound Recording App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Weather App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Xbox App?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.XboxApp* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Xbox Extras?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage -AllUsers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.XboxGameOverlay* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.XboxIdentityProvider* | Remove-AppxPackage" && PowerShell -Command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage" && reg delete "HKEY_CURRENT_USER\System\GameConfigStore\Parents" /f >nul && reg delete "HKEY_CURRENT_USER\System\GameConfigStore\Children" /f >nul && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Your Phone?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext F6 "Preinstalled" && echo  Bloatware
timeout 3 >nul
cls && cls
call :colortext FC "Remove" && echo  Adobe Photoshop Express (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *AdobeSystemsIncorporated.AdobePhotoshopExpress* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Remove Candy Crush (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *CandyCrush* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Remove Duolingo (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Duolingo-LearnLanguagesforFree* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Remove Facebook (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Facebook* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Remove Flipboard (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Flipboard* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Intel Graphics Control Panel (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *AppUp.IntelGraphicsControlPanel* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  LinkedIn (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *7EE7776C.LinkedInforWindows* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Uninstall" && echo  Microsoft OneDrive?
set /p con= 
if /i "%con%" == "yes" cls && %SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall >nul && %SystemRoot%\System32\OneDriveSetup.exe /uninstall >nul && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Mirkat (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Mirkat.Mirkat* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  MS Paint (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.MSPaint* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Network Speed Test (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.NetworkSpeedTest* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Spotify (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Spotify* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Realtek Audio Console (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *RealtekSemiconductorCorp.RealtekAudioControl* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Skype (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage" && cls 
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext FC "Remove" && echo  Twitter (MS Store version)?
set /p con= 
if /i "%con%" == "yes" cls && PowerShell -Command "Get-AppxPackage *Twitter* | Remove-AppxPackage" && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext F4 "Advanced" && echo  Debloating (not recommended)
timeout 2 >nul
echo Are you sure you want to continue?
set /p con=
if /i "%con%" == "yes" goto advanced
if /i "%con%" == "no" goto exit

:advanced
cls && cls
call :colortext F4 "PERMANENTLY REMOVE" && echo  All Startup entries?
set /p con= 
if /i "%con%" == "yes" cls && reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /va /f >nul && reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /va /f >nul && reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /va /f >nul && reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /va /f >nul && cls
if /i "%con%" == "no" ^ && cls

cls && cls
call :colortext F4 "PERMANENTLY REMOVE" && echo  OEM AppX Packages?
set /p con= 
if /i "%con%" == "yes" cls && cd C:\ProgramData >nul && takeown /f "Packages" >nul && takeown /f "Packages\*" >nul && rd /s /q "Packages" >nul && cls
if /i "%con%" == "no" ^ && cls
taskkill -F -FI "IMAGENAME eq SystemSettings.exe"
net stop wuauserv
net stop UsoSvc
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f
gpupdate /force
echo Deleting Windows Update Files
rd s q "C:\Windows\SoftwareDistribution"
md "C:\Windows\SoftwareDistribution"
net start wuauserv
net start UsoSvc
echo Disable Dynamic Tick
echo Disable High Precision Event Timer (HPET)
echo Disable Synthetic Timers
@echo
bcdedit /set disabledynamictick yes
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformtick yes
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "DisableInactivate" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "EnableDebugging" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "EnableMultimonDebugging" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "FullDebug" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Direct3D" /v "LoadDebugRuntime" /t REG_DWORD /d 0 /f
net stop audiosrv
net stop AudioEndpointBuilder
TASKKILL /F /IM audiodg.exe 2> NUL

for /f "delims=" %%a in ('REG QUERY "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render"') do (
    :: Add entries for audio effects properties
REG ADD "%%a\FxProperties" /v "{1b5c2483-0839-4523-ba87-95f89d27bd8c},3" /t REG_BINARY /d 03002E24010000000000000000 /f
REG ADD "%%a\FxProperties" /v "{73ae880e-8258-4e57-b85f-7daa6b7d5ef0},3" /t REG_BINARY /d 03002E24010000010000000000 /f
REG ADD "%%a\FxProperties" /v "{1da5d803-d492-4edd-8c23-e0c0ffee7f0e},5" /t REG_DWORD /d 1 /f
REG ADD "%%a\FxProperties" /v "{1864a4e0-efc1-45e6-a675-5786cbf3b9f0},4" /t REG_BINARY /d 03002E24010000000000000000 /f
REG ADD "%%a\FxProperties" /v "{61e8acb9-f04f-4f40-a65f-8f49fab3ba10},4" /t REG_BINARY /d 03002E24010000500000000000 /f
REG ADD "%%a\FxProperties" /v "{fc52a749-4be9-4510-896e-966ba6525980},3" /t REG_BINARY /d 0B00803F010000000000000000 /f
REG ADD "%%a\FxProperties" /v "{9c00eeed-edce-4cd8-ae08-cb05e8ef57a0},3" /t REG_BINARY /d 0300803F0100000004000000 /f
REG ADD "%%a\Properties" /v "{e4870e26-3cc5-4cd2-ba46-ca0a9a70ed04},1" /t REG_BINARY /d 41005E8101000000A0860100000000000000 /f
REG ADD "%%a\Properties" /v "{3d6e1656-2e50-4c4c-8d85-d0acae3c6c68},3" /t REG_BINARY /d 4100020001000000FEFF020080BB000000DC05000800200016002000030000000300000000000010080000AA00389B71 /f
REG ADD "%%a\Properties" /v "{e4870e26-3cc5-4cd2-ba46-ca0a9a70ed04},0" /t REG_BINARY /d 4100020001000000FEFF020080BB000000DC05000800200016002000030000000300000000000010080000AA00389B71 /f
REG ADD "%%a\Properties" /v "{3d6e1656-2e50-4c4c-8d85-d0acae3c6c68},2" /t REG_BINARY /d 4100D42C01000000FEFF020044AC000020620500080020001600200003000000030000000000001000800000AA00389B71 /f
REG ADD "%%a\Properties" /v "{e4870e26-3cc5-4cd2-ba46-ca0a9a70ed04},0" /t REG_BINARY /d 4100020001000000FEFF020044AC000020620500080020001600200003000000030000000000001000800000AA00389B71 /f
REG ADD "%%a\Properties" /v "{624f56de-fd24-473e-814a-de40aacaed16},3" /t REG_BINARY /d 4100630001000000FEFF020044AC000020620500080020001600200003000000030000000000001000800000AA00389B71 /f

reg delete "%%a\Properties" /v  "{624f56de-fd24-473e-814a-de40aacaed16},3" /f
reg delete "%%a\Properties" /v  "{3d6e1656-2e50-4c4c-8d85-d0acae3c6c68},2" /f

)

net start audiosrv
net start AudioEndpointBuilder
start audiodg.exe
takeown /f %SystemRoot%\System32\drivers\Acpidev.sys
takeown /f %SystemRoot%\System32\drivers\Acpipagr.sys
takeown /f %SystemRoot%\System32\drivers\Acpitime.sys
takeown /f %SystemRoot%\System32\drivers\Acpipmi.sys
icacls %SystemRoot%\System32\drivers\Acpidev.sys /grant %username%:F
icacls %SystemRoot%\System32\drivers\Acpipagr.sys /grant %username%:F
icacls %SystemRoot%\System32\drivers\Acpitime.sys /grant %username%:F
icacls %SystemRoot%\System32\drivers\Acpipmi.sys /grant %username%:F
ren %SystemRoot%\System32\drivers\Acpidev.sys AcpidevBACKUP.sys
ren %SystemRoot%\System32\drivers\Acpipagr.sys AcpipagrBACKUP.sys
ren %SystemRoot%\System32\drivers\Acpitime.sys AcpitimeBACKUP.sys
ren %SystemRoot%\System32\drivers\Acpipmi.sys AcpipmiBACKUP.sys
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{DEB039CC-B704-4F53-B43E-9DD4432FA2E9}\0000" /v "PerfLevelSrc" /t REG_DWORD /d 13154 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{DEB039CC-B704-4F53-B43E-9DD4432FA2E9}\0000" /v "PowerMizerEnable" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{DEB039CC-B704-4F53-B43E-9DD4432FA2E9}\0000" /v "PowermizerLevel" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Video\{DEB039CC-B704-4F53-B43E-9DD4432FA2E9}\0000" /v "PowermizerLevelAC" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "AllowRemoteDASD" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PassiveIntRealTimeWorkerPriority" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "countoperations" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PowerSavingTweaks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnableRuntimePowerManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PrimaryPushBufferSize" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "FlTransitionLatency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "D3PCLatency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMDeepLlEntryLatencyUsec" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PciLatencyTimerControl" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LOWLATENCY" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnablePreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "TdrLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "UseGpuTimer" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PlatformSupportMiracast" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "HwSchMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CpuPriorityContol" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CpuThreadCount" /t REG_DWORD /d "12" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CpuThreadSeperation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CpuPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "IOPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CpuPrioritySeperation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMHdcpKeyGlobZero" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PowerLimitEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "Throttle Rate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "Clock Rate" /t REG_DWORD /d "5000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "GPU Priority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "GpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CpuPriorityClass" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "IOPriorityClass" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "GpuSpeed" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /ve /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CpuCoresAlways" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CpuUtilization" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LatencyPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "GpuPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RenderingSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RenderingPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LatencySpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RenderingPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LatencyPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CpuSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "GpuRenderingPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "SpreadPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "GpuMax" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MinPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PerformancePriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PerformanceSpread" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "GpuMaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CpuMaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "GpuAccelerating" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CpuThreadPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RmDistRenderMax" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMEnableHdmi2" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMEnableOveclockingAllPstates" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DisableOverclockedPstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMForceLockedClocksMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMEnableClk" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnablePerformanceMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMMaximizePteTableSize" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "UseUncachedPCIMappings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMEnableVmm" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMGpuCacheEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DisableAsyncPstates" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnableForceIgpuDgpuFromUI" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnableCoreVoltage" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMNoECCFuseCheck" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnableComputeReset" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMOverrideP0Gpc2ClkMaxFreqKHz" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnableDx12OnMsHybrid" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnableDx12OnOptimus" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnableHybridPerfSLI" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMGsyncTswapRdyHi" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LimitSegmentsTo4GB" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "Disable4GBTAGLimit" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnableComputeAsync" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnableMClkSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RMClkSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DisableKmRenderBoost" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DisableKmRenderStage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DisableKmRender" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2ReserveVASpaceSizeForNvFBC" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2InvalidatePDEsForReserveVA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2EnableSLI" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2DisableRenderGDI" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2ForceInvalidateAllCpuCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2Use64KBPages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2EnableGdiBroadcast" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2EnableSLILinkMirroredWAR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2OSDualPteSupported" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2DisableSlowCePagingWar" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2ReplaceKindAtTransferVirtual" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2DisableBasicPrimeForGPUVA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2DisableSLIVirtualChannels" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2EnableFermiWDDMv2" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2ForceEngineResetForPageFault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "WDDMv2KmdHighAddrReserve" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CustomizeDuringSetup" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "HiberFileSizePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MfBufferingThreshold" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "TimerRebaseThresholdOnDripsExit" /t REG_DWORD /d "60" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnergyEstimationDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "ExitLatency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LatencyToleranceDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LatencyToleranceFSVP" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LowLatencyScalingPercentage" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LatencyToleranceIdleResiliency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PowerActionResumingWatchdogTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PowerActionTransitioningWatchdogTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "SourceSettingsVersion" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DirectedDripsOverride" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "BootHeteroPolicyOverride" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MfOverridesDisabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System\Global\NVTweak" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System\NVAPI" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "AllowRemoteDASD" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "countoperations" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DisableBufferedIoInit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LargeIrpStackLocations" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MediumIrpStackLocations" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "IoEnableSessionZeroAccessCheck" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PassiveIntRealTimeWorkerPriority" /t REG_DWORD /d "18" /f
echo Disabling IO Latency Cap:
FOR /F "eol=E" %%a in ('REG QUERY "HKLM\System\CurrentControlSet\Services" /S /F "IoLatencyCap"^| FINDSTR /V "IoLatencyCap"') DO (
Reg.exe add "%%a" /v "IoLatencyCap" /t REG_DWORD /d "0" /f
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\System\CurrentControlSet\services\=!
SET STR=!STR:\Parameters=!
)
)


timeout /t 1 /nobreak > nul
FOR /F "eol=E" %%x in ('REG QUERY "HKLM\SYSTEM\DriverDatabase\DriverPackages" /S /F "IoLatencyCap"^| FINDSTR /V "IoLatencyCap"') DO (
Reg.exe add "%%x" /v "IoLatencyCap" /t REG_DWORD /d "0" /f > nul
FOR /F "tokens=*" %%z IN ("%%a") DO (
SET STR=%%z
SET STR=!STR:HKLM\SYSTEM\DriverDatabase\DriverPackages\=!
SET STR=!STR:\Configurations\msahci_Inst\Services\storahci\Parameters=!
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "DisableAGPSupport" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "UseNonLocalVidMem" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "DisableDDSCAPSInDDSD" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulatePointSprites" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\DirectDraw" /v "EmulateStateBlocks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "DisableAGPSupport" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "UseNonLocalVidMem" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "DisableDDSCAPSInDDSD" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "EmulatePointSprites" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\DirectDraw" /v "EmulateStateBlocks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v EnableRID73779  /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v EnableRID73780  /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v EnableRID74361  /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID44231  /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID64640  /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID66610  /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TCCSupported" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\NVIDIA Corporation\Global\NVTweak\Devices\509901423-0\Color" /v "NvCplUseColorCorrection" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Audiosrv" /v "ErrorControl" /t REG_DWORD /d "2" /f
 Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "2710" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Latency Sensitive" /t REG_SZ /d "True" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\AudioEndpointBuilder" /v "Start" /t REG_DWORD /d "2" /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Audiosrv" /v "Start" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Latency Sensitive" /t REG_SZ /d "True" /f
set "WHITELIST=ACPI AcpiDev AcpiPmi AFD AMDPCIDev amdgpio2 amdgpio3 AmdPPM amdpsp amdsata amdsbs amdxata asmtxhci atikmdag BasicDisplay BasicRender dc1-controll Disk DXGKrnl e1iexpress e1rexpress genericusbfn hwpolicy IntcAzAudAdd kbdclass kbdhid MMCSS monitor mouclass mouhid mountmgr mt7612US MTConfig NDIS nvdimm nvlddmkm pci PktMon Psched rt640x64 RTCore64 RzCommon RzDev_0244 Tcpip usbehci usbhub USBHUB3 USBXHCI Wdf01000 xboxgip xinputhid"

set "DRIVERLIST="

for %%i in (%WHITELIST%) do (
    echo Checking for %%i...
    for /f "tokens=*" %%j in ('driverquery ^| findstr /i "%%i"') do (
        echo Found: %%j
        set "DRIVERLIST=!DRIVERLIST!%%j\0"
    )
)

echo Adding to registry...
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Memory Management" /v "LargePageDrivers" /t REG_MULTI_SZ /d "!DRIVERLIST:~0,-1!" /f /reg:32
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DebugPollInterval" /t REG_DWORD /d 1000 /f

echo Setting CopyBufferSize...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "CopyBufferSize" /t REG_DWORD /d 1048576 /f

echo Setting CopyFileBufferedSynchronousIo...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "CopyFileBufferedSynchronousIo" /t REG_DWORD /d 64 /f

echo Setting CopyFileChunkSize...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "CopyFileChunkSize" /t REG_DWORD /d 32768 /f

echo Setting CopyFileOverlappedCount...
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v "CopyFileOverlappedCount" /t REG_DWORD /d 32 /f
Reg.exe add "HKLM\System\ControlSet001\Services\umbus\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\USBHUB3\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\USBXHCI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\xinputhid\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\acpipagr\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\dc1-controller\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\intelpep\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\intelppm\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\kbdclass\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\kbdhid\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\mouhid\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\NdisVirtualBus\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\NdisWan\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\NvModuleTracker\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\partmgr\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f

REM Disable MemoryPressureProtection
PowerShell -Command "Set-NetTCPSetting -SettingName '*' -MemoryPressureProtection Disabled" >nul 2>&1

REM Get CPU information
for /f "tokens=2 delims=: " %%a in ('wmic cpu get name /value') do (
    set "CPU=%%a"
    goto :checkCPU
)
:checkCPU

REM Check CPU and set registry value accordingly
if "%CPU%"=="AMD" (
    Reg Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "2" /f 
) else (
    Reg Add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f 
)
PowerShell -Command "Set-NetTCPSetting -SettingName '*' -MemoryPressureProtection Disabled" >nul 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d 1 /f
powershell Disable-MMAgent -MemoryCompression -PageCombining
powershell Enable-MMAgent -ApplicationPreLaunch
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v PoolUsageMaximum /t REG_DWORD /d 60 /f
PowerShell -Command "Disable-MMAgent -PageCombining"

REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePageCombining /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingCombining /t REG_DWORD /d 1 /f
rem Adding registry keys for kernel settings
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "DebugPollInterval" /t REG_DWORD /d 1000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "MaxDynamicTickDuration" /t REG_DWORD /d 1000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "SerializeTimerExpiration" /t REG_DWORD /d 1 /f

rem Adding registry keys for explorer.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe" /v "UseLargePages" /t REG_DWORD /d 1 /f

rem Adding registry keys for chrome.exe
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe" /v "UseLargePages" /t REG_DWORD /d 1 /f

rem Adding registry keys for NlaSvc parameters
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "EnableNoGatewayLocationDetection" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "CorpLocationProbeTimeout" /t REG_DWORD /d 30 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "PassedPolicy" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v "DisableBranchCache" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v "TcpAutotuning" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\Tracing" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v "DisabledByDefault" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v "DisabledByDefault" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeGuaranteed" /t REG_DWORD /d 46 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeNetworkControl" /t REG_DWORD /d 56 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeGuaranteed" /t REG_DWORD /d 46 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeNetworkControl" /t REG_DWORD /d 56 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeGuaranteed" /t REG_DWORD /d 5 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeNetworkControl" /t REG_DWORD /d 7 /f
netsh int tcp set global autotuninglevel=normal
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNS\Parameters" /v "MaximumUdpPacketSize" /t REG_DWORD /d "1221" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNS\Parameters" /v "MaximumUdpPacketSize" /t REG_DWORD /d "1298" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNS\Parameters" /v "MaximumUdpPacketSize" /t REG_DWORD /d "1398" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "384" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "384" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "900" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "DynamicBacklogGrowthDelta" /t REG_DWORD /d "256" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableDynamicBacklog" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "extension" /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\dnsext.dll" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_SZ /d "Ԁ䲮" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "10800" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "64000" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "64000" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "409600" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "10800" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheTtl" /t REG_DWORD /d "14400" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "MaximumDynamicBacklog" /t REG_DWORD /d "131072" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "MaximumUdpPacketSize" /t REG_DWORD /d "4864" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "MaximumUdpPacketSize" /t REG_DWORD /d "4864" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "301" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "301" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "769" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "MinimumDynamicBacklog" /t REG_DWORD /d "512" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "MouseSensitivity" /t REG_SZ /d "10" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "ServerPriorityTimeLimit" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\dnsrslvr.dll" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\DNScache\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters" /v "TcpNoDelay" /t REG_DWORD /d "151807" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters\Probe\{25aa16d5-73d9-4cd8-91ff-0683b3bcd05a}" /v "LastProbeTime" /t REG_DWORD /d "1500872657" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters\Probe\{25aa16d5-73d9-4cd8-91ff-0683b3bcd05a}" /v "NetworkPerformsHijacking" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters\Probe\{e97ca175-e5e7-4580-895e-91be966166ba}" /v "LastProbeTime" /t REG_DWORD /d "1500872066" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Dnscache\Parameters\Probe\{e97ca175-e5e7-4580-895e-91be966166ba}" /v "NetworkPerformsHijacking" /t REG_DWORD /d "0" /f

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d 384 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d 64000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d 301 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d 0 /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "DisableSmartNameResolution" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "DisableSmartProtocolReordering" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableIdnMapping" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "PreferLocalOverLowerBindingDNS" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "RegistrationEnabled" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "UpdateSecurityLevel" /t REG_DWORD /d "0" /f
netsh int tcp set heuristics wsh=enabled forcews=enabled
netsh int tcp set heuristics disabled
for /f %%a in ('Reg query HKLM /v "*WakeOnMagicPacket" /s ^| findstr  "HKEY"') do (
for /f %%i in ('Reg query "%%a" /v "*EEE" ^| findstr "HKEY"') do (Reg add "%%i" /v "*EEE" /t Reg_DWORD /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "*FlowControl" ^| findstr "HKEY"') do (Reg add "%%i" /v "*FlowControl" /t Reg_DWORD /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "EnableSavePowerNow" ^| findstr "HKEY"') do (Reg add "%%i" /v "EnableSavePowerNow" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "EnablePowerManagement" ^| findstr "HKEY"') do (Reg add "%%i" /v "EnablePowerManagement" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "EnableDynamicPowerGating" ^| findstr "HKEY"') do (Reg add "%%i" /v "EnableDynamicPowerGating" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "EnableConnectedPowerGating" ^| findstr "HKEY"') do (Reg add "%%i" /v "EnableConnectedPowerGating" /t Reg_SZ /d "0" /f)
for /f %%i in ('Reg query "%%a" /v "AutoPowerSaveModeEnabled" ^| findstr "HKEY"') do (Reg add "%%i" /v "AutoPowerSaveModeEnabled" /t Reg_SZ /d "0" /f)
)
for /f %%r in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /f "1" /d /s^|Findstr HKEY_') do (
Reg add %%r /v "NonBestEffortLimit" /t Reg_DWORD /d "0" /f 
Reg add %%r /v "DeadGWDetectDefault" /t Reg_DWORD /d "1" /f 
Reg add %%r /v "PerformRouterDiscovery" /t Reg_DWORD /d "1" /f
Reg add %%r /v "TCPNoDelay" /t Reg_DWORD /d "1" /f
Reg add %%r /v "TcpAckFrequency" /t Reg_DWORD /d "1" /f
Reg add %%r /v "TcpInitialRTT" /t Reg_DWORD /d "2" /f
Reg add %%r /v "TcpDelAckTicks" /t Reg_DWORD /d "0" /f
Reg add %%r /v "MTU" /t Reg_DWORD /d "1500" /f
Reg add %%r /v "UseZeroBroadcast" /t Reg_DWORD /d "0" /f
)
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
 Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AdjustedNullSessionPipes" /t REG_DWORD /d "3" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "AdjustedNullSessionPipes" /t REG_DWORD /d "3" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "15" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "15" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareServer" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DeadGWDetectDefault" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DefaultRCVWindow" /t REG_DWORD /d "94258" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DefaultTTL" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "DisableCompression" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableStrictNameChecking" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DiskSpaceThreshold" /t REG_DWORD /d "5" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DnsPriority" /t REG_DWORD /d "1469" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DontAddDefaultGatewayDefault" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableAuthenticateUserSharing" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableAuthenticateUserSharing" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableDCA" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableForcedLogoff" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "enableforcedlogoff" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "enablesecuritysignature" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableTCPA" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "65535" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "95520" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "GlobalMaxTcpWindowSize" /t REG_DWORD /d "415029" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "Guid" /t REG_BINARY /d "6c235f05c156de48a3b844ebc7bdf782" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "Guid" /t REG_BINARY /d "46790396679b6e45b95f8817359b9e2a" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "Hidden" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "HostsPriority" /t REG_DWORD /d "572" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "IPEnableRouter" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "80" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "1000" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "KeepAliveTime" /t REG_DWORD /d "7200000" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "Lmannounce" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "LocalPriority" /t REG_DWORD /d "91" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxCmds" /t REG_DWORD /d "30" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxCmds" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxCmds" /t REG_DWORD /d "2048" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "6" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "22" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "4095" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "6" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "22" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "4095" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "415030" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxHashTableSize" /t REG_DWORD /d "4096" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "125" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "125" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "2048" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxThreads" /t REG_DWORD /d "30" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxThreads" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxUserPort" /t REG_DWORD /d "415028" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxWorkItems" /t REG_DWORD /d "8192" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "NetbtPriority" /t REG_DWORD /d "45" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "NullSessionPipes" /t REG_MULTI_SZ /d "" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "NullSessionPipes" /t REG_MULTI_SZ /d "" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "Path" /t REG_SZ /d "C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\FortniteClient-Win64-Shipping.exe" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "QualifyingDestinationThreshold" /t REG_DWORD /d "3" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "requiresecuritysignature" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "restrictnullsessaccess" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "restrictnullsessaccess" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\srvsvc.dll" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\srvsvc.dll" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17238" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "25344" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "65535" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\lanmanserver\parameters" /v "SizReqBuf" /t REG_DWORD /d "65535" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "95268" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "srvcomment" /t REG_SZ /d "" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "18" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "TCPDelAckTicks" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "TCPMaxDataRetransmissions" /t REG_DWORD /d "7" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "TcpNoDelay" /t REG_DWORD /d "64" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "TcpWindowSize" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "Version" /t REG_SZ /d "1.9.4" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\FsctlAllowlist" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DefaultReceiveWindow" /t REG_DWORD /d "1053256" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DefaultSendWindow" /t REG_DWORD /d "7878468" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DirectoryCacheEntriesMax" /t REG_DWORD /d "22" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMTU" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "DisableLargeMtu" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnablePlainTextPassword" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "FileInfoCacheEntriesMax" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "FileNotFoundCacheEntriesMax" /t REG_DWORD /d "296" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "KeepConn" /t REG_DWORD /d "86400" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "KeepConn" /t REG_DWORD /d "86400" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "30" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\lanmanworkstation\parameters" /v "MaxCmds" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "2048" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCollectionCount" /t REG_DWORD /d "32" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "MaxCollectionCount" /t REG_DWORD /d "32" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxThreads" /t REG_DWORD /d "30" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxThreads" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\lanmanworkstation\parameters" /v "MaxThreads" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "MaxThreads" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\LanmanWorkstation\Parameters" /v "ReconnectTimeout" /t REG_DWORD /d "5" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "ServiceDll" /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\wkssvc.dll" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "ServiceDllUnloadOnStop" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "UseLockReadUnlock" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "UtilizeNtCaching" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT" /v "Start" /t REG_DWORD /d "4" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "BcastNameQueryCount" /t REG_DWORD /d "3" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "BcastQueryTimeout" /t REG_DWORD /d "750" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "CacheTimeout" /t REG_DWORD /d "600000" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "EnableDns" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "EnableLMHOSTS" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "EnableLMHOSTS" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "EnableProxyRegCheck" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "NameServerPort" /t REG_DWORD /d "137" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "NameSrvQueryCount" /t REG_DWORD /d "3" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "NameSrvQueryTimeout" /t REG_DWORD /d "1500" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "NbProvider" /t REG_SZ /d "_tcp" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\Netbt\Parameters" /v "NoNameReleaseOnDemand" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "SessionKeepAlive" /t REG_DWORD /d "3600000" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "Size/Small/Medium/Large" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\NetBT\Parameters" /v "Size/Small/Medium/Large" /t REG_DWORD /d "3" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "TransportBindName" /t REG_SZ /d "\Device\\" /f
    Reg.exe add "HKLM\System\CurrentControlSet\services\NetBT\Parameters" /v "UseNewSmb" /t REG_DWORD /d "1" /f
for /f %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces" /s /f "NetbiosOptions"^| findstr "HKEY"') do Reg.exe add "%%i" /v "NetbiosOptions" /t REG_DWORD /d "2" /f
for /f %%k in ('reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces') do (
reg add %%k /v NetbiosOptions /t reg_dword /d 2 /f
) >nul


:: EXTRAS (just in case)

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Set Network Autotuning to Disabled
echo Setting Network AutoTuning to Disabled
netsh int tcp set global autotuninglevel=disabled
timeout /t 1 /nobreak > NUL

:: Disable ECN
echo Disabling Explicit Congestion Notification
netsh int tcp set global ecncapability=disabled
timeout /t 1 /nobreak > NUL

:: Enable DCA
echo Enabling Direct Cache Access
netsh int tcp set global dca=enabled
timeout /t 1 /nobreak > NUL

:: Enable NetDMA
echo Enabling Network Direct Memory Access
netsh int tcp set global netdma=enabled
timeout /t 1 /nobreak > NUL

:: Disable RSC
echo Disabling Recieve Side Coalescing
netsh int tcp set global rsc=disabled
timeout /t 1 /nobreak > NUL

:: Enable RSS
echo Enabling Recieve Side Scaling
netsh int tcp set global rss=enabled
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Ndis\Parameters" /v "RssBaseCpu" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable TCP Timestamps
echo Disabling TCP Timestamps
netsh int tcp set global timestamps=disabled
timeout /t 1 /nobreak > NUL

:: Set Initial RTO to 2ms
echo Setting Initial Retransmission Timer
netsh int tcp set global initialRto=2000
timeout /t 1 /nobreak > NUL

:: Set MTU Size to 1500
echo Setting MTU Size
netsh interface ipv4 set subinterface “Ethernet” mtu=1500 store=persistent
timeout /t 1 /nobreak > NUL

:: Disable NonSackRTTresiliency
echo Disabling Non Sack RTT Resiliency
netsh int tcp set global nonsackrttresiliency=disabled
timeout /t 1 /nobreak > NUL

:: Set Max Syn Retransmissions to 2
echo Setting Max Syn Retransmissions
netsh int tcp set global maxsynretransmissions=2
timeout /t 1 /nobreak > NUL

:: Disable MPP
echo Disabling Memory Pressure Protection
netsh int tcp set security mpp=disabled
timeout /t 1 /nobreak > NUL

:: Disable Security Profiles
echo Disabling Security Profiles
netsh int tcp set security profiles=disabled
timeout /t 1 /nobreak > NUL

:: Disable Heuristics
echo Disabling Windows Scaling Heuristics
netsh int tcp set heuristics disabled
timeout /t 1 /nobreak > NUL

:: Increase ARP Cache Size to 4096
echo Increasing ARP Cache Size
netsh int ip set global neighborcachelimit=4096
timeout /t 1 /nobreak > NUL

:: Enable CTCP
echo Enabling CTCP
netsh int tcp set supplemental Internet congestionprovider=ctcp
timeout /t 1 /nobreak > NUL

:: Disable Task Offloading
echo Disabling Task Offloading
netsh int ip set global taskoffload=disabled
timeout /t 1 /nobreak > NUL

:: Disable IPv6
echo Disabling IPv6
netsh int ipv6 set state disabled
timeout /t 1 /nobreak > NUL

:: Disable ISATAP
echo Disabling ISATAP
netsh int isatap set state disabled
timeout /t 1 /nobreak > NUL

:: Disable Teredo
echo Disabling Teredo
netsh int teredo set state disabled
timeout /t 1 /nobreak > NUL

:: Set TTL to 64
echo Configuring Time to Live
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Enable TCP Window Scaling
echo Enabling TCP Window Scaling
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Set TcpMaxDupAcks
echo Setting TcpMaxDupAcks to 2
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "2" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable SackOpts
echo Disabling TCP Selective ACKs
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Increase Maximum Port Number
echo Increasing Maximum Port Number
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Decrease Time to Wait in "TIME_WAIT" State
echo Decreasing Timed Wait Delay
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Set Network Priorities
echo Setting Network Priorities
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Adjust Sock Address Size
echo Configuring Sock Address Size
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Nagle's Algorithm
echo Disabling Nagle's Algorithm
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TCPNoDelay" /t REG_DWORD /d "1" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Delivery Optimization
echo Disabling Delivery Optimization
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Auto Disconnect for Idle Connections
echo Disabling Auto Disconnect
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Limit Number of SMB Sessions
echo Limiting SMB Sessions
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Oplocks
echo Disabling Oplocks
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Set IRP Stack Size
echo Setting IRP Stack Size
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "20" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Sharing Violations
echo Disabling Sharing Violations
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f >> APB_Log.txt
reg add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Get the Sub ID of the Network Adapter
for /f %%n in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}" /v "*SpeedDuplex" /s ^| findstr  "HKEY"') do (

:: Disable NIC Power Savings
echo Disabling NIC Power Savings
reg add "%%n" /v "AutoPowerSaveModeEnabled" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "AutoDisableGigabit" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "AdvancedEEE" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "DisableDelayedPowerUp" /t REG_SZ /d "2" /f >> APB_Log.txt
reg add "%%n" /v "*EEE" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EEE" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnablePME" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EEELinkAdvertisement" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnableSavePowerNow" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnablePowerManagement" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnableDynamicPowerGating" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnableConnectedPowerGating" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "EnableWakeOnLan" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "GigaLite" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "NicAutoPowerSaver" /t REG_SZ /d "2" /f >> APB_Log.txt
reg add "%%n" /v "PowerDownPll" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "PowerSavingMode" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "ReduceSpeedOnPowerDown" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "SmartPowerDownEnable" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "S5NicKeepOverrideMacAddrV2" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "S5WakeOnLan" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "ULPMode" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "WakeOnDisconnect" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "*WakeOnMagicPacket" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "*WakeOnPattern" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "WakeOnLink" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "WolShutdownLinkSpeed" /t REG_SZ /d "2" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Jumbo Frame
echo Disabling Jumbo Frame
reg add "%%n" /v "JumboPacket" /t REG_SZ /d "1514" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Configure Receive/Transmit Buffers
echo Configuring Buffer Sizes
reg add "%%n" /v "TransmitBuffers" /t REG_SZ /d "4096" /f >> APB_Log.txt
reg add "%%n" /v "ReceiveBuffers" /t REG_SZ /d "512" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Configure Offloads
echo Configuring Offloads
reg add "%%n" /v "IPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "LsoV1IPv4" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "LsoV2IPv4" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "LsoV2IPv6" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "PMARPOffload" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "PMNSOffload" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "TCPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "TCPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "UDPChecksumOffloadIPv6" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "UDPChecksumOffloadIPv4" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Enable RSS in NIC
echo Enabling RSS in NIC
reg add "%%n" /v "RSS" /t REG_SZ /d "1" /f >> APB_Log.txt
reg add "%%n" /v "*NumRssQueues" /t REG_SZ /d "2" /f >> APB_Log.txt
reg add "%%n" /v "RSSProfile" /t REG_SZ /d "3" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Flow Control
echo Disabling Flow Control
reg add "%%n" /v "*FlowControl" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "FlowControlCap" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Remove Interrupt Delays
echo Removing Interrupt Delays
reg add "%%n" /v "TxIntDelay" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "TxAbsIntDelay" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "RxIntDelay" /t REG_SZ /d "0" /f >> APB_Log.txt
reg add "%%n" /v "RxAbsIntDelay" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Remove Adapter Notification
echo Removing Adapter Notification Sending
reg add "%%n" /v "FatChannelIntolerant" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL

:: Disable Interrupt Moderation
echo Disabling Interrupt Moderation
reg add "%%n" /v "*InterruptModeration" /t REG_SZ /d "0" /f >> APB_Log.txt
timeout /t 1 /nobreak > NUL
)

:: Enable WeakHost Send and Recieve (melodytheneko)
echo Enabling WH Send and Recieve
powershell "Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue"
for /f %%r in ('Reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" /f "1" /d /s^|Findstr HKEY_') do (
Reg add %%r /v "TCPNoDelay" /t Reg_DWORD /d "1" /f
Reg add %%r /v "TcpAckFrequency" /t Reg_DWORD /d "1" /f
Reg add %%r /v "TcpDelAckTicks" /t Reg_DWORD /d "0" /f
) >nul
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "BackgroundSyncEnabled" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "EconomicalAdminPinning" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "Enabled" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "EventLoggingLevel" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "GoOfflineAction" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "NoCacheViewer" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "NoConfigCache" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "NoMakeAvailableOffline" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "NoReminders" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "NoReminders" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "SyncAtLogoff" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "SyncAtLogon" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "SyncEnabledForCostedNetwork" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "WorkOfflineDisabled" /t REG_DWORD /d "1" /f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v HostsPriority t REG_DWORD d 2 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v HungAppTimeout t REG_SZ d 1000 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v LocalPriority t REG_DWORD d 1 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v LowLevelHooksTimeout t REG_SZ d 1000 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v NetbtPriority t REG_DWORD d 4 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v NoInternetOpenWith t REG_DWORD d 1 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v NoLowDiskSpaceChecks t REG_DWORD d 1 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v NonBestEffortLimit t REG_DWORD d 0 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v NonBestEffortLimit t REG_DWORD d 1 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v NoResolveSearch t REG_DWORD d 1 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v SynAttackProtect t REG_DWORD d 1 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v TcpCreateAndConnectTcbRateLimitDepth t REG_DWORD d 0 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v TcPMaxDataRetransmissions t REG_DWORD d 5 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v TcpNumConnections t REG_DWORD d 1280 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v TcpTimedWaitDelay t REG_DWORD d 25 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v WaitToKillAppTimeout t REG_SZ d 2000 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPsched v MaxWorkItems t REG_DWORD d 8192 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPsched v NonBestEffortLimit t REG_DWORD d 0 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v AutoEndTasks t REG_SZ d 1 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v DisableTaskOffload t REG_DWORD d 0 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v DnsPriority t REG_DWORD d 3 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v EnableConnectionRateLimiting t REG_DWORD d 0 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v EnableDCA t REG_DWORD d 1 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPshed v EnableWsd t REG_DWORD d 0 f
    Reg.exe add HKLMSoftwarePoliciesMicrosoftWindowsPsched v MaxOutstandingSends t REG_DWORD d 0 f
    Reg.exe add HKLMSoftwarePoliciesMicrosoftWindowsPsched v NonBestEffortLimit t REG_DWORD d 0 f
    Reg.exe add HKLMSoftwarePoliciesMicrosoftWindowsPsched v TimerResolution t REG_DWORD d 1 f
    Reg.exe add HKLMSystemCurrentControlSetServicesPsched v MaxCmds t REG_DWORD d 2048 f
powershell Set-NetOffloadGlobalSetting -PacketCoalescingFilter disabled
netsh interface teredo set state disable
Powershell.exe -command "& {Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip}  
@echo Disable Microsoft LLDP Protocol Driver  
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp}  
@echo Disable Link-Layer Topology Discovery Mapper I/O Driver  
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_lltdio}  
@echo Disable Microsoft Network Adapter Multiplexor Protocol  
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_implat}  
@echo Disable Link-Layer Topology Discovery Responder  
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndr}  
@echo Disable Internet Protocol Version 6  
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6}  
@echo Disable File and Printer Sharing  
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_server}  
@echo Disable Client for Microsoft Networks  
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient}  
@echo Disable QoS Packet Schedular  
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_pacer}  

echo Network Adapter: Only Allow IPv4 . . .

powershell -Command "$progresspreference = 'silentlycontinue'"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_lldp -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_lltdio -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_implat -ErrorAction SilentlyContinue"
powershell -Command "Enable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_rspndr -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_server -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_msclient -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_pacer -ErrorAction SilentlyContinue"

:: Rerun to ensure settings stick
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_lldp -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_lltdio -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_implat -ErrorAction SilentlyContinue"
powershell -Command "Enable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_rspndr -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_server -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_msclient -ErrorAction SilentlyContinue"
powershell -Command "Disable-NetAdapterBinding -Name '*' -ComponentID ms_pacer -ErrorAction SilentlyContinue"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v Tcp1323Opts /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v Tcp1323Opts /t REG_DWORD /d 0 /f
netsh int tcp set global timestamps=disabled
netsh int tcp set global rsc=disabled
powershell  Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing disabled  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Off" /f   
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Highly Restricted" /f   
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Restricted" /f   
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Normal" /f   
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request" /t REG_SZ /d "Ignored" /f   
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request" /t REG_SZ /d "Allowed" /f   
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f   
netsh int tcp set supplemental custom congestionprovider=ctcp
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "0" /f 
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "0" /f 
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f 
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
reg add "HKCU\SYSTEM\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f 
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "__COMPAT_LAYER" /f
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ForegroundAgent" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ForegroundCachedFileUpdater" /v "Importance" /t REG_SZ /d "High" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ForegroundTaskCompletion" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f >nul
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d 0 /f >nul
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "ctfmon" /t REG_SZ /d "C:\Windows\System32\ctfmon.exe" /f >nul
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\VideoSettings" /v "VideoQualityOnBattery" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 3 /f >nul
REG ADD "HKCU\Software\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d 3 /f >nul
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d 0 /f >nul
REG ADD "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f >nul
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f >nul
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d 0 /f >nul
REG ADD "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d 0 /f >nul
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f >nul
REG ADD "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d 1 /f >nul
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f >nul
REG ADD "HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f >nul
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f >nul
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f >nul
REG ADD "HKCU\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f >nul
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f >nul
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f >nul
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" /v "ValidateBlitSubRects" /t REG_DWORD /d 0 /f >nul
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d 1 /f >nul
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "AcpiFirmwareWatchDog" /t REG_DWORD /d 0 /f >nul
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "AmliWatchdogAction" /t REG_DWORD /d 0 /f >nul
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "AmliWatchdogTimeout" /t REG_DWORD /d 1 /f >nul
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "WatchdogTimeout" /t REG_DWORD /d 1 /f >nul
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Throttle" /v "PerfEnablePackageIdle" /t REG_DWORD /d 0 /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f
netsh int ip set global flowlabel=disable
    Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "100" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d 4 /f >nul
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v "Start" /t REG_DWORD /d 4 /f >nul
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t REG_DWORD /d 4 /f >nul
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineCore" /f >nul
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\MicrosoftEdgeUpdateTaskMachineUA" /f >nul
REG ADD "HKLM\SOFTWARE\Policies\Google\Chrome" /v "StartupBoostEnabled" /t REG_DWORD /d 0 /f >nul
REG ADD "HKLM\SOFTWARE\Policies\Google\Chrome" /v "BackgroundModeEnabled" /t REG_DWORD /d 0 /f >nul
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" /v "Start" /t REG_DWORD /d 4 /f >nul
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\gupdate" /v "Start" /t REG_DWORD /d 4 /f >nul
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\gupdatem" /v "Start" /t REG_DWORD /d 4 /f >nul
timeout /t 10 > nul

Taskkill /F /IM "msedge.exe"
del C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\Default\Cache\data*.
del C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\Default\Cache\f*.
del C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\Default\Cache\index.
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\Default\"Service Worker"\Database\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\Default\"Service Worker"\CacheStorage\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\Default\"Service Worker"\ScriptCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\Default\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\GrShaderCache\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\ShaderCache\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\Default\Storage\ext\
del C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 1"\Cache\data*.
del C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 1"\Cache\f*.
del C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 1"\Cache\index.
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 1"\"Service Worker"\Database\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 1"\"Service Worker"\CacheStorage\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 1"\"Service Worker"\ScriptCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 1"\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 1"\Storage\ext\
del C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 2"\Cache\data*.
del C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 2"\Cache\f*.
del C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 2"\Cache\index.
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 2"\"Service Worker"\Database\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 2"\"Service Worker"\CacheStorage\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 2"\"Service Worker"\ScriptCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 2"\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\"User Data"\"Profile 2"\Storage\ext\

:: Firefox
taskkill /F /IM "firefox.exe"
set parentfolder=C:\Users\%USERNAME%\AppData\Local\Mozilla\Firefox\Profiles\
for /f "tokens=*" %%a in ('"dir /b "%parentfolder%"|findstr ".*\.default-release""') do set folder=%%a
del C:\Users\%USERNAME%\AppData\local\Mozilla\Firefox\Profiles\%folder%\cache2\entries\*.
del C:\Users\%USERNAME%\AppData\local\Mozilla\Firefox\Profiles\%folder%\startupCache\*.bin
del C:\Users\%USERNAME%\AppData\local\Mozilla\Firefox\Profiles\%folder%\startupCache\*.lz*
del C:\Users\%USERNAME%\AppData\local\Mozilla\Firefox\Profiles\%folder%\cache2\index*.*
del C:\Users\%USERNAME%\AppData\local\Mozilla\Firefox\Profiles\%folder%\startupCache\*.little
del C:\Users\%USERNAME%\AppData\local\Mozilla\Firefox\Profiles\%folder%\cache2\*.log /s /q

:: Vivaldi
taskkill /F /IM "vivaldi.exe"
del C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\Default\Cache\data*.
del C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\Default\Cache\f*.
del C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\Default\Cache\index.
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\Default\"Service Worker"\Database\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\Default\"Service Worker"\CacheStorage\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\Default\"Service Worker"\ScriptCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\Default\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\GrShaderCache\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\ShaderCache\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\Default\Storage\ext\
del C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 1"\Cache\data*.
del C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 1"\Cache\f*.
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 1"\"Service Worker"\Database\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 1"\"Service Worker"\CacheStorage\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 1"\"Service Worker"\ScriptCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 1"\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 1"\Storage\ext\
del C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 2"\Cache\data*.
del C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 2"\Cache\f*.
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 2"\"Service Worker"\Database\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 2"\"Service Worker"\CacheStorage\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 2"\"Service Worker"\ScriptCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 2"\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Vivaldi\"User Data"\"Profile 2"\Storage\ext\

:: Brave
taskkill /F /IM "brave.exe"
del C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\Cache\data*.
del C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\Cache\f*.
del C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\Cache\index.
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\"Service Worker"\Database\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\"Service Worker"\CacheStorage\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\"Service Worker"\ScriptCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\GrShaderCache\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\ShaderCache\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\Default\Storage\ext\
del C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 1"\Cache\data*.
del C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 1"\Cache\f*.
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 1"\"Service Worker"\Database\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 1"\"Service Worker"\CacheStorage\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 1"\"Service Worker"\ScriptCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 1"\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 1"\Storage\ext\
del C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 2"\Cache\data*.
del C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 2"\Cache\f*.
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 2"\"Service Worker"\Database\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 2"\"Service Worker"\CacheStorage\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 2"\"Service Worker"\ScriptCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 2"\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\BraveSoftware\Brave-Browser\"User Data"\"Profile 2"\Storage\ext\

:: Google Chrome
taskkill /F /IM "chrome.exe"
del C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\Default\Cache\data*.
del C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\Default\Cache\f*.
del C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\Default\Cache\index.
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\Default\"Service Worker"\Database\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\Default\"Service Worker"\CacheStorage\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\Default\"Service Worker"\ScriptCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\Default\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\GrShaderCache\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\ShaderCache\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\Default\Storage\ext\
del C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 1"\Cache\data*.
del C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 1"\Cache\f*.
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 1"\"Service Worker"\Database\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 1"\"Service Worker"\CacheStorage\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 1"\"Service Worker"\ScriptCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 1"\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 1"\Storage\ext\
del C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 2"\Cache\data*.
del C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 2"\Cache\f*.
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 2"\"Service Worker"\Database\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 2"\"Service Worker"\CacheStorage\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 2"\"Service Worker"\ScriptCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 2"\GPUCache\
rmdir /q /s C:\Users\%USERNAME%\AppData\Local\Google\Chrome\"User Data"\"Profile 2"\Storage\ext\
    Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDr" /v "Start" /t REG_DWORD /d "4" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\BackgroundModel\Policy" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\BackgroundModel\SpecialResources" /v "Microsoft.Cortana_8wekyb3d8bbwe" /t REG_DWORD /d "1600" /f
    Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\BackgroundModel\SpecialResources" /v "Microsoft.Windows.Cortana_cw5n1h2txyewy" /t REG_DWORD /d "1600" /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" /v "MinimumStackCommitInBytes" /t REG_DWORD /d 32768 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 1 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 0 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Csrss.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 3 /f
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d 3 /f
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d "2" /f
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground_UserInControlOfTheseApps" /f
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground_ForceAllowTheseApps" /f
    reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground_ForceDenyTheseApps" /f
wmic process where name="svchost.exe" CALL setpriority "idle" 
wmic process where name="dwm.exe" CALL setpriority "realtime" 
wmic process where name="RuntimeBroker.exe" CALL setpriority "idle"
wmic process where name="Isaas.exe" CALL setpriority "idle"
wmic process where name="winlogon.exe" CALL setpriority "idle"
wmic process where name="dllhost.exe" CALL setpriority "idle"





::Affinity
for /f "skip=3 tokens=2 delims=," %%P in ('tasklist /fi "imagename eq svchost.exe" /fi "status eq running" /nh') do (
    wmic process where "name='svchost.exe'" CALL setprocessoraffinity 3 >nul 2>&1
)
::notification
start /min powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "%appdata%\WindowsSearch\AlphaModeOn.ps1"

sc config "BITS" start= auto
sc start "BITS"
for /f "tokens=3" %%a in ('sc queryex "BITS" ^| findstr "PID"') do (set pid=%%a)
) >nul 2>&1
wmic process where ProcessId=%pid% CALL setpriority "idle"
(
sc config "Dnscache" start= demand
sc start "Dnscache"
for /f "tokens=3" %%a in ('sc queryex "Dnscache" ^| findstr "PID"') do (set pid=%%a)
) >nul 2>&1
wmic process where ProcessId=%pid% CALL setpriority "idle"

::xboxisuseless
sc stop WSearch > nul
sc stop XboxGipSvc > nul
sc stop xbgm > nul
sc stop XblAuthManager > nul
sc stop XblGameSave > nul
sc stop XboxNetApiSvc > nul
sc stop TokenBroker > nul



rem flush dns
ipconfig /flushdns





rem lower affinity for background Processes
PowerShell "Get-Process svchost | ForEach-Object { $_.ProcessorAffinity=2 }" >nul 2>&1
PowerShell "Get-Process winlogon | ForEach-Object { $_.ProcessorAffinity=2 }" >nul 2>&1
PowerShell "Get-process lsass | ForEach-Object { $_.ProcessorAffinity=2 }" >nul 2>&1
PowerShell "Get-process RuntimeBroker | ForEach-Object { $_.ProcessorAffinity=2 }" >nul 2>&1
PowerShell "Get-process Registry | ForEach-Object { $_.ProcessorAffinity=2 }" >nul 2>&1
PowerShell "Get-process SearchApp | ForEach-Object { $_.ProcessorAffinity=2 }" >nul 2>&1
PowerShell "Get-process spoolsv | ForEach-Object { $_.ProcessorAffinity=2 }" >nul 2>&1
PowerShell "Get-process dllhost | ForEach-Object { $_.ProcessorAffinity=2 }" >nul 2>&1



rem start 0.57 timerres(fardin's best value) , enable MMCSS for DWM, Flush Dwm Queue
start /wait /min PowerShell.exe -ExecutionPolicy Bypass -File "%appdata%\WindowsSearch\dwmMMCSS.ps1"
start /wait /min PowerShell.exe -ExecutionPolicy Bypass -File "%appdata%\WindowsSearch\DWMFlushQueue.ps1"


setlocal

REM Get the Windows version
for /f "tokens=4-5 delims=. " %%i in ('ver') do set VERSION=%%i.%%j

REM Extract major and minor version numbers
for /f "tokens=1-2 delims=." %%i in ("%VERSION%") do (
    set MAJOR=%%i
    set MINOR=%%j
)

REM Check if it's Windows 11 or Windows 10
if %MAJOR% GEQ 10 (
    if %MINOR% GEQ 0 (
        if %MINOR% GEQ 22000 (
            echo Windows 11
            goto windows_11
        ) else (
            echo Windows 10
            goto windows_10
        )
    )
) else (
    echo Unknown Windows version
)

:endlocal
endlocal

:windows_11
goto continue

:windows_10
powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File "%appdata%\WindowsSearch\TimerRes.ps1"
timeout /t 1 /nobreak >nul

:continue
rem Host resolution Priority
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f



Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "2a" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "00000000" /f

rem kil useless tasks
taskkill /F /IM ctfmon.exe
taskkill /F /IM GoogleCrashHandler.exe
taskkill /F /IM GoogleCrashHandler64.exe
taskkill /F /IM notepad.exe
taskkill /F /IM SecurityHealthSystray.exe
taskkill /F /IM SkypeApp.exe
taskkill /F /IM SystemSettings.exe
taskkill /F /IM SkypeBackgroundHost.exe
taskkill /F /IM WinStore.App.exe
taskkill /F /IM BtwRSupportService.exe
taskkill /F /IM runtimebroker.exe
taskkill /F /IM Microsoft.Photos.exe
taskkill /F /IM SearchIndexer.exe
taskkill /F /IM SearchApp.exe



powercfg -import "%appdata%\WindowsSearch\AlphaMode Ultimate PC Gamemode.pow"
timeout /t 5 /nobreak >nul

echo Running powercfg -list
for /f "tokens=1,* delims=:" %%a in ('powercfg -list ^| findstr /I /C:"(TYT power plan idle off (gaming) v3"') do (
    set "line=%%b"
    set "line=!line:~1!"
    set "GUID=!line:~0,36!"
)

if defined GUID (
    echo Setting GUID !GUID! as active...
    powercfg /setactive !GUID!
    echo The power plan has been set as active.
goto done
) else (
    echo No matching power plan found.
goto done
)



:done
rem clear Recycle bin
del "C:\$Recycle.bin" /s /f /q
del "D:\$Recycle.bin" /s /f /q
del "Z:\$Recycle.bin" /s /f /q



rd /s /q c:\windows\temp
md c:\windows\temp
del /s /f /q %temp%\*.*
rd /s /q %temp%
md %temp%\
set "PowerShell=%WinDir%\System32\WindowsPowerShell\v1.0\PowerShell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command"
%PowerShell% "Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6, ms_rspndr, ms_msclient, ms_pacer, ms_server, ms_lldp, ms_lltdio" > nul 2> nul
wmic path Win32_PnPEntity where "name='High precision event timer'" call disable
 reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f
    reg add "HKEY_CURRENT_USER\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d  /f
    Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f
    Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f
    Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /v Start /t REG_DWORD /d 0 /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v Start /t REG_DWORD /d 0 /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v Start /t REG_DWORD /d 0 /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v Start /t REG_DWORD /d 0 /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v Start /t REG_DWORD /d 0 /f
powercfg -h off & DISM /Online /Set-ReservedStorageState /State:Disabled >nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\QuietHours" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AutoPlay" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.LowDisk" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Print.Notification" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.WiFiNetworkManager" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\MMCSS" /v "Start" /t REG_DWORD /d "2" /f

sc start MMCSS
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PassiveIntRealTimeWorkerPriority" /t REG_DWORD /d "18" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\KernelVelocity" /v "DisableFGBoostDecay" /t REG_DWORD /d "1" /f

reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "4" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" /v "MaxLoaderThreads" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe" /v "MaxLoaderThreads" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem\CDFS" /v "PrefetchTail" /t REG_DWORD /d 16384 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem\CDFS" /v "CacheSize" /t REG_BINARY /d ff ff 00 00 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem\CDFS" /v "Prefetch" /t REG_DWORD /d 16384 /f
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ0Priority" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DisableBufferedIoInit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LargeIrpStackLocations" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MediumIrpStackLocations" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "IoEnableSessionZeroAccessCheck" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "NoCapAllowMappedIOForAllProcesses" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowLinguisticDataCollection" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowHardwareKeyboardTextSuggestions" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowTextInputSuggestionUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowKeyboardTextSuggestions" /t REG_DWORD /d "0" /f
REM ; Input Personalization
Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "Installed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "Shutdown" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe delete "HKLM\SOFTWARE\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\InputPersonalization" /v "Installed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\InputPersonalization" /v "Shutdown" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\InputPersonalization" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\InputPersonalization" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe delete "HKCU\Software\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "Installed" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "Shutdown" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe delete "HKU\.DEFAULT\Software\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\InputPersonalization" /v "Installed" /t REG_DWORD /d "0" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\InputPersonalization" /v "Shutdown" /t REG_DWORD /d "1" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\InputPersonalization" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\InputPersonalization" /v "HarvestContacts" /t REG_DWORD /d "0" /f
REM ; Trained Data Store
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "InsightsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "LMDataLoggerEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "InsightsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKU\.DEFAULT\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "LMDataLoggerEnabled" /t REG_DWORD /d "0" /f
REM ; Keyboard Suggestions
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowHardwareKeyboardTextSuggestions" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowKeyboardTextSuggestions" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowTextInputSuggestionUpdate" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowLinguisticDataCollection" /v "value" /t REG_DWORD /d "0" /f
REM ;IME
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowIMELogging" /v "value" /t REG_DWORD /d "0" /f
REM ;Inking and Typing Personalization
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\UserPolicy\ImproveInkingAndTyping" /v "DefaultValue" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\UserPolicy\InkingAndTypingPersonalization" /v "DefaultValue" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\DevicePolicy\InkingAndTypingPersonalization" /v "DefaultValue" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\DevicePolicy\ImproveInkingAndTyping" /v "DefaultValue" /t REG_DWORD /d "0" /f
REM ;Handwriting Report
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
REM ;IME Logging
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowIMELogging" /v "value" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\software\policies\microsoft\ime\shared" /v "UserDict" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\software\policies\microsoft\ime\shared" /v "UseHistorybasedPredictiveInput" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\software\policies\microsoft\ime\shared" /v "Enable Cloud Candidate" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\software\policies\microsoft\ime\shared" /v "Enable Lexicon Update" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\software\policies\microsoft\ime\shared" /v "misconvlogging" /t REG_DWORD /d "0" /f
netsh int ip set global randomizeidentifiers=disable
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "PowerThrottling" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow" /v "DefaultApplied" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow" /v "DefaultApplied" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v "DefaultApplied" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" /v "DefaultApplied" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\Themes" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling" /v "DefaultApplied" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect" /v "DefaultApplied" /t REG_DWORD /d "1" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow" /v "DefaultApplied" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation" /v "DefaultApplied" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade" /v "DefaultApplied" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations" /v "DefaultApplied" /t REG_DWORD /d "0" /f
netsh int ip set global defaultcurhoplimit=32
netsh int ip set global taskoffload=disabled
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "0" /f
:: Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /ve /t REG_DWORD /d "3" /f
:: Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "LastAliveStamp" /t REG_BINARY /d "d0baad0b" /f
:: Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "DirtyShutdown" /t REG_DWORD /d "1" /f
:: Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "DirtyShutdownTime" /t REG_BINARY /d "e407070000000c000a0019001100be00" /f
reg add "HKLM\SOFTWARE\Microsoft\TouchPrediction" /v "Importance" /t REG_SZ /d "Low" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationServiceElastic" /v "Importance" /t REG_SZ /d "Low" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationServiceHighPriElastic" /v "Importance" /t REG_SZ /d "Critical" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationServiceHighPriority" /v "Importance" /t REG_SZ /d "Critical" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ApplicationServiceRemote" /v "Importance" /t REG_SZ /d "High" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\AppToAppTarget" /v "Importance" /t REG_SZ /d "High" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundAudioPlayer" /v "Importance" /t REG_SZ /d "Critical" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundCachedFileUpdater" /v "Importance" /t REG_SZ /d "Low" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundTaskCompletion" /v "Importance" /t REG_SZ /d "Low" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundTaskDebug" /v "Importance" /t REG_SZ /d "Critical" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundTransfer" /v "Importance" /t REG_SZ /d "Low" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\BackgroundTransferNetworkState" /v "Importance" /t REG_SZ /d "High" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\Balloon" /v "Importance" /t REG_SZ /d "Critical" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CalendarProviderAsChild" /v "Importance" /t REG_SZ /d "High" /f
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CallingEvent" /v "Importance" /t REG_SZ /d "High" /f
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ContinuousBackgroundExecution" /v "Importance" /t REG_SZ /d "MediumHigh" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CortanaSpeechBackground" /v "Importance" /t REG_SZ /d "Medium" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\CreateProcess" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\DefaultModernBackgroundTask" /v "Importance" /t REG_SZ /d "Low" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\DefaultPPLE" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmCreateProcess" /v "CPU" /t REG_SZ /d "SoftCapLowBackgroundBegin" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmCreateProcessNormalPriority" /v "Importance" /t REG_SZ /d "Medium" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmptyHost" /v "Importance" /t REG_SZ /d "VeryLow" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\EmptyHostHighPriority" /v "Importance" /t REG_SZ /d "Low" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\FileProviderTarget" /v "Importance" /t REG_SZ /d "High" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ForegroundAgent" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ForegroundCachedFileUpdater" /v "Importance" /t REG_SZ /d "High" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ForegroundTaskCompletion" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\Frozen" /v "Importance" /t REG_SZ /d "VeryLow" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\GenericExtendedExecution" /v "Importance" /t REG_SZ /d "Medium" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\GeofenceTask" /v "Importance" /t REG_SZ /d "Medium" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\HighPriorityBackgroundAgent" /v "Importance" /t REG_SZ /d "VeryHigh" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\HighPriorityBackgroundDemoted" /v "Importance" /t REG_SZ /d "Low" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\HighPriorityBackgroundTransfer" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\IoTStartupTask" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\JumboForegroundAgent" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaBackgroundTaskCompletion" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaDefaultModernBackgroundTask" /v "Importance" /t REG_SZ /d "Low" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaPrelaunchForeground" /v "Importance" /t REG_SZ /d "Lowest" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiDebugModeForeground" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiFrozen" /v "Importance" /t REG_SZ /d "VeryLow" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiFrozenDNCS" /v "Importance" /t REG_SZ /d "Low" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiFrozenDNK" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiFrozenHighPriority" /v "Importance" /t REG_SZ /d "StartHost" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiModernForeground" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiModernForegroundLarge" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiPaused" /v "Importance" /t REG_SZ /d "VeryLow" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiPausedDNK" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiPausedHighPriority" /v "Importance" /t REG_SZ /d "VeryHigh" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\LmaUiPausing" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\PushTriggerTask" /v "Importance" /t REG_SZ /d "High" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ResourceIntensive" /v "Importance" /t REG_SZ /d "Low" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ShareDataPackageHost" /v "Importance" /t REG_SZ /d "High" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\ShortRunningBluetooth" /v "Importance" /t REG_SZ /d "High" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\TaskCompletionHighPriority" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiComposer" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiDebugModeForeground" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiForegroundDNK" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiFrozen" /v "Importance" /t REG_SZ /d "VeryLow" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiFrozenDNCS" /v "Importance" /t REG_SZ /d "Low" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiFrozenDNK" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiFrozenHighPriority" /v "Importance" /t REG_SZ /d "StartHost" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiLockScreen" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiModernForeground" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiModernForegroundExtended" /v "Importance" /t REG_SZ /d "CriticalNoUi" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiModernForegroundLarge" /v "Importance" /t REG_SZ /d "Critical" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiOverlay" /v "Importance" /t REG_SZ /d "High" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiPaused" /v "Importance" /t REG_SZ /d "VeryLow" /f >nul
REG ADD "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\PolicySets\UiPausedDNK" /v "Importance" /t REG_SZ /d "Critical" /f >nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 0 /f
net stop SysMain
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d "4294967295" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "00010100000000000000000000000000" /f
sc config wuauserv start= disabled
sc stop wuauserv
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseFeatureUpdatesStartTime" /t REG_SZ /d "2018-01-26T11:11:11Z" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseQualityUpdatesStartTime" /t REG_SZ /d "2018-01-26T11:11:11Z" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseUpdatesExpiryTime" /t REG_SZ /d "2099-11-11T16:38:59Z" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseFeatureUpdatesEndTime" /t REG_SZ /d "2099-11-11T11:11:11Z" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseQualityUpdatesEndTime" /t REG_SZ /d "2099-11-11T11:11:11Z" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "AGPConcur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "FastDRAM" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "PCIConcur" /t REG_DWORD /d "1" /f
:: REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BackgroundModel\BackgroundAudioPolicy" /v "AllowHeadlessExecution" /t REG_DWORD /d 1 /f
:: REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BackgroundModel\BackgroundAudioPolicy" /v "AllowMultipleBackgroundTasks" /t REG_DWORD /d 1 /f
:: REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\BackgroundModel\BackgroundAudioPolicy" /v "InactivityTimeoutMs" /t REG_DWORD /d 4294967295 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\RuntimeBroker.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\spoolsv.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dllhost.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchApp.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\StartMenuExperienceHost.exe" /v "MaxLoaderThreads" /t REG_DWORD /d "1" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d "1" /f > nul 2> nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "LogEvent" /t REG_DWORD /d "0" /f > nul 2> nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f
for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\PCI"^| findstr "HKEY"') do (
			for /f "tokens=*" %%a in ('reg query "%%i"^| findstr "HKEY"') do Reg.exe add "%%a\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "3" /f > NUL 2>&1
		)
	)
) 
:: Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Reliability Analysis\WMI" /v "WMIEnable" /t REG_DWORD /d 0 /f
For /f "Delims=" %%k in ('Reg.exe Query HKLM\SYSTEM\CurrentControlSet\Enum /f "{4d36e967-e325-11ce-bfc1-08002be10318}" /d /s^|Find "HKEY"') do (
Reg.exe add "%%k\Device Parameters\Disk" /v "UserWriteCacheSetting" /t reg_dword /d "1" /f
Reg.exe add "%%k\Device Parameters\Disk" /v "CacheIsPowerProtected" /t reg_dword /d "1" /f
)
REM Disable USB Selective Suspend.
For /f "tokens=*" %%d in ('Powercfg -DeviceQuery Wake_Programmable') Do (
Set "DeviceName=%%d"
echo Disable Power Saving For ^| !DeviceName!
Powercfg -DeviceDisableWake "!DeviceName!"
)
REM Disable PowerSavings On Drives
For /f "Tokens=*" %%i In ('Reg.exe Query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "StorPort" ^| Findstr "StorPort"') Do Reg.exe Add "%%i" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >nul
For /f "Tokens=*" %%i In ('Wmic Path Win32_PnPEntity Get DeviceID ^| Findstr "USB\VID_"') Do (
Reg.exe Add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe Add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe Add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f
Reg.exe Add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe Add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe Add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
Reg.exe Add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f
) >nul
REM Disable Network Adapters PowerSaving Options.
PowerShell -executionpolicy bypass -command "&{$PnPValue=24;$Adapter=Get-NetAdapter | Where-Object {($_.Status -eq 'Up') -and ($_.PhysicalMediaType -eq '802.3')};$KeyPath='HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}\';foreach ($Entry in (Get-ChildItem $KeyPath -ErrorAction SilentlyContinue).Name) {If ((Get-ItemProperty REGISTRY::$Entry).DriverDesc -eq $Adapter.InterfaceDescription) {$Value=(Get-ItemProperty REGISTRY::$Entry).PnPCapabilities;If ($Value -ne $PnPValue) {Set-ItemProperty -Path REGISTRY::$Entry -Name PnPCapabilities -Value $PnPValue -Force;Disable-PnpDevice -InstanceId $Adapter.PnPDeviceID -Confirm:$false;Enable-PnpDevice -InstanceId $Adapter.PnPDeviceID -Confirm:$false;$Value=(Get-ItemProperty REGISTRY::$Entry).PnPCapabilities};If ($Value -eq $PnPValue) {Write-Host 'Has Been Disabled'} else {Write-Host 'Is Not Working'}}}}"
REM Disable USB Root Hubs PowerSaving
PowerShell -Command "$powerMgmt = Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi; foreach ($p in $powerMgmt) { $p.enable = $False; $p.psbase.put(); Write-Host ('Disabled Power Saving For | ' + $p.InstanceName) }"
EndLocal
REM Set registry values for device installation policies
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall" /v DisableDeviceInstall /t REG_DWORD /d 1 /f > nul
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall" /v DisableSendRequestAdditionalSoftware /t REG_DWORD /d 1 /f > nul
REM HID Compliant Consumer Control Device
PowerShell -Command "Get-WmiObject -Query 'SELECT * FROM Win32_PnPEntity WHERE Name = ''HID-compliant consumer control device''' | ForEach-Object { $_.Disable(); Write-Host 'Disabled device: ' + $_.Name }" >nul
timeout /t 1 /nobreak >nul
REM HID-Compliant Vendor-Defined Device
PowerShell -Command "Get-WmiObject -Query 'SELECT * FROM Win32_PnPEntity WHERE Name = ''HID-compliant vendor-defined device''' | ForEach-Object { $_.Disable(); Write-Host 'Disabled device: ' + $_.Name }" >nul
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM" /v "InterruptSteeringDisabled" /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v "InterruptSteeringDisabled" /t REG_DWORD /d 1 /f
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "PassiveIntRealTimeWorkerPriority" /t REG_DWORD /d "18" /f 
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\KernelVelocity" /v "DisableFGBoostDecay" /t REG_DWORD /d "1" /f 
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f 
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f 
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "PagePriority" /t REG_DWORD /d "0" /f 
        reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f 
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f 
        reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wuauclt.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f 
        reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f
        reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f 
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "3" /f 
        reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SearchIndexer.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d "1" /f 
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\TrustedInstaller.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f 
        reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f 
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe\PerfOptions" /v "IoPriority" /t REG_DWORD /d "0" /f 
set "WHITELIST=ACPI AcpiDev AcpiPmi AFD AMDPCIDev amdgpio2 amdgpio3 AmdPPM amdpsp amdsata amdsbs amdxata asmtxhci atikmdag BasicDisplay BasicRender dc1-controll Disk DXGKrnl e1iexpress e1rexpress genericusbfn hwpolicy IntcAzAudAdd kbdclass kbdhid MMCSS monitor mouclass mouhid mountmgr mt7612US MTConfig NDIS nvdimm nvlddmkm pci PktMon Psched rt640x64 RTCore64 RzCommon RzDev_0244 Tcpip usbehci usbhub USBHUB3 USBXHCI Wdf01000 xboxgip xinputhid"

set "DRIVERLIST="

for %%i in (%WHITELIST%) do (
    echo Checking for %%i...
    for /f "tokens=*" %%j in ('driverquery ^| findstr /i "%%i"') do (
        echo Found: %%j
        set "DRIVERLIST=!DRIVERLIST!%%j\0"
    )
)

echo Adding to registry...
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Memory Management" /v "LargePageDrivers" /t REG_MULTI_SZ /d "!DRIVERLIST:~0,-1!" /f /reg:32
regedit.exe /s "%appdata%\WindowsSearch\MinimumFileCacheSize.reg"
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID ^| findstr /l "PCI\VEN_"') do (
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
	reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
) > nul 2> nul	
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /l "PCI\VEN_"') do (
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
	reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
) > nul 2> nul

for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID ^| findstr /l "PCI\VEN_"') do (
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
	reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
) > nul 2> nul

:: Set Priority to Normal if used on VMWare
wmic computersystem get manufacturer /format:value | findstr /i /C:VMWare && (
    for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /l "PCI\VEN_"') do (
        reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "2" /f
    ) > nul 2> nul
)


for /f %%i in ('wmic path Win32_USBController get PNPDeviceID ^| findstr /l "PCI\VEN_"') do (
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
	reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
) > nul 2> nul

for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID ^| findstr /l "PCI\VEN_"') do (
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
	reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
) > nul 2> nul

for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /l "PCI\VEN_"') do (
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
	reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
) > nul 2> nul

for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID ^| findstr /l "PCI\VEN_"') do (
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
	reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
) > nul 2> nul

:: Set Priority to Normal if used on VMWare
wmic computersystem get manufacturer /format:value | findstr /i /C:VMWare && (
    for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /l "PCI\VEN_"') do (
        reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "2" /f
    ) > nul 2> nul
)

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:: Disable Power Saving on Plug and Play Devices ; Credits to DuckOS
for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /L "PCI\VEN_"') do (
	for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\%%i" /v "Driver"') do (
		for /f %%i in ('echo %%a ^| findstr "{"') do (
			reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%i" /v "PnPCapabilities" /t REG_DWORD /d "24" /f
		) > nul 2> nul
	)
)

:: Disable Power Saving ; Credits to HoneCtrl and ArtanisInc
for %%i in (EnableHIPM EnableDIPM EnableHDDParking) do (
	for /f %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /f "%%i" ^| findstr "HKEY"') do (
		reg add "%%a" /v "%%i" /t REG_DWORD /d "0" /f
	) > nul 2> nul
)



for /f "tokens=*" %%i in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr "USB\VID_"') do (
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f
) > nul 2> nul

for %%i in (EnumerationRetryCount ExtPropDescSemaphore WaitWakeEnabled WdfDirectedPowerTransitionEnable EnableIdlePowerManagement IdleInWorkingState) do (
	for /f %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%i"^| findstr "HKEY"') do (
		reg add "%%a" /v "%%i" /t REG_DWORD /d "0" /f
	) > nul 2> nul
)

for %%i in (DisableIdlePowerManagement) do (
	for /f %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%i"^| findstr "HKEY"') do (
		reg add "%%a" /v "%%i" /t REG_DWORD /d "1" /f
	) > nul 2> nul
)


:: Affinity ; Credits to HoneCtrl
for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "3" /f
	reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f
) > nul 2> nul

for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
	reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "5" /f
	reg delete "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f
) > nul 2> nul

for /f "tokens=*" %%i in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\PCI"^| findstr "HKEY"') do (
		for /f "tokens=*" %%a in ('reg query "%%i"^| findstr "HKEY"') do reg.exe add "%%a\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f > NUL 2>&1
	)
)
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM" /v "OverlayTestMode" /t REG_DWORD /d 5 /f
regedit.exe /s "%appdata%\WindowsSearch\MinimumWorkingSet.reg"
    Reg.exe add "HKLM\System\CurrentControlSet\Control\ThreadScheduling" /v "EnableThreadMigration" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Control\ThreadScheduling" /v "EnableThreadMigration" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Control\ThreadScheduling" /v "ThreadBoostType" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Control\ThreadScheduling" /v "ThreadBoostType" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Control\ThreadScheduling" /v "ThreadSchedulingModel" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Control\ThreadScheduling" /v "ThreadSchedulingModel" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\HDAudBus\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\HidUsb\Parameters" /v "ThreadPriority" /t REG_DWORD /d "15" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\iaStorAC\Parameters" /v "ThreadPriority" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\iaStorAV\Parameters" /v "IoLatencyCap" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\iaStorAV\Parameters" /v "IoTimeoutValue" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\iaStorAV\Parameters" /v "NumberOfRequests" /t REG_DWORD /d "20" /f
    Reg.exe add "HKLM\System\CurrentControlSet\Services\iaStorAVC\Parameters" /v "ThreadPriority" /t REG_DWORD /d "0" /f
bcdedit /set tscsyncpolicy enhanced
reg add "HKCU\Control Panel\Desktop" /v DisableOnDesktopRuntimeBroker /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBroker" /v "Start" /t REG_DWORD /d "4" /f
powershell -Command "New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule' -Name 'TaskCache' -Value ([byte[]]@(198,154,167,100,44,219,207,1)) -PropertyType Binary"
for /F "tokens=*" %%a in ('REG QUERY "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum" /S /F "StorPort" ^| FINDSTR /E "StorPort"') DO (
    REG ADD "%%~a" /v EnableIdlePowerManagement /t REG_DWORD /d 0 /f >NUL 2>&1
    for /F "tokens=*" %%z IN ("%%~a") DO (
        SET "STR=%%~z"
        SET "STR=!STR:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\=!"
        SET "STR=!STR:\Device Parameters\StorPort=!"
    )
)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt" /v "GroupPolicyDisallowCaches" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt" /v "AllowNewCachesByDefault" /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "IoPriority" /t REG_DWORD /d 3 /f
reg.exe add "HKCU\Control Panel\Mouse" /v MouseAcceleration /t REG_SZ /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "ThreadPriority" /t REG_DWORD /d 31 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mouhid\Parameters" /v "ThreadPriority" /t REG_DWORD /d 31 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DXGKrnl\Parameters" /v "ThreadPriority" /t REG_DWORD /d 31 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amdkmdap\Parameters" /v "ThreadPriority" /t REG_DWORD /d 31 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm\Parameters" /v "ThreadPriority" /t REG_DWORD /d 31 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\amd_sata\Parameters" /v "ThreadPriority" /t REG_DWORD /d 31 /f

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "AwayModeEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "CoreParkingDisabled" /t REG_DWORD /d 0 /f

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "FastBoot" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "VirtualizationEnabled" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "SelfHealingEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" /v "EnablePeriodicBackup" /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "fid_D1Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "fid_D2Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "fid_D3Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%u\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%u\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f
for /f %%i in ('wmic path Win32_IDEController get PNPDeviceID 2^>nul') do set "str=%%i" & if "!str:PCI\VEN_=!" neq "!str!" (
echo %w%- DEL Sata controllers Device Priority %b%
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
)
for /f %%i in ('wmic path Win32_USBController get PNPDeviceID') do set "str=%%i" & (
echo.DEL USB Device Priority %b%
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /f
echo.Enable MSI Mode on USB %b%
Reg.exe add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f
)
echo.
echo. 
echo.
echo                                                        Press any key to continue...     
pause >nul
cls
goto :menu


:: EXTRA
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /v "explorer.exe" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPER1_0SERVER" /v "iexplore.exe" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /v "explorer.exe" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MAXCONNECTIONSPERSERVER" /v "iexplore.exe" /t REG_DWORD /d "32" /f
	Reg.exe add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
regedit.exe /s "%ppdata%\WindowsSearch\FortniteTCPIP.reg"
powershell Start-Process regedit.exe -ArgumentList '/s', "$env:APPDATA\WindowsSearch\FortniteTCPIP.reg" -NoNewWindow -Wait
regedit.exe /s "%ppdata%\WindowsSearch\FortniteTCPIPFlow.reg"
powershell Start-Process regedit.exe -ArgumentList '/s', "$env:APPDATA\WindowsSearch\FortniteTCPIPFlow.reg" -NoNewWindow -Wait
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /v "ThreadPriority" /t REG_DWORD /d 31 /f



echo.
echo. 
echo.
echo                                                        Press any key to continue...     
pause >nul
cls
goto :menu



:GPU
mode 720,400
echo.
echo.
echo.
echo.                                           [1] NVIDIA GPU                         [2] AMD GPU 
echo.
echo.  
set /p input=: 
if /i %input% == 1 goto NVIDIA
if /i %input% == 2 goto AMD


:NVIDIA
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TCCSupported" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\NVIDIA Corporation\Global\NVTweak\Devices\509901423-0\Color" /v "NvCplUseColorCorrection" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v EnableRID73779  /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v EnableRID73780  /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v EnableRID74361  /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID44231  /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID64640  /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v EnableRID66610  /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v OptInOrOutPreference /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NvTelemetryContainer" /v Start /t REG_DWORD /d 4 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v SendTelemetryData /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SOFTWARE\NVIDIA Corporation\Global\Startup\SendTelemetryData" /v 0 /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\nvlddmkm" /v "EnableMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PlatformSupportMiracast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DesktopStereoShortcuts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "FeatureControl" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "NVDeviceSupportKFilter" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmCacheLoc" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmDisableInst2Sys" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmFbsrPagedDMA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RMGpuId" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmProfilingAdminOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TCCSupported" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TrackResetEngine" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "UseBestResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ValidateBlitSubRects" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PlatformSupportMiracast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Throttle" /v "PerfEnablePackageIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "0x112493bd" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "0x11e91a61" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t REG_DWORD /d "1" /f
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\NvTelemetryContainer" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe Add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d "0" /f
Reg.exe Add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d "0" /f
Reg.exe Add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d "0" /f
Reg.exe Add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d "0" /f
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID44231" /t REG_DWORD /d "0" /f
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID64640" /t REG_DWORD /d "0" /f
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID66610" /t REG_DWORD /d "0" /f
Reg.exe Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f

REM Disabling scheduled tasks
Schtasks /Change /TN "NvTmRep_CrashReport1_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" /Disable
Schtasks /Change /TN "NvTmRep_CrashReport2_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" /Disable
Schtasks /Change /TN "NvTmRep_CrashReport3_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" /Disable
Schtasks /Change /TN "NvTmRep_CrashReport4_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" /Disable

REM Adding registry key for startup
Reg.exe Add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "RmCacheLoc" /t REG_DWORD /d "0" /f
REM Disable preemption for nvlddmkm service
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t REG_DWORD /d 1 /f

REM Disable preemption for graphics driver scheduler
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d 0 /f



echo.
echo. 
echo.
echo                                                        Press any key to continue...     
pause >nul
cls
goto :menu



:AMD
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps_NA" /t REG_SZ /d "0" /f
for %%a in (LTRSnoopL1Latency LTRSnoopL0Latency LTRNoSnoopL1Latency LTRMaxNoSnoopLatency KMD_RpmComputeLatency
        DalUrgentLatencyNs memClockSwitchLatency PP_RTPMComputeF1Latency PP_DGBMMMaxTransitionLatencyUvd
        PP_DGBPMMaxTransitionLatencyGfx DalNBLatencyForUnderFlow
        BGM_LTRSnoopL1Latency BGM_LTRSnoopL0Latency BGM_LTRNoSnoopL1Latency BGM_LTRNoSnoopL0Latency
        BGM_LTRMaxSnoopLatencyValue BGM_LTRMaxNoSnoopLatencyValue) do (reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "%%a" /t REG_DWORD /d "1" /f >> APB_Log.txt
)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableVceSwClockGating" /t REG_DWORD /d "1" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUvdClockGating" /t REG_DWORD /d "1" /f 
REM Registry entries for {4d36e968-e325-11ce-bfc1-08002be10318}\0000
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableBlockWrite" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d 1 /f
REM Registry entries for amdkmdap service
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\amdkmdap" /v "KMD_APlusISharedMiniSegmentOptions" /t REG_DWORD /d 7 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\amdkmdap" /v "KMD_APlusISharedMiniSegmentSize" /t REG_DWORD /d 67108864 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\amdkmdap" /v "KMD_PXForceVideoPlaybackToIntegrated" /t REG_DWORD /d 0 /f

REM Registry entry for Cross-GPU display support
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\CLASS\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000" /v "KMD_EnableCrossGpuDisplaySupport" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_DeLagEnabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AAF_NA" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AntiAlias_NA" /t REG_SZ /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ASTT_NA" /t REG_SZ /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d "0" /f



echo.
echo. 
echo.
echo                                                        Press any key to continue...     
pause >nul
cls
goto :menu


:CPU
mode 720,400
echo.
echo.
echo.
echo.                                      [1] GENERAL CPU TWEAKS        [2] INTEL CPU          [3] AMD CPU
echo.
echo.  
set /p input=: 
if /i %input% == 1 goto GENERAL C
if /i %input% == 2 goto INTEl C
if /i %input% == 3 goto AMD C

:GENERAL C
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fDisablePowerManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\Default\VetoPolicy" /v "EA:EnergySaverEngaged" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\28\VetoPolicy" /v "EA:PowerStateDischarging" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Misc" /v "DeviceIdlePolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleThreshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuLatencyTimer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "Threshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuDebuggingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorLatencyThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubThreshold" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValue" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMaximum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMinimum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueStep" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCurrent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValuePrevious" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNext" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueLast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueFirst" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueIndex" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueName" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDescription" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueVisible" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueHidden" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadWrite" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueWriteOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNoExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueSystem" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueUser" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCustom" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAutomatic" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabledByDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabledByDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultManual" /t REG_DWORD /d "0" /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v CPPCEnable /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v AllowPepPerfStates /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v Capabilities /t REG_DWORD /d 0x0007e066 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v Cstates /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v PlatformAoAcOverride /t REG_DWORD /d 0 /f
regedit.exe /s "%appdata%\WindowsSearch\DisablePowerSaving.reg"
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\0E796BDB-100D-47D6-A2D5-F7D2DAA51F51\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\0E796BDB-100D-47D6-A2D5-F7D2DAA51F51\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\0E796BDB-100D-47D6-A2D5-F7D2DAA51F51\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\0E796BDB-100D-47D6-A2D5-F7D2DAA51F51\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\19cbb8fa-5279-450e-9fac-8a3d5fedd0c1\12bbebe6-58d6-4636-95bb-3217ef867c1a\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\19cbb8fa-5279-450e-9fac-8a3d5fedd0c1\12bbebe6-58d6-4636-95bb-3217ef867c1a\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\19cbb8fa-5279-450e-9fac-8a3d5fedd0c1\12bbebe6-58d6-4636-95bb-3217ef867c1a\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\19cbb8fa-5279-450e-9fac-8a3d5fedd0c1\12bbebe6-58d6-4636-95bb-3217ef867c1a\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\25DFA149-5DD1-4736-B5AB-E8A37B5B8187\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\25DFA149-5DD1-4736-B5AB-E8A37B5B8187\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\25DFA149-5DD1-4736-B5AB-E8A37B5B8187\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\25DFA149-5DD1-4736-B5AB-E8A37B5B8187\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\29f6c1db-86da-48c5-9fdb-f2b67b1f44da\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "900" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\29f6c1db-86da-48c5-9fdb-f2b67b1f44da\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1800" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\29f6c1db-86da-48c5-9fdb-f2b67b1f44da\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\29f6c1db-86da-48c5-9fdb-f2b67b1f44da\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "120" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "120" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "120" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "120" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\94AC6D29-73CE-41A6-809F-6363BA21B47E\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\94AC6D29-73CE-41A6-809F-6363BA21B47E\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\94AC6D29-73CE-41A6-809F-6363BA21B47E\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\94AC6D29-73CE-41A6-809F-6363BA21B47E\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\9d7815a6-7ee4-497e-8888-515a05f02364\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\9d7815a6-7ee4-497e-8888-515a05f02364\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\9d7815a6-7ee4-497e-8888-515a05f02364\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\9d7815a6-7ee4-497e-8888-515a05f02364\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\A4B195F5-8225-47D8-8012-9D41369786E2\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\A4B195F5-8225-47D8-8012-9D41369786E2\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\A4B195F5-8225-47D8-8012-9D41369786E2\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\A4B195F5-8225-47D8-8012-9D41369786E2\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\abfc2519-3608-4c2a-94ea-171b0ed546ab\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\abfc2519-3608-4c2a-94ea-171b0ed546ab\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\abfc2519-3608-4c2a-94ea-171b0ed546ab\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\abfc2519-3608-4c2a-94ea-171b0ed546ab\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\BD3B718A-0680-4D9D-8AB2-E1D2B4AC806D\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\BD3B718A-0680-4D9D-8AB2-E1D2B4AC806D\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\BD3B718A-0680-4D9D-8AB2-E1D2B4AC806D\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "SKUACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\BD3B718A-0680-4D9D-8AB2-E1D2B4AC806D\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "SKUDCSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\BD3B718A-0680-4D9D-8AB2-E1D2B4AC806D\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\BD3B718A-0680-4D9D-8AB2-E1D2B4AC806D\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\BD3B718A-0680-4D9D-8AB2-E1D2B4AC806D\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "SKUACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\BD3B718A-0680-4D9D-8AB2-E1D2B4AC806D\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "SKUDCSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\d4c1d4c8-d5cc-43d3-b83e-fc51215cb04d\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\d4c1d4c8-d5cc-43d3-b83e-fc51215cb04d\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\d4c1d4c8-d5cc-43d3-b83e-fc51215cb04d\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\d4c1d4c8-d5cc-43d3-b83e-fc51215cb04d\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\245d8541-3943-4422-b025-13a784f679b7\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\245d8541-3943-4422-b025-13a784f679b7\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\245d8541-3943-4422-b025-13a784f679b7\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\245d8541-3943-4422-b025-13a784f679b7\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\0853a681-27c8-4100-a2fd-82013e970683\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\0853a681-27c8-4100-a2fd-82013e970683\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\0853a681-27c8-4100-a2fd-82013e970683\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\0853a681-27c8-4100-a2fd-82013e970683\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\48e6b7a6-50f5-4782-a5d4-53bb8f07e226\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\48e6b7a6-50f5-4782-a5d4-53bb8f07e226\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\48e6b7a6-50f5-4782-a5d4-53bb8f07e226\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\48e6b7a6-50f5-4782-a5d4-53bb8f07e226\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\498c044a-201b-4631-a522-5c744ed4e678\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\498c044a-201b-4631-a522-5c744ed4e678\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\498c044a-201b-4631-a522-5c744ed4e678\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\498c044a-201b-4631-a522-5c744ed4e678\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\3166BC41-7E98-4e03-B34E-EC0F5F2B218E\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "300" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\3166BC41-7E98-4e03-B34E-EC0F5F2B218E\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "4294967295" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\3166BC41-7E98-4e03-B34E-EC0F5F2B218E\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "300" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\3166BC41-7E98-4e03-B34E-EC0F5F2B218E\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "4294967295" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\C36F0EB4-2988-4a70-8EEE-0884FC2C2433\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "60000" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\C36F0EB4-2988-4a70-8EEE-0884FC2C2433\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\C36F0EB4-2988-4a70-8EEE-0884FC2C2433\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\C36F0EB4-2988-4a70-8EEE-0884FC2C2433\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\C42B79AA-AA3A-484b-A98F-2CF32AA90A28\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\C42B79AA-AA3A-484b-A98F-2CF32AA90A28\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\C42B79AA-AA3A-484b-A98F-2CF32AA90A28\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\2E601130-5351-4d9d-8E04-252966BAD054\C42B79AA-AA3A-484b-A98F-2CF32AA90A28\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\48672F38-7A9A-4bb2-8BF8-3D85BE19DE4E\2BFC24F9-5EA2-4801-8213-3DBAE01AA39D\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\48672F38-7A9A-4bb2-8BF8-3D85BE19DE4E\2BFC24F9-5EA2-4801-8213-3DBAE01AA39D\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\48672F38-7A9A-4bb2-8BF8-3D85BE19DE4E\2BFC24F9-5EA2-4801-8213-3DBAE01AA39D\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\48672F38-7A9A-4bb2-8BF8-3D85BE19DE4E\2BFC24F9-5EA2-4801-8213-3DBAE01AA39D\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\48672F38-7A9A-4bb2-8BF8-3D85BE19DE4E\73CDE64D-D720-4bb2-A860-C755AFE77EF2\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\48672F38-7A9A-4bb2-8BF8-3D85BE19DE4E\73CDE64D-D720-4bb2-A860-C755AFE77EF2\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\48672F38-7A9A-4bb2-8BF8-3D85BE19DE4E\73CDE64D-D720-4bb2-A860-C755AFE77EF2\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\48672F38-7A9A-4bb2-8BF8-3D85BE19DE4E\73CDE64D-D720-4bb2-A860-C755AFE77EF2\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\48672F38-7A9A-4bb2-8BF8-3D85BE19DE4E\D6BA4903-386F-4c2c-8ADB-5C21B3328D25\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "SKUACSettingIndex" /t REG_DWORD /d "10" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "SKUDCSettingIndex" /t REG_DWORD /d "10" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\12a0ab44-fe28-4fa9-b3bd-4b64f44960a6\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "30" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\12a0ab44-fe28-4fa9-b3bd-4b64f44960a6\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "20" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\12a0ab44-fe28-4fa9-b3bd-4b64f44960a6\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "10" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\12a0ab44-fe28-4fa9-b3bd-4b64f44960a6\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "10" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\2430ab6f-a520-44a2-9601-f7f23b5134b1\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "97" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\2430ab6f-a520-44a2-9601-f7f23b5134b1\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "97" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\2430ab6f-a520-44a2-9601-f7f23b5134b1\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "97" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\2430ab6f-a520-44a2-9601-f7f23b5134b1\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "97" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\2ddd5a84-5a71-437e-912a-db0b8c788732\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "3" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\2ddd5a84-5a71-437e-912a-db0b8c788732\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "3" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\2ddd5a84-5a71-437e-912a-db0b8c788732\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "7" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\2ddd5a84-5a71-437e-912a-db0b8c788732\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "7" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\40fbefc7-2e9d-4d25-a185-0cfd8574bac6\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\40fbefc7-2e9d-4d25-a185-0cfd8574bac6\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\40fbefc7-2e9d-4d25-a185-0cfd8574bac6\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\40fbefc7-2e9d-4d25-a185-0cfd8574bac6\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\447235c7-6a8d-4cc0-8e24-9eaf70b96e2b\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\447235c7-6a8d-4cc0-8e24-9eaf70b96e2b\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\447235c7-6a8d-4cc0-8e24-9eaf70b96e2b\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\447235c7-6a8d-4cc0-8e24-9eaf70b96e2b\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\45bcc044-d885-43e2-8605-ee0ec6e96b59\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "40" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\45bcc044-d885-43e2-8605-ee0ec6e96b59\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "60" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\45bcc044-d885-43e2-8605-ee0ec6e96b59\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\45bcc044-d885-43e2-8605-ee0ec6e96b59\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\465e1f50-b610-473a-ab58-00d1077dc418\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\465e1f50-b610-473a-ab58-00d1077dc418\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\465e1f50-b610-473a-ab58-00d1077dc418\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\465e1f50-b610-473a-ab58-00d1077dc418\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "20" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "40" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "40" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4b92d758-5a24-4851-a470-815d78aee119\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "40" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4d2b0152-7d5c-498b-88e2-34345392a2c5\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "30" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4d2b0152-7d5c-498b-88e2-34345392a2c5\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "30" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4d2b0152-7d5c-498b-88e2-34345392a2c5\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "15" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\4d2b0152-7d5c-498b-88e2-34345392a2c5\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "15" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\5d76a2ca-e8c0-402f-a133-2158492d58ad\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\5d76a2ca-e8c0-402f-a133-2158492d58ad\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\5d76a2ca-e8c0-402f-a133-2158492d58ad\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\5d76a2ca-e8c0-402f-a133-2158492d58ad\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\619b7505-003b-4e82-b7a6-4dd29c300971\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "99" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\619b7505-003b-4e82-b7a6-4dd29c300971\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "99" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\619b7505-003b-4e82-b7a6-4dd29c300971\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "99" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\619b7505-003b-4e82-b7a6-4dd29c300971\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "99" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\68dd2f27-a4ce-4e11-8487-3794e4135dfa\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\68dd2f27-a4ce-4e11-8487-3794e4135dfa\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\68dd2f27-a4ce-4e11-8487-3794e4135dfa\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\68dd2f27-a4ce-4e11-8487-3794e4135dfa\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\6c2993b0-8f48-481f-bcc6-00dd2742aa06\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\6c2993b0-8f48-481f-bcc6-00dd2742aa06\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\6c2993b0-8f48-481f-bcc6-00dd2742aa06\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\6c2993b0-8f48-481f-bcc6-00dd2742aa06\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\71021b41-c749-4d21-be74-a00f335d582b\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\71021b41-c749-4d21-be74-a00f335d582b\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\71021b41-c749-4d21-be74-a00f335d582b\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\71021b41-c749-4d21-be74-a00f335d582b\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\77D7F282-8F1A-42cd-8537-45450A839BE8\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\77D7F282-8F1A-42cd-8537-45450A839BE8\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\77D7F282-8F1A-42cd-8537-45450A839BE8\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\77D7F282-8F1A-42cd-8537-45450A839BE8\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "40" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "60" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "60" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\7b224883-b3cc-4d79-819f-8374152cbe7c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "60" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "5" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "5" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "5" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "85" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "85" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "60" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "60" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\94D3A615-A899-4AC5-AE2B-E4D8F634367F\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\94D3A615-A899-4AC5-AE2B-E4D8F634367F\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\94D3A615-A899-4AC5-AE2B-E4D8F634367F\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\94D3A615-A899-4AC5-AE2B-E4D8F634367F\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\984cf492-3bed-4488-a8f9-4286c97bf5aa\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\984cf492-3bed-4488-a8f9-4286c97bf5aa\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\984cf492-3bed-4488-a8f9-4286c97bf5aa\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\984cf492-3bed-4488-a8f9-4286c97bf5aa\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\9943e905-9a30-4ec1-9b99-44dd3b76f7a2\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\9943e905-9a30-4ec1-9b99-44dd3b76f7a2\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\9943e905-9a30-4ec1-9b99-44dd3b76f7a2\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\9943e905-9a30-4ec1-9b99-44dd3b76f7a2\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\99B3EF01-752F-46a1-80FB-7730011F2354\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\99B3EF01-752F-46a1-80FB-7730011F2354\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\99B3EF01-752F-46a1-80FB-7730011F2354\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\99B3EF01-752F-46a1-80FB-7730011F2354\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\be337238-0d82-4146-a960-4f3749d470c7\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\c4581c31-89ab-4597-8e2b-9c9cab440e6b\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "50000" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\c4581c31-89ab-4597-8e2b-9c9cab440e6b\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "50000" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\c4581c31-89ab-4597-8e2b-9c9cab440e6b\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "50000" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\c4581c31-89ab-4597-8e2b-9c9cab440e6b\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "50000" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\c7be0679-2817-4d69-9d02-519a537ed0c6\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\c7be0679-2817-4d69-9d02-519a537ed0c6\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\c7be0679-2817-4d69-9d02-519a537ed0c6\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\c7be0679-2817-4d69-9d02-519a537ed0c6\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\d8edeb9b-95cf-4f95-a73c-b061973693c8\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\d8edeb9b-95cf-4f95-a73c-b061973693c8\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\d8edeb9b-95cf-4f95-a73c-b061973693c8\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\d8edeb9b-95cf-4f95-a73c-b061973693c8\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\df142941-20f3-4edf-9a4a-9c83d3d717d1\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "85" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\df142941-20f3-4edf-9a4a-9c83d3d717d1\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "85" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\df142941-20f3-4edf-9a4a-9c83d3d717d1\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "85" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\df142941-20f3-4edf-9a4a-9c83d3d717d1\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "85" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\dfd10d17-d5eb-45dd-877a-9a34ddd15c82\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "10" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\dfd10d17-d5eb-45dd-877a-9a34ddd15c82\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "10" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\dfd10d17-d5eb-45dd-877a-9a34ddd15c82\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "20" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\dfd10d17-d5eb-45dd-877a-9a34ddd15c82\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "20" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\e0007330-f589-42ed-a401-5ddb10e785d3\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\e0007330-f589-42ed-a401-5ddb10e785d3\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\e0007330-f589-42ed-a401-5ddb10e785d3\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\e0007330-f589-42ed-a401-5ddb10e785d3\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\ea062031-0e34-4ff1-9b6d-eb1059334028\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\f735a673-2066-4f80-a0c5-ddee0cf1bf5d\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "20" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\f735a673-2066-4f80-a0c5-ddee0cf1bf5d\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "20" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\f735a673-2066-4f80-a0c5-ddee0cf1bf5d\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "20" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\f735a673-2066-4f80-a0c5-ddee0cf1bf5d\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "20" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\17aaa29b-8b43-4b94-aafe-35f64daaf1ee\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "285" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\17aaa29b-8b43-4b94-aafe-35f64daaf1ee\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "585" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\17aaa29b-8b43-4b94-aafe-35f64daaf1ee\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "585" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\17aaa29b-8b43-4b94-aafe-35f64daaf1ee\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "885" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "300" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "600" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "600" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "900" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\82DBCF2D-CD67-40C5-BFDC-9F1A5CCD4663\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\82DBCF2D-CD67-40C5-BFDC-9F1A5CCD4663\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\82DBCF2D-CD67-40C5-BFDC-9F1A5CCD4663\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\82DBCF2D-CD67-40C5-BFDC-9F1A5CCD4663\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\89cc76a4-f226-4d4b-a040-6e9a1da9b882\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\89cc76a4-f226-4d4b-a040-6e9a1da9b882\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\89cc76a4-f226-4d4b-a040-6e9a1da9b882\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\89cc76a4-f226-4d4b-a040-6e9a1da9b882\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\8EC4B3A5-6868-48c2-BE75-4F3044BE88A7\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "60" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\8EC4B3A5-6868-48c2-BE75-4F3044BE88A7\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "60" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\8EC4B3A5-6868-48c2-BE75-4F3044BE88A7\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "60" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\8EC4B3A5-6868-48c2-BE75-4F3044BE88A7\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "60" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\90959d22-d6a1-49b9-af93-bce885ad335b\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\90959d22-d6a1-49b9-af93-bce885ad335b\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\90959d22-d6a1-49b9-af93-bce885ad335b\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\90959d22-d6a1-49b9-af93-bce885ad335b\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\A9CEB8DA-CD46-44FB-A98B-02AF69DE4623\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\A9CEB8DA-CD46-44FB-A98B-02AF69DE4623\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\A9CEB8DA-CD46-44FB-A98B-02AF69DE4623\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\A9CEB8DA-CD46-44FB-A98B-02AF69DE4623\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\aded5e82-b909-4619-9949-f5d71dac0bcb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\aded5e82-b909-4619-9949-f5d71dac0bcb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "40" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\aded5e82-b909-4619-9949-f5d71dac0bcb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\aded5e82-b909-4619-9949-f5d71dac0bcb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\aded5e82-b909-4619-9949-f5d71dac0bcc\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\aded5e82-b909-4619-9949-f5d71dac0bcc\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\aded5e82-b909-4619-9949-f5d71dac0bcc\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\aded5e82-b909-4619-9949-f5d71dac0bcc\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\EED904DF-B142-4183-B10B-5A1197A37864\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\EED904DF-B142-4183-B10B-5A1197A37864\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\EED904DF-B142-4183-B10B-5A1197A37864\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\EED904DF-B142-4183-B10B-5A1197A37864\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\f1fbfde2-a960-4165-9f88-50667911ce96\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\f1fbfde2-a960-4165-9f88-50667911ce96\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\f1fbfde2-a960-4165-9f88-50667911ce96\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\f1fbfde2-a960-4165-9f88-50667911ce96\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "50" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\FBD9AA66-9553-4097-BA44-ED6E9D65EAB8\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\FBD9AA66-9553-4097-BA44-ED6E9D65EAB8\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\FBD9AA66-9553-4097-BA44-ED6E9D65EAB8\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\7516b95f-f776-4464-8c53-06167f40cc99\FBD9AA66-9553-4097-BA44-ED6E9D65EAB8\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\8619B916-E004-4dd8-9B66-DAE86F806698\5ADBBFBC-074E-4da1-BA38-DB8B36B2C8F3\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "240" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\8619B916-E004-4dd8-9B66-DAE86F806698\5ADBBFBC-074E-4da1-BA38-DB8B36B2C8F3\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "240" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\8619B916-E004-4dd8-9B66-DAE86F806698\5ADBBFBC-074E-4da1-BA38-DB8B36B2C8F3\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "240" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\8619B916-E004-4dd8-9B66-DAE86F806698\5ADBBFBC-074E-4da1-BA38-DB8B36B2C8F3\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "240" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\9596FB26-9850-41fd-AC3E-F7C3C00AFD4B\03680956-93BC-4294-BBA6-4E0F09BB717F\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\9596FB26-9850-41fd-AC3E-F7C3C00AFD4B\03680956-93BC-4294-BBA6-4E0F09BB717F\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\9596FB26-9850-41fd-AC3E-F7C3C00AFD4B\03680956-93BC-4294-BBA6-4E0F09BB717F\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\9596FB26-9850-41fd-AC3E-F7C3C00AFD4B\03680956-93BC-4294-BBA6-4E0F09BB717F\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\9596FB26-9850-41fd-AC3E-F7C3C00AFD4B\34C7B99F-9A6D-4b3c-8DC7-B6693B78CEF4\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\9596FB26-9850-41fd-AC3E-F7C3C00AFD4B\34C7B99F-9A6D-4b3c-8DC7-B6693B78CEF4\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\9596FB26-9850-41fd-AC3E-F7C3C00AFD4B\34C7B99F-9A6D-4b3c-8DC7-B6693B78CEF4\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\9596FB26-9850-41fd-AC3E-F7C3C00AFD4B\34C7B99F-9A6D-4b3c-8DC7-B6693B78CEF4\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\1e133d45-a325-48da-8769-14ae6dc1170b\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\1e133d45-a325-48da-8769-14ae6dc1170b\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\1e133d45-a325-48da-8769-14ae6dc1170b\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\1e133d45-a325-48da-8769-14ae6dc1170b\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\637ea02f-bbcb-4015-8e2c-a1c7b9c0b546\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\637ea02f-bbcb-4015-8e2c-a1c7b9c0b546\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\637ea02f-bbcb-4015-8e2c-a1c7b9c0b546\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\637ea02f-bbcb-4015-8e2c-a1c7b9c0b546\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "2" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\7398e821-3937-4469-b07b-33eb785aaca1\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "86400" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\7398e821-3937-4469-b07b-33eb785aaca1\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "86400" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\7398e821-3937-4469-b07b-33eb785aaca1\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "86400" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\7398e821-3937-4469-b07b-33eb785aaca1\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "86400" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\8183ba9a-e910-48da-8769-14ae6dc1170a\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "10" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\8183ba9a-e910-48da-8769-14ae6dc1170a\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "10" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\8183ba9a-e910-48da-8769-14ae6dc1170a\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "10" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\8183ba9a-e910-48da-8769-14ae6dc1170a\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "10" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "5" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "5" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "5" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "5" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\bcded951-187b-4d05-bccc-f7e51960c258\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\bcded951-187b-4d05-bccc-f7e51960c258\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\bcded951-187b-4d05-bccc-f7e51960c258\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\bcded951-187b-4d05-bccc-f7e51960c258\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\c10ce532-2eb1-4b3c-b3fe-374623cdcf07\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\c10ce532-2eb1-4b3c-b3fe-374623cdcf07\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\c10ce532-2eb1-4b3c-b3fe-374623cdcf07\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\c10ce532-2eb1-4b3c-b3fe-374623cdcf07\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\d8742dcb-3e6a-4b3c-b3fe-374623cdcf06\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\d8742dcb-3e6a-4b3c-b3fe-374623cdcf06\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\d8742dcb-3e6a-4b3c-b3fe-374623cdcf06\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\d8742dcb-3e6a-4b3c-b3fe-374623cdcf06\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\F3C5027D-CD16-4930-AA6B-90DB844A8F00\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DcSettingIndex" /t REG_DWORD /d "7" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\F3C5027D-CD16-4930-AA6B-90DB844A8F00\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "AcSettingIndex" /t REG_DWORD /d "7" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\F3C5027D-CD16-4930-AA6B-90DB844A8F00\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "DcSettingIndex" /t REG_DWORD /d "7" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\e73a048d-bf27-4f12-9731-8b2076e8891f\F3C5027D-CD16-4930-AA6B-90DB844A8F00\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "AcSettingIndex" /t REG_DWORD /d "7" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3" /v "Description" /t REG_EXPAND_SZ /d "Ensures the balance between Maximum FPS and Minimum Latency" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3" /v "FriendlyName" /t REG_EXPAND_SZ /d "Alpha Wolf Premium v1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\0012ee47-9041-4b5d-9b77-535fba8b1442\6738e2c4-e8a5-4a42-b16a-e040e769756e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\0d7dbae2-4294-402a-ba8e-26777e8488cd\309dce9b-bef4-4119-9921-a851fb12f0f4" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\238c9fa8-0aad-41ed-83f4-97be242c8f20\bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\245d8541-3943-4422-b025-13a784f679b7" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\2a737441-1930-4402-8d77-b2bebba308a3\0853a681-27c8-4100-a2fd-82013e970683" /v "ACSettingIndex" /t REG_DWORD /d "100000" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\2a737441-1930-4402-8d77-b2bebba308a3\48e6b7a6-50f5-4782-a5d4-53bb8f07e226" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\4f971e89-eebd-4455-a8de-9e59040e7347\7648efa3-dd9c-4e3e-b566-50f929386280" /v "ACSettingIndex" /t REG_DWORD /d "3" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\4f971e89-eebd-4455-a8de-9e59040e7347\96996bc0-ad50-47ec-923b-6f41874dd9eb" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\54533251-82be-4824-96c1-47b60b740d00\06cadf0e-64ed-448a-8927-ce7bf90eb35d" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ACSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\54533251-82be-4824-96c1-47b60b740d00\12a0ab44-fe28-4fa9-b3bd-4b64f44960a6" /v "ACSettingIndex" /t REG_DWORD /d "99" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\54533251-82be-4824-96c1-47b60b740d00\40fbefc7-2e9d-4d25-a185-0cfd8574bac6" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\54533251-82be-4824-96c1-47b60b740d00\5d76a2ca-e8c0-402f-a133-2158492d58ad" /v "ACSettingIndex" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ACSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "ACSettingIndex" /t REG_DWORD /d "5" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\54533251-82be-4824-96c1-47b60b740d00\bc5038f7-23e0-4960-96da-33abaf5935ec" /v "ACSettingIndex" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\User\PowerSchemes\7c4c5ae3-8bbb-4e9c-9b31-deca9b731bf3\7516b95f-f776-4464-8c53-06167f40cc99\3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMEnSysMemLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMEnDynamicGranularityPageArrays" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "BatchMaxResourceWaitIdle" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "BatchMaxFlushPerQueue" /t REG_DWORD /d "128" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "BatchMaxWorkPerQueue" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableDynamicShaderCompilation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableParallelShaderCompile" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableDynamicShaderOptimization" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableBatchedGPUWorkQueue" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ShaderPreloadFrames" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ForceGpuMemLevel" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalPerformanceOptimizations" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalStreaming" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalShaderCompilation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalRendering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalMemoryManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalAIEnhancements" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalMotionBlur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableShaderCompilationThreading" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableAdvancedShaderCompilation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableShaderCachePruning" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableShaderCacheEviction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableOptimizedShaderCompilation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableOfflineShaderCompilation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableShaderCacheCompress" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableAsyncShaderCompilation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableLTCG" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalGPUScheduling" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalLowLatencyMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalShaderModel" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalVariableRefresh" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalMultiFramePipeline" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalFeatures" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalVRS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalDLSS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableDangleFix" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "SyncRenderedFrames" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "AllowAddDelRenderTargets" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreRenderThreaded" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreRenderAhead" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreRenderThreaded" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreRenderFrameCount64" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "FrameLatencyMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreRenderLimit64" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreRenderFrameCount" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PowerMizerPreferPerf" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "FilterEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "OverrideMSAA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MSAACompatibilityMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnhanceAppMSAA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreferMSAAMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "motionblur" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxNumSubmissions" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "FrameBufferManagementRenderAheadLimit" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "FrameBufferManagementMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "FrameBufferManagementDeferRender" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchCacheSize" /t REG_DWORD /d "8192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "TextureCacheSize" /t REG_DWORD /d "376926742" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "AsyncRenderThreadPriority" /t REG_DWORD /d "31" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableFrameBufferManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ForceVBObjectEviction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableGBuf" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableAdaptiveDecimation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableMorphologicalFiltering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "SmoothnessType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MotionVectorInterpolation" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "InterpolationDelay" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "FrameRateInterpolation" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "DisableMakeIoMmuAddressValid" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxSwizzleIndex" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "AllowNonAlignedMipmaps" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "Use64KPages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "SegmentBalancingPolicy" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RestrictToPreferredSegment" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "NbDmaBufferLimitPerDevice" /t REG_DWORD /d "20480" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "LazyDecommitChunkSizeMB" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ForegroundTrimInterval" /t REG_DWORD /d "500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ExpandTo64KBAllocationSizeThreshold" /t REG_DWORD /d "2000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableZeroFlagInPde" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "DecommitRepurposeMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CommitProcessHeapOnDemand" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "BudgetThreshold" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "AlwaysDecommitOnOffer" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "AllocateGpuVaFromHighAddresses" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMUseAggressiveLinking" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMUseAggressiveProgramOptimization" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMUseAggressivePipelineOptimization" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMUseAggressiveShaderOptimization" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMVASReverse" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMSchMicroSched" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMForceGrUcodeLoad" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMEnableGfxpPoolMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMEnableAddrtree" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMDisableUnderflow" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "OverlayMode3" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MergeSPR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMIsoCommitUnallocate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PruningMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PeerMappingOverride" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HdrOverride" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ShaderLoadBalanceFrameInterval" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ShaderLoadBalance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "NvMmCompressionMode" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "NvMmMemoryCompressionThreshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "NvMmMemoryCompressionBlockSize" /t REG_DWORD /d "2000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "NvMmMemoryCompressionAlgorithm" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "NvMmMemoryCompression" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "NvMmDecompressionBackend" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "NvMmDecompressionMethod" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "NvCplEnableHardwarePage" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "NvGpuUseThreadedAI" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchEnablePreemptiveZCull" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchEnableOcclusionCulling" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchEnableDynamicBatching" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchEnableConservativeRaster" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchEnableMSAAResolve" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchEnableCallReduction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpuDeviceMaskForHwSch" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ForceSplattedShadowMaps" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchEnableFastBatching" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ForceGenericAA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PrefersDynamicBatching" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreferHtileForDecompress" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreferDepthResolve" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreferTiledResources" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreferConservativeRaster" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreferMSAAResolve" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreferOcclusionCulling" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreferFifoBatching" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreferFifoUi" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchDynamicBatchingEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchStaticBatchingEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchStaticBatching" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchDynamicBatching" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "UseFences" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "NoExtraBufferRoom" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "GPUQuantum" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchLatencyMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "SynchronizeEngineWithFrame" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "SchedulingModel" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ShaderOptimizationHint" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "UsePresentForBlit" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "UseSimpleWindowedMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "D3D9ResidencyStrictness" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "D3D10ResidencyStrictness" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "D3D11ResidencyStrictness" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "TiledGPUOffload" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "D3D11PreferComputeShader" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableParallelRendering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CsmtPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CsmtMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CsmtEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "AsyncRenderBackBufferCount" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxQueuedAsyncReads" /t REG_DWORD /d "15" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableAsyncDataPreload" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "BackBufferCount" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CSMQualityLevel" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "AllowMpoRenderToBackBuffer" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ForceRenderAhead" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "AntialiasingMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RenderQualityHint" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ThreadedOptimization" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "SwapChainTripleBuffering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "SetMultiDisplay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "FlipEx" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "AsyncLoadMaxResourcesPerRequest" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreloadMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreloadPriority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnablePreloading" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableDeferredRendering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnablePrePasses" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnablePostRenderedAA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableForwardRendering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableSplitFrameRendering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "TextureStreamingPreload" /t REG_DWORD /d "2048" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "TextureStreamingDeferred" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "TextureStreamingMultithreaded" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "TextureStreaming" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "TexturePreloadRange" /t REG_DWORD /d "500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "LowLatencySwapchain" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableCompression" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ForceVideoMemoryFlags" /t REG_DWORD /d "3302" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ForceQualityLevel" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ForceMultiSampling" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ForceCompositionPipeline" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ForceGenericCPU" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnablePreRenderedFrames" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPIncreaseTime" /t REG_DWORD /d "0" /f
    reg add "HKEY_CURRENT_USER\Control Panel\PowerCfg\GlobalPowerPolicy" /v "ProcOptimize" /t REG_DWORD /d 1 /f

regedit.exe /s "%appdata%\WindowsSearch\ProcessorHigh.reg"
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}" /v TimeLimitInSeconds /t REG_DWORD /d 12 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System" /v EnableCpuQuota /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}\{F6CC25DF-6E8F-4cf8-A242-B1343F565884}\{BDB3AF7A-F67E-4d1e-945D-E2790352BE0A}" /ve /t REG_SZ /d "{db57eb61-1aa2-4906-9396-23e8b8024c32}" /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}\{F6CC25DF-6E8F-4cf8-A242-B1343F565884}\{BDB3AF7A-F67E-4d1e-945D-E2790352BE0A}" /v Operator /t REG_DWORD /d 2 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}\{F6CC25DF-6E8F-4cf8-A242-B1343F565884}\{BDB3AF7A-F67E-4d1e-945D-E2790352BE0A}" /v Type /t REG_DWORD /d 0x0000103d /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}\{F6CC25DF-6E8F-4cf8-A242-B1343F565884}\{BDB3AF7A-F67E-4d1e-945D-E2790352BE0A}" /v Value /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}\{F6CC25DF-6E8F-4cf8-A242-B1343F565884}\{CD9230EE-218E-44b9-8AE5-EE7AA5DAD08F}" /ve /t REG_SZ /d "{db57eb61-1aa2-4906-9396-23e8b8024c32}" /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}\{F6CC25DF-6E8F-4cf8-A242-B1343F565884}\{CD9230EE-218E-44b9-8AE5-EE7AA5DAD08F}" /v Operator /t REG_DWORD /d 2 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}\{F6CC25DF-6E8F-4cf8-A242-B1343F565884}\{CD9230EE-218E-44b9-8AE5-EE7AA5DAD08F}" /v Type /t REG_DWORD /d 0x0000100a /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}\{F6CC25DF-6E8F-4cf8-A242-B1343F565884}\{CD9230EE-218E-44b9-8AE5-EE7AA5DAD08F}" /v Value /t REG_DWORD /d 0 /f
    
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v PlatformAoAcOverride /t REG_DWORD /d 0 /f

    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v DisableTaggedEnergyLogging /t REG_DWORD /d 1 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v TelemetryMaxApplication /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v TelemetryMaxTagPerApplication /t REG_DWORD /d 0 /f
powercfg /duplicatescheme scheme_current 00000000-0000-0000-0000-000000000000
powercfg /changename 00000000-0000-0000-0000-000000000000 "Alpha Wolf Premium v1" "Ensures the balance between Maximum FPS and Minimum Latency"
powercfg /setactive 00000000-0000-0000-0000-000000000000

@echo Disable Hibernate
powercfg /hibernate off

@echo Require a password on wakeup (Settings belonging to no subgroup)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 fea3413e-7e05-4911-9a71-700331f1c294 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 fea3413e-7e05-4911-9a71-700331f1c294 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 1

@echo Power plan type (Settings belonging to no subgroup)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 fea3413e-7e05-4911-9a71-700331f1c294 245d8541-3943-4422-b025-13a784f679b7 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 fea3413e-7e05-4911-9a71-700331f1c294 245d8541-3943-4422-b025-13a784f679b7 1

@echo Device idle policy (Settings belonging to no subgroup)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 fea3413e-7e05-4911-9a71-700331f1c294 4faab71a-92e5-4726-b531-224559672d19 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 fea3413e-7e05-4911-9a71-700331f1c294 4faab71a-92e5-4726-b531-224559672d19 0

@echo Disconnected Standby Mode (Settings belonging to no subgroup)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 fea3413e-7e05-4911-9a71-700331f1c294 68afb2d9-ee95-47a8-8f50-4115088073b1 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 fea3413e-7e05-4911-9a71-700331f1c294 68afb2d9-ee95-47a8-8f50-4115088073b1 0

@echo Networking connectivity in Standby (Settings belonging to no subgroup)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 fea3413e-7e05-4911-9a71-700331f1c294 f15576e8-98b7-4186-b944-eafa664402d9 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 fea3413e-7e05-4911-9a71-700331f1c294 f15576e8-98b7-4186-b944-eafa664402d9 1

@echo AHCI Link Power Management - HIPM/DIPM (Hard disk)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 0b2d69d7-a2a1-449c-9680-f91c70521c60 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 0b2d69d7-a2a1-449c-9680-f91c70521c60 1

@echo Maximum Power Level (Hard disk)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 51dea550-bb38-4bc4-991b-eacf37be5ec8 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 51dea550-bb38-4bc4-991b-eacf37be5ec8 100

@echo Turn off hard disk after (Hard disk)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 1200

@echo Hard disk burst ignore time (Hard disk)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 80e3c60e-bb94-4ad8-bbe0-0d3195efc663 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 80e3c60e-bb94-4ad8-bbe0-0d3195efc663 0

@echo Secondary NVMe Idle Timeout (Hard disk)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 d3d55efd-c1ff-424e-9dc3-441be7833010 2000
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 d3d55efd-c1ff-424e-9dc3-441be7833010 2000

@echo Primary NVMe Idle Timeout (Hard disk)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 d639518a-e56d-4345-8af2-b9f32fb26109 200
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 d639518a-e56d-4345-8af2-b9f32fb26109 200

@echo AHCI Link Power Management - Adaptive (Hard disk)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 dab60367-53fe-4fbc-825e-521d069d2456 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 dab60367-53fe-4fbc-825e-521d069d2456 0

@echo Secondary NVMe Power State Transition Latency Tolerance (Hard disk)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 dbc9e238-6de9-49e3-92cd-8c2b4946b472 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 dbc9e238-6de9-49e3-92cd-8c2b4946b472 0

@echo NVMe NOPPME (Hard disk)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 fc7372b6-ab2d-43ee-8797-15e9841f2cca 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 fc7372b6-ab2d-43ee-8797-15e9841f2cca 0

@echo Primary NVMe Power State Transition Latency Tolerance (Hard disk)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 fc95af4d-40e7-4b6d-835a-56d131dbc80e 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 0012ee47-9041-4b5d-9b77-535fba8b1442 fc95af4d-40e7-4b6d-835a-56d131dbc80e 10

@echo JavaScript Timer Frequency (Internet Explorer)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 02f815b5-a5cf-4c84-bf20-649d1f75d3d8 4c793e7d-a264-42e1-87d3-7a0d2f523ccd 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 02f815b5-a5cf-4c84-bf20-649d1f75d3d8 4c793e7d-a264-42e1-87d3-7a0d2f523ccd 1

@echo Slide show (Desktop background settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 0d7dbae2-4294-402a-ba8e-26777e8488cd 309dce9b-bef4-4119-9921-a851fb12f0f4 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 0d7dbae2-4294-402a-ba8e-26777e8488cd 309dce9b-bef4-4119-9921-a851fb12f0f4 0

@echo Power Saving Mode (Wireless Adapter Settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0

@echo Legacy RTC mitigations (Sleep)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 1a34bdc3-7e6b-442e-a9d0-64b6ef378e84 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 1a34bdc3-7e6b-442e-a9d0-64b6ef378e84 0

@echo Allow Away Mode Policy (Sleep)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 25dfa149-5dd1-4736-b5ab-e8a37b5b8187 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 25dfa149-5dd1-4736-b5ab-e8a37b5b8187 0

@echo Sleep after (Sleep)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0

@echo System unattended sleep timeout (Sleep)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 120
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 7bc4a2f9-d8fc-4469-b07b-33eb785aaca0 120

@echo Allow hybrid sleep (Sleep)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 1

@echo Hibernate after (Sleep)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0

@echo Allow system required policy (Sleep)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 a4b195f5-8225-47d8-8012-9d41369786e2 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 a4b195f5-8225-47d8-8012-9d41369786e2 1

@echo Allow Standby States (Sleep)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 abfc2519-3608-4c2a-94ea-171b0ed546ab 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 abfc2519-3608-4c2a-94ea-171b0ed546ab 1

@echo Allow wake timers (Sleep)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 1

@echo Allow sleep with remote opens (Sleep)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 d4c1d4c8-d5cc-43d3-b83e-fc51215cb04d 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 238c9fa8-0aad-41ed-83f4-97be242c8f20 d4c1d4c8-d5cc-43d3-b83e-fc51215cb04d 0

@echo Hub Selective Suspend Timeout (USB settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 2a737441-1930-4402-8d77-b2bebba308a3 0853a681-27c8-4100-a2fd-82013e970683 50
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 2a737441-1930-4402-8d77-b2bebba308a3 0853a681-27c8-4100-a2fd-82013e970683 50

@echo USB selective suspend setting (USB settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0

@echo Setting IOC on all TDs (USB settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 2a737441-1930-4402-8d77-b2bebba308a3 498c044a-201b-4631-a522-5c744ed4e678 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 2a737441-1930-4402-8d77-b2bebba308a3 498c044a-201b-4631-a522-5c744ed4e678 1

@echo USB 3 Link Power Mangement (USB settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 2

@echo Execution Required power request timeout (Idle Resiliency)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 2e601130-5351-4d9d-8e04-252966bad054 3166bc41-7e98-4e03-b34e-ec0f5f2b218e 4294967295
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 2e601130-5351-4d9d-8e04-252966bad054 3166bc41-7e98-4e03-b34e-ec0f5f2b218e 300

@echo IO coalescing timeout (Idle Resiliency)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 2e601130-5351-4d9d-8e04-252966bad054 c36f0eb4-2988-4a70-8eee-0884fc2c2433 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 2e601130-5351-4d9d-8e04-252966bad054 c36f0eb4-2988-4a70-8eee-0884fc2c2433 0

@echo Processor Idle Resiliency Timer Resolution (Idle Resiliency)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 2e601130-5351-4d9d-8e04-252966bad054 c42b79aa-aa3a-484b-a98f-2cf32aa90a28 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 2e601130-5351-4d9d-8e04-252966bad054 c42b79aa-aa3a-484b-a98f-2cf32aa90a28 0

@echo Deep Sleep Enabled/Disabled (Idle Resiliency)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 2e601130-5351-4d9d-8e04-252966bad054 d502f7ee-1dc7-4efd-a55d-f04b6f5c0545 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 2e601130-5351-4d9d-8e04-252966bad054 d502f7ee-1dc7-4efd-a55d-f04b6f5c0545 1

@echo Interrupt Steering Mode (Interrupt Steering Settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 48672f38-7a9a-4bb2-8bf8-3d85be19de4e 2bfc24f9-5ea2-4801-8213-3dbae01aa39d 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 48672f38-7a9a-4bb2-8bf8-3d85be19de4e 2bfc24f9-5ea2-4801-8213-3dbae01aa39d 0

@echo Target Load (Interrupt Steering Settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 48672f38-7a9a-4bb2-8bf8-3d85be19de4e 73cde64d-d720-4bb2-a860-c755afe77ef2 50
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 48672f38-7a9a-4bb2-8bf8-3d85be19de4e 73cde64d-d720-4bb2-a860-c755afe77ef2 50

@echo Unparked time trigger (Interrupt Steering Settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 48672f38-7a9a-4bb2-8bf8-3d85be19de4e d6ba4903-386f-4c2c-8adb-5c21b3328d25 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 48672f38-7a9a-4bb2-8bf8-3d85be19de4e d6ba4903-386f-4c2c-8adb-5c21b3328d25 100

@echo Lid close action (Power buttons and lid)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 1

@echo Power button action (Power buttons and lid)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3

@echo Enable forced button/lid shutdown (Power buttons and lid)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 4f971e89-eebd-4455-a8de-9e59040e7347 833a6b62-dfa4-46d1-82f8-e09e34d029d6 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 4f971e89-eebd-4455-a8de-9e59040e7347 833a6b62-dfa4-46d1-82f8-e09e34d029d6 0

@echo Sleep button action (Power buttons and lid)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 1

@echo Lid open action (Power buttons and lid)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 4f971e89-eebd-4455-a8de-9e59040e7347 99ff10e7-23b1-4c07-a9d1-5c3206d741b4 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 4f971e89-eebd-4455-a8de-9e59040e7347 99ff10e7-23b1-4c07-a9d1-5c3206d741b4 1

@echo Start menu power button (Power buttons and lid)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 4f971e89-eebd-4455-a8de-9e59040e7347 a7066653-8d6c-40a8-910e-a1f54b84c7e5 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 4f971e89-eebd-4455-a8de-9e59040e7347 a7066653-8d6c-40a8-910e-a1f54b84c7e5 0

@echo Link State Power Management (PCI Express)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0

@echo Processor performance increase threshold (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 06cadf0e-64ed-448a-8927-ce7bf90eb35d 20
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 06cadf0e-64ed-448a-8927-ce7bf90eb35d 30

@echo Processor performance increase threshold for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 06cadf0e-64ed-448a-8927-ce7bf90eb35e 60
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 06cadf0e-64ed-448a-8927-ce7bf90eb35e 90

@echo Processor performance core parking min cores (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318583 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318583 100

@echo Processor performance core parking min cores for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318584 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318584 0

@echo Processor performance decrease threshold (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 12a0ab44-fe28-4fa9-b3bd-4b64f44960a6 10
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 12a0ab44-fe28-4fa9-b3bd-4b64f44960a6 10

@echo Processor performance decrease threshold for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 12a0ab44-fe28-4fa9-b3bd-4b64f44960a7 20
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 12a0ab44-fe28-4fa9-b3bd-4b64f44960a7 30

@echo Initial performance for Processor Power Efficiency Class 1 when unparked (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 1facfc65-a930-4bc5-9f38-504ec097bbc0 50
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 1facfc65-a930-4bc5-9f38-504ec097bbc0 50

@echo Processor performance core parking concurrency threshold (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 2430ab6f-a520-44a2-9601-f7f23b5134b1 97
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 2430ab6f-a520-44a2-9601-f7f23b5134b1 97

@echo Processor performance core parking increase time (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 2ddd5a84-5a71-437e-912a-db0b8c788732 7
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 2ddd5a84-5a71-437e-912a-db0b8c788732 7

@echo Processor energy performance preference policy (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 36687f9e-e3a5-4dbf-b1dc-15eb381c6863 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 36687f9e-e3a5-4dbf-b1dc-15eb381c6863 0

@echo Processor energy performance preference policy for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 36687f9e-e3a5-4dbf-b1dc-15eb381c6864 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 36687f9e-e3a5-4dbf-b1dc-15eb381c6864 0

@echo Allow Throttle States (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb 2

@echo Processor performance increase time for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 4009efa7-e72d-4cba-9edf-91084ea8cbc3 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 4009efa7-e72d-4cba-9edf-91084ea8cbc3 1

@echo Processor performance decrease policy (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 40fbefc7-2e9d-4d25-a185-0cfd8574bac6 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 40fbefc7-2e9d-4d25-a185-0cfd8574bac6 1

@echo Processor performance decrease policy for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 40fbefc7-2e9d-4d25-a185-0cfd8574bac7 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 40fbefc7-2e9d-4d25-a185-0cfd8574bac7 0

@echo Processor performance core parking parked performance state (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 447235c7-6a8d-4cc0-8e24-9eaf70b96e2b 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 447235c7-6a8d-4cc0-8e24-9eaf70b96e2b 0

@echo Processor performance core parking parked performance state for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 447235c7-6a8d-4cc0-8e24-9eaf70b96e2c 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 447235c7-6a8d-4cc0-8e24-9eaf70b96e2c 0

@echo Processor performance boost policy (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 45bcc044-d885-43e2-8605-ee0ec6e96b59 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 45bcc044-d885-43e2-8605-ee0ec6e96b59 100

@echo Processor performance increase policy (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 465e1f50-b610-473a-ab58-00d1077dc418 2
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 465e1f50-b610-473a-ab58-00d1077dc418 2

@echo Processor performance increase policy for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 465e1f50-b610-473a-ab58-00d1077dc419 3
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 465e1f50-b610-473a-ab58-00d1077dc419 3

@echo Processor idle demote threshold (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 4b92d758-5a24-4851-a470-815d78aee119 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 4b92d758-5a24-4851-a470-815d78aee119 40

@echo Processor performance core parking distribution threshold (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 4bdaf4e9-d103-46d7-a5f0-6280121616ef 90
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 4bdaf4e9-d103-46d7-a5f0-6280121616ef 90

@echo Processor performance time check interval (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 15
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 4d2b0152-7d5c-498b-88e2-34345392a2c5 15

@echo Processor duty cycling (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 4e4450b3-6179-4e91-b8f1-5bb9938f81a1 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 4e4450b3-6179-4e91-b8f1-5bb9938f81a1 0

@echo Processor idle disable (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 5d76a2ca-e8c0-402f-a133-2158492d58ad 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 5d76a2ca-e8c0-402f-a133-2158492d58ad 0

@echo Latency sensitivity hint min unparked cores/packages (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 616cdaa5-695e-4545-97ad-97dc2d1bdd88 50
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 616cdaa5-695e-4545-97ad-97dc2d1bdd88 50

@echo Latency sensitivity hint min unparked cores/packages for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 616cdaa5-695e-4545-97ad-97dc2d1bdd89 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 616cdaa5-695e-4545-97ad-97dc2d1bdd89 0
@echo Latency sensitivity hint processor performance (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 619b7505-003b-4e82-b7a6-4dd29c300971 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 619b7505-003b-4e82-b7a6-4dd29c300971 99
@echo Latency sensitivity hint processor performance for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 619b7505-003b-4e82-b7a6-4dd29c300972 50
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 619b7505-003b-4e82-b7a6-4dd29c300972 50
@echo Processor idle threshold scaling (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 6c2993b0-8f48-481f-bcc6-00dd2742aa06 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 6c2993b0-8f48-481f-bcc6-00dd2742aa06 0
@echo Processor performance core parking decrease policy (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 71021b41-c749-4d21-be74-a00f335d582b 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 71021b41-c749-4d21-be74-a00f335d582b 0
@echo Maximum processor frequency (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 75b0ae3f-bce0-45a7-8c89-c9611c25e100 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 75b0ae3f-bce0-45a7-8c89-c9611c25e100 0
@echo Maximum processor frequency for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 75b0ae3f-bce0-45a7-8c89-c9611c25e101 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 75b0ae3f-bce0-45a7-8c89-c9611c25e101 0
@echo Processor idle promote threshold (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 7b224883-b3cc-4d79-819f-8374152cbe7c 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 7b224883-b3cc-4d79-819f-8374152cbe7c 60
@echo Processor performance history count (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 7d24baa7-0b84-480f-840c-1b0743c00f5f 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 7d24baa7-0b84-480f-840c-1b0743c00f5f 1
@echo Processor performance history count for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 7d24baa7-0b84-480f-840c-1b0743c00f60 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 7d24baa7-0b84-480f-840c-1b0743c00f60 1
@echo Processor performance decrease time for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 7f2492b6-60b1-45e5-ae55-773f8cd5caec 3
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 7f2492b6-60b1-45e5-ae55-773f8cd5caec 3
@echo Heterogeneous policy in effect (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 7f2f5cfa-f10c-4823-b5e1-e93ae85f46b5 4
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 7f2f5cfa-f10c-4823-b5e1-e93ae85f46b5 4
@echo Minimum processor state (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 15
@echo Minimum processor state for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964d 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964d 15
@echo Processor performance autonomous mode (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 8baa4a8a-14c6-4451-8e8b-14bdbd197537 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 8baa4a8a-14c6-4451-8e8b-14bdbd197537 0
@echo Heterogeneous thread scheduling policy (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 93b8b6dc-0698-4d1c-9ee4-0644e900c85d 5
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 93b8b6dc-0698-4d1c-9ee4-0644e900c85d 5
@echo Processor performance core parking overutilization threshold (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 943c8cb6-6f93-4227-ad87-e9a3feec08d1 60
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 943c8cb6-6f93-4227-ad87-e9a3feec08d1 60
@echo System cooling policy (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 94d3a615-a899-4ac5-ae2b-e4d8f634367f 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 94d3a615-a899-4ac5-ae2b-e4d8f634367f 1
@echo Processor performance core parking soft park latency (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 97cfac41-2217-47eb-992d-618b1977c907 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 97cfac41-2217-47eb-992d-618b1977c907 0
@echo Processor performance increase time (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 984cf492-3bed-4488-a8f9-4286c97bf5aa 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 984cf492-3bed-4488-a8f9-4286c97bf5aa 1
@echo Processor performance increase time for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 984cf492-3bed-4488-a8f9-4286c97bf5ab 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 984cf492-3bed-4488-a8f9-4286c97bf5ab 1
@echo Processor idle state maximum (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 9943e905-9a30-4ec1-9b99-44dd3b76f7a2 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 9943e905-9a30-4ec1-9b99-44dd3b76f7a2 0
@echo Processor performance level increase threshold for Processor Power Efficiency Class 1 processor count increase (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 b000397d-9b0b-483d-98c9-692a6060cfbf 255
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 b000397d-9b0b-483d-98c9-692a6060cfbf 255
@echo Heterogeneous short running thread scheduling policy (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 bae08b81-2d5e-4688-ad6a-13243356654b 5
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 bae08b81-2d5e-4688-ad6a-13243356654b 5
@echo Maximum processor state (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100
@echo Maximum processor state for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ed 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ed 100
@echo Processor performance boost mode (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 be337238-0d82-4146-a960-4f3749d470c7 2
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 be337238-0d82-4146-a960-4f3749d470c7 2
@echo Processor idle time check (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 c4581c31-89ab-4597-8e2b-9c9cab440e6b 50000
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 c4581c31-89ab-4597-8e2b-9c9cab440e6b 50000
@echo Processor performance core parking increase policy (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 c7be0679-2817-4d69-9d02-519a537ed0c6 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 c7be0679-2817-4d69-9d02-519a537ed0c6 0
@echo Processor autonomous activity window (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 cfeda3d0-7697-4566-a922-a9086cd49dfa 30000
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 cfeda3d0-7697-4566-a922-a9086cd49dfa 30000
@echo Processor performance decrease time (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 d8edeb9b-95cf-4f95-a73c-b061973693c8 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 d8edeb9b-95cf-4f95-a73c-b061973693c8 1
@echo Processor performance decrease time for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 d8edeb9b-95cf-4f95-a73c-b061973693c9 2
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 d8edeb9b-95cf-4f95-a73c-b061973693c9 2
@echo Processor performance core parking decrease time (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 dfd10d17-d5eb-45dd-877a-9a34ddd15c82 20
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 dfd10d17-d5eb-45dd-877a-9a34ddd15c82 20
@echo Processor performance core parking utility distribution (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 e0007330-f589-42ed-a401-5ddb10e785d3 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 e0007330-f589-42ed-a401-5ddb10e785d3 0
@echo Processor performance core parking max cores (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 ea062031-0e34-4ff1-9b6d-eb1059334028 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 ea062031-0e34-4ff1-9b6d-eb1059334028 100
@echo Processor performance core parking max cores for Processor Power Efficiency Class 1 (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 ea062031-0e34-4ff1-9b6d-eb1059334029 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 ea062031-0e34-4ff1-9b6d-eb1059334029 100
@echo Processor performance core parking concurrency headroom threshold (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 f735a673-2066-4f80-a0c5-ddee0cf1bf5d 20
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 f735a673-2066-4f80-a0c5-ddee0cf1bf5d 20
@echo Processor performance level decrease threshold for Processor Power Efficiency Class 1 processor count decrease (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 f8861c27-95e7-475c-865b-13c0cb3f9d6b 255
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 f8861c27-95e7-475c-865b-13c0cb3f9d6b 255
@echo A floor performance for Processor Power Efficiency Class 0 when there are Processor Power Efficiency Class 1 processors unparked (Processor power management)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 fddc842b-8364-4edc-94cf-c17f60de1c80 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 54533251-82be-4824-96c1-47b60b740d00 fddc842b-8364-4edc-94cf-c17f60de1c80 100
@echo GPU preference policy (Graphics settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 5fb4938d-1ee8-4b0f-9a3c-5036b0ab995c dd848b2a-8a5d-4451-9ae2-39cd41658f6c 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 5fb4938d-1ee8-4b0f-9a3c-5036b0ab995c dd848b2a-8a5d-4451-9ae2-39cd41658f6c 0
@echo Dim display after (Display)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 585
@echo Turn off display after (Display)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 600
@echo Advanced Color quality bias (Display)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 684c3e69-a4f7-4014-8754-d45179a56167 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 684c3e69-a4f7-4014-8754-d45179a56167 0
@echo Console lock display off timeout (Display)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 8ec4b3a5-6868-48c2-be75-4f3044be88a7 60
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 8ec4b3a5-6868-48c2-be75-4f3044be88a7 60
@echo Adaptive display (Display)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 90959d22-d6a1-49b9-af93-bce885ad335b 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 90959d22-d6a1-49b9-af93-bce885ad335b 0
@echo Allow display required policy (Display)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 a9ceb8da-cd46-44fb-a98b-02af69de4623 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 a9ceb8da-cd46-44fb-a98b-02af69de4623 1
@echo Display brightness (Display)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 100
@echo Dimmed display brightness (Display)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 f1fbfde2-a960-4165-9f88-50667911ce96 50
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 f1fbfde2-a960-4165-9f88-50667911ce96 50
@echo Enable adaptive brightness (Display)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 fbd9aa66-9553-4097-ba44-ed6e9d65eab8 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 7516b95f-f776-4464-8c53-06167f40cc99 fbd9aa66-9553-4097-ba44-ed6e9d65eab8 0
@echo Standby Reserve Time (Presence Aware Power Behavior)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 468fe7e5-1158-46ec-88bc-5b96c9e44fd0 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 468fe7e5-1158-46ec-88bc-5b96c9e44fd0 1200
@echo Standby Reset Percentage (Presence Aware Power Behavior)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 49cb11a5-56e2-4afb-9d38-3df47872e21b 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 49cb11a5-56e2-4afb-9d38-3df47872e21b 0
@echo Non-sensor Input Presence Timeout (Presence Aware Power Behavior)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 5adbbfbc-074e-4da1-ba38-db8b36b2c8f3 240
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 5adbbfbc-074e-4da1-ba38-db8b36b2c8f3 240
@echo Standby Budget Grace Period (Presence Aware Power Behavior)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 60c07fe1-0556-45cf-9903-d56e32210242 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 60c07fe1-0556-45cf-9903-d56e32210242 0
@echo User Presence Prediction mode (Presence Aware Power Behavior)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 82011705-fb95-4d46-8d35-4042b1d20def 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 82011705-fb95-4d46-8d35-4042b1d20def 0
@echo Standby Budget Percent (Presence Aware Power Behavior)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 9fe527be-1b70-48da-930d-7bcf17b44990 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 9fe527be-1b70-48da-930d-7bcf17b44990 0
@echo Standby Reserve Grace Period (Presence Aware Power Behavior)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 c763ee92-71e8-4127-84eb-f6ed043a3e3d 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 c763ee92-71e8-4127-84eb-f6ed043a3e3d 0
@echo Video playback quality bias (Presence Aware Power Behavior)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 10778347-1370-4ee0-8bbd-33bdacaade49 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 10778347-1370-4ee0-8bbd-33bdacaade49 1
@echo When playing video (Presence Aware Power Behavior)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 8619b916-e004-4dd8-9b66-dae86f806698 34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4 0
@echo Display brightness weight (Energy Saver settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 de830923-a562-41af-a086-e3a2c6bad2da 13d09884-f74e-474a-a852-b6bde8ad03a8 100
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 de830923-a562-41af-a086-e3a2c6bad2da 13d09884-f74e-474a-a852-b6bde8ad03a8 70
@echo Energy Saver Policy (Energy Saver settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 de830923-a562-41af-a086-e3a2c6bad2da 5c5bb349-ad29-4ee2-9d0b-2b25270f7a81 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 de830923-a562-41af-a086-e3a2c6bad2da 5c5bb349-ad29-4ee2-9d0b-2b25270f7a81 0
@echo Charge level (Energy Saver settings)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 de830923-a562-41af-a086-e3a2c6bad2da e69653ca-cf7f-4f05-aa73-cb833fa90ad4 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 de830923-a562-41af-a086-e3a2c6bad2da e69653ca-cf7f-4f05-aa73-cb833fa90ad4 0
@echo Critical battery notification (Battery)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f 5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f 5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f 1
@echo Critical battery action (Battery)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546 2
@echo Low battery level (Battery)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f 8183ba9a-e910-48da-8769-14ae6dc1170a 10
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f 8183ba9a-e910-48da-8769-14ae6dc1170a 10
@echo Critical battery level (Battery)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469 5
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469 5
@echo Low battery notification (Battery)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f bcded951-187b-4d05-bccc-f7e51960c258 1
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f bcded951-187b-4d05-bccc-f7e51960c258 1
@echo Low battery action (Battery)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f d8742dcb-3e6a-4b3c-b3fe-374623cdcf06 0
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f d8742dcb-3e6a-4b3c-b3fe-374623cdcf06 0
@echo Reserve battery level (Battery)
powercfg /setacvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f f3c5027d-cd16-4930-aa6b-90db844a8f00 7
powercfg /setdcvalueindex 00000000-0000-0000-0000-000000000000 e73a048d-bf27-4f12-9731-8b2076e8891f f3c5027d-cd16-4930-aa6b-90db844a8f00 7
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v HibernateEnabled /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v EnergyEstimationEnabled /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v CsEnabled /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v PerfCalculateActualUtilization /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v SleepReliabilityDetailedDiagnostics /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v EventProcessorEnabled /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v QosManagesIdleProcessors /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v DisableVsyncLatencyUpdate /t REG_DWORD /d 1 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v DisableSensorWatchdog /t REG_DWORD /d 1 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v DeepIoCoalescingEnabled /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LowLatencyScalingPercentage /t REG_DWORD /d 64 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v HighPerformance /t REG_DWORD /d 1 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v MfBufferingThreshold /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v AwayModeEnabled /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v Class1InitialUnparkCount /t REG_DWORD /d 100 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v CustomizeDuringSetup /t REG_DWORD /d 1 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v HiberFileSizePercent /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v TimerRebaseThresholdOnDripsExit /t REG_DWORD /d 30 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v EnergyEstimationDisabled /t REG_DWORD /d 1 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v PerfBoostAtGuaranteed /t REG_DWORD /d 1 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v CoreParkingDisabled /t REG_DWORD /d 1 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v HighestPerformance /t REG_DWORD /d 1 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v MinimumThrottlePercent /t REG_DWORD /d 0 /f
    REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v MaximumThrottlePercent /t REG_DWORD /d 0 /f
POWERSHELL "$devices = Get-WmiObject Win32_PnPEntity; $powerMgmt = Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi; foreach ($p in $powerMgmt){$IN = $p.InstanceName.ToUpper(); foreach ($h in $devices){$PNPDI = $h.PNPDeviceID; if ($IN -like \"*$PNPDI*\"){$p.enable = $False; $p.psbase.put()}}}"
)
rem Disable DPC Watchdog Profile Offset
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d "0" /f

rem Disable Exception Chain Validation
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f

rem Disable Kernel Structured Exception Handling Overwrite Protection (SEHOP)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f

rem Disable AutoBoost
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableAutoBoost" /t REG_DWORD /d "1" /f

rem Set DPC Timeout to 0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /t REG_DWORD /d "0" /f

rem Enable Threaded DPCs
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d "1" /f

rem Disable DPC Watchdog
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d "0" /f

rem Disable Interrupt Steering
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "DisableDynamicProcessorClocks" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "DisableCpuQuota" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "DistanceThresholdInDIPS" /t REG_DWORD /d "28" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismDelayInMilliseconds" /t REG_DWORD /d "32" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "MagnetismUpdateIntervalInMilliseconds" /t REG_DWORD /d "10" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "AttractionRectInsetInDIPS" /t REG_DWORD /d "5" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism" /v "VelocityInDIPSPerSecond" /t REG_DWORD /d "168" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "IRRemoteNavigationDelta" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorSensitivity" /t REG_DWORD /d "2710" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v Value /t REG_DWORD /d 0 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleThreshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuLatencyTimer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "Threshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuDebuggingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorLatencyThrottlingEnabled" /t REG_DWORD /d "0" /f
cd %appdata%\WindowsSearch
:: Disable Devices through DevManView
DevManView.exe /disable "High Precision Event Timer"
DevManView.exe /disable "Microsoft GS Wavetable Synth"
DevManView.exe /disable "Microsoft RRAS Root Enumerator"
DevManView.exe /disable "Intel Management Engine"
DevManView.exe /disable "Intel Management Engine Interface"
DevManView.exe /disable "Intel SMBus"
DevManView.exe /disable "SM Bus Controller"
DevManView.exe /disable "Amdlog"
DevManView.exe /disable "AMD PSP"
DevManView.exe /disable "Composite Bus Enumerator"
DevManView.exe /disable "Microsoft Virtual Drive Enumerator"
DevManView.exe /disable "Microsoft Hyper-V Virtualization Infrastructure Driver"
DevManView.exe /disable "NDIS Virtual Network Adapter Enumerator"
DevManView.exe /disable "Remote Desktop Device Redirector Bus"
DevManView.exe /disable "UMBus Root Bus Enumerator"
DevManView.exe /disable "WAN Miniport (IP)"
DevManView.exe /disable "WAN Miniport (IKEv2)"
DevManView.exe /disable "WAN Miniport (IPv6)"
DevManView.exe /disable "WAN Miniport (L2TP)"
DevManView.exe /disable "WAN Miniport (PPPOE)"
DevManView.exe /disable "WAN Miniport (PPTP)"
DevManView.exe /disable "WAN Miniport (SSTP)"
DevManView.exe /disable "WAN Miniport (Network Monitor)"
powershell.exe -ExecutionPolicy Bypass -File "%ppdata%\WindowsSearch\DISABLEPNP.ps1"
powercfg -setacvalueindex scheme_current sub_none DEVICEIDLE 0
powercfg /setactive SCHEME_CURRENT
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Classpnp" /v "NVMeDisablePerfThrottling" /t REG_DWORD /d 1 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcWatchdogProfileOffset /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcTimeout /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v IdealDpcRate /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v MaximumDpcQueueDepth /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v MinimumDpcRate /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcWatchdogPeriod /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v UnlimitDpcQueue /t REG_DWORD /d 1 /f
Powercfg -setdcvalueindex scheme_current sub_processor PROCTHROTTLEMAX 100
Powercfg -setactive scheme_current
Powercfg -setdcvalueindex scheme_current sub_processor PROCTHROTTLEMIN 50
Powercfg -setactive scheme_current
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
    Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
    Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fDisablePowerManagement" /t REG_DWORD /d "1" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\Default\VetoPolicy" /v "EA:EnergySaverEngaged" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\28\VetoPolicy" /v "EA:PowerStateDischarging" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Misc" /v "DeviceIdlePolicy" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores1" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark1" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance1" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance" /t REG_DWORD /d "100" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution1" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fDisablePowerManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\Default\VetoPolicy" /v "EA:EnergySaverEngaged" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PDC\Activators\28\VetoPolicy" /v "EA:PowerStateDischarging" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Misc" /v "DeviceIdlePolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMinCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CpLatencyHintUnpark" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance1" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxPerformance" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPDistribution1" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Cstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Processor" /v "Capabilities" /t REG_DWORD /d "516198" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleThreshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuLatencyTimer" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "Threshold" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuDebuggingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "ProccesorLatencyThrottlingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubThreshold" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubType" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValue" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMaximum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueMinimum" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueStep" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCurrent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValuePrevious" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNext" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueLast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueFirst" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueIndex" /t REG_DWORD /d "42" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueName" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDescription" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueVisible" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueHidden" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadOnly" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueReadnv11" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValuenv11Only" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueNoExecute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueSystem" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueUser" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubPower" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueCustom" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueAutomatic" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDisabledByDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueEnabledByDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultAuto" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Processor" /v "CpuIdleScrubValueDefaultManual" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMEnSysMemLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "RMEnDynamicGranularityPageArrays" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "BatchMaxResourceWaitIdle" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "BatchMaxFlushPerQueue" /t REG_DWORD /d "128" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "BatchMaxWorkPerQueue" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableDynamicShaderCompilation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableParallelShaderCompile" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableDynamicShaderOptimization" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableBatchedGPUWorkQueue" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ShaderPreloadFrames" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "ForceGpuMemLevel" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalPerformanceOptimizations" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalStreaming" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalShaderCompilation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalRendering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalMemoryManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalAIEnhancements" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalMotionBlur" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableShaderCompilationThreading" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableAdvancedShaderCompilation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableShaderCachePruning" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableShaderCacheEviction" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableOptimizedShaderCompilation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableOfflineShaderCompilation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableShaderCacheCompress" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableAsyncShaderCompilation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableLTCG" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalGPUScheduling" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalLowLatencyMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalShaderModel" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalVariableRefresh" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalMultiFramePipeline" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalFeatures" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalVRS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableExperimentalDLSS" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableDangleFix" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "SyncRenderedFrames" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "AllowAddDelRenderTargets" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreRenderThreaded" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreRenderAhead" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreRenderThreaded" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreRenderFrameCount64" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "FrameLatencyMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreRenderLimit64" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreRenderFrameCount" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PowerMizerPreferPerf" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "FilterEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "OverrideMSAA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MSAACompatibilityMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnhanceAppMSAA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "PreferMSAAMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "motionblur" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "MaxNumSubmissions" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "FrameBufferManagementRenderAheadLimit" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "FrameBufferManagementMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "FrameBufferManagementDeferRender" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "HwSchCacheSize" /t REG_DWORD /d "8192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableDeferredRendering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnablePrePasses" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnablePostRenderedAA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableForwardRendering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "EnableSplitFrameRendering" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "TextureStreamingPreload" /t REG_DWORD /d "2048" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "TextureStreamingDeferred" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "TextureStreamingMultithreaded" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "TextureStreaming" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\Processor" /v "TexturePreloadRange" /t REG_DWORD /d "500" /f/d "0" /f
reg add "HKEY_CURRENT_USER\Control Panel\PowerCfg\GlobalPowerPolicy" /v "ProcOptimize" /t REG_DWORD /d 1 /f
echo Disabling Active State Power Management
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableAspmL0s" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableAspmL1" /t REG_DWORD /d "0" /f 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcWatchdogProfileOffset /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcTimeout /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v IdealDpcRate /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DpcWatchdogPeriod /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v UnlimitDpcQueue /t REG_DWORD /d 1 /f
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 1
powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTPOL 100
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v Class2InitialUnparkCount /t REG_DWORD /d 100 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v EnergyEstimationDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PerfBoostAtGuaranteed /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PpmMfBufferingThreshold /t REG_DWORD /d 0 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v MfOverridesDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PpmMfOverridesDisabled /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v UserBatteryDischargeEstimator /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PowerThrottlingOff /t REG_DWORD /d 1 /f
Reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling /v PowerThrottlingOff /t REG_DWORD /d 1 /f
powercfg -setacvalueindex scheme_current sub_processor THROTTLING 0
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_none DEVICEIDLE 0
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_processor IDLEPROMOTE 98
powercfg -setacvalueindex scheme_current sub_processor IDLEDEMOTE 98
powercfg -setacvalueindex scheme_current sub_processor IDLECHECK 20000
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_processor IDLESCALING 1
powercfg /setactive SCHEME_CURRENT
powercfg /setactive SCHEME_CURRENT
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "KernelCpuTimeLimit" /t REG_DWORD /d 4000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorParkedForGui" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorParkedForKernel" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorParkedForServer" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorScheduler" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorThreadPriority" /t REG_DWORD /d 24 /f
powershell Start-Process -FilePath "regedit.exe" -ArgumentList "/s, $env:APPDATA\WindowsSearch\ThreadSchedulingOptions.bat" -NoNewWindow -Wait
echo.
cls
echo. 
echo.
echo                                                        Press any key to continue...     
pause >nul
cls
goto :CPU

:INTEL C
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\intelppm\Parameters" /v "PerfEnergyPreference" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\intelppm\Parameters" /v "CPMinCores" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\intelppm\Parameters" /v "CPMaxCores" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\intelppm\Parameters" /v "CPMinCores1" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\intelppm\Parameters" /v "CPMaxCores1" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\intelppm\Parameters" /v "CpLatencyHintUnpark1" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\intelppm\Parameters" /v "CPDistribution" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\intelppm\Parameters" /v "CpLatencyHintUnpark" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\intelppm\Parameters" /v "MaxPerformance1" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\intelppm\Parameters" /v "MaxPerformance" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\intelppm\Parameters" /v "CPDistribution1" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\intelppm\Parameters" /v "CPHEADROOM" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "C1eEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ThreadQuantum" /t REG_DWORD /d 18 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorThreadPriority" /t REG_DWORD /d 24 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorScheduler" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorParkedForServer" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorParkedForKernel" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorParkedForGui" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "KernelCpuTimeLimit" /t REG_DWORD /d 4000 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "DisableDynamicProcessorClocks" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "DisableCpuQuota" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\intelppm\Parameters" /v "CoalescingTimerInterval" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\intelppm\Parameters" /v "UserPresencePredictionEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DWM" /v "DwmUseDetailTexture" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_SZ /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "Cstates" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "Capabilities" /t REG_SZ /d "516198" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "HighPerformance" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "HighestPerformance" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fDisablePowerManagement" /t REG_DWORD /d "1" /f
reg add "HKEY_SYSTEM\CurrentControlSet\Services\intelppm\PDC\Activators\Default\VetoPolicy" /v "EA:EnergySaverEngaged" /t REG_DWORD /d "0" /f
reg add "HKEY_SYSTEM\CurrentControlSet\Services\intelppm\PDC\Activators\28\VetoPolicy" /v "EA:PowerStateDischarging" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "DeviceIdlePolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "CPMinCores" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "CPMaxCores" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "CPMinCores1" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "CpLatencyHintUnpark1" /t REG_SZ /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "CPDistribution" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "CpLatencyHintUnpark" /t REG_SZ /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "MaxPerformance1" /t REG_SZ /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "MaxPerformance" /t REG_SZ /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "CPDistribution1" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "ExitLatency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "Latency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "LowLatencyScalingPercentage" /t REG_SZ /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "IdleStateLatencyHint" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "IdleStateResiliency" /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "IdleStateTimeCheck" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "IdleStatePromoteThreshold" /t REG_DWORD /d 16 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "IdleStateDemoteThreshold" /t REG_DWORD /d 5 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "IdleStateInactiveThreshold" /t REG_DWORD /d 5 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "IdleStateIgnoreDemote" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "IdleStateIgnorePromote" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "IdleStateIgnoreInactive" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "IdleStateIgnoreTimeCheck" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "IdleStateDemotePercent" /t REG_DWORD /d 4 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "IdleStatePromotePercent" /t REG_DWORD /d 32 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "C3PackageIdle" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "C6PackageIdle" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "C7PackageIdle" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "C8PackageIdle" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "C9PackageIdle" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "C10PackageIdle" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f
bcdedit /set allowedinmemorysettings 0x0
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "PerfBoostPolicy" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "ReduceProcessorFrequency" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "ReduceProcessorFrequencyOnBattery" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "AllowPerfBoostPolicy" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\intelppm\Parameters" /v "PPM_Disable_PerfBoostMode" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\intelppm\Parameters" /v "CoreParkingOverUtilizationThreshold" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\intelppm\Parameters" /v "CoreParkingOverUtilizationThresholdHistory" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\intelppm\Parameters" /v "CoreParkingUnderUtilizationThreshold" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\intelppm\Parameters" /v "CoreParkingUnderUtilizationThresholdHistory" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\intelppm\Parameters" /v "MJm58c3rHqfYBhsLdqd1s7hew76sNfiS1y" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\intelppm\Parameters" /v "TurboBoostPowerMax" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\intelppm\Parameters" /v "TurboBoostPowerMaxDutyCycle" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\intelppm\Parameters" /v "TurboBoostPowerMaxEnable" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\intelppm\Parameters" /v "TurboBoostPowerMaxTime" /t REG_DWORD /d 4294967295 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\IntelPPM" /v Start /t REG_DWORD /d 3 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM" /v Start /t REG_DWORD /d 3 /f
bcdedit /set isolatedcontext No
:: takeown /f "C:\Windows\System32\mcupdate_GenuineIntel.dll" /r /d y > nul 2>&1
::del "C:\Windows\System32\mcupdate_GenuineIntel.dll" /s /f /q > nul 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "AcpiFirmwareWatchDog" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "AmliWatchdogAction" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "AmliWatchdogTimeout" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\intelppm\Parameters" /v "WatchdogTimeout" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f



echo.
echo. 
echo.
echo                                                        Press any key to continue...     
pause >nul
cls
goto :menu


:AMD C
powercfg -setacvalueindex 95533644-e700-4a79-a56c-a89e8cb109d9 238c9fa8-0aad-41ed-83f4-97be242c8f20 25dfa149-5dd1-4736-b5ab-e8a37b5b8187 0
Powercfg -setactive scheme_current
powercfg -setdcvalueindex 95533644-e700-4a79-a56c-a89e8cb109d9 238c9fa8-0aad-41ed-83f4-97be242c8f20 25dfa149-5dd1-4736-b5ab-e8a37b5b8187 0
Powercfg -setactive scheme_current
powercfg /setACvalueindex scheme_current SUB_PROCESSOR SYSCOOLPOL 1
powercfg /setDCvalueindex scheme_current SUB_PROCESSOR SYSCOOLPOL 1
powercfg /setactive SCHEME_CURRENT
Powercfg -setdcvalueindex scheme_current sub_processor PROCTHROTTLEMAX 100
Powercfg -setactive scheme_current
Powercfg -setdcvalueindex scheme_current sub_processor PROCTHROTTLEMIN 50
Powercfg -setactive scheme_current
Powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMAX 100
Powercfg -setactive scheme_current
Powercfg -setacvalueindex scheme_current sub_processor PROCTHROTTLEMIN 100
Powercfg -setactive scheme_current
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_processor THROTTLING 0
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_none DEVICEIDLE 0
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_processor IDLEPROMOTE 98
powercfg -setacvalueindex scheme_current sub_processor IDLEDEMOTE 98
powercfg -setacvalueindex scheme_current sub_processor IDLECHECK 20000
powercfg /setactive SCHEME_CURRENT
powercfg -setacvalueindex scheme_current sub_processor IDLESCALING 1
powercfg /setactive SCHEME_CURRENT
reg add "HKLM\SYSTEM\ControlSet001\Services\AmdPPM\Parameters" /v "PPM_Disable_PerfBoostMode" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\AmdPPM\Parameters" /v "CoreParkingOverUtilizationThreshold" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\AmdPPM\Parameters" /v "CoreParkingOverUtilizationThresholdHistory" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\AmdPPM\Parameters" /v "CoreParkingUnderUtilizationThreshold" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\AmdPPM\Parameters" /v "CoreParkingUnderUtilizationThresholdHistory" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\AmdPPM\Parameters" /v "MJm58c3rHqfYBhsLdqd1s7hew76sNfiS1y" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\AmdPPM\Parameters" /v "TurboBoostPowerMax" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\AmdPPM\Parameters" /v "TurboBoostPowerMaxDutyCycle" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\AmdPPM\Parameters" /v "TurboBoostPowerMaxEnable" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\ControlSet001\Services\AmdPPM\Parameters" /v "TurboBoostPowerMaxTime" /t REG_DWORD /d 4294967295 /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DistributeTimers" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Throttle" /v "PerfEnablePackageIdle" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v "PlatformAoAcOverride" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\USB\AutomaticSurpriseRemoval" /v "AttemptRecoveryFromUsbPowerDrain" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Bluetooth" /v "QuickPair" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v "CPPCEnable" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Processor" /v "AllowPepPerfStates" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Quota System" /v "EnableCpuQuota" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "CountOperations" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\fssProv" /v "EncryptProtocol" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "ASPMOptOut" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /v "ScreenSaveActive" /t REG_SZ /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" /v "DisableRpcOver" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client" /v "ShowShutdownDialog" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WlanSvc\AnqpCache" /v "OsuRegistrationStatus" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NvCache" /v "OptimizeBootAndResume" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\NvCache" /v "EnablePowerModeState" /t REG_DWORD /d 0 /f
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\5e5da0cf-4a66-43a8-834e-b807e29f7358" /v "DynamicTick" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\5e5da0cf-4a66-43a8-834e-b807e29f7358" /v "EnergyDriverPolicy" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\5e5da0cf-4a66-43a8-834e-b807e29f7358" /v "EnergyDriverPolicyVideo" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\5e5da0cf-4a66-43a8-834e-b807e29f7358" /v "TimerBResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\5e5da0cf-4a66-43a8-834e-b807e29f7358" /v "TimerMinResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\5e5da0cf-4a66-43a8-834e-b807e29f7358" /v "TimerReliability" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0" /v "DynamicTick" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0" /v "EnergyDriverPolicy" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0" /v "EnergyDriverPolicyVideo" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0" /v "TimerBResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0" /v "TimerMinResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\7bc4a2f9-d8fc-4469-b07b-33eb785aaca0" /v "TimerReliability" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DynamicTick" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyDriverPolicy" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyDriverPolicyVideo" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TimerBResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TimerMinResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TimerReliability" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyDriver" /v "DynamicTick" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyDriver" /v "EnergyDriverPolicy" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyDriver" /v "EnergyDriverPolicyVideo" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyDriver" /v "TimerBResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyDriver" /v "TimerMinResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyDriver" /v "TimerReliability" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442" /v "DynamicTick" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442" /v "EnergyDriverPolicy" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442" /v "EnergyDriverPolicyVideo" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442" /v "TimerBResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442" /v "TimerMinResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\0012ee47-9041-4b5d-9b77-535fba8b1442" /v "TimerReliability" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\6fe69556-704a-47a0-8f24-c28d936fda47" /v "ConfigurableTSCIncreaseEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\bc5038f7-23e0-4960-96da-33abaf5935ec\GlobalPowerPolicy" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d "156250" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Throttle" /v "PerfEnablePackageIdle" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DynamicTick" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyDriverPolicy" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyDriverPolicyVideo" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TimerBResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TimerMinResolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TimerReliability" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnablePerCpuClockTickScheduling" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableTsx" /t REG_DWORD /d "1" /f
rem Termed for now, under benchmarking
rem takeown /f "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /r /d y > nul 2>&1
rem del "C:\Windows\System32\mcupdate_AuthenticAMD.dll" /s /f /q > nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\AmdPPM\Parameters" /v "PerfEnergyPreference" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\AmdPPM\Parameters" /v "CPMinCores" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\AmdPPM\Parameters" /v "CPMaxCores" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\AmdPPM\Parameters" /v "CPMinCores1" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\AmdPPM\Parameters" /v "CPMaxCores1" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\AmdPPM\Parameters" /v "CpLatencyHintUnpark1" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\AmdPPM\Parameters" /v "CPDistribution" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\AmdPPM\Parameters" /v "CpLatencyHintUnpark" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\AmdPPM\Parameters" /v "MaxPerformance1" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\AmdPPM\Parameters" /v "MaxPerformance" /t REG_DWORD /d 100 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\AmdPPM\Parameters" /v "CPDistribution1" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Policy\Settings\AmdPPM\Parameters" /v "CPHEADROOM" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\amdppm\Parameters" /v "C1eEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ThreadQuantum" /t REG_DWORD /d 18 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorThreadPriority" /t REG_DWORD /d 24 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorScheduler" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorParkedForServer" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorParkedForKernel" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "ProcessorParkedForGui" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "KernelCpuTimeLimit" /t REG_DWORD /d 4000 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "DisableDynamicProcessorClocks" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "DisableCpuQuota" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AmdPPM\Parameters" /v "CoalescingTimerInterval" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AmdPPM\Parameters" /v "UserPresencePredictionEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DWM" /v "DwmUseDetailTexture" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_SZ /d "2" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "Cstates" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "Capabilities" /t REG_SZ /d "516198" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "HighPerformance" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "HighestPerformance" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy" /v "fDisablePowerManagement" /t REG_DWORD /d "1" /f
reg add "HKEY_SYSTEM\CurrentControlSet\Services\AmdPPM\PDC\Activators\Default\VetoPolicy" /v "EA:EnergySaverEngaged" /t REG_DWORD /d "0" /f
reg add "HKEY_SYSTEM\CurrentControlSet\Services\AmdPPM\PDC\Activators\28\VetoPolicy" /v "EA:PowerStateDischarging" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DeviceIdlePolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "PerfEnergyPreference" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CPMinCores" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CPMaxCores" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CPMinCores1" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CPMaxCores1" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CpLatencyHintUnpark1" /t REG_SZ /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CPDistribution" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CpLatencyHintUnpark" /t REG_SZ /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MaxPerformance1" /t REG_SZ /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MaxPerformance" /t REG_SZ /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CPDistribution1" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CPHEADROOM" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CPCONCURRENCY" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "ExitLatency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "Latency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "LatencyToleranceDefault" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "LatencyToleranceFSVP" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "LowLatencyScalingPercentage" /t REG_SZ /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "HighPerformance" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "HighestPerformance" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MaximumPerformancePercent" /t REG_SZ /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "InitialUnparkCount" /t REG_SZ /d "100" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "Latency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MonitorLatencyTolerance" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "TransitionLatency" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Throttle" /v "PerfEnablePackageIdle" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "AllowPepPerfStates" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\AmdPPM\Parameters" /v "CPPCEnable" /t REG_DWORD /d "0" /f



echo.
echo. 
echo.
echo                                                        Press any key to continue...     
pause >nul
cls
goto :menu


:BIOS
mode 720,400
echo.
echo.
echo.
echo.                                             [1] INTEL BIOS          [2] AMD BIOS
echo.
echo.  
set /p input=: 
if /i %input% == 1 goto INTEL B
if /i %input% == 2 goto AMD B

:INTEL B
curl -g -k -L -# -o "C:\Windows\SCEWIN_64.exe" "https://cdn.discordapp.com/attachments/1234529829496553642/1234537153246007326/SCEWIN_64.exe?ex=66613691&is=665fe511&hm=fcf572ff18fcd482f172054e6c9fbdcb7d8708d4fd6f0d9ff07f61ec9a94fcf4&" 2>&1

curl -g -k -L -# -o "C:\Windows\amifldrv64.sys" "https://cdn.discordapp.com/attachments/1234529829496553642/1234537141644558477/amifldrv64.sys?ex=6661368f&is=665fe50f&hm=9ad48dcc9f585cc22518f08ddb04087a3f8950dd4aea447a74912e52f1cb4318&" 2>&1
cls
SCEWIN_64.exe /i /ms "Global C-state Control" /qv 0x0 /lang en-US
cls
echo. Disabling Ps2 Devices...
SCEWIN_64.exe /i /ms "PS2 Devices Support" /qv 0x0 /lang en-US
cls
echo. Disabling TPM State...
SCEWIN_64.exe /i /ms "TPM State" /qv 0x0 /lang en-US
cls
echo. Disabling Secure Boot... //this so bad for windows 11
SCEWIN_64.exe /i /ms "Secure Boot" /qv 0x0 /lang en-US
cls
echo. Disabling BME DMA Mitigation...
SCEWIN_64.exe /i /ms "Secure Boot" /qv 0 /lang en-US
cls
echo. Disabling Fast Boot...
SCEWIN_64.exe /i /ms "Fast Boot" /qv 0x0 /lang en-US
cls
echo. Disabling Power On By Device...
SCEWIN_64.exe /i /ms "Power On By Mouse" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Power On By Keyboard" /qv 0x0 /lang en-US
cls
echo. Disabling Wake On Lan...
SCEWIN_64.exe /i /ms "Wake on LAN" /qv 0x0 /lang en-US
cls
echo. Enabling Bootup NumLock State...
SCEWIN_64.exe /i /ms "Bootup NumLock State" /qv 0x1 /lang en-US
cls
echo. Disabling Network Stack Driver...
SCEWIN_64.exe /i /ms "Network Stack Driver Support" /qv 0x0 /lang en-US
cls
echo. disabling XHCI Hand Off...
SCEWIN_64.exe /i /ms "XHCI Hand-Off" /qv 0x0 /lang en-US
cls
echo. disabling Legacy Usb Support...
SCEWIN_64.exe /i /ms "Legacy USB Support" /qv 0x0 /lang en-US
cls
echo. Disabling Resume By Alarm...
SCEWIN_64.exe /i /ms "Resume by Alarm" /qv 0x0 /lang en-US
cls
echo. Disabling Fullscreen Logo Display...
SCEWIN_64.exe /i /ms "Full Screen LOGO Show" /qv 0x0 /lang en-US
cls
echo. Disabling Security Device Support...
SCEWIN_64.exe /i /ms "Security Device Support" /qv 0x0 /lang en-US
cls
echo. Disabling CNVI Mode...
SCEWIN_64.exe /i /ms "CNVI Mode" /qv 0x0 /lang en-US
cls
echo. Disabling Intel RMT State...
SCEWIN_64.exe /i /ms "Intel RMT State" /qv 0x0 /lang en-US
cls
echo. Disabling Intel Ready Mode Technology...
SCEWIN_64.exe /i /ms "Intel Ready Mode Technology" /qv 0x0 /lang en-US
cls
echo. Disabling Energy Efficient P-state...
SCEWIN_64.exe /i /ms "Energy Efficient P-state" /qv 0x0 /lang en-US
cls
echo. Disabling Energy Performance Gain...
SCEWIN_64.exe /i /ms "Energy Performance Gain" /qv 0x0 /lang en-US
cls
echo. Disabling Energy Efficient Turbo...
SCEWIN_64.exe /i /ms "Energy Efficient Turbo" /qv 0x0 /lang en-US
cls
echo. Disabling BME DMA Mitigation...
SCEWIN_64.exe /i /ms "BME DMA Mitigation" /qv 0x0 /lang en-US
cls
echo. Disabling Enable RH Prevention...
SCEWIN_64.exe /i /ms "Enable RH Prevention" /qv 0x0 /lang en-US
cls
echo. Disabling Per Bank Refresh...
SCEWIN_64.exe /i /ms "Per Bank Refresh" /qv 0x0 /lang en-US
cls
echo. Disabling Intel(R) SpeedStep(tm)...
SCEWIN_64.exe /i /ms "Intel(R) SpeedStep(tm)" /qv 0x0 /lang en-US
cls
echo. Disabling cpu-states
SCEWIN_64.exe /i /ms "CPU C-States" /qv 0x0 /lang en-US
cls
echo. Disabling intel speed shift technology
SCEWIN_64.exe /i /ms "Intel(R) Speed Shift Technology" /qv 0x0 /lang en-US
cls
echo. Disabling Energy Efficient P-state
SCEWIN_64.exe /i /ms "Energy Efficient P-state" /qv 0x0 /lang en-US
cls
echo. Disabling me state
SCEWIN_64.exe /i /ms "ME State" /qv 0x0 /lang en-US
cls
echo. Disabling Power Down Mode
SCEWIN_64.exe /i /ms "Power Down Mode" /qv 0x0 /lang en-US
cls
echo.Energy Efficient Turbo
CEWIN_64.exe /i /ms "Energy Efficient Turbo" /qv 0x0 /lang en-US
cls
echo. Disabling TPM State
SCEWIN_64.exe /i /ms "TPM State" /qv 0x0 /lang en-US
cls
echo. Disabling command Rate Support
SCEWIN_64.exe /i /ms "command Rate Support" /qv 0x0 /lang en-US
cls
echo. Disabling RC6(Render Standby)
SCEWIN_64.exe /i /ms "RC6(Render Standby)" /qv 0x0 /lang en-US
cls
echo. Disabling Type C Support
SCEWIN_64.exe /i /ms "Type C Support" /qv 0x0 /lang en-US
cls
echo. Disabling LAN Wake From DeepSx
SCEWIN_64.exe /i /ms "LAN Wake From DeepSx" /qv 0x0 /lang en-US
cls
echo. Disabling PCH Cross Throttling
SCEWIN_64.exe /i /ms "PCH Cross Throttling" /qv 0x0 /lang en-US
cls
echo. Disabling Power Down Unused Lanes
SCEWIN_64.exe /i /ms "Power Down Unused Lanes" /qv 0x0 /lang en-US
cls
echo. Disabling BME DMA Mitigation
SCEWIN_64.exe /i /ms "BME DMA Mitigation" /qv 0x0 /lang en-US
cls
echo. Disablling ACPI Standby State
SCEWIN_64.exe /i /ms "ACPI Standby State" /qv 0x0 /lang en-US
cls
echo. Disabling USB2 PHY Sus Well Power Gating
SCEWIN_64.exe /i /ms "USB2 PHY Sus Well Power Gating" /qv 0x0 /lang en-US
cls
echo. Disabling HW Notification
SCEWIN_64.exe /i /ms "HW Notification" /qv 0x0 /lang en-US
cls
echo. Disabling DMI Link ASPM Control
SCEWIN_64.exe /i /ms "DMI Link ASPM Control" /qv 0x0 /lang en-US
cls
echo. Disabling PCIe Spread Spectrum Clocking
SCEWIN_64.exe /i /ms "PCIe Spread Spectrum Clocking" /qv 0x0 /lang en-US
cls
echo. Disabling C6DRAM
SCEWIN_64.exe /i /ms "C6DRAM" /qv 0x0 /lang en-US
cls
echo. Disabling Intel Virtualization Tech
SCEWIN_64.exe /i /ms "Intel Virtualization Tech" /qv 0x0 /lang en-US
cls
echo. Disabling CPU AES Instructions
SCEWIN_64.exe /i /ms "CPU AES Instructions" /qv 0x0 /lang en-US
cls
echo. Disabling EIST
SCEWIN_64.exe /i /ms "EIST" /qv 0x0 /lang en-US
cls
echo. Disabling Enable RH Prevention
SCEWIN_64.exe /i /ms "Enable RH Prevention" /qv 0x0 /lang en-US
cls
echo. Disabling Race To Halt
SCEWIN_64.exe /i /ms "Race To Halt" /qv 0x0 /lang en-US
cls
echo. Disabling Intel RMT State
SCEWIN_64.exe /i /ms "Intel RMT State" /qv 0x0 /lang en-US
cls
echo. Disabling Intel Adaptive Thermal Monitor
SCEWIN_64.exe /i /ms "Intel Adaptive Thermal Monitor" /qv 0x0 /lang en-US
cls
echo. Disabling HDC Control
SCEWIN_64.exe /i /ms "HDC Control" /qv 0x0 /lang en-US
cls
echo. Disabling SMM Code Access Check
SCEWIN_64.exe /i /ms "SMM Code Access Check" /qv 0x0 /lang en-US
cls
echo. Disabling SMM Use Delay Indication
SCEWIN_64.exe /i /ms "SMM Use Delay Indication" /qv 0x0 /lang en-US
cls
echo Disabling SMM Use Block Indication
SCEWIN_64.exe /i /ms "SMM Use Block Indication" /qv 0x0 /lang en-US
cls
echo. Disabling SMM Use SMM en-US Indication
SCEWIN_64.exe /i /ms "SMM Use SMM en-US Indication" /qv 0x0 /lang en-US
cls
echo. Disabling LTR
SCEWIN_64.exe /i /ms "LTR" /qv 0x0 /lang en-US
cls
echo. Enabling I/O Resources Padding
SCEWIN_64.exe /i /ms "I/O Resources Padding" /qv 0x20 /lang en-US
cls
echo. Enabling MMIO 32 bit Resources Padding
SCEWIN_64.exe /i /ms "MMIO 32 bit Resources Padding" /qv 0x80 /lang en-US
cls
echo. Enabling PFMMIO 32 bit Resources Padding
SCEWIN_64.exe /i /ms "PFMMIO 32 bit Resources Padding" /qv 0x80 /lang en-US
cls
echo Enabling PFMMIO 64 bit Resources Padding
SCEWIN_64.exe /i /ms "PFMMIO 64 bit Resources Padding" /qv 0x2000 /lang en-US
cls
echo. Disabling CNVI MODE
SCEWIN_64.exe /i /ms "CNVI MODE" /qv 0x0 /lang en-US
cls
echo. Disabling CWIFI SAR 
SCEWIN_64.exe /i /ms "CWIFI SAR" /qv 0x0 /lang en-US
cls
echo. Disabling CNVI MODE
SCEWIN_64.exe /i /ms "CNVI MODE" /qv 0x0 /lang en-US
cls
echo. Disabling WWAN Reset Workaround
SCEWIN_64.exe /i /ms "WWAN Reset Workaround" /qv 0x0 /lang en-US
cls
echo. Disabling WWAN Device
SCEWIN_64.exe /i /ms "WWAN Device" /qv 0x0 /lang en-US
cls
echo. Disabling C6DRAM
SCEWIN_64.exe /i /ms "C6DRAM" /qv 0x0 /lang en-US
cls
echo. Disabling 1394 controller
SCEWIN_64.exe /i /ms "1394 controller" /qv 0x0 /lang en-US
cls
echo. Disabling Legacy USB support
SCEWIN_64.exe /i /ms "Legacy USB support" /qv 0x0 /lang en-US
cls
echo. Disabling CPU Spread Spectrum
SCEWIN_64.exe /i /ms "CPU Spread Spectrum" /qv 0x0 /lang en-US
cls
echo. Disabling Execute Disable Bit
SCEWIN_64.exe /i /ms "Execute Disable Bit" /qv 0x0 /lang en-US
cls
echo. Disabling iGPU Multi-Monitor
SCEWIN_64.exe /i /ms "iGPU Multi-Monitor" /qv 0x0 /lang en-US
cls
echo. Disabling Power Saving Features...
SCEWIN_64.exe /i /ms "PEP TBT RP" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP LAN(GBE)" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP CSME" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP SDXCE" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP EMMC" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PUIS Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "EC Low Power Mode" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Intel Ready Mode Technology" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Intel RMT State" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP CPU" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP Graphics" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP IPU" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP GNA" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP PEG0" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP SATA" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP enumerated SATA ports" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP PCIe LAN" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP PCIe WLAN" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP PCIe GFX" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP PCIe Other" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP PCIe Storage" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP PCIe DG1" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP UART" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP I2C0" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP I2C1" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP I2C2" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP I2C3" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP I2C4" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP I2C5" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP I2C6" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP I2C7" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP SPI" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP XHCI" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP Audio" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP SDXC" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP CSME" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP HECI3" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP LAN(GBE)" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP THC0" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP THC1" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP TCSS" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP VMD" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP EMMC" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEP TBT RP" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "C6DRAM" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "AP threads Idle Manner" /qv 0x3 /lang en-US
SCEWIN_64.exe /i /ms "PECI" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Intel Trusted Execution Technology" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "HDC Control" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Race To Halt (RTH)" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Energy Performance Gain" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Energy Efficient P-state" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Energy Efficient Turbo" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "CFG Lock" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Tcc Offset Time Window" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Bi-directional PROCHOT#" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "ACPI T-States" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Enable xdpclock" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "WDT Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "BCLK Aware Adaptive Voltage" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Ring Down Bin" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PET Progress" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "WatchDog" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Thunderbolt Boot Support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Wake From Thunderbolt(TM) Devices" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Thunderbolt Usb Support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Windows 10 Thunderbolt support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "IGD VTD Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "IPU VTD Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "IOP VTD Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "JTAG C10 Power Gate" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "USB3 Type-C UFP2DFP Kernel/Platform Debug Support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Three Strike Counter" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "CrashLog Feature" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "RAM" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Legacy UART" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "USB3" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Serial IO UART" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Trace Hub" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "MRC Serial Debug Messages" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Serial Debug Messages" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "CPU Wakeup Timer" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Enable Hibernation" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "ACPI Standby State" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "SR-IOV Support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "BME DMA Mitigation" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Extended Tag" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "Maximum Payload" /qv 0x5 /lang en-US
SCEWIN_64.exe /i /ms "Maximum Read Request" /qv 0x5 /lang en-US
SCEWIN_64.exe /i /ms "ASPM" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "ARI Forwarding" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "LTR Mechanism Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Clock Power Management" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Port 60/64 Emulation" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "USB S5 Wakeup Support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Ipv4 PXE Support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Ipv6 PXE Support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Option ROM Messages" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Launch PXE OpROM policy" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Type C Support" /qv 0x2 /lang en-US
SCEWIN_64.exe /i /ms "Enable RH Prevention" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Enable/Disable IED (Intel Enhanced Debug)" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "CHAP Device (B0:D7:F0)" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Thermal Device (B0:D4:F0)" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "GNA Device (B0:D8:F0)" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "ALS Support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "VDD Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PAVP Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Enable Display Audio Link in Pre-OS" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "DMI Gen3 ASPM" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "DMI ASPM" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "RC6(Render Standby)" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEG0 Hotplug" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEG1 Hotplug" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEG2 Hotplug" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PCIe Spread Spectrum Clocking" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "LAN Wake From DeepSx" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Wake on LAN Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "SLP_LAN# Low on DC Power" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "DeepSx Power Policies" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "DeepSx Wake on WLAN and BT Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Foxville I225 Wake on LAN Support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Wake on WLAN and BT Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Disable DSX ACPRESENT PullDown" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "PS_ON Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Enhance Port 80h LPC Decoding" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Legacy IO Low Latency" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "PCH Cross Throttling" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "IOAPIC 24-119 Entries" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Enable 8254 Clock Gate" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "USB2 PHY Sus Well Power Gating" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Intel Rapid Recovery Technology" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Smart Response Technology" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Intel(R) Optane(TM) Memory" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "System Acceleration with Intel(R) Optane(TM) Memory" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "CPU Attached Storage" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Disable Gen2 Pll Shutdown and L1 Controller Power gating" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "RGB Light" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Modern StandBy" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "LAN Option ROM" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "USB Standby Power at S4/S5" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEG0 - ASPM" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEG1 - ASPM" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PEG2 - ASPM" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PCIE Spread Spectrum" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PCI Delay Optimization" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "PCI Express Clock Gating" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PCI Express Power Gating" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Power Gating" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Vmax Stress" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "IOTG Spread Spectrum" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "LPM S0i3.4" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "LPM S0i3.3" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "LPM S0i3.2" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "LPM S0i3.1" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "LPM S0i3.0" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "LPM S0i2.2" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "LPM S0i2.1" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "LPM S0i2.0" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Intel(R) Turbo Boost Max Technology 3.0" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "CPU PkgC10 Long Sleep" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Tcc Offset Lock Enable" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Power Loss Notification Feature" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PS2 Keyboard and Mouse" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Enable DCI ModPHY Power Gate" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "USB DbC Enable Mode" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "CPU Run Control" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "CPU Run Control Lock" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "USB Overcurrent Override for DbC" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Processor trace memory allocation" /qv 0xFF /lang en-US
SCEWIN_64.exe /i /ms "Clock Power Management" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Hardware Autonomous Width" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "Hardware Autonomous Speed" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "BIOS Hot-Plug Support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Cpu CrashLog (Device 10)" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "DMI Link ASPM Control" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "OS IDLE Mode" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "S0ix Auto Demotion" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Hybrid Storage Detection and Configuration Mode" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "FIVR Dynamic PM" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "ECC Support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Row Hammer Mode" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "In-Band ECC Support" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "LPMode" /qv 0x2 /lang en-US
SCEWIN_64.exe /i /ms "KT Device" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "IPU Device (B0:D5:F0)" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Intel(R) Speed Shift Technology Interrupt Control" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "HwP Autonomous Per Core P State" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "HwP Autonomous EPP Grouping" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Enhanced Thermal Velocity Boost" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "TVB Voltage Optimizations" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Thermal Velocity Boost" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Interrupt Redirection Mode Selection" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "Disable Fast PKG C State Ramp for IA Domain" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "INT3400 Device" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Enable Remote Platform Erase Feature" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "ITBT RTD3" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PCI Buses Padding" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "I/O Resources Padding" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "MMIO 32 bit Resources Padding" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "PFMMIO 32 bit Resources Padding" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Pcie Pll SSC" /qv 0xFE /lang en-US
SCEWIN_64.exe /i /ms "WoV (Wake on Voice)" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Bluetooth Sideband" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "BT Intel HFP" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "BT Intel A2DP" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "DMI Gen3 L1 Exit Latency" /qv 0x1 /lang en-US
SCEWIN_64.exe /i /ms "CPU Run Control" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "CPU Run Control Lock" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "FIVR Spread Spectrum" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "RFI Spread Spectrum" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /ms "Per Core P State OS control mode" /qv 0x0 /lang en-US
SCEWIN_64.exe /i /lang en-US /ms "PUIS Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "EC Low Power Mode" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Intel Ready Mode Technology" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Intel RMT State" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP CPU" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP Graphics" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP IPU" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP GNA" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP PEG0" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP SATA" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP enumerated SATA ports" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP PCIe LAN" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP PCIe WLAN" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP PCIe GFX" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP PCIe Other" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP PCIe Storage" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP PCIe DG1" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP UART" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C0" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C1" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C2" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C3" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C4" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C5" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C6" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C7" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP SPI" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP XHCI" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP Audio" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP SDXC" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP CSME" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP HECI3" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP LAN(GBE)" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP THC0" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP THC1" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP TCSS" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP VMD" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP EMMC" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PEP TBT RP" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "C6DRAM" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "AP threads Idle Manner" /qv 0x3
SCEWIN_64.exe /i /lang en-US /ms "PECI" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Intel Trusted Execution Technology" /qv 0x0
SCEWIN_64.exe /i /lang en-US /lang en-US /ms "HDC Control" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Race To Halt (RTH)" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Energy Performance Gain" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Energy Efficient P-state" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Energy Efficient Turbo" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "CFG Lock" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Tcc Offset Time Window" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Bi-directional PROCHOT#" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "ACPI T-States" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Enable xdpclock" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "WDT Enable" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "BCLK Aware Adaptive Voltage" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Ring Down Bin" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PET Progress" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "WatchDog" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Thunderbolt Boot Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Wake From Thunderbolt(TM) Devices" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Thunderbolt Usb Support" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Windows 10 Thunderbolt support" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "IGD VTD Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "IPU VTD Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "IOP VTD Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "JTAG C10 Power Gate" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "USB3 Type-C UFP2DFP Kernel/Platform Debug Support" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Three Strike Counter" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "CrashLog Feature" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "RAM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Legacy UART" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "USB3" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Serial IO UART" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Trace Hub" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "MRC Serial Debug Messages" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Serial Debug Messages" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "CPU Wakeup Timer" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable Hibernation" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "ACPI Standby State" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "SR-IOV Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "BME DMA Mitigation" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Extended Tag" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "Maximum Payload" /qv 0x5 
SCEWIN_64.exe /i /lang en-US /ms "Maximum Read Request" /qv 0x5 
SCEWIN_64.exe /i /lang en-US /ms "ASPM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "ARI Forwarding" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LTR Mechanism Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Clock Power Management" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Port 60/64 Emulation" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "USB S5 Wakeup Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Ipv4 PXE Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Ipv6 PXE Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Option ROM Messages" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Launch PXE OpROM policy" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Type C Support" /qv 0x2 
SCEWIN_64.exe /i /lang en-US /ms "Enable RH Prevention" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable/Disable IED (Intel Enhanced Debug)" /qv 0x0  
SCEWIN_64.exe /i /lang en-US /ms "CHAP Device (B0:D7:F0)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Thermal Device (B0:D4:F0)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "GNA Device (B0:D8:F0)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "ALS Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "VDD Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PAVP Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable Display Audio Link in Pre-OS" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "DMI Gen3 ASPM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "DMI ASPM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "RC6(Render Standby)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEG0 Hotplug" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEG1 Hotplug" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEG2 Hotplug" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PCIe Spread Spectrum Clocking" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "LAN Wake From DeepSx" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Wake on LAN Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "SLP_LAN# Low on DC Power" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "DeepSx Power Policies" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "DeepSx Wake on WLAN and BT Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Foxville I225 Wake on LAN Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Wake on WLAN and BT Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Disable DSX ACPRESENT PullDown" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "PS_ON Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enhance Port 80h LPC Decoding" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Legacy IO Low Latency" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "PCH Cross Throttling" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "IOAPIC 24-119 Entries" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable 8254 Clock Gate" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "USB2 PHY Sus Well Power Gating" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Intel Rapid Recovery Technology" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Smart Response Technology" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Intel(R) Optane(TM) Memory" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "System Acceleration with Intel(R) Optane(TM) Memory" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "CPU Attached Storage" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Disable Gen2 Pll Shutdown and L1 Controller Power gating" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "RGB Light" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Modern StandBy" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LAN Option ROM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "USB Standby Power at S4/S5" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEG0 - ASPM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEG1 - ASPM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEG2 - ASPM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PCIE Spread Spectrum" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PCI Delay Optimization" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "PCI Express Clock Gating" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PCI Express Power Gating" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Power Gating" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Vmax Stress" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "IOTG Spread Spectrum" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i3.4" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i3.3" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i3.2" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i3.1" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i3.0" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i2.2" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i2.1" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i2.0" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Intel(R) Turbo Boost Max Technology 3.0" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "CPU PkgC10 Long Sleep" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Tcc Offset Lock Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Power Loss Notification Feature" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PS2 Keyboard and Mouse" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable DCI ModPHY Power Gate" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "USB DbC Enable Mode" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "CPU Run Control" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "CPU Run Control Lock" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "USB Overcurrent Override for DbC" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Processor trace memory allocation" /qv 0xFF 
SCEWIN_64.exe /i /lang en-US /ms "Clock Power Management" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Hardware Autonomous Width" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "Hardware Autonomous Speed" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "BIOS Hot-Plug Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Cpu CrashLog (Device 10)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "DMI Link ASPM Control" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "OS IDLE Mode" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "S0ix Auto Demotion" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Hybrid Storage Detection and Configuration Mode" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "FIVR Dynamic PM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "ECC Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Row Hammer Mode" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "In-Band ECC Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPMode" /qv 0x2 
SCEWIN_64.exe /i /lang en-US /ms "KT Device" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "IPU Device (B0:D5:F0)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Intel(R) Speed Shift Technology Interrupt Control" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "HwP Autonomous Per Core P State" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "HwP Autonomous EPP Grouping" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enhanced Thermal Velocity Boost" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "TVB Voltage Optimizations" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Thermal Velocity Boost" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Interrupt Redirection Mode Selection" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "Disable Fast PKG C State Ramp for IA Domain" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "INT3400 Device" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable Remote Platform Erase Feature" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "ITBT RTD3" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PCI Buses Padding" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "I/O Resources Padding" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "MMIO 32 bit Resources Padding" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PFMMIO 32 bit Resources Padding" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Pcie Pll SSC" /qv 0xFE 
SCEWIN_64.exe /i /lang en-US /ms "WoV (Wake on Voice)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Bluetooth Sideband" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "BT Intel HFP" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "BT Intel A2DP" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "DMI Gen3 L1 Exit Latency" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "CPU Run Control" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "CPU Run Control Lock" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "FIVR Spread Spectrum" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "RFI Spread Spectrum" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Per Core P State OS control mode" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PUIS Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "EC Low Power Mode" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Intel Ready Mode Technology" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Intel RMT State" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP CPU" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP Graphics" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP IPU" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP GNA" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP PEG0" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP SATA" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP enumerated SATA ports" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP PCIe LAN" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP PCIe WLAN" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP PCIe GFX" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP PCIe Other" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP PCIe Storage" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP PCIe DG1" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP UART" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C0" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C1" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C2" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C3" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C4" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C5" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C6" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP I2C7" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP SPI" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP XHCI" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP Audio" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP SDXC" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP CSME" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP HECI3" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP LAN(GBE)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP THC0" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP THC1" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP TCSS" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP VMD" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP EMMC" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEP TBT RP" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "C6DRAM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "AP threads Idle Manner" /qv 0x3 
SCEWIN_64.exe /i /lang en-US /ms "PECI" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Intel Trusted Execution Technology" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "HDC Control" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Race To Halt (RTH)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Energy Performance Gain" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Energy Efficient P-state" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Energy Efficient Turbo" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "CFG Lock" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Tcc Offset Time Window" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Bi-directional PROCHOT#" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "ACPI T-States" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable xdpclock" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "WDT Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "BCLK Aware Adaptive Voltage" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Ring Down Bin" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PET Progress" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "WatchDog" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Thunderbolt Boot Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Wake From Thunderbolt(TM) Devices" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Thunderbolt Usb Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Windows 10 Thunderbolt support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "IGD VTD Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "IPU VTD Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "IOP VTD Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "JTAG C10 Power Gate" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "USB3 Type-C UFP2DFP Kernel/Platform Debug Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Three Strike Counter" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "CrashLog Feature" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "RAM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Legacy UART" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "USB3" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Serial IO UART" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Trace Hub" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "MRC Serial Debug Messages" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Serial Debug Messages" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "CPU Wakeup Timer" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable Hibernation" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "ACPI Standby State" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "SR-IOV Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "BME DMA Mitigation" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Extended Tag" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "Maximum Payload" /qv 0x5 
SCEWIN_64.exe /i /lang en-US /ms "Maximum Read Request" /qv 0x5 
SCEWIN_64.exe /i /lang en-US /ms "ASPM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "ARI Forwarding" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LTR Mechanism Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Clock Power Management" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Port 60/64 Emulation" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "USB S5 Wakeup Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Ipv4 PXE Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Ipv6 PXE Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Option ROM Messages" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Launch PXE OpROM policy" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Type C Support" /qv 0x2 
SCEWIN_64.exe /i /lang en-US /ms "Enable RH Prevention" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable/Disable IED (Intel Enhanced Debug)" /qv 0x0  
SCEWIN_64.exe /i /lang en-US /ms "CHAP Device (B0:D7:F0)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Thermal Device (B0:D4:F0)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "GNA Device (B0:D8:F0)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "ALS Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "VDD Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PAVP Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable Display Audio Link in Pre-OS" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "DMI Gen3 ASPM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "DMI ASPM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "RC6(Render Standby)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEG0 Hotplug" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEG1 Hotplug" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEG2 Hotplug" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PCIe Spread Spectrum Clocking" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "LAN Wake From DeepSx" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Wake on LAN Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "SLP_LAN# Low on DC Power" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "DeepSx Power Policies" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "DeepSx Wake on WLAN and BT Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Foxville I225 Wake on LAN Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Wake on WLAN and BT Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Disable DSX ACPRESENT PullDown" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "PS_ON Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enhance Port 80h LPC Decoding" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Legacy IO Low Latency" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "PCH Cross Throttling" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "IOAPIC 24-119 Entries" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable 8254 Clock Gate" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "USB2 PHY Sus Well Power Gating" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Intel Rapid Recovery Technology" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Smart Response Technology" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Intel(R) Optane(TM) Memory" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "System Acceleration with Intel(R) Optane(TM) Memory" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "CPU Attached Storage" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Disable Gen2 Pll Shutdown and L1 Controller Power gating" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "RGB Light" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Modern StandBy" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LAN Option ROM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "USB Standby Power at S4/S5" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEG0 - ASPM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEG1 - ASPM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PEG2 - ASPM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PCIE Spread Spectrum" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PCI Delay Optimization" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "PCI Express Clock Gating" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PCI Express Power Gating" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Power Gating" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Vmax Stress" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "IOTG Spread Spectrum" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i3.4" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i3.3" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i3.2" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i3.1" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i3.0" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i2.2" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i2.1" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPM S0i2.0" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Intel(R) Turbo Boost Max Technology 3.0" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "CPU PkgC10 Long Sleep" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Tcc Offset Lock Enable" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Power Loss Notification Feature" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "PS2 Keyboard and Mouse" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable DCI ModPHY Power Gate" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "USB DbC Enable Mode" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "CPU Run Control" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "CPU Run Control Lock" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "USB Overcurrent Override for DbC" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Processor trace memory allocation" /qv 0xFF 
SCEWIN_64.exe /i /lang en-US /ms "Clock Power Management" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Hardware Autonomous Width" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "Hardware Autonomous Speed" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "BIOS Hot-Plug Support" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Cpu CrashLog (Device 10)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "DMI Link ASPM Control" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "OS IDLE Mode" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "S0ix Auto Demotion" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Hybrid Storage Detection and Configuration Mode" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "FIVR Dynamic PM" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "ECC Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Row Hammer Mode" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "In-Band ECC Support" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "LPMode" /qv 0x2 
SCEWIN_64.exe /i /lang en-US /ms "KT Device" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "IPU Device (B0:D5:F0)" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Intel(R) Speed Shift Technology Interrupt Control" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "HwP Autonomous Per Core P State" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "HwP Autonomous EPP Grouping" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Enhanced Thermal Velocity Boost" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "TVB Voltage Optimizations" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Thermal Velocity Boost" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Interrupt Redirection Mode Selection" /qv 0x1
SCEWIN_64.exe /i /lang en-US /ms "Disable Fast PKG C State Ramp for IA Domain" /qv 0x1
SCEWIN_64.exe /i /lang en-US /ms "INT3400 Device" /qv 0x0 
SCEWIN_64.exe /i /lang en-US /ms "Enable Remote Platform Erase Feature" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "ITBT RTD3" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PCI Buses Padding" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "I/O Resources Padding" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "MMIO 32 bit Resources Padding" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "PFMMIO 32 bit Resources Padding" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Pcie Pll SSC" /qv 0xFE 
SCEWIN_64.exe /i /lang en-US /ms "WoV (Wake on Voice)" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Bluetooth Sideband" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "BT Intel HFP" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "BT Intel A2DP" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "DMI Gen3 L1 Exit Latency" /qv 0x1 
SCEWIN_64.exe /i /lang en-US /ms "CPU Run Control" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "CPU Run Control Lock" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "FIVR Spread Spectrum" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "RFI Spread Spectrum" /qv 0x0
SCEWIN_64.exe /i /lang en-US /ms "Per Core P State OS control mode" /qv 0x0
echo.
echo. 
echo.
echo                                                        Press any key to continue...     
pause >nul
cls
goto :menu


:AMD B
curl -g -k -L -# -o "C:\Windows\SCEWIN_64.exe" "https://github.com/mosol1/WindowsSearch/raw/main/SCEWIN_64.exe" 2>&1
curl -g -k -L -# -o "C:\Windows\amifldrv64.sys" "https://github.com/mosol1/WindowsSearch/raw/main/amifldrv64.sys" 2>&1

cls
echo.
SCEWIN_64.exe /i /ms "Above 4G memory" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ACPI Standby State" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ACPI T-States" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ALS Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "AMD Cool'N'Quiet" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "AP threads Idle Manner" /qv 0x3 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ARI Forwarding" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ASPM" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "BCLK Aware Adaptive Voltage" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Bi-directional PROCHOT#" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "BIOS Hot-Plug Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Bluetooth Sideband" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "BME DMA Mitigation" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "C6 Mode" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "C6DRAM" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CFG Lock" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CHAP Device (B0:D7:F0)" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Chipset Power Saving Features" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Clock Power Management" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CPU Attached Storage" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Cpu CrashLog (Device 10)" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CPU PkgC10 Long Sleep" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CPU Run Control Lock" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CPU Run Control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CPU Wakeup Timer" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CrashLog Feature" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CSM Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DeepSx Power Policies" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DeepSx Wake on WLAN and BT Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Disable DSX ACPRESENT PullDown" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Disable Fast PKG C State Ramp for IA Domain" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Disable Gen2 Pll Shutdown and L1 Controller Power gating" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DMI ASPM" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DMI Gen3 ASPM" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DMI Gen3 L1 Exit Latency" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DMI Link ASPM Control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "EC Low Power Mode" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ECC Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Enable 8254 Clock Gate" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Enable DCI ModPHY Power Gate" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Enable Display Audio Link in Pre-OS" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Enable Hibernation" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Enable ote Platform Erase Feature" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Enable RH Prevention" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Enable xdpclock" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Energy Efficient P-state" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Energy Efficient Turbo" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Energy Performance Gain" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Enhance Port 80h LPC Decoding" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Enhanced Thermal Velocity Boost" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Extended Tag" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "FIVR Dynamic PM" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "FIVR Spread Spectrum" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Foxville I225 Wake on LAN Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "GNA Device (B0:D8:F0)" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Hardware Autonomous Speed" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Hardware Autonomous Width" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "HDC Control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "HwP Autonomous EPP Grouping" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "HwP Autonomous Per Core P State" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Hybrid Storage Detection and Configuration Mode" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "I/O Resources Padding" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "IGD VTD Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "In-Band ECC Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "INT3400 Device" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Interrupt Redirection Mode Selection" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "IOAPIC 24-119 Entries" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "IOMMU" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "IOP VTD Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "IOTG Spread Spectrum" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "IPU Device (B0:D5:F0)" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "IPU VTD Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Ipv4 PXE Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Ipv6 PXE Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ITBT RTD3" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "JTAG C10 Power Gate" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "KT Device" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LAN Option ROM" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LAN Wake From DeepSx" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Launch PXE OpROM policy" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Legacy IO Low Latency" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Legacy UART" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LPM S0i2.0" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LPM S0i2.1" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LPM S0i2.2" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LPM S0i3.0" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LPM S0i3.1" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LPM S0i3.2" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LPM S0i3.3" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LPM S0i3.4" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LPMode" /qv 0x2 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LTR Mechanism Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Maximum Payload" /qv 0x5 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Maximum Read Request" /qv 0x5 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "MMIO 32 bit Resources Padding" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Modern StandBy" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "MRC Serial Debug Messages" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Network Stack Driver Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Option ROM Messages" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "OS IDLE Mode" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PAVP Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PCH Cross Throttling" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PCI Buses Padding" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PCI Delay Optimization" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PCI Express Clock Gating" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PCI Express Power Gating" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PCIB Clock Run" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Pcie Pll SSC" /qv 0xFE /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PCIe Spread Spectrum Clocking" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PCIE Spread Spectrum" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PECI" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEG0 - ASPM" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEG0 Hotplug" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEG1 - ASPM" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEG1 Hotplug" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEG2 - ASPM" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEG2 Hotplug" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP Audio" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP CPU" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP CSME" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP EMMC" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP enumerated SATA ports" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP GNA" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP Graphics" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP HECI3" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP I2C0" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP I2C1" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP I2C2" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP I2C3" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP I2C4" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP I2C5" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP I2C6" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP I2C7" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP IPU" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP LAN(GBE)" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP PCIe DG1" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP PCIe GFX" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP PCIe LAN" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP PCIe Other" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP PCIe Storage" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP PCIe WLAN" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP PEG0" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP SATA" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP SDXC" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP SPI" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP TBT RP" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP TCSS" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP THC0" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP THC1" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP UART" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP VMD" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PEP XHCI" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Per Core P State OS control mode" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PET Progress" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PFMMIO 32 bit Resources Padding" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Port 60/64 Emulation" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Power Gating" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Power Loss Notification Feature" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Processor trace memory allocation" /qv 0xFF /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PS2 Devices Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PS2 Keyboard and Mouse" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PS_ON Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PSS Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PUIS Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Race To Halt (RTH)" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "RAM" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "RC6(Render Standby)" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "RFI Spread Spectrum" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "RGB Light" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Ring Down Bin" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Row Hammer Mode" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "S0ix Auto Demotion" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Serial Debug Messages" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Serial IO UART" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SLP_LAN# Low on DC Power" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Smart Response Technology" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SR-IOV Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Tcc Offset Lock Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Tcc Offset Time Window" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Thermal Device (B0:D4:F0)" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Thermal Velocity Boost" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Three Strike Counter" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Thunderbolt Boot Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Thunderbolt Usb Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "TPM State" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Trace Hub" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "TVB Voltage Optimizations" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Type C Support" /qv 0x2 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "USB2 PHY Sus Well Power Gating" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "USB3 Type-C UFP2DFP Kernel/Platform Debug Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "USB3" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "USB DbC Enable Mode" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "USB Overcurrent Override for DbC" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "USB S5 Wakeup Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "USB Standby Power at S4/S5" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "VDD Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Vmax Stress" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Wake From Thunderbolt(TM) Devices" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Wake on LAN Enable" /qv 0x0 /lang en-UScls
cls
echo.
SCEWIN_64.exe /i /ms "Wake on WLAN and BT Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "WatchDog" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "WDT Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Windows 10 Thunderbolt support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "WoV (Wake on Voice)" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "1TB remap" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "3-link xGMI max speed" /qv 0x13 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "4-link xGMI max speed" /qv 0x13 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "_OSC For PCI0" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "AB Clock Gating" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ACP CLock Gating" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ACP Power Gating" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ACPI _CST C1 Declaration" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ACPI Sleep State" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ACPI SRAT L3 Cache As NUMA Domain" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ACPI Standby State" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ACS Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Aggresive SATA Device Sleep Port 0" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Aggresive SATA Device Sleep Port 1" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ALink RAS Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "APBDIS" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ASPM Mode Control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "ASPM Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "BME DMA Mitigation" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Bootup NumLock State" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CC1" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CC6 memory region encryption" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Chipset Power Saving Features" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Core Watchdog Timer Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CPPC Preferred Cores" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CPPC" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CPU PCIE ASPM Mode Control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "CV test" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "D3 Cold Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "D3Cold Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Data Scramble" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Debug Port Table" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DF Cstates" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Disable DF sync flood propagation" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Disable DF to external downstream IP SyncFloodPropagation" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DMA Protection" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DMAr Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DRAM ECC Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DRAM Latency Enhance" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DRAM map inversion" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DRAM scrub time" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "DRAM UECC Retry" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "EHCI D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "eMMC Boot" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Enable AER Cap" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Extended Tag" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Fixed SOC Pstate" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Freeze DF module queues on error" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Global C-state Control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "GMI encryption control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "I2C 0 D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "I2C 1 D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "I2C 2 D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "I2C 3 D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "I2C 4 D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "I2C 5 D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Indirect Branch Prediction Speculation" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Integrated Graphics" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "IOMMU" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Ipv4 PXE Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Ipv6 PXE Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "L1 Stream HW Prefetcher" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "L2 Stream HW Prefetcher" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LCLK DPM Enhanced PCIe Detection" /qv 0x2 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LCLK DPM" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "LN2 Mode 1" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Loopback Mode" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Maximum Payload" /qv 0x5 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Maximum Read Request" /qv 0x5 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "MCA error thresh enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Modern Standby Type" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "NBIO Poison Consumption" /qv 0x2 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "NBIO RAS Control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "NBIO RAS Global Control" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "NBIO SyncFlood Generation" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "OC Mode" /qv 0x3 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Onboard PCIE LAN PXE ROM" /qv 0x0 /lang en-US 
cls
echo.
SCEWIN_64.exe /i /ms "Option ROM Messages" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Parallel Port" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PCIe ARI Enumeration" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PCIe ARI Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PCIe Ten Bit Tag Support" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Periodic Directory Rinse" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Platform First Error Handling" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PM L1 SS" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Poison scrubber control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Power Down Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Power Supply Idle Control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PSPP Policy" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "PSS Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Redirect scrubber control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Remote Display Feature" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "S3/Modern Standby Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SATA D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Sata RAS Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SB C1E Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SB Clock Spread Spectrum" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SD D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Serial(COM) Port" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SmartShift Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SMEE" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SMT Control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SMU and PSP Debug" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SoC/Uncore OC Mode" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Spread Spectrum" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SR-IOV Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SRIS" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "STAPM Boost" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Streaming Stores Control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "SVM Mode" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "System Hub Watchdog Timer" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "System probe filter" /qv 0x1 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "TCM State" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Thunderbolt Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "TPM State" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "TSME" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Turn On LED in S5" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "UART 0 D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "UART 1 D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "UART 2 D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "UART 3 D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "USB ecc SMI Enable" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "USB Phy Power Down" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "VGA Palette Snoop" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Wake on PME" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "xGMI encryption control" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "XHCI D3 Support" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "XHCI Hand-off" /qv 0x0 /lang en-US
cls
echo.
SCEWIN_64.exe /i /ms "Xtrig7 Workaround" /qv 0x0 /lang en-US
cls
exit



echo.
echo. 
echo.
echo                                                        Press any key to continue...     
pause >nul
cls
goto :menu


:CLEANER
del log.klg

echo IE Temporary Files List.
del /f /s /q "%userprofile%\Local Settings\Temporary Internet Files\*.*"
del /f /s /q "%userprofile%\Local Settings\Temp\*.*"

echo Temporary Files *.tmp *._tmp *.log *.chk *.old deleted...
del /f /s /q %systemdrive%\*.tmp
del /f /s /q %systemdrive%\*._mp
rem .log
rem del /f /s /q %systemdrive%\*.log
del /f /s /q %systemdrive%\*.gid
del /f /s /q %systemdrive%\*.chk
del /f /s /q %systemdrive%\*.old

echo Temporary files written to memory are deleted...
del /f /s /q %systemdrive%\recycled\*.*
del /f /s /q %windir%\*.bak
del /f /s /q %windir%\prefetch\*.*
rd /s /q %windir%\temp & md %windir%\temp

rem cookies deleted...
rem del /f /q %userprofile%\COOKIES s\*.*
rem del /f /q %userprofile%\recent\*.*

echo Useless Disk cleaning deletes files...
%windir%\system32\sfc.exe /purgecache

@echo on  
ipconfig/release                  
ipconfig/renew                   
ipconfig/flushdns                 
ipconfig /registerdns           
arp -d                                  
Nbtstat -R                         
Nbtstat -RR
del /f /q /s %systemdrive%\*.old
del /f /s /q %systemdrive%\*._mp
del /f /q /s %systemdrive%\*.bak
del /f /q /s %systemdrive%\*.log
del /f /q /s %systemdrive%\*.tmp
del /f /q /s %systemdrive%\*.chk
del /f /s /q %systemdrive%\*.gid
del /f /q /s %systemdrive%\RECYCLER\*.*
del /f /q /s %WinDir%\Temp\*.*
del /f /q /s %WinDir%\Prefetch\*.*
del /f /q /s %WinDir%\Driver Cache\i386\*.*
del /f /q /s %WinDir%\system32\dllcache\*.*
del /f /q /s %WinDir%$hf_mig$\*.*
del /f /q /s %WinDir%\Driver Cache\*.*ll
del /f /q /s %WinDir%\addins\*.*
del /f /q /s %WinDir%\LastGood\*.*
del /f /q /s %WinDir%\Offline Web Pages\*.*
del /f /q /s %WinDir%$NtServicePackUninstall$\*.*
del /f /q /s %WinDir%\Provisioning\*.*
del /f /q /s %WinDir%\ServicePackFiles\*.*
del /f /q /s %WinDir%\Web klasörü\*.*
del /f /q /s %WinDir%\Connection Wizard\*.*
del /f /q /s %WinDir%\EHome\*.*
del /f /q /s %WinDir%\Assembly\*.*
del /f /q /s %WinDir%\SoftwareDistribution\Download\*.*
del /f /q /s %WinDir%\mui\*.*
del /f /q /s %WinDir%\Config\*.*
del /f /q /s %WinDir%\msapps\*.*
del /f /s /q %winDir%\*.bak
del /f /q /s %userprofile%\AppData/Local/Temp\*.*
del /f /s /q %windir%\prefetch\*.*
DEL /f /s /q %windir%\*.bak
del /f /s /q %windir%\prefetch\*.*
del /f /q %SystemRoot%\comsetup.log
del /f /q %SystemRoot%\DtcInstall.log
del /f /q %localappdata%\Microsoft\Windows\WebCache\*.*
del /f /q  %SystemRoot%\Logs\CBS\CBS.log
del /f /q  %SystemRoot%\Logs\DISM\DISM.log
del /f /q "%SystemRoot%\Logs\NetSetup\*"
del /f /q "%LocalAppData%\Microsoft\CLR_v4.0\UsageTraces\*"
del /f /q "%LocalAppData%\Microsoft\CLR_v4.0_32\UsageTraces\*"
del /f /q %SystemRoot%\Temp\CBS\*
del /s /f /q %localappdata%\Microsoft\Windows\WebCache\*.*
del /s /f /q %SystemRoot%\setupapi.log
del /s /f /q %SystemRoot%\Panther\*
del /s /f /q %SystemRoot%\inf\setupapi.app.log
del /s /f /q %SystemRoot%\inf\setupapi.dev.log
del /s /f /q %SystemRoot%\inf\setupapi.offline.log
@echo Please wait......
timeout /t 5
pushd "C:\Temp" && (rd /s /q "C:\Temp" 2>nul & popd)
pushd "%windir%\temp" && (rd /s /q "%windir%\temp" 2>nul & popd)
pushd "%temp%" && (rd /s /q "%temp%" 2>nul & popd)
Powershell -Command "$bin = (New-Object -ComObject Shell.Application).NameSpace(10);$bin.items() | ForEach { Write-Host "Deleting $($_.Name) from Recycle Bin"; Remove-Item $_.Path -Recurse -Force}"
pushd "C:\Windows\Temp" && (rd /s /q "C:\Windows\Temp" 2>nul & popd)
pushd "%windir%\Prefetch " && (rd /s /q "%windir%\Prefetch" 2>nul & popd)
pushd "%windir%\system32\dllcache" && (rd /s /q "%windir%\system32\dllcache" 2>nul & popd)
pushd "%windir%\spool\printers" && (rd /s /q "%windir%\spool\printers" 2>nul & popd)
pushd "%USERPROFILE%\Local Settings\History" && (rd /s /q "%USERPROFILE%\Local Settings\History" 2>nul & popd)
pushd "%USERPROFILE%\Local Settings\Temporary Internet Files" && (rd /s /q "%USERPROFILE%\Local Settings\Temporary Internet Files" 2>nul & popd)
pushd "%USERPROFILE%\AppData\Local\Microsoft\Windows\Temporary Internet Files" && (rd /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\Temporary Internet Files" 2>nul & popd)
pushd "%USERPROFILE%\Local Settings\Temp" && (rd /s /q "%USERPROFILE%\Local Settings\Temp" 2>nul & popd)
pushd "%USERPROFILE%\AppData\Local\Temp" && (rd /s /q "%USERPROFILE%\AppData\Local\Temp" 2>nul & popd)
::pushd "%AppData%\Microsoft\Windows\Recent\" && (rd /s /q "%AppData%\Microsoft\Windows\Recent\" 2>nul & popd) //THIS WILL REMOVE USER PINNED ITEMS
pushd "%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer" && (rd /s /q "%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer" 2>nul & popd)
DEL /F /S /Q /A %LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db
DEL /f /s /q /a %LocalAppData%\Microsoft\Windows\Explorer\*.db
DEL /q /f /s %USERPROFILE%\AppData\Roaming\Microsoft\Office\*.tmp 

cls
if exist "%profiles%\%%u\Local Settings\Temp" echo Deletando....
if exist "%profiles%\%%u\Local Settings\Temp" cd "%profiles%\%%u\Local Settings\Temp"
if exist "%profiles%\%%u\Local Settings\Temp" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%profiles%\%%u\Local Settings\Temp" rmdir /s /q "%profiles%\%%u\Local Settings\Temp"

cls
if exist "%profiles%\%%u\AppData\Local\Temp" echo Deletando....
if exist "%profiles%\%%u\AppData\Local\Temp" cd "%profiles%\%%u\AppData\Local\Temp"
if exist "%profiles%\%%u\AppData\Local\Temp" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%profiles%\%%u\AppData\Local\Temp" rmdir /s /q "%profiles%\%%u\AppData\Local\Temp"

cls
if exist "%profiles%\%%u\AppData\Local\Microsoft\Windows\Temporary Internet Files" echo Deletando....
if exist "%profiles%\%%u\AppData\Local\Microsoft\Windows\Temporary Internet Files" cd "%profiles%\%%u\AppData\Local\Microsoft\Windows\Temporary Internet Files"
if exist "%profiles%\%%u\AppData\Local\Microsoft\Windows\Temporary Internet Files" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%profiles%\%%u\AppData\Local\Microsoft\Windows\Temporary Internet Files" rmdir /s /q "%profiles%\%%u\AppData\Local\Microsoft\Windows\Temporary Internet Files"

cls
if exist "%profiles%\%%u\AppData\Local\Microsoft\Windows\WER\ReportArchive" echo Deletando....
if exist "%profiles%\%%u\AppData\Local\Microsoft\Windows\WER\ReportArchive" cd "%profiles%\%%u\AppData\Local\Microsoft\Windows\WER\ReportArchive"
if exist "%profiles%\%%u\AppData\Local\Microsoft\Windows\WER\ReportArchive" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%profiles%\%%u\AppData\Local\Microsoft\Windows\WER\ReportArchive" rmdir /s /q "%profiles%\%%u\AppData\Local\Microsoft\Windows\WER\ReportArchive"


cls
if exist "%Systemroot%\Temp" echo Deletando....
if exist "%Systemroot%\Temp" cd "%Systemroot%\Temp"
if exist "%Systemroot%\Temp" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%Systemroot%\Temp" rmdir /s /q "%Systemroot%\Temp"

cls
if exist "%SYSTEMDRIVE%\Temp" echo Deletando....
if exist "%SYSTEMDRIVE%\Temp" cd "%SYSTEMDRIVE%\Temp"
if exist "%SYSTEMDRIVE%\Temp" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%SYSTEMDRIVE%\Temp" rmdir /s /q "%Systemroot%\Temp"

cls
if exist "%profiles%\%%u\AppData\Local\Mozilla\Firefox\Profiles" echo Deletando....
if exist "%profiles%\%%u\AppData\Local\Mozilla\Firefox\Profiles" cd "%profiles%\%%u\AppData\Local\Mozilla\Firefox\Profiles"
if exist "%profiles%\%%u\AppData\Local\Mozilla\Firefox\Profiles" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%profiles%\%%u\AppData\Local\Mozilla\Firefox\Profiles" rmdir /s /q "%profiles%\%%u\AppData\Local\Mozilla\Firefox\Profiles"

cls
if exist "%profiles%\%%u\AppData\Local\Microsoft\Windows\INetCache" echo Deletando....
if exist "%profiles%\%%u\AppData\Local\Microsoft\Windows\INetCache" cd "%profiles%\%%u\AppData\Local\Microsoft\Windows\INetCache"
if exist "%profiles%\%%u\AppData\Local\Microsoft\Windows\INetCache" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%profiles%\%%u\AppData\Local\Microsoft\Windows\INetCache" rmdir /s /q "%profiles%\%%u\AppData\Local\Microsoft\Windows\INetCache"

cls
if exist "%profiles%\%%u\AppData\Local\Microsoft\Terminal Server Client\Cache" echo Deletando....
if exist "%profiles%\%%u\AppData\Local\Microsoft\Terminal Server Client\Cache" cd "%profiles%\%%u\AppData\Local\Microsoft\Terminal Server Client\Cache"
if exist "%profiles%\%%u\AppData\Local\Microsoft\Terminal Server Client\Cache" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%profiles%\%%u\AppData\Local\Microsoft\Terminal Server Client\Cache" rmdir /s /q "%profiles%\%%u\AppData\Local\Microsoft\Terminal Server Client\Cache"

cls
if exist "%profiles%\%%u\AppData\Local\Opera Software\Opera Next\Cache" echo Deletando....
if exist "%profiles%\%%u\AppData\Local\Opera Software\Opera Next\Cache" cd "%profiles%\%%u\AppData\Local\Opera Software\Opera Next\Cache"
if exist "%profiles%\%%u\AppData\Local\Opera Software\Opera Next\Caches" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%profiles%\%%u\AppData\Local\Opera Software\Opera Next\Cache" rmdir /s /q "%profiles%\%%u\AppData\Local\Opera Software\Opera Next\Cache"


cls
if exist "%profiles%\%%u\AppData\Local\Vivaldi\User Data\Default\Cache" echo Deletando....
if exist "%profiles%\%%u\AppData\Local\Vivaldi\User Data\Default\Cache" cd "%profiles%\%%u\AppData\Local\Vivaldi\User Data\Default\Cache"
if exist "%profiles%\%%u\AppData\Local\Vivaldi\User Data\Default\Cache" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%profiles%\%%u\AppData\Local\Vivaldi\User Data\Default\Cache" rmdir /s /q "%profiles%\%%u\AppData\Local\Vivaldi\User Data\Default\Cache"


cls
if exist "%profiles%\%%u\Windows\SoftwareDistribution\DataStore" echo Deletando....
if exist "%profiles%\%%u\Windows\SoftwareDistribution\DataStore" cd "%profiles%\%%u\Windows\SoftwareDistribution\DataStore"
if exist "%profiles%\%%u\Windows\SoftwareDistribution\DataStore" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%profiles%\%%u\Windows\SoftwareDistribution\DataStore" rmdir /s /q "%profiles%\%%u\Windows\SoftwareDistribution\DataStore"


cls
if exist "%profiles%\%%u\Windows\SoftwareDistribution\Download" echo Deletando....
if exist "%profiles%\%%u\Windows\SoftwareDistribution\Download" cd "%profiles%\%%u\Windows\SoftwareDistribution\Download"
if exist "%profiles%\%%u\Windows\SoftwareDistribution\Download" del *.* /F /S /Q /A: R /A: H /A: A
if exist "%profiles%\%%u\Windows\SoftwareDistribution\Download" rmdir /s /q "%profiles%\%%u\Windows\SoftwareDistribution\Download"



echo.
echo. 
echo.
echo                                                        Press any key to continue...     
pause >nul
cls
goto :menu





                                