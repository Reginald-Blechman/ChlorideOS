��&cls
@echo off
@chcp 65001 >nul
shift /0
color 0d
title Tweaks OS Booster Full
echo By JohnzinN
cd %systemroot%\system32
call :IsAdmin
SETLOCAL EnableDelayedExpansion
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set "DEL=%%a"
)

SET "el1= [1;34m                                   __       __             _            
SET "el2= [1;34m                               __ / /___   / /   ___   ___(_) ___   ___ 
SET "el3= [1;34m                              / // // _ \ / _ \ / _ \ /_ // // _ \ / _ \
SET "el4= [1;34m                              \___/ \___//_//_//_//_//__//_//_//_//_//_/
                                                                                                   
cls
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.                                                    Tweaks OS Booster Full
echo.                                                 _____________________________ 
echo.
echo.
echo.          %el1%
echo.          %el2%
echo.          %el3%
echo.          %el4%
echo.          %el5%
echo.          %el6%
echo.          %el7%
echo. 
echo.
echo.
echo  Pressione Enter...
pause >nul

cls
::Tweaks
title Tweaks OS Boosting...
taskkill /f /im explorer.exe >nul
bcdedit /set linearaddress57 OptOut
bcdedit /set increaseuserva 268435328
bcdedit /set firstmegabytepolicy UseAll
bcdedit /set avoidlowmemory 0x8000000
bcdedit /set nolowmem Yes
bcdedit /set allowedinmemorysettings 0x0
bcdedit /set isolatedcontext No
bcdedit /set vsmlaunchtype Off
bcdedit /set vm No
bcdedit /set configaccesspolicy Default
bcdedit /set MSI Default
bcdedit /set usephysicaldestination No
bcdedit /set usefirmwarepcisettings No
bcdedit /set allowedinmemorysettings 0
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformtick Yes
bcdedit /set tscsyncpolicy Enhanced
bcdedit /set debug No
bcdedit /set pae ForceEnable
bcdedit /set bootmenupolicy Legacy
bcdedit /set sos Yes
bcdedit /set disabledynamictick Yes
bcdedit /set disableelamdrivers Yes
bcdedit /set quietboot Yes
bcdedit /set ems No
bcdedit /set linearaddress57 optin
bcdedit /set noumex Yes
bcdedit /set bootems No
bcdedit /set graphicsmodedisabled No
bcdedit /set extendedinput Yes
bcdedit /set highestmode Yes
bcdedit /set forcefipscrypto No
bcdedit /set perfmem 0
bcdedit /set configflags 0
bcdedit /set uselegacyapicmode No
bcdedit /set onecpu No
bcdedit /set halbreakpoint No
bcdedit /set forcelegacyplatform No
bcdedit /set useplatformclock no
bcdedit /set useplatformtick yes
bcdedit /set firstmegabytepolicy UseAll 
bcdedit /set forcefipscrypto No
bcdedit /set nx AlwaysOff
bcdedit /timeout 2
bcdedit /set {globalsettings} custom:16000067 true
bcdedit /set {globalsettings} custom:16000069 true
bcdedit /set {globalsettings} custom:16000068 true
bcdedit /set nx optout
bcdedit /set bootux disabled
bcdedit /set bootmenupolicy standard
bcdedit /set hypervisorlaunchtype off
bcdedit /set tpmbootentropy ForceDisable
cls
fsutil behavior set memoryusage 2
fsutil behavior set mftzone 4
fsutil behavior set disablelastaccess 1
fsutil behavior set disabledeletenotify 0
fsutil behavior set encryptpagingfile 0
cls
::RegTweaks
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "NonPagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "PagedPoolQuota" /t REG_DWORD /d "0" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "SystemPages" /t REG_SZ /d "ffffffff" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ValueMax" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ValueMax" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "VsyncIdleTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "67108864" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Capture" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "BackgroundPriority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Priority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Distribution" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "BackgroundPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Priority" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Playback" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Pro Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Priority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Window Manager" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_AutoGameModeDefaultProfile" /t REG_BINARY /d "01000100000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "Win32_GameModeRelatedProcesses" /t REG_BINARY /d "010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_DWORD /d "4096" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_DWORD /d "8192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\943c8cb6-6f93-4227-ad87-e9a3feec08d1" /v "Attributes" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\2a737441-1930-4402-8d77-b2bebba308a3\d4e98f31-5ffe-4ce1-be31-1b38b384c009\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\381b4222-f694-41f0-9685-ff5bb260df2e" /v "DCSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ACSettingIndex" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
cls
::Services Bluetooth Disable
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\bthserv" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\BTAGService" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v "Start" /t reg_DWORD /d "4" /f
::Services Disable
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\SENS" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\UevAgentService" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\AsssignedAccessManagerSvc" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\PeerDistSvc" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\p2psvc" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\p2pimsvc" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\PhoneSvc" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\cbdhsvc" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\SmsRouter" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\CscService" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\SEMgrSvc" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\PNRPsvc" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\PNRPAutoreg" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\WdNisSvc" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t reg_DWORD /d "3" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t reg_DWORD /d "2" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\SENS" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\TabletInputService" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\SgrmBroker" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdate" /v "Start" /t reg_DWORD /d "4" /f
reg ADD "HKLM\SYSTEM\CurrentControlSet\Services\edgeupdatem" /v "Start" /t reg_DWORD /d "4" /f
::Windows Update Disable
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" /v "PausedFeatureStatus" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UpdatePolicy\Settings" /v "PausedQualityStatus" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX" /v "IsConvergedUpdateStackEnabled" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursEnd" /t REG_DWORD /d "17" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursStart" /t REG_DWORD /d "8" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "AllowAutoWindowsUpdateDownloadOverMeteredNetwork" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "DeferFeatureUpdatesPeriodInDays" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "DeferQualityUpdatesPeriodInDays" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "FlightCommitted" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "LastToastAction" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "UxOption" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "InsiderProgramEnabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PendingRebootStartTime" /t REG_SZ /d "2019-07-28T03:07:38Z" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseFeatureUpdatesStartTime" /t REG_SZ /d "2019-07-28T10:38:56Z" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseQualityUpdatesStartTime" /t REG_SZ /d "2019-07-28T10:38:56Z" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseUpdatesExpiryTime" /t REG_SZ /d "2099-01-01T10:38:56Z" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseFeatureUpdatesEndTime" /t REG_SZ /d "2099-01-01T10:38:56Z" /f
REG ADD "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "PauseQualityUpdatesEndTime" /t REG_SZ /d "2099-01-01T10:38:56Z" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ShutdownWithoutLogon" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DontDisplayLastUserName" /t REG_DWORD /d "0" /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\OneSyncSvc" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TokenBroker" /v Start /t REG_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vmcompute" /v Start /t reg_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\cbdhsvc" /v Start /t REG_DWORD /d 00000004 /f
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wisvc" /v Start /t REG_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnUserService" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SSDPSRV" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmms" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\vmicvmsession" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\hidserv" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LanmanServer" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LanmanWorkstation" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SSDPSRV" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\SysMain" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Themes" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WSearch" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\PlugPlay" /v Start /t reg_DWORD /d 00000004 /f
REG add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\DoSvc" /v Start /t reg_DWORD /d 00000004 /f
cls
net accounts /maxpwage:unlimited
powercfg /hibernate off
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
cls
for /f "tokens=2 delims==" %%a in ('wmic os get TotalVisibleMemorySize /format:value') do set mem=%%a
set /a ram=%mem% + 768000
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "%ram%" /f
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients" /f
cls
sc stop BITS
for /f "tokens=3" %%a in ('sc queryex "BITS" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "low"
sc start DsSvc
for /f "tokens=3" %%a in ('sc queryex "DsSvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start Dhcp
for /f "tokens=3" %%a in ('sc queryex "Dhcp" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start DPS 
for /f "tokens=3" %%a in ('sc queryex "DPS" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start Dnscache
for /f "tokens=3" %%a in ('sc queryex "Dnscache" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start WinHttpAutoProxySvc
for /f "tokens=3" %%a in ('sc queryex "WinHttpAutoProxySvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start DcpSvc
for /f "tokens=3" %%a in ('sc queryex "BITS" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "DcpSvc"
sc start WlanSvc
for /f "tokens=3" %%a in ('sc queryex "WlanSvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start LSM
for /f "tokens=3" %%a in ('sc queryex "LSM" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start smphost
for /f "tokens=3" %%a in ('sc queryex "smphost" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "low"
sc start PNRPsvc
for /f "tokens=3" %%a in ('sc queryex "PNRPsvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "low"
sc start SensrSvc
for /f "tokens=3" %%a in ('sc queryex "SensrSvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "low"
sc start Wcmsvc
for /f "tokens=3" %%a in ('sc queryex "Wcmsvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "low"
sc start Wersvc
for /f "tokens=3" %%a in ('sc queryex "Wersvc" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "low"
sc start Spooler
for /f "tokens=3" %%a in ('sc queryex "Spooler" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
sc start vds
for /f "tokens=3" %%a in ('sc queryex "vds" ^| findstr "PID"') do (set pid=%%a)
wmic process where ProcessId=%pid% CALL setpriority "realtime"
cls
sc config "wsearch" start= disabled
sc stop wsearch
sc config "WerSvc" start= disabled
sc config "DiagTrack" start= disabled
sc config SysMain start= disabled
sc stop SysMain
cls
sc config iphlpsvc start= disabled
sc config SCardSvr start= disabled
sc config WpcMonSvc start= disabled
sc config PimIndexMaintenanceSvc_725a1 start= disabled
sc config diagsvc start= disabled
sc config Experiência de Telemetria start= disabled
sc config Fax start= disabled
sc config WdiServiceHost start= disabled
sc config WdiSystemHost start= disabled
sc config seclogon start= disabled
sc config AppVClient start= disabled
sc config Microsoft Update Health Service start= disabled
sc config ssh-agent start= disabled
sc config FDResPub start= disabled
sc config RemoteRegistry start= disabled
sc config RRemoteAccess start= disabled
sc config LanmanServer start= disabled
sc config Serviço Coletor de Padrões de Hub de Diagnóstico da Microsoft (R) start= disabled
sc config WbioSrvc start= disabled
sc config NetTcpPortSharing start= disabled
sc config WMPNetworkSvc start= disabled
sc config SensrSvc start= disabled
sc config DPS start= disabled
sc config Serviço de Relatórios de Erro do Windows start= disabled
sc config dmwappushservice start= disabled
sc config SensorService start= disabled
sc config TabletInputService start= disabled
sc config PhoneSvc start= disabled
sc config UevAgentService start= disabled
sc config WpnUserService_725a1 start= disabled
sc config Serviço do Participante do Programa Windows Insider start= disabled
sc config shpamsvc start= disabled
sc config SysMain start= disabled
sc config TapiSrv start= disabled
sc config WSearch start= disabled
sc config SCPolicySvc start= disabled
sc config ScDeviceEnum start= disabled
sc config gupdate start= disabled
sc config gupdatem start= disabled
sc config edgeupdate start= disabled
sc config edgeupdatem start= disabled
sc config autotimesvc start= disabled
sc config SensorDataService start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config PhoneSvc start= disabled
sc config TapiSrv start= disabled
sc config Wecsvc start= disabled
sc config SEMgrSvc start= disabled
sc config BDESVC start= disabled
sc config DevQueryBroker start= disabled
cls
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /end /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /end /tn "\Microsoft\Windows\Application Experience\StartupAppTask"
schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /disable"
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /end /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable
cls
for /f "tokens=2 delims==" %%a in ('wmic os get TotalVisibleMemorySize /format:value') do set mem=%%a
set /a ram=%mem% + 1024000
reg add "hklm\system\currentcontrolset\control" /v "svchostsplitthresholdinkb" /t reg_dword /d "%ram%" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DontDisplayLastUserName" /t REG_DWORD /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 00000000 /f
cls

echo Disabling AllJoyn Router Service...
sc stop AJRouter
sc config AJRouter start= disabled

echo Disabling AppX Deployment Service (AppXSVC)...
sc stop AppXSvc
sc config AppXSvc start= disabled

echo Disabling Application Layer Gateway Service...
sc stop ALG
sc config ALG start= disabled

echo Disabling Application Management...
sc stop AppMgmt
sc config AppMgmt start= disabled

echo Disabling App Readiness...
sc stop AppReadiness
sc config AppReadiness start= disabled

echo Disabling Auto Time Zone Updater...
sc stop tzautoupdate
sc config tzautoupdate start= disabled

echo Disabling AssignedAccessManager Service...
sc stop AssignedAccessManagerSvc
sc config AssignedAccessManagerSvc start= disabled

echo Disabling Background Intelligent Transfer Service...
sc stop BITS
sc config BITS start= disabled

echo Disabling BitLocker Drive Encryption Service...
sc stop BDESVC
sc config BDESVC start= disabled

echo Disabling Block Level Backup Engine Service...
sc stop wbengine
sc config wbengine start= disabled

echo Disabling Bluetooth Audio Gateway Service...
sc stop BTAGService
sc config BTAGService start= disabled

echo Disabling Bluetooth Support Service...
sc stop bthserv
sc config bthserv start= disabled

echo Disabling Bluetooth Handsfree Service...
sc stop BthHFSrv
sc config BthHFSrv start= disabled

echo Disabling BranchCache...
sc stop PeerDistSvc
sc config PeerDistSvc start= disabled

echo Disabling CNG Key Isolation...
sc stop KeyIso
sc config KeyIso start= disabled

echo Disabling Certificate Propagation...
sc stop CertPropSvc
sc config CertPropSvc start= disabled

echo Disabling Client License Service (ClipSVC)...
sc stop ClipSVC
sc config ClipSVC start= disabled

echo Disabling Connected User Experiences and Telemetry...
sc stop DiagTrack
sc config DiagTrack start= disabled

echo Disabling Credential Manager...
sc stop VaultSvc
sc config VaultSvc start= disabled

echo Disabling Connected Devices Platform Service...
sc stop CDPSvc
sc config CDPSvc start= disabled

echo Disabling Data Usage...
sc stop DusmSvc
sc config DusmSvc start= disabled

echo Disabling Delivery Optimization...
sc stop DoSvc
sc config DoSvc start= disabled

echo Disabling Diagnostic Execution Service...
sc stop diagsvc
sc config diagsvc start= disabled

echo Disabling Diagnostic Policy Service...
sc stop DPS
sc config DPS start= disabled

echo Disabling Diagnostic Service Host...
sc stop WdiServiceHost
sc config WdiServiceHost start= disabled

echo Disabling Diagnostic System Host...
sc stop WdiSystemHost
sc config WdiSystemHost start= disabled

echo Disabling Distributed Link Tracking Client...
sc stop TrkWks
sc config TrkWks start= disabled

echo Disabling Distributed Transaction Coordinator...
sc stop MSDTC
sc config MSDTC start= disabled

echo Disabling dmwappushsvc...
sc stop dmwappushservice
sc config dmwappushservice start= disabled

echo Disabling Display Enhancement Service...
sc stop DisplayEnhancementService
sc config DisplayEnhancementService start= disabled

echo Disabling Downloaded Maps Manager...
sc stop MapsBroker
sc config MapsBroker start= disabled

echo Disabling Function Discovery Provider Host...
sc stop fdPHost
sc config fdPHost start= disabled

echo Disabling Function Discovery Resource Publication...
sc stop FDResPub
sc config FDResPub start= disabled

echo Disabling Encrypting File System (EFS)...
sc stop EFS
sc config EFS start= disabled

echo Disabling Enterprise App Management Service...
sc stop EntAppSvc
sc config EntAppSvc start= disabled

echo Disabling File History Service...
sc stop fhsvc
sc config fhsvc start= disabled

echo Disabling Geolocation Service...
sc stop lfsvc
sc config lfsvc start= disabled

echo Disabling GraphicsPerfSvc...
sc stop GraphicsPerfSvc
sc config GraphicsPerfSvc start= disabled

echo Disabling HomeGroup Listener...
sc stop HomeGroupListener
sc config HomeGroupListener start= disabled

echo Disabling HomeGroup Provider...
sc stop HomeGroupProvider
sc config HomeGroupProvider start= disabled

echo Disabling HV Host Service...
sc stop HvHost
sc config HvHost start= disabled

echo Disabling Host Network Service...
sc stop hns
sc config hns start= disabled

echo Disabling Hyper-V Data Exchange Service...
sc stop vmickvpexchange
sc config vmickvpexchange start= disabled

echo Disabling Hyper-V Guest Service Interface...
sc stop vmicguestinterface
sc config vmicguestinterface start= disabled

echo Disabling Hyper-V Guest Shutdown Service...
sc stop vmicshutdown
sc config vmicshutdown start= disabled

echo Disabling Hyper-V Heartbeat Service...
sc stop vmicheartbeat
sc config vmicheartbeat start= disabled

echo Disabling Hyper-V PowerShell Direct Service...
sc stop vmicvmsession
sc config vmicvmsession start= disabled

echo Disabling Hyper-V Remote Desktop Virtualization Service...
sc stop vmicrdv
sc config vmicrdv start= disabled

echo Disabling Hyper-V Time Synchronization Service...
sc stop vmictimesync
sc config vmictimesync start= disabled

echo Disabling Hyper-V Volume Shadow Copy Requestor...
sc stop vmicvss
sc config vmicvss start= disabled

echo Disabling Internet Explorer ETW Collector Service...
sc stop IEEtwCollectorService
sc config IEEtwCollectorService start= disabled

echo Disabling IP Helper...
sc stop iphlpsvc
sc config iphlpsvc start= disabled

echo Disabling IP Translation Configuration Service...
sc stop IpxlatCfgSvc
sc config IpxlatCfgSvc start= disabled

echo Disabling IPsec Policy Agent...
sc stop PolicyAgent
sc config PolicyAgent start= disabled

echo Disabling Infrared monitor service...
sc stop irmon
sc config irmon start= disabled

echo Disabling Internet Connection Sharing (ICS)...
sc stop SharedAccess
sc config SharedAccess start= disabled

echo Disabling Link-Layer Topology Discovery Mapper...
sc stop lltdsvc
sc config lltdsvc start= disabled

echo Disabling Microsoft (R) Diagnostics Hub Standard Collector Service...
sc stop diagnosticshub.standardcollector.service
sc config diagnosticshub.standardcollector.service start= disabled

echo Disabling Microsoft Account Sign-in Assistant...
sc stop wlidsvc
sc config wlidsvc start= disabled

echo Disabling Microsoft App-V Client...
sc stop AppVClient
sc config AppVClient start= disabled

echo Disabling Microsoft Passport...
sc stop NgcSvc
sc config NgcSvc start= disabled

echo Disabling Microsoft Passport Container...
sc stop NgcCtnrSvc
sc config NgcCtnrSvc start= disabled

echo Disabling Microsoft Storage Spaces SMP...
sc stop smphost
sc config smphost start= disabled

echo Disabling Microsoft Store Install Service...
sc stop InstallService
sc config InstallService start= disabled

echo Disabling Microsoft Windows SMS Router Service...
sc stop SmsRouter
sc config SmsRouter start= disabled

echo Disabling Microsoft iSCSI Initiator Service...
sc stop MSiSCSI
sc config MSiSCSI start= disabled

echo Disabling Natural Authentication...
sc stop NaturalAuthentication
sc config NaturalAuthentication start= disabled

echo Disabling Netlogon...
sc stop Netlogon
sc config Netlogon start= disabled

echo Disabling Network Connected Devices Auto-Setup...
sc stop NcdAutoSetup
sc config NcdAutoSetup start= disabled

echo Disabling Network Connection Broker...
sc stop NcbService
sc config NcbService start= disabled

echo Disabling Network Connectivity Assistant...
sc stop NcaSvc
sc config NcaSvc start= disabled

echo Disabling Offline Files...
sc stop CscService
sc config CscService start= disabled

echo Disabling Optimize drives...
sc stop defragsvc
sc config defragsvc start= disabled

echo Disabling Payments and NFC/SE Manager...
sc stop SEMgrSvc
sc config SEMgrSvc start= disabled

echo Disabling Peer Name Resolution Protocol...
sc stop PNRPsvc
sc config PNRPsvc start= disabled

echo Disabling Peer Networking Grouping...
sc stop p2psvc
sc config p2psvc start= disabled

echo Disabling Peer Networking Identity Manager...
sc stop p2pimsvc
sc config p2pimsvc start= disabled

echo Disabling Performance Logs & Alerts...
sc stop pla
sc config pla start= disabled

echo Disabling Phone Service...
sc stop PhoneSvc
sc config PhoneSvc start= disabled

echo Disabling Portable Device Enumerator Service...
sc stop WPDBusEnum
sc config WPDBusEnum start= disabled

echo Disabling Print Spooler...
sc stop Spooler
sc config Spooler start= disabled

echo Disabling Printer Extensions and Notifications...
sc stop PrintNotify
sc config PrintNotify start= disabled

echo Disabling Program Compatibility Assistant Service...
sc stop PcaSvc
sc config PcaSvc start= disabled

echo Disabling Parental Controls...
sc stop WpcMonSvc
sc config WpcMonSvc start= disabled

echo Disabling Quality Windows Audio Video Experience...
sc stop QWAVE
sc config QWAVE start= disabled

echo Disabling Remote Access Auto Connection Manager...
sc stop RasAuto
sc config RasAuto start= disabled

echo Disabling Remote Access Connection Manager...
sc stop RasMan
sc config RasMan start= disabled

echo Disabling Remote Desktop Configuration...
sc stop SessionEnv
sc config SessionEnv start= disabled

echo Disabling Remote Desktop Services...
sc stop TermService
sc config TermService start= disabled

echo Disabling Remote Desktop Services UserMode Port Redirector...
sc stop UmRdpService
sc config UmRdpService start= disabled

echo Disabling Remote Procedure Call (RPC) Locator...
sc stop RpcLocator
sc config RpcLocator start= disabled

echo Disabling Remote Registry...
sc stop RemoteRegistry
sc config RemoteRegistry start= disabled

echo Disabling Retail Demo Service...
sc stop RetailDemo
sc config RetailDemo start= disabled

echo Disabling Routing and Remote Access...
sc stop RemoteAccess
sc config RemoteAccess start= disabled

echo Disabling Radio Management Service...
sc stop RmSvc
sc config RmSvc start= disabled

echo Disabling SNMP Trap...
sc stop SNMPTRAP
sc config SNMPTRAP start= disabled

echo Disabling Secondary Logon...
sc stop seclogon
sc config seclogon start= disabled

echo Disabling Security Center...
sc stop wscsvc
sc config wscsvc start= disabled

echo Disabling Security Accounts Manager...
sc stop SamSs
sc config SamSs start= disabled

echo Disabling Sensor Data Service...
sc stop SensorDataService
sc config SensorDataService start= disabled

echo Disabling Sensor Monitoring Service...
sc stop SensrSvc
sc config SensrSvc start= disabled

echo Disabling Sensor Service...
sc stop SensorService
sc config SensorService start= disabled

echo Disabling Server...
sc stop LanmanServer
sc config LanmanServer start= disabled

echo Disabling Server...
sc stop ssh-agent
sc config ssh-agent start= disabled

echo Disabling Shared PC Account Manager...
sc stop shpamsvc
sc config shpamsvc start= disabled

echo Disabling Shell Hardware Detection...
sc stop ShellHWDetection
sc config ShellHWDetection start= disabled

echo Disabling Smart Card...
sc stop SCardSvr
sc config SCardSvr start= disabled

echo Disabling Smart Card Device Enumeration Service...
sc stop ScDeviceEnum
sc config ScDeviceEnum start= disabled

echo Disabling Smart Card Removal Policy...
sc stop SCPolicySvc
sc config SCPolicySvc start= disabled

echo Disabling Spatial Data Service...
sc stop SharedRealitySvc
sc config SharedRealitySvc start= disabled

echo Disabling Storage Service...
sc stop StorSvc
sc config StorSvc start= disabled

echo Disabling Storage Tiers Management...
sc stop TieringEngineService
sc config TieringEngineService start= disabled

echo Disabling Superfetch (SysMain)...
sc stop SysMain
sc config SysMain start= disabled

echo Disabling System Guard Runtime Monitor Broker...
sc stop SgrmBroker
sc config SgrmBroker start= disabled

echo Disabling Telephony...
sc stop TapiSrv
sc config TapiSrv start= disabled

echo Disabling Themes...
sc stop Themes
sc config Themes start= disabled

echo Disabling Tile Data model server...
sc stop tiledatamodelsvc
sc config tiledatamodelsvc start= disabled

echo Disabling Touch Keyboard and Handwriting Panel Service...
sc stop TabletInputService
sc config TabletInputService start= disabled

echo Disabling Update Orchestrator Service...
sc stop UsoSvc
sc config UsoSvc start= disabled

echo Disabling User Experience Virtualization Service...
sc stop UevAgentService
sc config UevAgentService start= disabled

echo Disabling WalletService...
sc stop WalletService
sc config WalletService start= disabled

echo Disabling WMI Performance Adapter...
sc stop wmiApSrv
sc config wmiApSrv start= disabled

echo Disabling WWAN AutoConfig...
sc stop WwanSvc
sc config WwanSvc start= disabled

echo Disabling Web Account Manager...
sc stop TokenBroker
sc config TokenBroker start= disabled

echo Disabling WebClient...
sc stop WebClient
sc config WebClient start= disabled

echo Disabling Wi-Fi Direct Services Connection Manager Service...
sc stop WFDSConMgrSvc
sc config WFDSConMgrSvc start= disabled

echo Disabling Windows Backup...
sc stop SDRSVC
sc config SDRSVC start= disabled

echo Disabling Windows Biometric Service...
sc stop WbioSrvc
sc config WbioSrvc start= disabled

echo Disabling Windows Camera Frame Server...
sc stop FrameServer
sc config FrameServer start= disabled

echo Disabling Windows Connect Now - Config Registrar...
sc stop wcncsvc
sc config wcncsvc start= disabled

echo Disabling Windows Defender Advanced Threat Protection Service...
sc stop Sense
sc config Sense start= disabled

echo Disabling Windows Defender Antivirus Network Inspection Service...
sc stop WdNisSvc
sc config WdNisSvc start= disabled

echo Disabling Windows Defender Antivirus Service...
sc stop WinDefend
sc config WinDefend start= disabled

echo Disabling Windows Defender Security Center Service...
sc stop SecurityHealthService
sc config SecurityHealthService start= disabled

echo Disabling Windows Encryption Provider Host Service...
sc stop WEPHOSTSVC
sc config WEPHOSTSVC start= disabled

echo Disabling Windows Error Reporting Service...
sc stop WerSvc
sc config WerSvc start= disabled

echo Disabling Windows Event Collector...
sc stop Wecsvc
sc config Wecsvc start= disabled

echo Disabling Windows Font Cache Service...
sc stop FontCache
sc config FontCache start= disabled

echo Disabling Windows Image Acquisition (WIA)...
sc stop StiSvc
sc config StiSvc start= disabled

echo Disabling Windows Insider Service...
sc stop wisvc
sc config wisvc start= disabled

echo Disabling Windows License Manager Service...
sc stop LicenseManager
sc config LicenseManager start= disabled

echo Disabling Windows Mobile Hotspot Service...
sc stop icssvc
sc config icssvc start= disabled

echo Disabling Windows Media Player Network Sharing Service...
sc stop WMPNetworkSvc
sc config WMPNetworkSvc start= disabled

echo Disabling Windows Presentation Foundation Font Cache 3.0.0.0...
sc stop FontCache3.0.0.0
sc config FontCache3.0.0.0 start= disabled

echo Disabling Windows Push Notifications System Service...
sc stop WpnService
sc config WpnService start= disabled

echo Disabling Windows Perception Simulation Service...
sc stop perceptionsimulation
sc config perceptionsimulation start= disabled

echo Disabling Windows Perception Service...
sc stop spectrum
sc config spectrum start= disabled

echo Disabling Windows Remote Management (WS-Management)...
sc stop WinRM
sc config WinRM start= disabled

echo Disabling Windows Search...
sc stop WSearch
sc config WSearch start= disabled

echo Disabling Windows Security Service...
sc stop SecurityHealthService
sc config SecurityHealthService start= disabled

echo Disabling Windows Time...
sc stop W32Time
sc config W32Time start= disabled

echo Disabling Windows Update...
sc stop wuauserv
sc config wuauserv start= disabled

echo Disabling Windows Update Medic Service...
sc stop WaaSMedicSvc
sc config WaaSMedicSvc start= disabled

echo Disabling Workstation...
sc stop LanmanWorkstation
sc config LanmanWorkstation start= disabled

echo Disabling Xbox Accessory Management Service...
sc stop XboxGipSvc
sc config XboxGipSvc start= disabled

echo Disabling Xbox Game Monitoring...
sc stop xbgm
sc config xbgm start= disabled

echo Disabling Xbox Live Auth Manager...
sc stop XblAuthManager
sc config XblAuthManager start= disabled

echo Disabling Xbox Live Game Save...
sc stop XblGameSave
sc config XblGameSave start= disabled

echo Disabling Xbox Live Networking Service...
sc stop XboxNetApiSvc
sc config XboxNetApiSvc start= disabled
start explorer.exe >nul
cls

title Tweaks OS Booster Full !
echo.
echo.
echo   Otimização Feita com Sucesso!
echo.
echo   Recomendado Reiniciar Seu PC Para Que Tudo Seja Aplicado!
echo.
pause >nul
exit