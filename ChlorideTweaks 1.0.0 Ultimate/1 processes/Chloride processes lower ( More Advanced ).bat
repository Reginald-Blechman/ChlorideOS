@echo off
setlocal

:Menu
echo ===========================
echo Choose an option:
echo 1. Apply Tweaks
echo 2. Revert Tweaks
echo 3. Exit
echo ===========================
set /p choice="Enter your choice: "

if "%choice%"=="1" goto ApplyTweaks
if "%choice%"=="2" goto RevertTweaks
if "%choice%"=="3" exit

echo Invalid choice. Please select 1, 2, or 3.
goto Menu

:ApplyTweaks
echo Applying tweaks...

rem Apply registry changes
reg add "HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "MicrophoneCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f

rem Disable services
sc config wlidsvc start= disabled
sc config DisplayEnhancementService start= disabled
sc config DiagTrack start= disabled
sc config DusmSvc start= disabled
sc config TabletInputService start= disabled
sc config RetailDemo start= disabled
sc config Fax start= disabled
sc config SharedAccess start= disabled
sc config lfsvc start= disabled
sc config WpcMonSvc start= disabled
sc config SessionEnv start= disabled
sc config MicrosoftEdgeElevationService start= disabled
sc config edgeupdate start= disabled
sc config edgeupdatem start= disabled
sc config autotimesvc start= disabled
sc config CscService start= disabled
sc config TermService start= disabled
sc config SensorDataService start= disabled
sc config SensorService start= disabled
sc config SensrSvc start= disabled
sc config shpamsvc start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config PhoneSvc start= disabled
sc config TapiSrv start= disabled
sc config UevAgentService start= disabled
sc config WalletService start= disabled
sc config TokenBroker start= disabled
sc config WebClient start= disabled
sc config MixedRealityOpenXRSvc start= disabled
sc config stisvc start= disabled
sc config WbioSrvc start= disabled
sc config icssvc start= disabled
sc config Wecsvc start= disabled
sc config XboxGipSvc start= disabled
sc config XblAuthManager start= disabled
sc config XboxNetApiSvc start= disabled
sc config XblGameSave start= disabled
sc config SEMgrSvc start= disabled
sc config iphlpsvc start= disabled
sc config Backupper Service start= disabled
sc config BthAvctpSvc start= disabled
sc config BDESVC start= disabled
sc config cbdhsvc start= disabled
sc config CDPSvc start= disabled
sc config CDPUserSvc start= disabled
sc config DevQueryBroker start= disabled
sc config DevicesFlowUserSvc start= disabled
sc config dmwappushservice start= disabled
sc config DispBrokerDesktopSvc start= disabled
sc config TrkWks start= disabled
sc config dLauncherLoopback start= disabled
sc config EFS start= disabled
sc config fdPHost start= disabled
sc config FDResPub start= disabled
sc config IKEEXT start= disabled
sc config NPSMSvc start= disabled
sc config WPDBusEnum start= disabled
sc config PcaSvc start= disabled
sc config RasMan start= disabled
sc config RetailDemo start=disabled
sc config SstpSvc start= disabled
sc config ShellHWDetection start= disabled
sc config SSDPSRV start= disabled
sc config SysMain start= disabled
sc config OneSyncSvc start= disabled
sc config lmhosts start= disabled
sc config UserDataSvc start= disabled
sc config UnistoreSvc start= disabled
sc config Wcmsvc start= disabled
sc config FontCache start= disabled
sc config W32Time start= disabled
sc config tzautoupdate start= disabled
sc config DsSvc start= disabled
sc config DevicesFlowUserSvc_5f1ad start= disabled
sc config diagsvc start= disabled
sc config DialogBlockingService start= disabled
sc config PimIndexMaintenanceSvc_5f1ad start= disabled
sc config MessagingService_5f1ad start= disabled
sc config AppVClient start= disabled
sc config MsKeyboardFilter start= disabled
sc config NetTcpPortSharing start= disabled
sc config ssh-agent start= disabled
sc config SstpSvc start= disabled
sc config OneSyncSvc_5f1ad start= disabled
sc config wercplsupport start= disabled
sc config WMPNetworkSvc start= disabled
sc config WerSvc start= disabled
sc config WpnUserService_5f1ad start= disabled
sc config WinHttpAutoProxySvc start= disabled
sc config DsmSvc start= disabled

rem Delete scheduled tasks
schtasks /DELETE /TN "AMDInstallLauncher" /f
schtasks /DELETE /TN "AMDLinkUpdate" /f
schtasks /DELETE /TN "AMDRyzenMasterSDKTask" /f
schtasks /DELETE /TN "Driver Easy Scheduled Scan" /f
schtasks /DELETE /TN "ModifyLinkUpdate" /f
schtasks /DELETE /TN "SoftMakerUpdater" /f
schtasks /DELETE /TN "StartCN" /f
schtasks /DELETE /TN "StartDVR" /f

rem Disable various tasks
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /Disable
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable

echo Tweaks applied successfully.
pause
goto Menu

:RevertTweaks
echo Reverting tweaks...

rem Revert registry changes
reg delete "HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /f
reg delete "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /f
reg delete "HKLM\System\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /f
reg delete "HKLM\System\CurrentControlSet\Services\xbgm" /v "Start" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "MicrophoneCaptureEnabled" /f
reg delete "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /f
reg delete "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /f
reg delete "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /f
reg delete "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /f
reg delete "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /f

rem Enable services (you need to specify the correct start type)
sc config wlidsvc start= auto
sc config DisplayEnhancementService start= auto
sc config DiagTrack start= auto
sc config DusmSvc start= auto
sc config TabletInputService start= auto
sc config RetailDemo start= auto
sc config Fax start= auto
sc config SharedAccess start= auto
sc config lfsvc start= auto
sc config WpcMonSvc start= auto
sc config SessionEnv start= auto
sc config MicrosoftEdgeElevationService start= auto
sc config edgeupdate start= auto
sc config edgeupdatem start= auto
sc config autotimesvc start= auto
sc config CscService start= auto
sc config TermService start= auto
sc config SensorDataService start= auto
sc config SensorService start= auto
sc config SensrSvc start= auto
sc config shpamsvc start= auto
sc config diagnosticshub.standardcollector.service start= auto
sc config PhoneSvc start= auto
sc config TapiSrv start= auto
sc config UevAgentService start= auto
sc config WalletService start= auto
sc config TokenBroker start= auto
sc config WebClient start= auto
sc config MixedRealityOpenXRSvc start= auto
sc config stisvc start= auto
sc config WbioSrvc start= auto
sc config icssvc start= auto
sc config Wecsvc start= auto
sc config XboxGipSvc start= auto
sc config XblAuthManager start= auto
sc config XboxNetApiSvc start= auto
sc config XblGameSave start= auto
sc config SEMgrSvc start= auto
sc config iphlpsvc start= auto
sc config Backupper Service start= auto
sc config BthAvctpSvc start= auto
sc config BDESVC start= auto
sc config cbdhsvc start= auto
sc config CDPSvc start= auto
sc config CDPUserSvc start= auto
sc config DevQueryBroker start= auto
sc config DevicesFlowUserSvc start= auto
sc config dmwappushservice start= auto
sc config DispBrokerDesktopSvc start= auto
sc config TrkWks start= auto
sc config dLauncherLoopback start= auto
sc config EFS start= auto
sc config fdPHost start= auto
sc config FDResPub start= auto
sc config IKEEXT start= auto
sc config NPSMSvc start= auto
sc config WPDBusEnum start= auto
sc config PcaSvc start= auto
sc config RasMan start= auto
sc config RetailDemo start= auto
sc config SstpSvc start= auto
sc config ShellHWDetection start= auto
sc config SSDPSRV start= auto
sc config SysMain start= auto
sc config OneSyncSvc start= auto
sc config lmhosts start= auto
sc config UserDataSvc start= auto
sc config UnistoreSvc start= auto
sc config Wcmsvc start= auto
sc config FontCache start= auto
sc config W32Time start= auto
sc config tzautoupdate start= auto
sc config DsSvc start= auto
sc config DevicesFlowUserSvc_5f1ad start= auto
sc config diagsvc start= auto
sc config DialogBlockingService start= auto
sc config PimIndexMaintenanceSvc_5f1ad start= auto
sc config MessagingService_5f1ad start= auto
sc config AppVClient start= auto
sc config MsKeyboardFilter start= auto
sc config NetTcpPortSharing start= auto
sc config ssh-agent start= auto
sc config SstpSvc start= auto
sc config OneSyncSvc_5f1ad start= auto
sc config wercplsupport start= auto
sc config WMPNetworkSvc start= auto
sc config WerSvc start= auto
sc config WpnUserService_5f1ad start= auto
sc config WinHttpAutoProxySvc start= auto
sc config DsmSvc start= auto

rem Recreate scheduled tasks
rem Add commands to recreate any necessary tasks here

echo Tweaks reverted successfully.
pause
goto Menu
