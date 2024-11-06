@echo off
echo Reverting changes to advanced services and registry...

:: Re-enable previously disabled advanced services
sc config AJRouter start= demand > nul
sc config AppXSvc start= demand > nul
sc config ALG start= demand > nul
sc config AppMgmt start= demand > nul
sc config tzautoupdate start= demand > nul
sc config AssignedAccessManagerSvc start= demand > nul
sc config BITS start= demand > nul
sc config BDESVC start= demand > nul
sc config wbengine start= demand > nul
sc config BTAGService start= demand > nul
sc config bthserv start= demand > nul
sc config BthHFSrv start= demand > nul
sc config PeerDistSvc start= demand > nul
sc config CertPropSvc start= demand > nul
sc config ClipSVC start= demand > nul
sc config DiagTrack start= demand > nul
sc config VaultSvc start= demand > nul
sc config CDPSvc start= demand > nul
sc config DusmSvc start= demand > nul
sc config DoSvc start= demand > nul
sc config diagsvc start= demand > nul
sc config DPS start= demand > nul
sc config WdiServiceHost start= demand > nul
sc config WdiSystemHost start= demand > nul
sc config TrkWks start= demand > nul
sc config MSDTC start= demand > nul
sc config dmwappushservice start= demand > nul
sc config DisplayEnhancementService start= demand > nul
sc config MapsBroker start= demand > nul
sc config fdPHost start= demand > nul
sc config FDResPub start= demand > nul
sc config EFS start= demand > nul
sc config EntAppSvc start= demand > nul
sc config fhsvc start= demand > nul
sc config lfsvc start= demand > nul
sc config HomeGroupListener start= demand > nul
sc config HomeGroupProvider start= demand > nul
sc config HvHost start= demand > nul
sc config hns start= demand > nul
sc config vmickvpexchange start= demand > nul
sc config vmicguestinterface start= demand > nul
sc config vmicshutdown start= demand > nul
sc config vmicheartbeat start= demand > nul
sc config vmicvmsession start= demand > nul
sc config vmicrdv start= demand > nul
sc config vmictimesync start= demand > nul
sc config vmicvss start= demand > nul
sc config IEEtwCollectorService start= demand > nul
sc config iphlpsvc start= demand > nul 
sc config IpxlatCfgSvc start= demand > nul
sc config PolicyAgent start= demand > nul
sc config irmon start= demand > nul
sc config SharedAccess start= demand > nul
sc config lltdsvc start= demand > nul
sc config diagnosticshub.standardcollector.service start= demand > nul
sc config wlidsvc start= demand > nul
sc config AppVClient start= demand > nul
sc config smphost start= demand > nul
sc config InstallService start= demand > nul
sc config SmsRouter start= demand > nul
sc config MSiSCSI start= demand > nul
sc config NaturalAuthentication start= demand > nul
sc config CscService start= demand > nul
sc config defragsvc start= demand > nul
sc config SEMgrSvc start= demand > nul
sc config PNRPsvc start= demand > nul
sc config p2psvc start= demand > nul
sc config p2pimsvc start= demand > nul
sc config pla start= demand > nul
sc config PhoneSvc start= demand > nul
sc config WPDBusEnum start= demand > nul
sc config Spooler start= demand > nul
sc config PrintNotify start= demand > nul
sc config PcaSvc start= demand > nul
sc config WpcMonSvc start= demand > nul
sc config QWAVE start= demand > nul
sc config RasAuto start= demand > nul
sc config RasMan start= demand > nul
sc config SessionEnv start= demand > nul
sc config TermService start= demand > nul
sc config UmRdpService start= demand > nul
sc config RpcLocator start= demand > nul
sc config RemoteRegistry start= demand > nul
sc config RetailDemo start= demand > nul
sc config RemoteAccess start= demand > nul
sc config RmSvc start= demand > nul 
sc config SNMPTRAP start= demand > nul
sc config seclogon start= demand > nul
sc config wscsvc start= demand > nul
sc config SamSs start= demand > nul
sc config SensorDataService start= demand > nul
sc config SensrSvc start= demand > nul
sc config SensorService start= demand > nul
sc config LanmanServer start= demand > nul
sc config shpamsvc start= demand > nul
sc config ShellHWDetection start= demand > nul
sc config SCardSvr start= demand > nul
sc config ScDeviceEnum start= demand > nul
sc config SCPolicySvc start= demand > nul
sc config SharedRealitySvc start= demand > nul
sc config StorSvc start= demand > nul
sc config TieringEngineService start= demand > nul
sc config SysMain start= demand > nul
sc config SgrmBroker start= demand > nul
sc config lmhosts start= demand > nul
sc config TapiSrv start= demand > nul
sc config Themes start= demand > nul
sc config tiledatamodelsvc start= demand > nul
sc config TabletInputService start= demand > nul
sc config UsoSvc start= demand > nul
sc config UevAgentService start= demand > nul
sc config WalletService start= demand > nul
sc config wmiApSrv start= demand > nul
sc config TokenBroker start= demand > nul
sc config WebClient start= demand > nul
sc config WFDSConMgrSvc start= demand > nul
sc config SDRSVC start= demand > nul
sc config WbioSrvc start= demand > nul
sc config FrameServer start= demand > nul
sc config wcncsvc start= demand > nul
sc config Sense start= demand > nul
sc config WdNisSvc start= demand > nul
sc config WinDefend start= demand > nul
sc config SecurityHealthService start= demand > nul
sc config WEPHOSTSVC start= demand > nul
sc config WerSvc start= demand > nul
sc config Wecsvc start= demand > nul
sc config FontCache start= demand > nul
sc config StiSvc start= demand > nul
sc config wisvc start= demand > nul
sc config LicenseManager start= demand > nul
sc config icssvc start= demand > nul
sc config WMPNetworkSvc start= demand > nul
sc config FontCache3.0.0.0 start= demand > nul
sc config WpnService start= demand > nul
sc config perceptionsimulation start= demand > nul
sc config spectrum start= demand > nul
sc config WinRM start= demand > nul
sc config WSearch start= demand > nul
sc config SecurityHealthService start= demand > nul
sc config W32Time start= demand > nul
sc config wuauserv start= demand > nul
sc config WaaSMedicSvc start= demand > nul
sc config LanmanWorkstation start= demand > nul
sc config XboxGipSvc start= demand > nul
sc config xbgm start= demand > nul
sc config XblAuthManager start= demand > nul
sc config XblGameSave start= demand > nul
sc config XboxNetApiSvc start= demand > nul

:: Delete registry changes made in the previous script
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BluetoothUserService" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CaptureService" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BcastDVRUserService" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PrintWorkflowUserSvc" /f > nul 
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\OneSyncSvc" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnUserService" /f > nul

echo Advanced services and registry changes have been reverted.
