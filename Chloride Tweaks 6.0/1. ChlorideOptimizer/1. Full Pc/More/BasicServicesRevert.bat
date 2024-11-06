@echo off
echo Reverting changes to services and registry...

:: Re-enable previously disabled services
sc config DoSvc start= demand > nul
sc config diagsvc start= demand > nul
sc config DPS start= demand > nul
sc config dmwappushservice start= demand > nul
sc config MapsBroker start= demand > nul
sc config lfsvc start= demand > nul
sc config CscService start= demand > nul
sc config SEMgrSvc start= demand > nul
sc config PhoneSvc start= demand > nul
sc config RemoteRegistry start= demand > nul
sc config RetailDemo start= demand > nul
sc config SysMain start= demand > nul
sc config WalletService start= demand > nul
sc config WSearch start= demand > nul
sc config W32Time start= demand > nul

:: Delete registry changes (MessagingService and WpnUserService)
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MessagingService" /f > nul
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\WpnUserService" /f > nul

echo Services and registry changes have been reverted.
