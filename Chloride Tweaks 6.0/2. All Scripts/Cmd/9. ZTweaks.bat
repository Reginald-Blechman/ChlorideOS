��

rem Hi Nigga kid, you found my source code! You are awesome!
rem Bro really decompiled ZTweaks to see source code :skull:

@echo off
cls
mode 122,30
setlocal EnableDelayedExpansion
set local=1.5
set updated=20.04.2023
title Ztweaks - ZenoxTweaks [v1.5] 
reg add HKLM /F >nul 2>&1
if %errorlevel% neq 0 start "" /wait /I /min powershell -NoProfile -Command start -verb runas "'%~s0'" && exit /b
goto update
:admin
cls    
chcp 65001 >nul 2>&1
cd /d "%~dp0"
goto :update

:menu1
cls
@echo off
cd %HOMEPATH%\AppData\Local\Temp
echo x=msgbox("Note that you must run ZTweaks.bat as an administrator for the changes to take effect on your system. If they are not there will be no changes on your system.",16,"ZTweaks")> inf.vbs
inf.vbs
del inf.vbs
goto update

:update
start https://discord.gg/MKtBtrjkyn
cls
setlocal EnableDelayedExpansion
set localtwo=%local%
if exist "%temp%\zupdater.bat" DEL /S /Q /F "%temp%\zupdater.bat" >nul 2>&1
curl -g -L -# -o "%temp%\zupdater.bat" "https://raw.githubusercontent.com/stormwrld/ztweaks/main/ZTweaksVer" >nul 2>&1
call "%temp%\zupdater.bat"
if "%local%" gtr "%localtwo%" (
echo.
set string="[95m   _   _           _       _         _____                     _ 
set string2="[95m  | | | |_ __   __| | __ _| |_ ___  |  ___|__  _   _ _ __   __| |
set string3="[95m  | | | | '_ \ / _` |/ _` | __/ _ \ | |_ / _ \| | | | '_ \ / _` |       | Your Version: %localtwo%
set string4="[95m  | |_| | |_) | (_| | (_| | ||  __/ |  _| (_) | |_| | | | | (_| |       | New version: %local%
set string5="[95m   \___/| .__/ \__,_|\__,_|\__\___| |_|  \___/ \__,_|_| |_|\__,_|  
set string6="[95m        |_|                                   
for /f "useback tokens=*" %%g in ('!string!') do set string=%%~g       
for /f "useback tokens=*" %%g in ('!string2!') do set string2=%%~g   
for /f "useback tokens=*" %%g in ('!string3!') do set string3=%%~g   
for /f "useback tokens=*" %%g in ('!string4!') do set string4=%%~g   
for /f "useback tokens=*" %%g in ('!string5!') do set string5=%%~g    
for /f "useback tokens=*" %%g in ('!string6!') do set string6=%%~g  
echo !string!     
echo !string2!   
echo !string3! 
echo !string4!
echo !string5!  
echo !string6!
echo                [95m y - Update     
echo                [95m n - Go to Menu 
echo.
	%SystemRoot%\System32\choice.exe /c:YN /n /m "%DEL% >"                         
	set choice=!errorlevel!
	if !choice! == 1 (
		curl -L -o %0 "https://github.com/stormwrld/ztweaks/releases/latest/download/ZTweaks.bat" >nul 2>&1
		call %0
		exit /b
	)
)


goto menu

:restorebeta
cls
echo [91mWould you like to create a system restore point? [y] - yes \ [n] - no[0m
set /p choose="[91m>[0m "
if /i "%choose%"=="y" goto restore
if /i "%choose%"=="n" goto menu
goto error

:restore
cls
@echo off
echo Creating restore point... [91mDon't leave the software if until it's finished! [0m
wmic /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "ZTweaks / before tweaks", 100, 12 >nul 2>&1
timeout 3 >nul
echo [91mDone! I am redirecting to the menu.[0m
timeout 2 >nul 
goto menu

:menu
cls
cls
echo.                                        
set string="[95m                                            __________                    _    
set string2="[95m                                           |__  /_   _|_      _____  __ _| | _____  
set string3="[95m                                             / /  | | \ \ /\ / / _ \/ _` | |/ / __| 
set string4="[95m                                            / /_  | |  \ V  V /  __/ (_| |   <\__ \
set string5="[95m                                           /____| |_|   \_/\_/ \___|\__,_|_|\_\___/
for /f "useback tokens=*" %%g in ('!string!') do set string=%%~g       
for /f "useback tokens=*" %%g in ('!string2!') do set string2=%%~g   
for /f "useback tokens=*" %%g in ('!string3!') do set string3=%%~g   
for /f "useback tokens=*" %%g in ('!string4!') do set string4=%%~g   
for /f "useback tokens=*" %%g in ('!string5!') do set string5=%%~g    
echo !string!     
echo !string2!   
echo !string3! 
echo !string4!
echo !string5!                                                                                 
echo                                                        [90mVersion: %localtwo%[0m
echo                                                      [92mUpdated: %updated%[0m
echo [90m________________________________________________________________________________________________________________________[0m
echo.
echo                                                       Logged in as [91m%USERNAME%[0m                                                   
echo.
echo                 [90m[[0m [91m1[0m [90m][0m System Restore Point Backup       [90m[[0m [91m2[0m [90m][0m Main FPS Tweaks      [90m[[0m [91m3[0m [90m][0m Nvidia GPU Tweaks
echo.
echo.
echo                            [90m[[0m [91m4[0m [90m][0m Internet Tweaks           [90m[[0m [91m5[0m [90m][0m Ethernet Tweaks      [90m[[0m [91m6[0m [90m][0m System Cleaner[0m  
echo.
echo.
echo                    [90m[[0m [91m7[0m [90m][0m Debloat Removal         [90m[[0m [91m8[0m [90m][0m About the Tweaker
echo.
echo.
set /p choose="[91m>[0m "
if /i "%choose%"=="1" goto restorebeta
if /i "%choose%"=="2" goto tweaks
if /i "%choose%"=="3" goto nvidia_tweaks
if /i "%choose%"=="4" goto optimizewifi
if /i "%choose%"=="5" goto optimizeeth
if /i "%choose%"=="6" goto cleaner
if /i "%choose%"=="7" goto debloat
if /i "%choose%"=="8" goto about
endlocal
goto error

:nvidia_tweaks
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\NVAPI" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmDistRenderMax" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMEnableHdmi2" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMEnableOveclockingAllPstates" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableOverclockedPstates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMForceLockedClocksMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMEnableClk" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnablePerformanceMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMMaximizePteTableSize" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "UseUncachedPCIMappings" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMEnableVmm" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMGpuCacheEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableAsyncPstates" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableForceIgpuDgpuFromUI" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableCoreVoltage" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMNoECCFuseCheck" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableComputeReset" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMOverrideP0Gpc2ClkMaxFreqKHz" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableDx12OnMsHybrid" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableDx12OnOptimus" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableHybridPerfSLI" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMGsyncTswapRdyHi" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "LimitSegmentsTo4GB" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "Disable4GBTAGLimit" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableComputeAsync" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableMClkSlowdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RMClkSlowDown" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableKmRenderBoost" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableKmRenderStage" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableKmRender" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2ReserveVASpaceSizeForNvFBC" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2InvalidatePDEsForReserveVA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2EnableSLI" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2DisableRenderGDI" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2ForceInvalidateAllCpuCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2Use64KBPages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2EnableGdiBroadcast" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2EnableSLILinkMirroredWAR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2OSDualPteSupported" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2DisableSlowCePagingWar" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2ReplaceKindAtTransferVirtual" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2DisableBasicPrimeForGPUVA" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2DisableSLIVirtualChannels" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2EnableFermiWDDMv2" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2ForceEngineResetForPageFault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "WDDMv2KmdHighAddrReserve" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CustomizeDuringSetup" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HiberFileSizePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MfBufferingThreshold" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PerfCalculateActualUtilization" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TimerRebaseThresholdOnDripsExit" /t REG_DWORD /d "60" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "ExitLatencyCheckEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Latency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceFSVP" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyTolerancePerfOverride" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceScreenOffIR" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceVSyncEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "RtlCapabilityCheckLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "QosManagesIdleProcessors" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableVsyncLatencyUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableSensorWatchdog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InterruptSteeringDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LowLatencyScalingPercentage" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighestPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MinimumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumThrottlePercent" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaximumPerformancePercent" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MaxIAverageGraphicsLatencyInOneBucket" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MiracastPerfTrackGraphicsLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepReliabilityDetailedDiagnostics" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EventProcessorEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Class1InitialUnparkCount" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LatencyToleranceIdleResiliency" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnableRuntimePowerManagement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LOWLATENCY" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PowerActionResumingWatchdogTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PowerActionTransitioningWatchdogTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "PowerSavingTweaks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "SourceSettingsVersion" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "TdrLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "UseGpuTimer" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DirectedDripsOverride" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "BootHeteroPolicyOverride" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "MfOverridesDisabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyActivelyUsed" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleShortTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultD3TransitionLatencyIdleVeryLongTime" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle0" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle0MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle1" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceIdle1MonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceMemory" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceNoContextMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceOther" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultLatencyToleranceTimerPeriod" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceActivelyUsed" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceMonitorOff" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "DefaultMemoryRefreshLatencyToleranceNoContext" /t REG_DWORD /d "1" /f
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
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\audiodg.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dllhost.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\dwm.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsm.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ntoskrnl.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rundll32.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\services.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\smss.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\svchost.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskeng.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\wininit.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\winlogon.exe" /v "UseLargePages" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PerfLevelSrc" /t REG_DWORD /d "8738" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerMizerLevelAC" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PowerSaverHsyncOn" /t REG_DWORD /d "0" /f
timeout 1 >nul
echo [91mSuccesfull! Returning to menu...[0m
timeout 2 >nul
goto menu


:debloat
cls
PowerShell -Command "Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.NetworkSpeedTest* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.News* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Office.Lens* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Office.OneNote* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Office.Sway* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.People* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Print3D* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Office.Todo.List* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Whiteboard* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *microsoft.windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.WindowsMaps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.WindowsStore* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.StorePurchaseApp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxApp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxGameOverlay* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxIdentityProvider* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.ZuneMusic* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *EclipseManager* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *ActiproSoftwareLLC* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *AdobeSystemsIncorporated.AdobePhotoshopExpress* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Duolingo-LearnLanguagesforFree* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *PandoraMediaInc* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *CandyCrush* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *BubbleWitch3Saga* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Wunderlist* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Flipboard* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Facebook* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Royal Revolt* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Sway* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Speed Test* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Dolby* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.MSPaint* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"
timeout 1 >nul
echo [91mSuccesfull deleted Bloatware applications. Returning to menu...[0m
timeout 2 >nul
goto menu

:cleaner
cls
@echo off
echo [91mCleaning temporary files...[0m
timeout 2 >nul
del /s /f /q %SYSTEMDRIVE%\windows\temp\*.* 
rd /s /q %SYSTEMDRIVE%\windows\temp 
md c:\windows\temp
del /s /f /q %SYSTEMDRIVE%\WINDOWS\Prefetch 
del /s /f /q %temp%\*.* 
rd /s /q %temp%
cls
echo [91mSuccesfull deleted temporary files![0m
timeout 1 >nul
cls
timeout 2 >nul
echo [91mCleaning logs...[0m
md %temp%
del /q /f /s %SYSTEMDRIVE%\Temp\*.* 
del /q /f /s %WINDIR%\Prefetch\*.* 
del /q /f /s %SYSTEMDRIVE%\*.log 
del /q /f /s %SYSTEMDRIVE%\*.bak 
del /q /f /s %SYSTEMDRIVE%\*.gid 
del /s /f /q %SYSTEMDRIVE%\AMD\*.*
del /s /f /q %SYSTEMDRIVE%\NVIDIA\*.*
del /s /f /q %SYSTEMDRIVE%\INTEL\*.*
cls
echo [91mSuccesfull cleaned logs![0m
timeout 1 >nul
cls
echo [91mCleaning temporary register files...[0m
timeout 2 >nul
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
reg delete "HKCU\Software\Microsoft\Search Assistant\ACMru" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU" /va /f
reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentURLList" /va /f
reg delete "HKCU\Software\Microsoft\Direct3D\MostRecentApplication" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Direct3D\MostRecentApplication" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /va /f
timeout 1 >nul
echo [91mSucessfull Cleaned! Returning to menu...[0m
timeout 2 >nul
goto menu

:error
cls
@echo off
echo [91mFailure:[0m Enter valid number option. [95mError d02[0m
timeout 3 >NUL
echo [91mIf you have a problem: [0m[96mdiscord.gg/MKtBtrjkyn[0m
timeout 2 >nul
echo [91mPress enter to return to menu.[0m
pause>nul
goto menu

:optimizeeth
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_SZ /d "ffffffff" /f   
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched /v TimerResolution /t REG_DWORD /d 1 /f   
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 10 /f   
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f   
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "00000000" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "00000000" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "00000010" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "00000000" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "00000006" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "00000005" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "00000004" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "00000007" /f >nul 2>&1  
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "00000016" /f >nul 2>&1  
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "00000016" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "0200" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "1700" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "00000000" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "4294967295" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_DWORD /d "00000001" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "00065534" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "00000030" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "00000000" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f >nul 2>&1  
Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPCongestionControl" /t REG_DWORD /d "00000001" /f >nul 2>&1 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /d "1" /t REG_DWORD /f >nul 2>&1  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /d "1" /t REG_DWORD /f >nul 2>&1  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "00000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /t REG_DWORD /d "00000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDCA" /t REG_DWORD /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "00000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "00000001" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableRSS" /t REG_DWORD /d "00000001" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "00000001" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "00000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IRPStackSize" /t REG_DWORD /d "0000001e" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSize" /t REG_DWORD /d "00010000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "00000001" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SizReqBuf" /t REG_DWORD /d "51319" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "00000001" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\OCMsetup" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\Security" /v "SecureDSCommunication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\setup" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Setup" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "80" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "170372" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "HiberbootEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /t REG_DWORD /d "1073741824" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeBestEffort" /t REG_DWORD /d "99" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeControlledLoad" /t REG_DWORD /d "99" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "99" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "99" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingConforming" /v "ServiceTypeQualitative" /t REG_DWORD /d "99" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeBestEffort" /t REG_DWORD /d "99" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeControlledLoad" /t REG_DWORD /d "99" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "99" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "99" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\DiffservByteMappingNonConforming" /v "ServiceTypeQualitative" /t REG_DWORD /d "99" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeNonConforming" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeBestEffort" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeControlledLoad" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeQualitative" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "170372" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v "EnableBITSMaxBandwidth" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "PeerCachingLatencyThreshold" /t REG_DWORD /d "268435456" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service" /v "Enable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "UpdateSecurityLevel" /t REG_DWORD /d "598" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "RegistrationTtl" /t REG_DWORD /d "1117034098" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Network Connections" /v "NC_AllowNetBridge_NLA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Network Connections" /v "NC_AllowAdvancedTCPIPConfig" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SizReqBuf" /t REG_DWORD /d "53819" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "00000001" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "23" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "00000008" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "StrictTimeWaitSeqCheck" /t REG_DWORD /d "00000001" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d "00000008" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "000003e8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "00000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPInitalRtt" /t REG_DWORD /d "00049697" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "00000002" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "de7a" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "00000076d" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpFinWait2Delay" /t REG_DWORD /d "00000076d" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPDelAckTicks" /t REG_DWORD /d "00000001" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IPAutoconfigurationEnabled" /t REG_DWORD /d "00000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "33" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MTU" /t REG_DWORD /d "420" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MSS" /t REG_DWORD /d "412" /f
netsh int tcp set supplemental Internet congestionprovider=ctcp >nul 2>&1  
netsh int tcp set heuristics disabled >nul 2>&1  
netsh int tcp set global initialRto=2000 >nul 2>&1  
netsh int tcp set global rsc=disabled >nul 2>&1  
netsh int tcp set global chimney=disabled >nul 2>&1  
netsh int tcp set global dca=enabled >nul 2>&1  
netsh int tcp set global netdma=disabled >nul 2>&1  
netsh int tcp set global ecncapability=enabled >nul 2>&1  
netsh int tcp set global timestamps=disabled >nul 2>&1  
netsh int tcp set global nonsackrttresiliency=disabled >nul 2>&1  
netsh int tcp set global rss=enabled >nul 2>&1  
netsh int tcp set global MaxSynRetransmissions=2 >nul 2>&1 
netsh int tcp set heuristics disabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global fastopen=enabled
netsh Int tcp set global nonsackrttresiliency=disabled
netsh Int tcp set global netdma=enabled
netsh Int tcp set global congestionprovider=ctcp
netsh Int tcp set global dca=enabled
netsh interface tcp set global ecncapability=disabled
netsh int tcp set global ecncapability=enabled
netsh int tcp set global rss=enabled
netsh int tcp set global chimney=enabled
netsh interface ipv4 set subinterface â€œEthernetâ€ mtu=1500 store=persistent
netsh int ipv4 set dynamicportrange protocol=tcp start=1025 num=64511
netsh Int ipv4 set glob defaultcurhoplimit=255
netsh Int tcp set global maxsynretransmissions=2
netsh int tcp set global initialRto=2000
wmic process where ProcessId=%pid% CALL setpriority "realtime"
wmic process where ProcessId=%pid% CALL setpriority "realtime"
WMIC nicconfig where ipenabled=true call setdnsserversearchorder ("8.8.8.8","8.8.4.4") >NUL 2>&1
ipconfig /flushdns
ipconfig /registerdns
ipconfig /release
ipconfig /renew
netsh winsock reset
timeout 1 >nul
echo [91mSuccesfull deleted Bloatware applications. Returning to menu...[0m
timeout 2 >nul
goto menu

:optimizewifi
cls
POWERSHELL "Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue"
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableUserTOSSetting" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "CorpLocationProbeTimeout" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "LdapTimeoutMs" /t REG_DWORD /d "5000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "ShowDomainEndpointInterfaces" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "EnableNoGatewayLocationDetection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "MinimumInternetHopCount" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxThreads" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCollectionCount" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxWorkItems" /t REG_DWORD /d "8192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "2048" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxCmds" /t REG_DWORD /d "2048" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableStrictNameChecking" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "autodisconnect" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "EnableOplocks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SharingViolationRetries" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableUserTOSSetting" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "CorpLocationProbeTimeout" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "LdapTimeoutMs" /t REG_DWORD /d "5000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "ShowDomainEndpointInterfaces" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "EnableNoGatewayLocationDetection" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "MinimumInternetHopCount" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCmds" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxThreads" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "MaxCollectionCount" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxWorkItems" /t REG_DWORD /d "8192" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxMpxCt" /t REG_DWORD /d "2048" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "MaxCmds" /t REG_DWORD /d "2048" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "DisableStrictNameChecking" /t REG_DWORD /d "1" /f
WMIC nicconfig where ipenabled=true call setdnsserversearchorder ("8.8.8.8","8.8.4.4") >NUL 2>&1
ipconfig /flushdns
ipconfig /registerdns
ipconfig /release
ipconfig /renew
netsh winsock reset
timeout 1 >nul
goto menu

:reboot2
echo [91mYou need to reboot your pc after tweaks. Do you want to continue? [y] - yes \n- [n] - no[0m
set /p choose="[91m>[0m "
if /i "%choose%"=="y" goto reboot
if /i "%choose%"=="n" goto menu

:about
cls
@echo off
echo.
set string="[95m                                            __________                    _    
set string2="[95m                                           |__  /_   _|_      _____  __ _| | _____  
set string3="[95m                                             / /  | | \ \ /\ / / _ \/ _` | |/ / __| [92mUpdated: 02.02.2023[0m
set string4="[95m                                            / /_  | |  \ V  V /  __/ (_| |   <\__ \
set string5="[95m                                           /____| |_|   \_/\_/ \___|\__,_|_|\_\___/
for /f "useback tokens=*" %%g in ('!string!') do set string=%%~g       
for /f "useback tokens=*" %%g in ('!string2!') do set string2=%%~g   
for /f "useback tokens=*" %%g in ('!string3!') do set string3=%%~g   
for /f "useback tokens=*" %%g in ('!string4!') do set string4=%%~g   
for /f "useback tokens=*" %%g in ('!string5!') do set string5=%%~g    
echo !string!     
echo !string2!   
echo !string3! 
echo !string4!
echo !string5!                                                                                 
echo                                                        [90mVersion: %localtwo%[0m
echo [90m                         __________________________________________________________________________[0m
echo.
echo                                                       Logged in as [91m%USERNAME%[0m   
echo.
echo                                       [90m[[0m [91mDeveloper: caxzy#3907[0m [90m][0m
echo.
echo                                       [90m[[0m [91mDiscord Server: discord.gg/MKtBtrjkyn[0m [90m][0m
echo.
echo                                                      [90m [X to go menu][0m
echo.
set /p choose="[91m>[0m "
if /i "%choose%"=="x" goto menu

:tweaks
cls
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\r5apex.exe\PerfOptions" /F /V "CpuPriorityClass" /T REG_DWORD /d 3 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\FortniteClient-Win64-Shipping.exe\PerfOptions" /F /V "CpuPriorityClass" /T REG_DWORD /d 3 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\VALORANT.exe\PerfOptions" /F /V "CpuPriorityClass" /T REG_DWORD /d 3 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cod.exe\PerfOptions" /F /V "CpuPriorityClass" /T REG_DWORD /d 3 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\javaw.exe\PerfOptions" /F /V "CpuPriorityClass" /T REG_DWORD /d 3 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csgo.exe\PerfOptions" /F /V "CpuPriorityClass" /T REG_DWORD /d 3 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\gta-sa.exe\PerfOptions" /F /V "CpuPriorityClass" /T REG_DWORD /d 3 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}" /v "TimeLimitInSeconds" /t REG_DWORD /d "18" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "DisableTaggedEnergyLogging" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxApplication" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\EnergyEstimation\TaggedEnergy" /v "TelemetryMaxTagPerApplication" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKCU\Control Panel\PowerCfg\GlobalPowerPolicy" /v "Policies" /t REG_BINARY /d "01000000020000000100000000000000020000000000000000000000000000002c0100003232030304000000040000000000000000000000840300002c01000000000000840300000001646464640000" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d "0" /f
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
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t REG_DWORD /d "150000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Background Only" /t REG_SZ /d "True" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Clock Rate" /t REG_DWORD /d "10000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "GPU Priority" /t REG_DWORD /d "8" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Priority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "Scheduling Category" /t REG_SZ /d "Medium" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio" /v "SFIO Priority" /t REG_SZ /d "Normal" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Wecsvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WerSvc" /v "Start" /t REG_DWORD /d "4" /f
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_Enabled" /T REG_DWORD /d 0 
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_FSEBehaviorMode" /T REG_DWORD /d 2 
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_HonorUserFSEBehaviorMode" /T REG_DWORD /d 0 
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_DXGIHonorFSEWindowsCompatible" /T REG_DWORD /d 0 
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_EFSEFeatureFlags" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowCommercialDataPipeline" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowDesktopAnalyticsProcessing" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowDeviceNameInTelemetry" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowTelemetry" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowUpdateComplianceProcessing" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowWUfBCloudProcessing" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableEnterpriseAuthProxy" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "MicrosoftEdgeDataOptIn" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableTelemetryOptInChangeNotification" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableTelemetryOptInSettingsUx" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableDiagnosticDataViewer" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "EnableConfigFlighting" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DoNotShowFeedbackNotifications" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "LimitEnhancedDiagnosticDataWindowsAnalytics" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "EnableSmartScreen" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\FileHistory" /F /V "Disabled" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FindMyDevice" /F /V "AllowFindMyDevice" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /F /V "LocationSyncEnabled" /T REG_DWORD /d 0 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /F /V "Value" /T REG_SZ /d "Deny" 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /V "DisableLocation" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /V "DisableLocationScripting" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /V "DisableSensors" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /F /V "DisableWindowsLocationProvider" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" /F /V "AutoDownloadAndUpdateMapData" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Maps" /F /V "AllowUntriggeredNetworkTrafficOnSettingsPage" /T REG_DWORD /d 0 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /F /V "Value" /T REG_SZ /d "Deny" 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /F /V "Value" /T REG_SZ /d "Deny" 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /F /V "Value" /T REG_SZ /d "Deny" 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /F /V "Value" /T REG_SZ /d "Deny" 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /F /V "Value" /T REG_SZ /d "Deny" 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /F /V "Value" /T REG_SZ /d "Deny" 
Reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /F /V "Value" /T REG_SZ /d "Deny" 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Messaging" /F /V "AllowMessageSync" /T REG_DWORD /d 0 
cls
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /F /V "NoActiveHelp" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "DisableWebSearch" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "DisableRemovableDriveIndexing" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowCortanaAboveLock" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowCloudSearch" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowSearchToUseLocation" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "ConnectedSearchUseWeb" /T REG_DWORD /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /F /V "SafeSearchMode" /T REG_DWORD /d 0 
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /F /V "IsDeviceSearchHistoryEnabled" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Speech" /F /V "AllowSpeechModelUpdate" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableApplicationSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableAppSyncSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableWebBrowserSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableDesktopThemeSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableSyncOnPaidNetwork" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableWindowsSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableCredentialsSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisablePersonalizationSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableStartLayoutSettingSync" /T REG_DWORD /d 2 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /f /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\TabletPC" /F /V "TurnOffTouchInput" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\TabletPC" /F /V "TurnOffPanning" /T REG_DWORD /d 1 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /F /V "AllowLinguisticDataCollection" /T REG_DWORD /d 0 
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /F /V "AllowWindowsInkWorkspace" /T REG_DWORD /d 0  
rmdir C:\Windows\system32\adminrightstest >NUL 2>&1 
SC CONFIG Winmgmt start= auto >NUL 2>&1  
SC CONFIG TrustedInstaller start= demand >NUL 2>&1 
SC CONFIG AppInfo start= demand >NUL 2>&1 
SC CONFIG DeviceInstall start= demand >NUL 2>&1 
SC START Winmgmt >NUL 2>&1 
SC START TrustedInstaller >NUL 2>&1 
SC START AppInfo >NUL 2>&1 
SC START DeviceInstall >NUL 2>&1 
SC START Dhcp >NUL 2>&1 
wmic process where name="javaw.exe" CALL setpriority "realtime" 
wmic process where name="svchost.exe" CALL setpriority "realtime" 
PowerShell "get-process svchost | %% { $_.ProcessorAffinity=2 }" 
PowerShell "get-process svchost | foreach { $_.ProcessorAffinity=2 }" 
PowerShell "get-process winlogon | %% { $_.ProcessorAffinity=2 }" 
PowerShell "get-process winlogon | foreach { $_.ProcessorAffinity=2 }" 
PowerShell "get-process dwm | %% { $_.ProcessorAffinity=2 }" 
PowerShell "get-process dwm | foreach { $_.ProcessorAffinity=2 }" 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDCA" /t REG_DWORD /d "" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableRSS" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IRPStackSize" /t REG_DWORD /d "0000001e" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxFreeTcbs" /t REG_DWORD /d "65535" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxHashTableSize" /t REG_DWORD /d "00010000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SizReqBuf" /t REG_DWORD /d "51319" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "00000005" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "StrictTimeWaitSeqCheck" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d "00000008" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "000003e8" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPInitalRtt" /t REG_DWORD /d "00046325" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "00000002" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "de7a" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "00000042d" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpFinWait2Delay" /t REG_DWORD /d "00000042d" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPDelAckTicks" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IPAutoconfigurationEnabled" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "38" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "239" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "240" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "1740" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "1741" /f 
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f 
Reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f 
Reg.exe add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f 
Reg.exe add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "10" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "10" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "ffffffff" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "IoPageLockLimit" /t REG_DWORD /d "000f0000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "00000180" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "0000FA00" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "0000012D" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\OCMsetup" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\Security" /v "SecureDSCommunication" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters\setup" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Setup" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "80" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "170372" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\System" /v "HiberbootEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "MaxOutstandingSends" /t REG_DWORD /d "1073741824" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "4294967295" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeNonConforming" /t REG_DWORD /d "7" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeBestEffort" /t REG_DWORD /d "7" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeControlledLoad" /t REG_DWORD /d "7" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeGuaranteed" /t REG_DWORD /d "7" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeNetworkControl" /t REG_DWORD /d "7" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Psched\UserPriorityMapping" /v "ServiceTypeQualitative" /t REG_DWORD /d "7" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "170372" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v "EnableBITSMaxBandwidth" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\NetCache" /v "PeerCachingLatencyThreshold" /t REG_DWORD /d "268435456" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PeerDist\Service" /v "Enable" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "UpdateSecurityLevel" /t REG_DWORD /d "598" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "RegistrationTtl" /t REG_DWORD /d "1117034098" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Network Connections" /v "NC_AllowNetBridge_NLA" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Network Connections" /v "NC_AllowAdvancedTCPIPConfig" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SizReqBuf" /t REG_DWORD /d "53819" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "23" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpAckFrequency" /t REG_DWORD /d "00000008" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "StrictTimeWaitSeqCheck" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d "00000008" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "KeepAliveInterval" /t REG_DWORD /d "000003e8" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpCreateAndConnectTcbRateLimitDepth" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPInitalRtt" /t REG_DWORD /d "00049697" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "00000002" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpNumConnections" /t REG_DWORD /d "de7a" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "00000076d" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpFinWait2Delay" /t REG_DWORD /d "00000076d" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TCPDelAckTicks" /t REG_DWORD /d "00000001" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IPAutoconfigurationEnabled" /t REG_DWORD /d "00000000" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "33" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MTU" /t REG_DWORD /d "420" /f 
reg.exe add HKLM\SYSTEM\CurrentControlSet\services\NvTelemetryContainer /v Start /t REG_DWORD /d 4 /f 
reg.exe add HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client /v OptInOrOutPreference /t REG_DWORD /d 0 /f  
reg.exe add HKLM\SOFTWARE\Microsoft\Direct3D /v DisableVidMemVBs /t REG_DWORD /d 0 /f           
reg.exe add HKLM\SOFTWARE\Microsoft\Direct3D /v FlipNoVsync /t REG_DWORD /d 1 /f               
reg.exe add HKLM\SOFTWARE\Microsoft\Direct3DDrivers /v SoftwareOnly /t REG_DWORD /d 0 /f       
reg.exe add HKLM\SOFTWARE\Microsoft\Direct3D /v MMX Fast Path /t REG_DWORD /d 1 /f             
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers /v TdrLevel /t REG_DWORD /d 0 /f             
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers /v TdrDebugMode /t REG_DWORD /d 0 /f         
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v EnergyEstimationEnabled /t REG_DWORD /d 0 /f        
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v CsEnabled /t REG_DWORD /d 0 /f      
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v PerfCalculateActualUtilization /t REG_DWORD /d 0 /f                 
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v SleepReliabilityDetailedDiagnostics /t REG_DWORD /d 0 /f            
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v EventProcessorEnabled /t REG_DWORD /d 0 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v QosManagesIdleProcessors /t REG_DWORD /d 0 /f       
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v DisableVsyncLatencyUpdate /t REG_DWORD /d 1 /f   
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v DisableSensorWatchdog /t REG_DWORD /d 1 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v ExitLatencyCheckEnabled /t REG_DWORD /d 0 /f        
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling /v PowerThrottlingOff /t REG_DWORD /d 1 /f             
reg.exe add HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorMagnetism /v MagnetismUpdateIntervalInMilliseconds /t REG_DWORD /d 1 /f           
reg.exe add HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed /v CursorUpdateInterval /t REG_DWORD /d 1 /f               
reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability /v TimeStampInterval /t REG_DWORD /d 0 /f               
reg.exe add HKCU\Software\Microsoft\Windows\DWM /v CompositionPolicy /t REG_DWORD /d 0 /f      
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\amdlog /v Start /t REG_DWORD /d 4 /f        
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v DisableDMACopy /t REG_DWORD /d 1 /f     
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v StutterMode /t REG_DWORD /d 0 /f        
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v EnableUlps /t REG_DWORD /d 0 /f         
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v PP_SclkDeepSleepDisable /t REG_DWORD /d 1 /f            
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v PP_ThermalAutoThrottlingEnable /t REG_DWORD /d 0 /f     
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000 /v DisableDrmdmaPowerGating /t REG_DWORD /d 1 /f           
reg.exe add HKLM\Software\Microsoft\Windows Nt\CurrentVersion\Multimedia\SystemProfilE\Tasks\Games /v GPU Priority /t REG_DWORD /d 8 /f        
reg.exe add HKLM\Software\Microsoft\Windows Nt\CurrentVersion\Multimedia\SystemProfilE\Tasks\Games /v Priority /t REG_DWORD /d 6 /f 
reg.exe add HKLM\Software\Microsoft\Windows Nt\CurrentVersion\Multimedia\SystemProfilE\Tasks\Games /v Scheduling Category /t REG_SZ /d High /f                        
reg.exe add HKCU\SOFTWARE\Microsoft\InputPersonalization /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f                 
reg.exe add HKCU\SOFTWARE\Microsoft\InputPersonalization /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f                
reg.exe add HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore /v   HarvestContacts /t REG_DWORD /d 0 /f            
reg.exe add HKLM\SOFTWARE\Policies\Google\Chrome /v MetricsReportingEnabled /t REG_DWORD /d 0 /f               
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports /v PreventHandwritingErrorReports /t REG_DWORD /d 1 /f            
reg.exe add HKCU\Control Panel\International\User Profile /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f   
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableLocation /t REG_DWORD /d 1 /f                
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableLocationScripting /t REG_DWORD /d 1 /f       
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableSensors /t REG_DWORD /d 1 /f                 
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableWindowsLocationProvider /t REG_DWORD /d 1 /f                 
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\lfsvc /v Start /t REG_DWORD /d 4 /f         
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration /v Status /t REG_DWORD /d 0 /f  
reg.exe add HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions /v SensorPermissionState /t REG_DWORD /d 0 /f                 
reg.exe add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides /v SensorPermissionState /t REG_DWORD /d 0 /f   
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection /v AllowTelemetry /t REG_DWORD /d 00000000 /f               
reg.exe add HKLM\Software\Policies\Microsoft\Windows\DataCollection /v AllowTelemetry /t REG_DWORD /d 00000000 /f              
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat /v AITEnable /t REG_DWORD /d 0 /f               
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice /v Start /t REG_DWORD /d 4 /f              
reg.exe add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo /v Enabled /t REG_DWORD /d 0 /f     
reg.exe add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo /v Enabled /t REG_DWORD /d 0 /f     
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f             
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat /v DisableInventory /t REG_DWORD /d 1 /f        
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows /v CEIPEnable /t REG_DWORD /d 0 /f              
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\SQMClient /v CorporateSQMURL /t REG_SZ /d 0.0.0.0 /f 
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent /v DisableSoftLanding /t REG_DWORD /d 1 /f   
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0 /v NoActiveHelp /t REG_DWORD /d 1 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener /v Start /t REG_DWORD /d 0 /f       
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener /v Start /t REG_DWORD /d 0 /f   
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger /v Start /t REG_DWORD /d 0 /f       
reg.exe add HKCU\SOFTWARE\Microsoft\Siuf\Rules /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f    
reg.exe add HKCU\SOFTWARE\Microsoft\Siuf\Rules /v PeriodInNanoSeconds /t REG_DWORD /d 0 /f      
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f     
reg.exe add HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0 /v NoExplicitFeedback /t REG_DWORD /d 1 /f  
reg.exe add HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences /v UsageTracking /t REG_DWORD /d 0 /f              
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer /v NoUseStoreOpenWith /t REG_DWORD /d 1 /f       
reg.exe add HKLM\SYSTEM\ControlSet001\Services\FrameServer /v Start /t REG_DWORD /d 4 /f       
reg.exe add HKCU\System\GameConfigStore /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f        
reg.exe add HKCU\System\GameConfigStore /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 0 /f               
reg.exe add HKCU\System\GameConfigStore /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f          
reg.exe add HKCU\System\GameConfigStore /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Control\PriorityControl /v Win32PrioritySeparation /t REG_DWORD /d fff55555 /f                 
cls               
reg.exe add HKLM\SYSTEM\ControlSet001\Control\Power /v HibernateEnabled /t REG_DWORD /d 0 /f   
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Power /v HibernateEnabled /t REG_DWORD /d 0 /f                
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/Main /v Enabled /t REG_DWORD /d 0 /f   
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/PfApLog /v Enabled /t REG_DWORD /d 0 /f                
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/StoreLog /v Enabled /t REG_DWORD /d 0 /f               
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f             
reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled /v Value /t REG_SZ /d Deny /f    
reg.exe add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions /v CpuPriorityClass /t REG_DWORD /d 4 /f      
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers /v HwSchedMode /t REG_DWORD /d 2 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v LargeSystemCache /t REG_DWORD /d 1 /f   
reg.exe add HKCU\Control Panel\Mouse /v MouseHoverTime /t REG_SZ /d 0 /f         
reg.exe add HKU\.DEFAULT\Control Panel\Mouse /v MouseThreshold1 /t REG_SZ /d 0 /f              
reg.exe add HKU\.DEFAULT\Control Panel\Mouse /v MouseThreshold2 /t REG_SZ /d 0 /f              
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters /v TreatAbsolutePointerAsAbsolute /t REG_DWORD /d 1 /f    
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\mouhid\Parameters /v TreatAbsoluteAsRelative /t REG_DWORD /d 0 /f          
reg.exe add HKCU\Control Panel\Mouse /v SmoothMouseXCurve /t REG_BINARY /d 000000000000000000a0000000000000004001000000000000800200000000000000050000000000 /f                 
reg.exe add HKCU\Control Panel\Mouse /v SmoothMouseYCurve /t REG_BINARY /d 000000000000000066a6020000000000cd4c050000000000a0990a00000000003833150000000000 /f                 
reg.exe add HKLM\SYSTEM\CurrentControlSet\Servicesmouclass\Parameters /v MouseDataQueueSize /t REG_DWORD /d 16 /f              
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters /v KeyboardDataQueueSize /t REG_DWORD /d 16 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v EnableCfg /t REG_DWORD /d 0 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v FeatureSettings /t REG_DWORD /d 1 /f                
reg.exe add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile /v NoLazyMode /t REG_DWORD /d 0 /f       
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\amdlog /v Start /t REG_DWORD /d 3 /f                  
reg.exe add HKLM\SYSTEM\ControlSet001\Services\TapiSrv /v Start /t REG_DWORD /d 3 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\FontCache3.0.0.0 /v Start /t REG_DWORD /d 3 /f   
reg.exe add HKLM\SYSTEM\ControlSet001\Services\WpcMonSvc /v Start /t REG_DWORD /d 3 /f         
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SEMgrSvc /v Start /t REG_DWORD /d 2 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\PNRPsvc /v Start /t REG_DWORD /d 3 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\WEPHOSTSVC /v Start /t REG_DWORD /d 3 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Services\p2psvc /v Start /t REG_DWORD /d 3 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\p2pimsvc /v Start /t REG_DWORD /d 3 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\PhoneSvc /v Start /t REG_DWORD /d 3 /f 
reg.exe add HKLM\SYSTEM\ControlSet001\Services\Wecsvc /v Start /t REG_DWORD /d 3 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\RmSvc /v Start /t REG_DWORD /d 3 /f             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SensorDataService /v Start /t REG_DWORD /d 3 /f                 
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SensrSvc /v Start /t REG_DWORD /d 3 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\perceptionsimulation /v Start /t REG_DWORD /d 3 /f              
reg.exe add HKLM\SYSTEM\ControlSet001\Services\StiSvc /v Start /t REG_DWORD /d 3 /f             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\OneSyncSvc /v Start /t REG_DWORD /d 2 /f        
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\ConsentUxUserSvc /v Start /t REG_DWORD /d 3 /f              
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\DevicePickerUserSvc /v Start /t REG_DWORD /d 3 /f           
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\UnistoreSvc /v Start /t REG_DWORD /d 3 /f   
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\DevicesFlowUserSvc /v Start /t REG_DWORD /d 3 /f            
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\CaptureService /v Start /t REG_DWORD /d 3 /f                
reg.exe add HKLM\SYSTEM\ControlSet001\Services\autotimesvc /v Start /t REG_DWORD /d 3 /f       
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\MessagingService /v Start /t REG_DWORD /d 3 /f              
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\CDPUserSvc /v Start /t REG_DWORD /d 2 /f     
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc /v Start /t REG_DWORD /d 3 /f        
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\BcastDVRUserService /v Start /t REG_DWORD /d 3 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\UserDataSvc /v Start /t REG_DWORD /d 3 /f   
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\DeviceAssociationBrokerSvc /v Start /t REG_DWORD /d 3 /f    
reg.exe add HKLM\SYSTEM\ControlSet001\Services\edgeupdatem /v Start /t REG_DWORD /d 3 /f       
reg.exe add HKLM\SYSTEM\ControlSet001\Services\MicrosoftEdgeElevationService /v Start /t REG_DWORD /d 3 /f     
reg.exe add HKLM\SYSTEM\ControlSet001\Services\ALG /v Start /t REG_DWORD /d 3 /f                
reg.exe add HKLM\SYSTEM\ControlSet001\Services\IpxlatCfgSvc /v Start /t REG_DWORD /d 3 /f      
reg.exe add HKLM\SYSTEM\ControlSet001\Services\icssvc /v Start /t REG_DWORD /d 3 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\DusmSvc /v Start /t REG_DWORD /d 2 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\MapsBroker /v Start /t REG_DWORD /d 2 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Services\SensorService /v Start /t REG_DWORD /d 3 /f     
reg.exe add HKLM\SYSTEM\ControlSet001\Services\svsvc /v Start /t REG_DWORD /d 3 /f             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\MSiSCSI /v Start /t REG_DWORD /d 3 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\Netlogon /v Start /t REG_DWORD /d 3 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\CscService /v Start /t REG_DWORD /d 3 /f        
reg.exe add HKLM\SYSTEM\ControlSet001\Services\AppReadiness /v Start /t REG_DWORD /d 3 /f      
reg.exe add HKLM\SYSTEM\ControlSet001\Services\wisvc /v Start /t REG_DWORD /d 3 /f             
reg.exe add HKLM\SYSTEM\ControlSet001\Services\lltdsvc /v Start /t REG_DWORD /d 3 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\TrkWks /v Start /t REG_DWORD /d 2 /f            
reg.exe add HKLM\SYSTEM\ControlSet001\Services\AppIDSvc /v Start /t REG_DWORD /d 3 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\CryptSvc /v Start /t REG_DWORD /d 2 /f          
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableLocation /t REG_DWORD /d 0 /f                
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableLocationScripting /t REG_DWORD /d 0 /f       
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableSensors /t REG_DWORD /d 0 /f                 
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors /v DisableWindowsLocationProvider /t REG_DWORD /d 0 /f                 
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\lfsvc /v Start /t REG_DWORD /d 3 /f         
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration /v Status /t REG_DWORD /d 1 /f  
reg.exe add HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions /v SensorPermissionState /t REG_DWORD /d 1 /f                 
reg.exe add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides /v SensorPermissionState /t REG_DWORD /d 1 /f   
reg.exe add HKLM\SYSTEM\ControlSet001\Services\DiagTrack /v Start /t REG_DWORD /d 3 /f         
reg.exe add HKLM\SYSTEM\ControlSet001\Services\diagsvc /v Start /t REG_DWORD /d 3 /f           
reg.exe add HKLM\SYSTEM\ControlSet001\Services\dmwappushsvc /v Start /t REG_DWORD /d 3 /f      
reg.exe add HKLM\SYSTEM\ControlSet001\Services\diagnosticshub.standardcollector.service /v Start /t REG_DWORD /d 3 /f          
reg.exe add HKLM\SYSTEM\ControlSet001\Services\TroubleshootingSvc /v Start /t REG_DWORD /d 3 /f                
reg.exe add HKLM\SYSTEM\ControlSet001\Services\DsSvc /v Start /t REG_DWORD /d 3 /f             
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice /v Start /t REG_DWORD /d 3 /f              
reg.exe add HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer /v NoUseStoreOpenWith /t REG_DWORD /d 0 /f       
reg.exe add HKLM\SYSTEM\ControlSet001\Services\FrameServer /v Start /t REG_DWORD /d 3 /f       
reg.exe add HKCU\System\GameConfigStore /v GameDVR_Enabled /t REG_DWORD /d 1 /f                
reg.exe add HKLM\Software\Policies\Microsoft\Windows /v AllowGameDVR /t REG_DWORD /d 1 /f      
reg.exe add HKLM\SYSTEM\ControlSet001\Control\PriorityControl /v Win32PrioritySeparation /t REG_DWORD /d 28 /f                 
reg.exe add HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters /v EnablePrefetcher /t REG_DWORD /d 1 /f    
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters /v EnablePrefetcher /t REG_DWORD /d 1 /f                
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/Main /v Enabled /t REG_DWORD /d 1 /f    
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/PfApLog /v Enabled /t REG_DWORD /d 1 /f                
reg.exe add HKLM\Software\Microsoft\Windows\CurrentVersion\WINEVt\Channels\Microsoft-Windows-Superfetch/StoreLog /v Enabled /t REG_DWORD /d 1 /f               
reg.exe add HKLM\SYSTEM\CurrentControlSet\Servicesmouclass\Parameters /v MouseDataQueueSize /t REG_DWORD /d 100 /f             
reg.exe add HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters /v KeyboardDataQueueSize /t REG_DWORD /d 100 /f          
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v FeatureSettingsOverride /t REG_DWORD /d 2 /f            
reg.exe add HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management /v FeatureSettingsOverrideMask /t REG_DWORD /d 2 /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Application Name" /t REG_SZ /d "fortniteclient-win64-shipping.exe" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "DSCP value" /t REG_SZ /d "46" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local IP" /t REG_SZ /d "*" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local Port" /t REG_SZ /d "*" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Protocol" /t REG_SZ /d "UDP" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote IP" /t REG_SZ /d "*" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote Port" /t REG_SZ /d "*" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "throttle Rate" /t REG_SZ /d "-1" /f 
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "version" /t REG_SZ /d "1.0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "ContigFileAllocSize" /t REG_DWORD /d "64" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "5000" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f  
Reg.exe add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "4000" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_SZ /d "150000" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsAll" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "GameFluidity" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGames" /t REG_DWORD /d "16" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Games" /v "FpsStatusGamesAll" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f 
Reg.exe add "HKLM\System\CurrentControlSet\Services\VxD\BIOS" /v "CPUPriority" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Off" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Highly Restricted" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Restricted" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Normal" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request" /t REG_SZ /d "Ignored" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request" /t REG_SZ /d "Allowed" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableUserTOSSetting" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "CorpLocationProbeTimeout" /t REG_DWORD /d "30" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "LdapTimeoutMs" /t REG_DWORD /d "5000" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "ShowDomainEndpointInterfaces" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "EnableNoGatewayLocationDetection" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "MinimumInternetHopCount" /t REG_DWORD /d "2" /f   
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\NVAPI" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "0" /f    
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Diagnostics\Performance" /F /V "DisableDiagnosticTracing" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /F /V "EventProcessorEnabled" /T REG_DWORD /d 0  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /F /V "MonitorLatencyTolerance" /T REG_DWORD /d 0  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\DXGKrnl" /F /V "MonitorRefreshLatencyTolerance" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /F /V "MenuShowDelay" /T REG_SZ /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "MouseSensitivity" /T REG_SZ /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "SmoothMouseXCurve" /T REG_BINARY /d 0000000000000000C0CC0C0000000000809919000000000040662600000000000033330000000000  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "SmoothMouseYCurve" /T REG_BINARY /d 0000000000000000000038000000000000007000000000000000A800000000000000E00000000000  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "MouseSpeed" /T REG_SZ /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "MouseThreshold1" /T REG_SZ /d 0  
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /F /V "MouseThreshold2" /T REG_SZ /d 0  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "ConvertibleSlateMode" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f  
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f  
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f  
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate" /v "value" /t REG_DWORD /d "1" /f      
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d "3" /f   
reg add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f reg add "HKCU\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d "2" /f   
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d "9012038010020000" /f   
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShellState" /t REG_BINARY /d "240000003E28000000000000000000000000000001000000130000000000000072000000" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "1" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "0" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "0" /f   
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f   
reg add "HKLM\System\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f   
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d "0.0.0.0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" /v "KeyboardDataQueueSize" /t REG_DWORD /d "16" /f reg add "HKLM\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" /v "MouseDataQueueSize" /t REG_DWORD /d "16" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_DWORD /d "0" /f  
cls  
for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr /l "USB\VID_"') do (  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" -ot reg -actn setowner -ownr "n:Administrators"  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" -ot reg -actn ace -ace "n:Administrators;p:full"  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 00000000 /f  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 00000000 /f  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 00000000 /f  
)  
for /f %%a in ('wmic PATH Win32_USBHub GET DeviceID ^| findstr /l "USB\ROOT_HUB"') do (  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" -ot reg -actn setowner -ownr "n:Administrators"  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 00000000 /f  
)  
cls  
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f  
cls  
netsh interface teredo set state disabled  
netsh interface 6to4 set state disabled  
netsh winsock reset  
netsh int isatap set state disable  
netsh int ip set global taskoffload=disabled  
netsh int ip set global neighborcachelimit=4096  
netsh int tcp set global timestamps=disabled  
netsh int tcp set heuristics disabled  
netsh int tcp set global chimney=disabled  
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
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_SZ /d "ffffffff" /f      
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Application Name" /t REG_SZ /d "fortniteclient-win64-shipping.exe" /f   
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "DSCP value" /t REG_SZ /d "46" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local IP" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local Port" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Protocol" /t REG_SZ /d "UDP" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote IP" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote Port" /t REG_SZ /d "*" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "throttle Rate" /t REG_SZ /d "-1" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "version" /t REG_SZ /d "1.0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\rt640x64\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\stornvme\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\USBXHCI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f     
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f       
icacls "C:\Program Files (x86)\Microsoft\Edge" /t /c /q /grant administrators:F    
takeown /f "C:\Program Files (x86)\Microsoft\Edge"    
taskkill /f /im msedge.exe    
cd %PROGRAMFILES(X86)%\Microsoft\Edge\Application\8*\Installer  
setup --uninstall --force-uninstall --system-level       
cd "C:\Program Files (x86)\Microsoft\Edge\Application"  
rmdir /S /Q "C:\Program Files (x86)\Microsoft\Edge\Application"  
rmdir /S /Q "C:\Program Files (x86)\Microsoft\Edge"     
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowClipboardHistory" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCrossDeviceClipboard" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogEnable" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WUDF" /v "LogLevel" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Credssp" /v "DebugLogLevel" /t REG_DWORD /d "0" /f >nul 2>&1 
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "0" /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "0" /f 
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_DWORD /d "0" /f
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_SZ /d "00000000" /f    
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f  
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d "1" /f  
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d "1" /f             
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f   
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f  
taskkill -F -FI "IMAGENAME eq SystemSettings.exe"   
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v "DisabledComponents" /t REG_DWORD /d "32" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT" /v "Start" /t REG_DWORD /d "4" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t REG_DWORD /d "4" /f 
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain" /F /V "Start" /T REG_DWORD /d 4  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f   
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableUserTOSSetting" /t REG_DWORD /d "0" /f   
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "CorpLocationProbeTimeout" /t REG_DWORD /d "30" /f   
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "LdapTimeoutMs" /t REG_DWORD /d "5000" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LowLatencyScalingPercentage" /t REG_DWORD /d "100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}" /v "TimeLimitInSeconds" /t REG_DWORD /d "18" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "ShowDomainEndpointInterfaces" /t REG_DWORD /d "1" /f   
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "EnableNoGatewayLocationDetection" /t REG_DWORD /d "1" /f   
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NlaSvc\Parameters\Internet" /v "MinimumInternetHopCount" /t REG_DWORD /d "2" /     
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\NVAPI" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f       
Reg add "HKLM\TK_SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f      
Reg add "HKLM\TK_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v "DriverUpdateWizardWuSearchEnabled" /t REG_DWORD /d "0" /f   
Reg add "HKLM\TK_SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d "1" /f >nul     
rd s q "C:\Windows\SoftwareDistribution"  
md "C:\Windows\SoftwareDistribution"        
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /F /V "fAllowUnsolicited" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /F /V "fAllowToGetHelp" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /F /V "UseBandwidthOptimization" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /F /V "LoggingEnabled" /T REG_DWORD /d 0  
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\intelppm\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\pci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\kbdclass\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\kbdhid\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NdisWan\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\EhStorClass\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\HDAudBus\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\partmgr\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\ACPI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\acpipagr\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\BasicDisplay\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\BasicRender\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\dc1-controller\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\intelpep\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\MEIx64\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\monitor\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\mouhid\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\msisadrv\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NdisVirtualBus\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\NvModuleTracker\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\storahci\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\umbus\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\USBHUB3\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\USBXHCI\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\vdrvroot\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\WUDFWpdFsParameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\xinputhid\Parameters" /v "DmaRemappingCompatible" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f >nul 2>&1   
taskkill /f /im Cortana.exe  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f   
rd /s /q "%WinDir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" >nul 2>&1    
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f   
rd /s /q "%WinDir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" >nul 2>&1  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f    
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\Software\Microsoft\Windows\DWM" /v "CompositionPolicy" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorUpdateInterval" /t REG_DWORD /d "1" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /d 0 /t REG_DWORD /f     
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMax" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\ControlSet002\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "ValueMin" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c" /v "ValueMax" /t REG_DWORD /d "100" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\893dee8e-2bef-41e0-89c6-b55d0929964c\DefaultPowerSchemeValues\8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c" /v "ValueMax" /t REG_DWORD /d "100" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "VsyncIdleTimeout" /t REG_DWORD /d "0" /f  
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "1298" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f  
reg add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f  
reg add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d "1" /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d "1" /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d "1" /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d "1" /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d "1" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsMftZoneReservation" /t REG_DWORD /d "1" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisable8dot3NameCreation" /t REG_DWORD /d "1" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NTFSDisableLastAccessUpdate" /t REG_DWORD /d "1" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "2000" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AlwaysUnloadDLL" /t REG_DWORD /d "1" /f  
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AlwaysUnloadDLL" /v "Default" /t REG_DWORD /d "1" /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d "0" /f  
reg add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f    
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f   
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f   
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f   
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f   
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f   
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f     
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Memory Management" /v "DisablePagingCombining" /t REG_DWORD /d "1" /f   
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f   
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "000000000000000000a0000000000000004001000000000000800200000000000000050000000000" /f  
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "000000000000000066a6020000000000cd4c050000000000a0990a00000000003833150000000000" /f   
cd C:\Windows\SystemApps  
timeout 1 >nul /nobreak  
icacls "C:\Windows\SystemApps\Microsoft.XboxGameCallableUI_cw5n1h2txyewy" /t /c /q /grant administrators:F    
takeown /F C:\Windows\SystemApps\Microsoft.XboxGameCallableUI_cw5n1h2txyewy /R /D Y    
rmdir /S /Q C:\Windows\SystemApps\Microsoft.XboxGameCallableUI_cw5n1h2txyewy   
icacls "C:\Windows\SystemApps\Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe" /t /c /q /grant administrators:F  
takeown /F C:\Windows\SystemApps\Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe /R /D Y  
rmdir /S /Q C:\Windows\SystemApps\Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe  
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f  
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f    
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 0 /f  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /V "Background Only" /T REG_SZ /d "False"  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /V "Clock Rate" /T REG_DWORD /d 2710  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /V "GPU Priority" /T REG_DWORD /d 8  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /V "Priority" /T REG_DWORD /d 6  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /V "Scheduling Category" /T REG_SZ /d "High"  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /F /V "SFIO Priority" /T REG_SZ /d "High"    
REG ADD "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI" /F /V "DisableMFUTracking" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /F /V "DisableMFUTracking" /T REG_DWORD /d 1  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /F /V "Start_TrackProgs" /T REG_DWORD /d 0    
REG ADD "HKEY_CURRENT_USER\Control Panel\International\User Profile" /F /V "HttpAcceptLanguageOptOut" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /F /V "Value" /T REG_SZ /d "Deny"  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /F /V "Value" /T REG_SZ /d "Deny"  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /F /V "Value" /T REG_SZ /d "Deny"  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /F /V "Value" /T REG_SZ /d "Deny"    
REG ADD "HKEY_CURRENT_USER\Control Panel\Accessibility\MouseKeys" /F /V "Flags" /T REG_SZ /d "0"  
REG ADD "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /F /V "Flags" /T REG_SZ /d "0"  
REG ADD "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /F /V "Flags" /T REG_SZ /d "0"  
REG ADD "HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys" /F /V "Flags" /T REG_SZ /d "0"  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /F /V "SearchOrderConfig" /T REG_DWORD /d 0    
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization" /F /V "RestrictImplicitTextCollection" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization" /F /V "RestrictImplicitInkCollection" /T REG_DWORD /d 1  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /F /V "HarvestContacts" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings" /F /V "AcceptedPrivacyPolicy" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization" /F /V "AllowInputPersonalization" /T REG_DWORD /d 0  
Reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationEnabled" /t REG_DWORD /d "0" /f  
Reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationOnLockScreenEnabled" /t REG_DWORD /d "0" /f  
Reg add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationLastUsed" /t REG_DWORD /d "0" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /V "AllowOnlineTips" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /F /V "NoWindowMinimizingShortcuts" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /F /V "DODownloadMode" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /V "NoInstrumentation" /T REG_DWORD /d 1  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /V "NoBalloonFeatureAdvertisements" /T REG_DWORD /d 1  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /V "TaskbarNoNotification" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /F /V "HidePeopleBar" /T REG_DWORD /d 1  
REG ADD "HLEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /V "HideSCAHealth" /T REG_DWORD /d 1  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /F /V "EnableTransparency" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\QuietHours" /F /V "Enable" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "NoTileApplicationNotification" /T REG_DWORD /d 1  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP" /F /V "CdpSessionUserAuthzPolicy" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP" /F /V "NearShareChannelUserAuthzPolicy" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP" /F /V "RomeSdkChannelUserAuthzPolicy" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "DatabaseMigrationCompleted" /T REG_DWORD /d 1  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "ToastEnabled" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "LockScreenToastEnabled" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\Maps" /F /V "AutoUpdateEnabled" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "NoToastApplicationNotificationOnLockScreen" /T REG_DWORD /d 1  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "NoToastApplicationNotificationOnLockScreen" /T REG_DWORD /d 1  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /F /V "TailoredExperiencesWithDiagnosticDataEnabled" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /F /V "disabletailoredexperiencesWithDiagnosticData" /T REG_DWORD /d 1  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /F /V "AgentActivationLastUsed" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /F /V "NoCloudApplicationNotification" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /F /V "PreventHandwritingDataSharing" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /F /V "PreventHandwritingErrorReports" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /F /V "DoReport" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /F /V "Disabled" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" /F /V "DontSearchWindowsUpdate" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "DisableLockScreenAppNotifications" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "UploadUserActivities" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "PublishUserActivities" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "AllowCrossDeviceClipboard" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "AllowClipboardHistory" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "EnableActivityFeed" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "HiberbootEnabled" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /F /V "AllowStorageSenseGlobal" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /F /V "AllowStorageSenseTemporaryFilesCleanup" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\StorageSense" /F /V "AllowStorageSenseTemporaryFilesCleanup" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\ScheduledDiagnostics" /F /V "EnabledExecution" /T REG_DWORD /d 0  
Reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f    
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /F /V "DisabledByGroupPolicy" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessAccountInfo" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessGazeInput" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessCallHistory" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessContacts" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsGetDiagnosticInfo" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessEmail" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessLocation" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessMessaging" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessMotion" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessNotifications" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessTasks" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessCalendar" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessTrustedDevices" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessBackgroundSpatialPerception" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsActivateWithVoice" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsActivateWithVoiceAboveLock" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsSyncWithDevices" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessRadios" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsAccessPhone" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /F /V "LetAppsRunInBackground" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /V "NoDriveTypeAutoRun" /T REG_DWORD /d 255  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /V "NoAutorun" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics" /F /V "Enabled" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /F /V "DisableSoftLanding" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /F /V "DisableCloudOptimizedContent" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /F /V "DisableWindowsConsumerFeatures" /T REG_DWORD /d 1  
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /F /V "SystemResponsiveness" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /F /V "MaintenanceDisabled" /T REG_DWORD /d 1  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /F /V "UseNexusForGameBarEnabled" /T REG_DWORD /d 0    
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Allow" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.Office.OneNote_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.SkypeApp_kzf8qxf38zg5c" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.Windows.Photos_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.WindowsCamera_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f    
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam\NonPackaged" /v "Value" /t REG_SZ /d "Allow" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Allow" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.549981C3F5F10_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.MixedReality.Portal_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Office.OneNote_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.SkypeApp_kzf8qxf38zg5c" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Win32WebViewHost_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Windows.Photos_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.Windows.SecureAssessmentBrowser_cw5n1h2txyewy" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.WindowsCamera_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f    
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.XboxApp_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f  
Reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe" /v "Value" /t REG_SZ /d "Deny" /f    
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_Enabled" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_FSEBehaviorMode" /T REG_DWORD /d 2  
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_HonorUserFSEBehaviorMode" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_DXGIHonorFSEWindowsCompatible" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\System\GameConfigStore" /F /V "GameDVR_EFSEFeatureFlags" /T REG_DWORD /d 0    
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowCommercialDataPipeline" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowDesktopAnalyticsProcessing" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowDeviceNameInTelemetry" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowTelemetry" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowUpdateComplianceProcessing" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "AllowWUfBCloudProcessing" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableEnterpriseAuthProxy" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "MicrosoftEdgeDataOptIn" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableTelemetryOptInChangeNotification" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableTelemetryOptInSettingsUx" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DisableDiagnosticDataViewer" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "EnableConfigFlighting" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "DoNotShowFeedbackNotifications" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /F /V "LimitEnhancedDiagnosticDataWindowsAnalytics" /T REG_DWORD /d 0   
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /F /V "EnableSmartScreen" /T REG_DWORD /d 0    
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Messaging" /F /V "AllowMessageSync" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /F /V "NoActiveHelp" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "DisableWebSearch" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "DisableRemovableDriveIndexing" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowCortanaAboveLock" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowCloudSearch" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "AllowSearchToUseLocation" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /F /V "ConnectedSearchUseWeb" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /F /V "SafeSearchMode" /T REG_DWORD /d 0  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /F /V "IsDeviceSearchHistoryEnabled" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Speech" /F /V "AllowSpeechModelUpdate" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableApplicationSettingSync" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableAppSyncSettingSync" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableWebBrowserSettingSync" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableDesktopThemeSettingSync" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableSettingSync" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableSyncOnPaidNetwork" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableWindowsSettingSync" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableCredentialsSettingSync" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisablePersonalizationSettingSync" /T REG_DWORD /d 2  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /F /V "DisableStartLayoutSettingSync" /T REG_DWORD /d 2  
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "000000000000000000a0000000000000004001000000000000800200000000000000050000000000" /f  
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "000000000000000066a6020000000000cd4c050000000000a0990a00000000003833150000000000" /f    
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AccessibilityTemp" /v "narrator" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Narrator\NoRoam" /v "RunningState" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "SettingsVersion" /t REG_DWORD /d "3" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableTextPrediction" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableDoubleTapSpace" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableInkingWithTouch" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "Insights" /t REG_BINARY /d "01000000071de8c131cc8360a3d6d9c1330a686b165aba2e235f5a5c" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceAppSuggestionsEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "TabletMode" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "SignInMode" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "ConvertibleSlateModePromptPreference" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\StateStore" /v "ResetCacheCount" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "WindowArrangementActive" /t REG_SZ /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "BackOffInterval" /t REG_DWORD /d "5" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "CheckBackMDNotRetrieved" /t REG_DWORD /d "5" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "CheckBackMDRetrieved" /t REG_DWORD /d "8" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "DeviceMetadataServiceURL" /t REG_SZ /d "http://go.microsoft.com/fwlink/?LinkID=252669&clcid=0x409" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "MaxRetryLimit" /t REG_DWORD /d "5" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "RequestBatchSize" /t REG_DWORD /d "25" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "CreateEncryptedOnlyTickets" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fEnableChatControl" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "MaxTicketExpiry" /t REG_DWORD /d "6" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "MaxTicketExpiryUnits" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "InstalledWin32AppsRevision" /t REG_SZ /d "{E00F4E01-A5F6-488E-A733-D341606BBD99}" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "InstalledPackagedAppsRevision" /t REG_SZ /d "{EE5761AF-9340-40EE-AFFB-D3F7ECEC59BD}" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaMUID" /t REG_SZ /d "MUID=62b4e7c3c0a24010b4c5abdfe4f2b796" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaStateLastRun" /t REG_BINARY /d "3247f55f00000000" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "IsAssignedAccess" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "NamespaceSettingsRevision" /t REG_SZ /d "{EBDF1464-A4D5-443C-ACE8-21C7FCDF002F}" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "AnyAboveLockAppsActive" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338394Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338396Enabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackAuthorization" /t REG_DWORD /d "775" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DiagTrackStatus" /t REG_DWORD /d "2" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "UploadPermissionReceived" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TraceManager" /v "MiniTraceSlotContentPermitted" /t REG_DWORD /d "1" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TraceManager" /v "MiniTraceSlotEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "PrivacyConsentPresentationVersion" /t REG_DWORD /d "2" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "PrivacyConsentSettingsVersion" /t REG_DWORD /d "3" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "Migrated" /t REG_DWORD /d "4" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f 
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Allow" /f  
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f 
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f 
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\Shell\USB" /v "NotifyOnWeakCharger" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "Win8DpiScaling" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "WindowArrangementActive" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "DragFullWindows" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "Pattern" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "WindowArrangementActive" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "ActiveWndTrackTimeout" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "BlockSendInputResets" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "EnablePerProcessSystemDPI" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "Beep" /t REG_SZ /d "No" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "ExtendedSounds" /t REG_SZ /d "No" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "KeyboardDelay" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "MouseSensitivity" /t REG_SZ /d "10" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "MouseSpeed" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "MouseThreshold1" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "MouseThreshold2" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "Win8DpiScaling" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "DpiScalingVer" /t REG_DWORD /d "4096" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "ScreenSaverIsSecure" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "PaintDesktopVersion" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "WallpaperOriginX" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "WallpaperOriginY" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "ForegroundLockTimeout" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop" /v "LastUpdated" /t REG_DWORD /d "4294967295" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "ActiveWindowTracking" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "Beep" /t REG_SZ /d "No" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "ExtendedSounds" /t REG_SZ /d "No" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseTrails" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000c0cc0c0000000000809919000000000040662600000000000033330000000000" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000a800000000000000e00000000000" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "SnapToDefaultButton" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Mouse" /v "SwapMouseButtons" /t REG_SZ /d "0" /f 
Reg.exe add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_SZ /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f 
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Locked" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "TelemetrySalt" /t REG_DWORD /d "2" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "FirstRunTelemetryComplete" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AppReadinessLogonComplete" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "EdgeDesktopShortcutCreated" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "PostAppInstallTasksCompleted" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "DesktopProcess" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ServerAdminUI" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "2" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCompColor" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowInfoTip" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTypeOverlay" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowStatusBar" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StoreAppsOnTaskbar" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "StartMenuInit" /t REG_DWORD /d "13" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarStateLastRun" /t REG_BINARY /d "465df45f00000000" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ReindexedProfile" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSmallIcons" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ExtendedUIHoverTime" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DesktopLivePreviewHoverTime" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "nonetcrawling" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSizeMove" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "2" /f 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /f /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\TabletPC" /F /V "TurnOffTouchInput" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\TabletPC" /F /V "TurnOffPanning" /T REG_DWORD /d 1  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /F /V "AllowLinguisticDataCollection" /T REG_DWORD /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /F /V "AllowWindowsInkWorkspace" /T REG_DWORD /d 0    
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /f /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /f /d 0  
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 0 /f  
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d 0 /f  
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f  
REG ADD "HKLM\Software\Microsoft\FTH" /F /V "Enabled" /T REG_DWORD /d 0   
for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr /l "USB\VID_"') do (  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" -ot reg -actn setowner -ownr "n:Administrators"  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" -ot reg -actn ace -ace "n:Administrators;p:full"  
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 00000000 /f  
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f  
)  
for /f %%a in ('wmic PATH Win32_USBHub GET DeviceID ^| findstr /l "USB\ROOT_HUB"') do (  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\WDF" -ot reg -actn setowner -ownr "n:Administrators"  
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 00000000 /f  
)  
for /f %%a in ('wmic PATH Win32_USBHub GET DeviceID ^| findstr /l "USB\VID_"') do (  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\WDF" -ot reg -actn setowner -ownr "n:Administrators"  
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 00000000 /f  
)  
for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr /l "PCI\VEN_"') do (  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\WDF" -ot reg -actn setowner -ownr "n:Administrators"  
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 00000000 /f  
)   
Powershell.exe -command "& {Enable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip}    
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_lldp}    
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_lltdio}    
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_implat}   
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_rspndr}  
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6}   
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_server}  
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_msclient}  
Powershell.exe -command "& {Disable-NetAdapterBinding -Name "*" -ComponentID ms_pacer}  
icacls "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy" /t /c /q /grant administrators:F    
takeown /F C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy /R /D Y    
taskkill /F /IM StartMenuExperienceHost*  >nul 2>nul  
rmdir /S /Q C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy            
reg delete HKCR\Extensions\ContractId\Windows.ComponentUI\PackageId\Microsoft.Windows.StartMenuExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f    
reg delete HKCR\Extensions\ContractId\Windows.AppService\PackageId\Microsoft.Windows.ShellExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f   
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.Windows.ShellExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.Windows.StartMenuExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\MicrosoftWindows.UndockedDevKit_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y /f    
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.Windows.ShellExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.Windows.StartMenuExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\MicrosoftWindows.UndockedDevKit_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.Windows.ShellExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy /f    
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.Windows.ShellExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.Windows.StartMenuExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\MicrosoftWindows.UndockedDevKit_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy /f    
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.Windows.ShellExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.Windows.StartMenuExperienceHost_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Launch\PackageId\MicrosoftWindows.UndockedDevKit_10.0.19041.423_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0 /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.BingWeather_4.25.20211.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.GetHelp_10.1706.13331.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.Getstarted_8.2.22942.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.MicrosoftEdge_44.19041.423.0_neutral__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.MicrosoftOfficeHub_18.1903.1152.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.MixedReality.Portal_2000.19081.1301.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.MSPaint_6.1907.29027.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.Office.OneNote_16001.12026.20112.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.People_10.1902.633.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.WindowsAlarms_10.1906.2182.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.WindowsCamera_2018.826.98.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.WindowsFeedbackHub_1.1907.3152.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.WindowsCalculator_10.1906.55.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.WindowsMaps_5.1906.1972.0_x64__8wekyb3d8bbwe /f    
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.Xbox.TCUI_1.23.28002.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxApp_48.49.31001.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.19041.423.0_neutral_neutral_cw5n1h2txyewy /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameOverlay_1.46.11001.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGamingOverlay_2.34.28001.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxSpeechToTextOverlay_1.17.29001.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.ZuneMusic_10.19071.19011.0_x64__8wekyb3d8bbwe /f  
reg delete HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.ZuneVideo_10.19071.19011.0_x64__8wekyb3d8bbwe /f    
schtasks /change /TN "Microsoft\Windows\Device Information\Device" /DISABLE    
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "10" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "LazyModeTimeout" /t REG_DWORD /d "150000" /f >nul 2>&1  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "1" /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f    
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowSleepOption" /t REG_DWORD /d "0" /f   
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" /v "ShowLockOption" /t REG_DWORD /d "0" /f     
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f  
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f  
reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Power" /v "SleepStudyDisabled" /t REG_DWORD /d "1" /f >nul 2>&1  
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f  
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f    
Powershell -Command "Get-ScheduledTask -TaskName XblGameSaveTask | Disable-ScheduledTask"  
Powershell -Command "Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask"  
Powershell -Command "Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask"  
Powershell -Command "Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask"  
Powershell -Command "Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask"    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v "TimeStampInterval" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Off" /f   
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Highly Restricted" /f   
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Restricted" /f   
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Tcp Autotuning Level" /t REG_SZ /d "Normal" /f   
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request" /t REG_SZ /d "Ignored" /f   
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\QoS" /v "Application DSCP Marking Request" /t REG_SZ /d "Allowed" /f   
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_SZ /d "10" /f  
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f  
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f  
Reg.exe add "HKU\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d "3" /f  
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f  
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f  
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f  
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f  
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d "0" /f  
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f    
cd C:\Windows\System32  
del /f mcupdate_genuineintel.dll  
del /f mcupdate_authenticamd.dll    
REG ADD "HKLM\Software\Microsoft\FTH" /F /V "Enabled" /T REG_DWORD /d 0    
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d "2" /f    
for /f %%a in ('wmic PATH Win32_PnPEntity GET DeviceID ^| findstr /l "USB\VID_"') do (  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" -ot reg -actn setowner -ownr "n:Administrators"  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" -ot reg -actn ace -ace "n:Administrators;p:full"  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v SelectiveSuspendOn /t REG_DWORD /d 00000000 /f  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v SelectiveSuspendEnabled /t REG_BINARY /d 00 /f  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v EnhancedPowerManagementEnabled /t REG_DWORD /d 00000000 /f  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters" /v AllowIdleIrpInD3 /t REG_DWORD /d 00000000 /f  
)  
for /f %%a in ('wmic PATH Win32_USBHub GET DeviceID ^| findstr /l "USB\ROOT_HUB"') do (  
C:\Windows\SetACL.exe -on "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" -ot reg -actn setowner -ownr "n:Administrators"  
reg.exe add "HKLM\SYSTEM\ControlSet001\Enum\%%a\Device Parameters\WDF" /v IdleInWorkingState /t REG_DWORD /d 00000000 /f  
)  
 
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f >nul 2>&1  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "UseActionCenterExperience" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAHealth" /t REG_DWORD /d "1" /f >nul 2>&1  
reg add "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1  
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\Software\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >nul 2>&1  
reg add "HKLM\Software\Policies\Microsoft\Windows\safer\codeidentifiers" /v "authenticodeenabled" /t REG_DWORD /d "0" /f >nul 2>&1  
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul 2>&1  
reg add "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1  
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "LockScreenToastEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "QuietHoursTelemetryLastRun" /t REG_BINARY /d "2d41e95f00000000" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "TabletMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "SignInMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v "ConvertibleSlateModePromptPreference" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell\StateStore" /v "ResetCacheCount" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WindowArrangementActive" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogProfileOffset" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcTimeout" /t REG_DWORD /d "0" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d "0" /f    
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "LowLatencyScalingPercentage" /t REG_DWORD /d "100" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power\Profile\Events\{54533251-82be-4824-96c1-47b60b740d00}\{0DA965DC-8FCF-4c0b-8EFE-8DD5E7BC959A}\{7E01ADEF-81E6-4e1b-8075-56F373584694}" /v "TimeLimitInSeconds" /t REG_DWORD /d "18" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NoLazyMode" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "AlwaysOn" /t REG_DWORD /d "1" /f  
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HighPerformance" /t REG_DWORD /d "1" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Background Only" /t REG_SZ /d "False" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "10000" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "2" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Latency Sensitive" /t REG_SZ /d "True" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Background Only" /t REG_SZ /d "False" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "10000" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "GPU Priority" /t REG_DWORD /d "8" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Scheduling Category" /t REG_SZ /d "High" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "SFIO Priority" /t REG_SZ /d "High" /f    
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Latency Sensitive" /t REG_SZ /d "True" /f        
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f    
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f    
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f    
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d "1" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d "0" /f    
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f    
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d "1" /f    
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d "0" /f        
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NV Hostname" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DataBasePath" /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\drivers\etc" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "NameServer" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ForwardBroadcasts" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "IPEnableRouter" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Domain" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Hostname" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SearchList" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "UseDomainNameDevolution" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DeadGWDetectDefault" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DontAddDefaultGatewayDefault" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableSecurityFilters" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "ArpAlwaysSourceRoute" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DisableIPSourceRouting" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableAddrMaskReply" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableBCastArpReply" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableDeadGWDetect" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "KeapAliveTime" /t REG_DWORD /d "300000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "MaxUserPort" /t REG_DWORD /d "65534" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDupAcks" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpRecSegmentSize" /t REG_DWORD /d "2446674" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectResponseRetransmissions" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectRetransmissions" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxHalfOpen" /t REG_DWORD /d "300" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxHalfOpenRetried" /t REG_DWORD /d "200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxPortExhausted" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\NdisWanIp" /v "LLInterface" /t REG_SZ /d "WANARP" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\NdisWanIp" /v "IpConfig" /t REG_MULTI_SZ /d "Tcpip\Parameters\Interfaces\{0DD48E26-3D78-4179-94E1-B985BD446474}\0Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}\0Tcpip\Parameters\Interfaces\{823A9830-5EC9-48B8-B5EF-EF5F087EBB7D}\0Tcpip\Parameters\Interfaces\{749A9614-EC83-4CC3-B32B-C3696B9AEEED}" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\NdisWanIp" /v "NumInterfaces" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\NdisWanIp" /v "IpInterfaces" /t REG_BINARY /d "268ed40d783d794194e1b985bd4464741e8b4db51492a64090ba39c6fc82e86b30983a82c95eb848b5efef5f087ebb7d14969a7483ecc34cb32bc3696b9aeeed" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "LLInterface" /t REG_SZ /d "ARP1394" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "IpConfig" /t REG_MULTI_SZ /d "Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "LLInterface" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Adapters\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "IpConfig" /t REG_MULTI_SZ /d "Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DNSRegisteredAdapters" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0DD48E26-3D78-4179-94E1-B985BD446474}" /v "UseZeroBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0DD48E26-3D78-4179-94E1-B985BD446474}" /v "EnableDHCP" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0DD48E26-3D78-4179-94E1-B985BD446474}" /v "IPAddress" /t REG_MULTI_SZ /d "0.0.0.0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0DD48E26-3D78-4179-94E1-B985BD446474}" /v "SubnetMask" /t REG_MULTI_SZ /d "0.0.0.0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0DD48E26-3D78-4179-94E1-B985BD446474}" /v "DefaultGateway" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0DD48E26-3D78-4179-94E1-B985BD446474}" /v "EnableDeadGWDetect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0DD48E26-3D78-4179-94E1-B985BD446474}" /v "DontAddDefaultGateway" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{749A9614-EC83-4CC3-B32B-C3696B9AEEED}" /v "UseZeroBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{749A9614-EC83-4CC3-B32B-C3696B9AEEED}" /v "EnableDHCP" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{749A9614-EC83-4CC3-B32B-C3696B9AEEED}" /v "IPAddress" /t REG_MULTI_SZ /d "0.0.0.0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{749A9614-EC83-4CC3-B32B-C3696B9AEEED}" /v "SubnetMask" /t REG_MULTI_SZ /d "0.0.0.0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{749A9614-EC83-4CC3-B32B-C3696B9AEEED}" /v "DefaultGateway" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{749A9614-EC83-4CC3-B32B-C3696B9AEEED}" /v "EnableDeadGWDetect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{749A9614-EC83-4CC3-B32B-C3696B9AEEED}" /v "DontAddDefaultGateway" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{823A9830-5EC9-48B8-B5EF-EF5F087EBB7D}" /v "UseZeroBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{823A9830-5EC9-48B8-B5EF-EF5F087EBB7D}" /v "EnableDHCP" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{823A9830-5EC9-48B8-B5EF-EF5F087EBB7D}" /v "IPAddress" /t REG_MULTI_SZ /d "0.0.0.0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{823A9830-5EC9-48B8-B5EF-EF5F087EBB7D}" /v "SubnetMask" /t REG_MULTI_SZ /d "0.0.0.0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{823A9830-5EC9-48B8-B5EF-EF5F087EBB7D}" /v "DefaultGateway" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{823A9830-5EC9-48B8-B5EF-EF5F087EBB7D}" /v "EnableDeadGWDetect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{823A9830-5EC9-48B8-B5EF-EF5F087EBB7D}" /v "DontAddDefaultGateway" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "UseZeroBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "EnableDHCP" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "IPAddress" /t REG_MULTI_SZ /d "0.0.0.0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "SubnetMask" /t REG_MULTI_SZ /d "0.0.0.0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "DefaultGateway" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "DefaultGatewayMetric" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "NameServer" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "Domain" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "RegistrationEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "RegisterAdapterName" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "TCPAllowedPorts" /t REG_MULTI_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "UDPAllowedPorts" /t REG_MULTI_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{9A2FF573-9392-4328-A76E-3CC5A195D9E2}" /v "RawIPAllowedProtocols" /t REG_MULTI_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "UseZeroBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "EnableDeadGWDetect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "EnableDHCP" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "IPAddress" /t REG_MULTI_SZ /d "192.168.0.1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "SubnetMask" /t REG_MULTI_SZ /d "255.255.255.0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "DefaultGateway" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "DefaultGatewayMetric" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "NameServer" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "Domain" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "RegistrationEnabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "RegisterAdapterName" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "TCPAllowedPorts" /t REG_MULTI_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "UDPAllowedPorts" /t REG_MULTI_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "RawIPAllowedProtocols" /t REG_MULTI_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{A8C43F70-D71E-41C5-8CE7-41258A8A7E37}" /v "NTEContextList" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "UseZeroBroadcast" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "EnableDHCP" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "IPAddress" /t REG_MULTI_SZ /d "0.0.0.0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "SubnetMask" /t REG_MULTI_SZ /d "0.0.0.0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "DefaultGateway" /t REG_MULTI_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "EnableDeadGWDetect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "DontAddDefaultGateway" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "NTEContextList" /t REG_MULTI_SZ /d "0x00000002" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "DhcpClassIdBin" /t REG_BINARY /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "DhcpIPAddress" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "DhcpSubnetMask" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "Domain" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "NameServer" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "RegistrationEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{B54D8B1E-9214-40A6-90BA-39C6FC82E86B}" /v "RegisterAdapterName" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "UseDelayedAcceptance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "HelperDllName" /t REG_EXPAND_SZ /d "%%SystemRoot%%\System32\wshtcpip.dll" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "Mapping" /t REG_BINARY /d "0b00000003000000020000000100000006000000020000000100000000000000020000000000000006000000000000000000000006000000000000000100000006000000020000000200000011000000020000000200000000000000020000000000000011000000000000000000000011000000000000000200000011000000020000000300000000000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "AllowUnqualifiedQuery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DisableMediaSenseEventLog" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DisableRss" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DisableTaskOffload" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DisableTcpChimneyOffload" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "DnsOutstandingQueriesCount" /t REG_DWORD /d "1000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableAddrMaskReply" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableBcastArpReply" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableConnectionRateLimiting" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableDca" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableHeuristics" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableIPAutoConfigurationLimits" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableTCPA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "EnableWsd" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "IPEnableRouter" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "QualifyingDestinationThreshold" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "StrictTimeWaitSeqCheck" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "SynAttackProtect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "TCPMaxDataRetransmissions" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "RssBaseCpu" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\services\NDIS\Parameters" /v "MaxNumRssCpus" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastCopyReceiveThreshold" /t REG_DWORD /d "1500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters" /v "FastSendDatagramThreshold" /t REG_DWORD /d "1500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*SpeedDuplex" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*FlowControl" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*RSS" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*TCPConnectionOffloadIPv4" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*TCPConnectionOffloadIPv6" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*IPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*TCPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*TCPChecksumOffloadIPv6" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*UDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*UDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*LsoV1IPv4" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*LsoV2IPv4" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*LsoV2IPv6" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*TCPUDPChecksumOffloadIPv4" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\00xx" /v "*TCPUDPChecksumOffloadIPv6" /t REG_SZ /d "3" /f
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Application Name" /t REG_SZ /d "fortniteclient-win64-shipping.exe" /f     
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "DSCP value" /t REG_SZ /d "46" /f    
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local IP" /t REG_SZ /d "*" /f    
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local IP Prefix Length" /t REG_SZ /d "*" /f    
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Local Port" /t REG_SZ /d "*" /f    
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Protocol" /t REG_SZ /d "UDP" /f    
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote IP" /t REG_SZ /d "*" /f    
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote IP Prefix Length" /t REG_SZ /d "*" /f    
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "Remote Port" /t REG_SZ /d "*" /f    
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "throttle Rate" /t REG_SZ /d "-1" /f    
REG ADD "HKEY_LOCAL_MACHINE\SOftWARE\Policies\Microsoft\Windows\QoS\fortnite" /v "version" /t REG_SZ /d "1.0" /f
for %%x in (
"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
"\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
"\Microsoft\Windows\Time Zone\SynchronizeTimeZone"
"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
"\Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task"
"\Microsoft\Windows\UpdateOrchestrator\Reboot"
"\Microsoft\Windows\USB\Usb-Notifications"
"\Microsoft\Windows\WDI\ResolutionHost"
"\Microsoft\Windows\WindowsUpdate\Scheduled Start"
"\Microsoft\Windows\Workplace Join\Automatic-Device-Join"
"\Microsoft\Windows\Workplace Join\Recovery-Check"
"\Microsoft\Windows\Diagnosis\Scheduled"
"\Microsoft\Windows\Location\Notifications"
"\Microsoft\Windows\Location\WindowsActionDialog"
"\Microsoft\Windows\Offline Files\Background Synchronization"
"\Microsoft\Windows\Offline Files\Logon Synchronization"
"\Microsoft\Windows\Time Synchronization\ForceSynchronizeTime"
"\Microsoft\Windows\Time Synchronization\SynchronizeTime"
)Do (
    schtasks /Change /TN %%x /Disable
)
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableContextDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "ForceFlipTrueImmediateMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "ForceIndependentFlip" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "MaxYieldInterval" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "NumberOfDmaPacketPool" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "QuantumUnit" /t REG_DWORD /d "250000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "QueuedPresentLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "YieldPercentage" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "VsyncIdleTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableContextDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "ForceFlipTrueImmediateMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "ForceIndependentFlip" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "MaxYieldInterval" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "NumberOfDmaPacketPool" /t REG_DWORD /d "256" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "QuantumUnit" /t REG_DWORD /d "250000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "QueuedPresentLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "YieldPercentage" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "RMDisablePostL2Compression" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "RmDisableRegistryCaching" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "RmGpsPsEnablePerCpuCoreDpc" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisableWriteCombining" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "GPUPreemptionLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "ComputePreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidGfxPreemptionVGPU" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidBufferPreemptionForHighTdrTimeout" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableAsyncMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableSCGMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PerfAnalyzeMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidGfxPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableMidBufferPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableCEPreemption" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisableCudaContextPreemption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisablePreemptionOnS3S4" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "MonitorLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "MonitorRefreshLatencyTolerance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "AdaptiveVsyncEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "AllowDeepCStates" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "BuffersInFlight" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "ComputePreemptionLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "D3PCLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "Disable_OverlayDSQualityEnhancement" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisableAsyncPstates" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisableGDIAcceleration" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisableKmRender" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisableKmRenderBoost" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisableOverclockedPstates" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisablePFonDP" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DisablePreemption" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f
cls
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableAggressivePStateBoost" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableAggressivePStateOnly" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableDirectFlip" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableIndependentFlip" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePerformanceMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnableRuntimePowerManagement" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "FlTransitionLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "LOWLATENCY" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "Node3DLowLatency" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PciLatencyTimerControl" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PowerSavingTweaks" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "PrimaryPushBufferSize" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "RmClkPowerOffDramPllWhenUnused" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "RMDeepLlEntryLatencyUsec" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "RmFbsrPagedDMA" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "TdrDdiDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "TdrDebugMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "TdrDelay" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "TdrLevel" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "TdrLimitCount" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "TdrLimitTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "TdrTestMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "UseGpuTimer" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers\BlockList\Kernel" /va /reg:64 /f >NUL 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "DpiMapIommuContiguous" /t REG_DWORD /d "1" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MaximumDpcQueueDepth" /t REG_DWORD /d "1" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MinimumDpcRate" /t REG_DWORD /d "1" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "ThreadDpcEnable" /t REG_DWORD /d "1" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "AdjustDpcThreshold" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DpcWatchdogPeriod" /t REG_DWORD /d "0" /f >NUL 2>&1
Reg.exe add "HKLM\System\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >NUL 2>&1
timeout 1 >nul
cls
timeout 2 >nul
echo [91mSuccesfull! Returning to menu...[0m
timeout 2 >nul
goto menu

:reboot
shutdown /r /c /f "Restarting PC after tweaks - ZenoxTweaks"
goto menu