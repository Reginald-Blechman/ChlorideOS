@echo off
::BCDEDITREVERT
bcdedit /deletevalue configaccesspolicy >nul 2>&1
bcdedit /deletevalue MSI >nul 2>&1
bcdedit /deletevalue usephysicaldestination >nul 2>&1
bcdedit /deletevalue usefirmwarepcisettings >nul 2>&1
bcdedit /deletevalue useplatformtick >nul 2>&1 
bcdedit /deletevalue useplatformclockJ >nul 2>&1 
bcdedit /deletevalue disabledynamictick >nul 2>&1
bcdedit /deletevalue tscsyncpolicy >nul 2>&1
bcdedit /deletevalue x2apicpolicy >nul 2>&1
bcdedit /deletevalue ems >nul 2>&1
bcdedit /deletevalue bootems >nul 2>&1
bcdedit /deletevalue vm >nul 2>&1
bcdedit /deletevalue sos >nul 2>&1
bcdedit /deletevalue quietboot >nul 2>&1
bcdedit /deletevalue integrityservices >nul 2>&1
bcdedit /deletevalue bootux >nul 2>&1
bcdedit /deletevalue bootlog >nul 2>&1
bcdedit /deletevalue tpmbootentropy >nul 2>&1
bcdedit /deletevalue disableelamdrivers >nul 2>&1
bcdedit /deletevalue hypervisorlaunchtype >nul 2>&1
bcdedit /deletevalue isolatedcontext >nul 2>&1
bcdedit /deletevalue pae >nul 2>&1
bcdedit /deletevalue vsmlaunchtype >nul 2>&1