@echo off

POWERSHELL "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
POWERSHELL "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Client"
POWERSHELL "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server"
POWERSHELL "Set-SmbClientConfiguration -RequireSecuritySignature $True -Force"
POWERSHELL "Set-SmbClientConfiguration -EnableSecuritySignature $True -Force"
POWERSHELL "Set-SmbServerConfiguration -EncryptData $True -Force"
POWERSHELL "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
echo.