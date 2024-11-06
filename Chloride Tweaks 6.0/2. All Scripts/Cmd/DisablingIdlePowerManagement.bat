:: Disabling IDLE POWER MANAGEMENT

echo %w%- Disabling Idle Power Managment %b%
for /f "tokens=*" %%i in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "StorPort" ^| findstr "StorPort"') do Reg.exe add "%%i" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f  >nul 2>&1