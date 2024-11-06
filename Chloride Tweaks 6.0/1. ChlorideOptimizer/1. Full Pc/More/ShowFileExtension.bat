::showfile extentions 
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
Reg.exe add "HKCR\lnkfile" /v "NeverShowExt" /f
Reg.exe add "HKCR\IE.AssocFile.URL" /v "NeverShowExt" /f
Reg.exe add "HKCR\IE.AssocFile.WEBSITE" /v "NeverShowExt" /f
Reg.exe add "HKCR\InternetShortcut" /v "NeverShowExt" /f
Reg.exe add "HKCR\Microsoft.Website" /v "NeverShowExt" /f
Reg.exe add "HKCR\piffile" /v "NeverShowExt" /f
Reg.exe add "HKCR\SHCmdFile" /v "NeverShowExt" /f
Reg.exe add "HKCR\LibraryFolder" /v "NeverShowExt" /f
echo.
echo.