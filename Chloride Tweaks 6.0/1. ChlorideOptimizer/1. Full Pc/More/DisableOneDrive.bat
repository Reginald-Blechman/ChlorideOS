::Disable one drive

%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall

 rd "%UserProfile%\OneDrive" /s /q
   rd "%LocalAppData%\Microsoft\OneDrive" /s /q
   rd "%ProgramData%\Microsoft OneDrive" /s /q
   rd "C:\OneDriveTemp" /s /q
   del "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /s /f /q
   
    REG Delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
   REG Delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
   REG ADD "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /d "0" /t REG_DWORD /f