curl -g -k -L -# -o "%temp%\nvidiaProfileInspector.zip" "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip" 
powershell -NoProfile Expand-Archive '%temp%\nvidiaProfileInspector.zip' -DestinationPath 'C:\Exm\NvidiaProfileInspector\'
curl -g -k -L -# -o "C:\Exm\NvidiaProfileInspector" https://cdn.discordapp.com/attachments/1129168931081428992/1166780815213080616/Exm_Premium_Profile_V4.nip?ex=654bbc50&is=65394750&hm=6404e907d88781058599c408cc26758f7982e4c92465caf2f1d954f97d87d17d&"


start "" /wait "C:\exm\NvidiaProfileInspector\nvidiaProfileInspector.exe" "C:\exm\NvidiaProfileInspector\Exm_Premium_Profile_V4.nip"
