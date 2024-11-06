@echo off
curl -g -k -L -# -o "C:\EXM_WallPaper.png" "https://cdn.discordapp.com/attachments/1176509230484824157/1211352281845469254/Clean_Windows_Background_Desktop_wallpaper_art_Microsoft.png?ex=65ede2b9&is=65db6db9&hm=be012ecc0a8fe07d11c5937bd567c1e559b8af0bc97a4ac3d7647be044d083f0&"


reg add "HKCU\control panel\desktop" /v wallpaper /t REG_SZ /d "" /f 
reg add "HKCU\control panel\desktop" /v wallpaper /t REG_SZ /d "C:\EXM_WallPaper.png" /f 
reg delete "HKCU\Software\Microsoft\Internet Explorer\Desktop\General" /v WallpaperStyle /f

RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters 
exit
pause