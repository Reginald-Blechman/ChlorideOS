@echo off

REM Set temporary directory
set "tempDir=%TEMP%\nvidiaProfileInspector"

REM Create a temporary directory
mkdir "%tempDir%"

REM Download NvidiaProfileInspector zip file
powershell -command "(New-Object Net.WebClient).DownloadFile('https://github.com/Orbmu2k/nvidiaProfileInspector/releases/download/2.4.0.4/nvidiaProfileInspector.zip', '%tempDir%\nvidiaProfileInspector.zip')"

REM Extract the contents of the zip file
powershell Expand-Archive -Path "%tempDir%\nvidiaProfileInspector.zip" -DestinationPath "%tempDir%"

REM Start NvidiaProfileInspector
start "" "%tempDir%\nvidiaProfileInspector.exe"

REM Apply the .nip profile
timeout /t 5 /nobreak >nul
"%tempDir%\nvidiaProfileInspector.exe" "%tempDir%\Exm_Premium_Profile_V5.nip"
