@echo off

REM Set temporary directory
set "tempDir=%TEMP%\nvidiaProfileInspector"

REM Create a temporary directory
mkdir "%tempDir%"

REM Download the .nip profile file
echo Downloading .nip profile...
powershell -command "(New-Object Net.WebClient).DownloadFile('https://www.dropbox.com/scl/fi/fdzgc9kjrha5x1pr37h6z/Exm_Premium_Profile_V5.nip?rlkey=3g23xv61x7xwp8ovsey701jsv&dl=1', '%tempDir%\Exm_Premium_Profile_V5.nip')"
echo .nip profile downloaded.

REM Download NvidiaProfileInspector zip file
echo Downloading NvidiaProfileInspector...
powershell -command "(New-Object Net.WebClient).DownloadFile('https://github.com/Orbmu2k/nvidiaProfileInspector/releases/download/2.4.0.4/nvidiaProfileInspector.zip', '%tempDir%\nvidiaProfileInspector.zip')"
echo NvidiaProfileInspector downloaded.

REM Extract the contents of the zip file
echo Extracting NvidiaProfileInspector...
powershell Expand-Archive -Path "%tempDir%\nvidiaProfileInspector.zip" -DestinationPath "%tempDir%"
echo NvidiaProfileInspector extracted.

REM Start NvidiaProfileInspector and apply the .nip profile
echo Applying .nip profile...
start "" "%tempDir%\nvidiaProfileInspector.exe" "%tempDir%\Exm_Premium_Profile_V5.nip"
echo .nip profile applied.

REM Pause to keep the window open (optional)
pause
