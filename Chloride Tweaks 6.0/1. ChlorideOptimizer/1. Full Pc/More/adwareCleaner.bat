@echo off

REM Set temporary directory
set "tempDir=%TEMP%\AdwCleaner"

REM Create a temporary directory
mkdir "%tempDir%"

REM Download AdwCleaner from the provided link
powershell -command "(New-Object Net.WebClient).DownloadFile('https://www.dropbox.com/scl/fi/ogkah5ra3xb47wzcllmof/adwcleaner.exe?rlkey=ejsgbvbpsun5l4pbqef5i4mdb&dl=1', '%tempDir%\AdwCleaner.exe')"

REM Run AdwCleaner from the temporary directory
start "" "%tempDir%\AdwCleaner.exe"