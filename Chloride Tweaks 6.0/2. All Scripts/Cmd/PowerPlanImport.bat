@echo off

REM Set temporary directory
set "tempDir=%TEMP%\PowerPlan"

REM Create a temporary directory
mkdir "%tempDir%"

REM Download the power plan file
echo Downloading power plan...
powershell -command "(New-Object Net.WebClient).DownloadFile('https://www.dropbox.com/scl/fi/nigqklkq1xindmozv5sok/Exm_Premium_Power_Plan_V4.pow?rlkey=xk2o4lxxbyoug63km3kquh7r6&dl=1', '%tempDir%\Exm_Premium_Power_Plan_V3.pow')"
echo Power plan downloaded.

REM Import the power plan
echo Importing power plan...
powercfg -import "%tempDir%\Exm_Premium_Power_Plan_V3.pow"
echo Power plan imported.

REM Open Power Options control panel
echo Opening Power Options...
powercfg.cpl
