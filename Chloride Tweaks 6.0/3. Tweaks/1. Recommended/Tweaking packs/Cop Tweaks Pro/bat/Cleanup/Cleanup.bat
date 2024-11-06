takeown /f "%temp%" /r /d y & RD /S /Q %temp% & MKDIR %temp% & takeown /f "%temp%" /r /d y & takeown /f "C:\Windows\Temp" /r /d y & RD /S /Q C:\Windows\Temp & MKDIR C:\Windows\Temp & takeown /f "C:\Windows\Temp" /r /d y
cd C:/ & del *.log /a /s /q /f
del C:\Windows\prefetch\*.*/s/q
cls