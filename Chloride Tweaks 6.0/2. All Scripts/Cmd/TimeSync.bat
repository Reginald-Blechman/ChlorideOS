::timesync
net stop w32time
w32tm /unregister
w32tm /register
w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org" /reliable:YES
net start w32time
w32tm /config /update
w32tm /resync /rediscover
echo.