::Disable limiting 

echo Stopping Network Throttoling

netsh advfirewall firewall add rule name="StopThrottling" dir=in action=block remoteip=173.194.55.0/24,206.111.0.0/16 enable=yes

echo Disabling Network Limiting

netsh interface tcp set heuristics disabled