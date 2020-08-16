@echo off
for /F "tokens=1" %%K in (' nthash-win64 /enumproc ^| findstr /i "lsass" ') do ( nthash-win64 /runastoken /pid:%%K /system )