@echo off
net start trustedinstaller
for /F "tokens=1" %%K in (' nthash-win64 /enumproc ^| findstr /i "trustedinstaller" ') do ( nthash-win64 /runastoken /pid:%%K /system )