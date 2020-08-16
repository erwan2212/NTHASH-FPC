@echo off
rem lets copy our provider to win sys
copy nplogon.dll %systemroot%\system32 /y
@setlocal enableextensions enabledelayedexpansion
rem lets setup our provider
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nplogon\NetworkProvider" /v "Class" /d 2 /t REG_DWORD /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nplogon\NetworkProvider" /v "Name" /d "nplogon" /t REG_SZ /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nplogon\NetworkProvider" /v "ProviderPath" /d "%SystemRoot%\System32\nplogon.dll" /t REG_EXPAND_SZ /f
rem lets check the provider list
for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" /v "ProviderOrder" ^|findstr /ri "REG_SZ"') do set ret=%%a%
echo %ret%
rem do we need to add our provider?
ECHO %ret% | FINDSTR /C:"nplogon" >nul & IF ERRORLEVEL 1 (ECHO updating) else (goto :end)
(set "extra=%ret%,nplogon")
echo %extra%
rem lets add our provider
reg add "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" /v "ProviderOrder" /d %extra% /t REG_SZ /f
:end
echo done