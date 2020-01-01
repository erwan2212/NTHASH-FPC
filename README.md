# NTHASH-FPC <br/>
A tribute to https://github.com/gentilkiwi/mimikatz... <br/>
And generally speaking a tool to handle windows passwords and perform lateral movement. <br/>
https://attack.mitre.org/matrices/enterprise/windows/ is definitely worth reading as well. <br/>

<br/>
Command line as below: <br/>
NTHASH /setntlm [/server:hostname] /user:username /newhash:xxx <br/>
NTHASH /setntlm [/server:hostname] /user:username /newpwd:xxx <br/>
NTHASH /changentlm [/server:hostname] /user:username /oldpwd:xxx /newpwd:xxx <br/>
NTHASH /changentlm [/server:hostname] /user:username /oldhash:xxx /newpwd:xxx <br/>
NTHASH /changentlm [/server:hostname] /user:username /oldpwd:xxx /newhash:xxx <br/>
NTHASH /changentlm [/server:hostname] /user:username /oldhash:xxx /newhash:xxx <br/>
NTHASH /getntlmhash /password:password <br/>
NTHASH /getsid /user:username [/server:hostname] <br/>
NTHASH /getusers [/server:hostname] <br/>
NTHASH /getdomains [/server:hostname <br/>
NTHASH /dumpsam <br/>
NTHASH /dumphashes [/offline] <br/>
NTHASH /getsamkey [/offline] <br/>
NTHASH /getsyskey [/offline] <br/>
NTHASH /getlsakeys <br/>
NTHASH /wdigest <br/>
NTHASH /logonpasswords <br/>
NTHASH /pth /user:username /password:myhash /domain:mydomain <br/>
NTHASH /enumcred <br/>
NTHASH /enumcred2 <br/>
NTHASH /enumvault <br/>
NTHASH /chrome [/binary:path_to_database] <br/>
NTHASH /ccookies [/binary:path_to_database] <br/>
NTHASH /firefox [/binary:path_to_database] <br/>
NTHASH /fcookies [/binary:path_to_database] <br/>
NTHASH /bytetostring /input:hexabytes <br/>
NTHASH /stringtobyte /input:string <br/>
NTHASH /filetobyte /binary:filename <br/>
NTHASH /bytetofile /input:hexabytes <br/>   
NTHASH /widestringtobyte /input:string <br/>
NTHASH /base64encodew /input:string <br/>
NTHASH /base64encode /input:string <br/>
NTHASH /base64decode /input:base64string <br/>
NTHASH /cryptunprotectdata /binary:filename <br/>
NTHASH /cryptunprotectdata /input:string <br/>
NTHASH /cryptprotectdata /input:string <br/>
NTHASH /getlsasecret /input:secret <br/>
NTHASH /dpapimk <br/>
NTHASH /cryptunprotectdata /binary:filename <br/>
NTHASH /cryptunprotectdata /input:string <br/>
NTHASH /cryptprotectdata /input:string <br/>
NTHASH /decodeblob /binary:filename [/input:hexabytes] <br/>
NTHASH /decodemk /binary:filename [/input:hexabytes] <br/>
NTHASH /gethash /mode:hashid /input:hexabytes <br/>
NTHASH /gethmac /mode:hashid /input:hexabytes /key:hexabytes <br/>
NTHASH /getcipher /mode:cipherid /input:hexabytes /key:hexabytes <br/>
NTHASH /getlsasecret /input:secret <br/>
NTHASH /dpapi_system <br/>
NTHASH /runasuser /user:username /password:password [/binary: x:\folder\bin.exe] <br/>
NTHASH /runastoken /pid:12345 [/binary: x:\folder\bin.exe] <br/>
NTHASH /runaschild /pid:12345 [/binary: x:\folder\bin.exe] <br/>
NTHASH /runas [/binary: x:\folder\bin.exe] <br/>
NTHASH /runts /user:session_id [/binary: x:\folder\bin.exe] <br/>
NTHASH /enumpriv <br/>
NTHASH /enumproc <br/>
NTHASH /dumpproc /pid:12345 <br/>
NTHASH /runwmi /binary: x:\folder\bin.exe [/server:hostname] <br/>
NTHASH /context <br/>
NTHASH /a_command /verbose <br/>
NTHASH /a_command /system <br/>

<br/>

Commands are commented with more details <a href="https://erwan2212.github.io/NTHASH-FPC/syntax.html" target="_blank">here</A>.

<br/>

todo/news: <br/>
-decrypt sam hashes online (rather than patching lsass) and offline : done in v1.1 <br/>
-deal with new AES cipher used in latest win10 1607 : done in 1.2 <br/>
-enum Lsasrv.dll!LogonSessionList: done in 1.3 <br/>
-enum Wdigest.dll!l_LogSessList: done in 1.3 <br/>
-decrypt dpapi encrypted vault and/or credentials : done in 1.4 <br/>
-patch LogonSessionList and perform pth: done in 1.4 <br/>
-decrypt chrome and firefox passwords: done in 1.4 <br/>
-decrypt firefox and chrome passwords/cookies : done in 1.5 </br>
-dpapimk command to dump all masterkeys : done in 1.6 </br>
-getlsassecret using LsaRetrievePrivateData: done in 1.6</br>
-todo : work out offline decryption of lsasecrets as well as currval and oldval </br>
-todo : work out LsaICryptUnprotectData thru dll injection </br>
-todo : work out masterkey decryption based on sha1 user password: done in 1.7 </br>
-todo : work out credential blob decryption based on decrypted masterkey: done in 1.7 </br>
