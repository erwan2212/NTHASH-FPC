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
NTHASH /getsyskey <br/>
NTHASH /runasuser /user:username /password:password [/binary: x:\folder\bin.exe] <br/>
NTHASH /runastoken /pid:12345 [/binary: x:\folder\bin.exe] <br/>
NTHASH /runaschild /pid:12345 [/binary: x:\folder\bin.exe] <br/>
NTHASH /enumpriv <br/>
NTHASH /enumproc <br/>
NTHASH /enummod /pid:12345 <br/>
NTHASH /dumpprocess /pid:12345 <br/>
NTHASH /dumpprocess:pid <br/>
NTHASH /a_command /verbose <br/>

<b>changentlm</b>, using a legacy api, may not work if your ntlm hashes are encrypted with AES (i.e starting with win10 1607. <br/>

<b>setntlm</b> on the other hand should always work and allow one to bypass password policy.  <br/>

<b>dumpsam</b> will temporarily patch a module in lsass to be able to dump your SAM ntlm hashes (need to cover/test as many windows version as possible). <br/>

todo:
-decrypt sam hashes online (rather than patching lsass) and offline
-enum logondata
-patch logondata (and perform pth)
