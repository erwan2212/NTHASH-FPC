# NTHASH-FPC <br/>
A tribute to Mimikatz... <br/>
Command line as below: <br/>
NTHASH /setntlm [/server:hostname] /user:username /newhash:xxx
NTHASH /setntlm [/server:hostname] /user:username /newpwd:xxx
NTHASH /changentlm [/server:hostname] /user:username /oldpwd:xxx /newpwd:xxx
NTHASH /changentlm [/server:hostname] /user:username /oldhash:xxx /newpwd:xxx
NTHASH /changentlm [/server:hostname] /user:username /oldpwd:xxx /newhash:xxx
NTHASH /changentlm [/server:hostname] /user:username /oldhash:xxx /newhash:xxx
NTHASH /gethash /password:password
NTHASH /getsid /user:username [/server:hostname]
NTHASH /getusers [/server:hostname]
NTHASH /getdomains [/server:hostname]
NTHASH /dumpsam
NTHASH /runas /user:username /password:password
NTHASH /dumpprocess:pid
NTHASH /a_command /verbose

changentlm, using a legacy api, may not work if your ntlm hashes are encrypted with AES (i.e starting with win10 1607. <br/>

setntlm on the other hand should always work and allow one to bypass password policy.  <br/>

dumpsam will temporarily patch a module in lsass to be able to dump your SAM ntlm hashes (need to cover/test as many windows version as possible). <br/>

todo:
-decrypt sam hashes online (rather than patching lsass) and offline
-enum logondata
-patch logondata (and perform pth)