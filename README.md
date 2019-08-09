# NTHASH-FPC <br/>
A tribute to Mimikatz... <br/>
Command line as below: <br/>
NTHASH /setntlm [/server:hostname] /user:username /newhash:xxx <br/>
NTHASH /changentlm [/server:hostname] /user:username /oldpwd:xxx /newpwd:xxx <br/>
NTHASH /changentlm [/server:hostname] /user:username /oldhash:xxx /newpwd:xxx <br/>
NTHASH /changentlm [/server:hostname] /user:username /oldpwd:xxx /newhash:xxx <br/>
NTHASH /changentlm [/server:hostname] /user:username /oldhash:xxx /newhash:xxx <br/>
NTHASH /gethash:password <br/>
NTHASH /getsid /user:username [/server:hostname] <br/>
NTHASH /getusers [/server:hostname] <br/>
NTHASH /getdomains [/server:hostname] <br/>
NTHASH /dumpsam <br/>
NTHASH /dumpprocess:pid <br/>
NTHASH /a_command /verbose <br/>

changentlm, using a legacy api, may not work if your ntlm hashes are encrypted with AES (i.e starting with win10 1607. <br/>
setntlm on the other hand should always work.  <br/>
dumpsam will temporarily patch a module in lsass to be able to dump your SAM ntlm hashes (need to cover/test as many windows version as possible). <br/>