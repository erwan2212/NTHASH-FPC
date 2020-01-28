# NTHASH-FPC <br/>
A tribute to https://github.com/gentilkiwi/mimikatz... <br/>
And generally speaking a tool to handle hashes and ciphers with a particular focus on windows secrets and lateral movement. <br/>
https://attack.mitre.org/matrices/enterprise/windows/ is definitely worth reading when about lateral movement. <br/>

I wrote a series of articles <a href="http://labalec.fr/erwan/?s=nthash&searchsubmit=">here</a> to illustrate what can be done with nthash.

Syntax/Commands are detailed (as much as possible) <a href="https://erwan2212.github.io/NTHASH-FPC/syntax.html" target="_blank">here</A>.

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
-todo : work out LsaICryptUnprotectData thru dll injection </br>
-work out masterkey decryption based on sha1 user password: done in 1.7 </br>
-work out credential blob decryption based on decrypted masterkey: done in 1.7 </br>
-work out offline decryption of lsasecrets as well: done in 1.7 </br>
-todo : work out credhist decryption </br>
-use ms symbol server to retrieve offset on the fly: done in 1.8 </br>
-introduce pipe - /input will always be fed by the pipe in : done o, 1.8 </br>
