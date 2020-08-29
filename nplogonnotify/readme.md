In previous articles (http://labalec.fr/erwan/?cat=118), we have seen that hashed passwords are as good as clear text passwords.

Thus, sometimes, it is nice to retrieve passwords at once in clear text.
Under windows, you can register a network provider which will be called every time a user logs on.
And the beauty of it is that the credential manager will pass on the username and password in clear text.
Of course, you need to be a local admin to do so : we are not talking escalating privileges here but pivoting/lateral movement.

You need to implement 2 functions in your dll, nicely documented by Microsoft (https://docs.microsoft.com/en-us/windows/win32/api/npapi/nf-npapi-nplogonnotify).

Once done, you can do pretty much what you want from within that function.

I am providing an example here (source code and binary) which will log to a text file the username/password.
setup.cmd will register the dll for you : no reboot needed – at next logon, username/password will be written to c:\nplogon.txt.

This was greatly inspired by this post : https://twitter.com/0gtweet/status/1282962201943343105 .
