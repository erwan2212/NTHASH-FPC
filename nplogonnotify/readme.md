In previous articles (http://labalec.fr/erwan/?cat=118), we have seen that hashed passwords are as good as clear text passwords.

Thus, sometimes, it is nice to retrieve passwords at once in clear text.
Under windows, you can register a network provider which will be called every time a user logs on.
And the beauty of it is that it the credential manager will pass on the username and password in clear text.
Of course, you need to be a local admin to do so : we not talking escalation here but pivoting/lateral movement.

You need to implement 2 functions in your dll, nicely documented by Microsoft (https://docs.microsoft.com/en-us/windows/win32/api/npapi/nf-npapi-nplogonnotify).

Once done, you can do pretty much what you want with the data.

I am providing an example here (source code and binary) which will log to a text file the username/password.
setup.cmd will register the dll for you : no reboot needed – next logon will be logged.
