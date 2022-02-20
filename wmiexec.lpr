{$mode delphi}{$H+}
program wmiexec;

uses windows,sysutils,uwmi,activex;



procedure log(msg:string;mode:byte);
begin
  writeln(msg);
end;

procedure main;
var
  p:dword;
  server,binary,user,password,pid,input:string;
  _long:longint;
  label fin;
begin

    //*******************************
    p:=pos('/server:',cmdline);
    if p>0 then
         begin
         server:=copy(cmdline,p,255);
         server:=stringreplace(server,'/server:','',[rfReplaceAll, rfIgnoreCase]);
         delete(server,pos(' ',server),255);
         end;
    p:=pos('/binary:',cmdline);
    if p>0 then
         begin
         binary:=copy(cmdline,p,1024);
         binary:=stringreplace(binary,'/binary:','',[rfReplaceAll, rfIgnoreCase]);
         delete(binary,pos('/',binary),1024);
         binary:=trim(binary);
         end;
    p:=pos('/user:',cmdline);
        if p>0 then
             begin
             user:=copy(cmdline,p,255);
             user:=stringreplace(user,'/user:','',[rfReplaceAll, rfIgnoreCase]);
             delete(user,pos(' ',user),255);
             end;
    p:=pos('/password:',cmdline);
    if p>0 then
         begin
         password:=copy(cmdline,p,512);
         password:=stringreplace(password,'/password:','',[rfReplaceAll, rfIgnoreCase]);
         delete(password,pos(' ',password),512);
         end;
    p:=pos('/pid:',cmdline);
    if p>0 then
         begin
         pid:=copy(cmdline,p,255);
         pid:=stringreplace(pid,'/pid:','',[rfReplaceAll, rfIgnoreCase]);
         delete(pid,pos(' ',pid),255);
         end;
    p:=pos('/input:',cmdline);
    if p>0 then
         begin
         input:=copy(cmdline,p,2048);
         input:=stringreplace(input,'/input:','',[rfReplaceAll, rfIgnoreCase]);
         delete(input,pos(' /',input),2048);
         input:=trim(input);
         end;
    //*******************************

    p:=pos('/tasklist',cmdline); //can be done with wmic
    if p>0 then
       begin
       uwmi._EnumProc (server,user,password);
       goto fin;
       end;

    //eg shutdown -r -f -t 0
    //eg cmd %2fC echo toto %3e c:\temp\toto.txt
    p:=pos('/taskrun',cmdline); //can be done with wmic but escaping chars is a PITA
          if p>0 then
             begin
             if binary='' then exit;
             binary:=StringReplace (binary,'%2f','/',[rfReplaceAll,rfIgnoreCase]);
             binary:=StringReplace (binary,'%3e','>',[rfReplaceAll,rfIgnoreCase]);
             uwmi._Create (server,binary,user,password);
             goto fin;
             end;

    p:=pos('/taskkill',cmdline);  //can be done with wmic
            if p>0 then
               begin
               if pid='' then exit;
               if not TryStrToInt (pid,_long ) then begin log('invalid pid',1);exit;end;
               uwmi._Killproc  (server,user,password,strtoint(pid));
               goto fin;
               end;

    p:=pos('/dir',cmdline);  //can be done with wmic
                if p>0 then
                   begin
                   //if input='' then exit;
                   if input='' then input:='c:\';
                   uwmi._ListFolder(server,user,password,input );
                   goto fin;
                   end;

    p:=pos('/reboot',cmdline);  //can be done with wmic
                         if p>0 then
                         begin
                         if input='' then input:='c:\temp\file.tmp';
                         uwmi._reboot(server,user,password);
                         goto fin;
                         end;
    p:=pos('/copy',cmdline);  //can be done with wmic
             if p>0 then
             begin
             if input='' then input:='c:\temp\file.tmp';
             uwmi._CopyFile(server,user,password,binary,input) ;
             goto fin;
             end;

   fin:
   //game over
end;

begin
   writeln('wmiexec 1.0 - erwan2212@gmail.com');
   if paramcount=0 then
   begin
   writeln ('wmiexec /tasklist [/server:xxx] [/username:xxx] [/password:xxx]');
   writeln ('wmiexec /taskrun [/server:xxx] [/username:xxx] [/password:xxx] [/binary:command]');
   writeln ('wmiexec /taskkill [/server:xxx] [/username:xxx] [/password:xxx] /pid:1234]');
   writeln ('wmiexec /dir [/server:xxx] [/username:xxx] [/password:xxx] [/input:path]');
   writeln ('wmiexec /reboot [/server:xxx] [/username:xxx] [/password:xxx]');
   writeln (' ');
   writeln ('examples:');
   writeln ('wmiexec /taskrun /server:myserver /username:myusername /password:mypassword /binary:shutdown -r -f -t 0');
   writeln ('wmiexec /taskrun /server:myserver /username:myusername /password:mypassword /binary:cmd %2fC mkdir c:\temp\myfolder');
   writeln ('wmiexec /taskrun /server:myserver /username:myusername /password:mypassword /binary:cmd %2fC echo hello %3e c:\temp\test.txt');
   exit;
   end;

   try
   CoInitialize(nil);

   try
   main;
   except
     on e:exception do writeln(e.message);
   end;

   finally
   CoUninitialize;
   end;
end.

