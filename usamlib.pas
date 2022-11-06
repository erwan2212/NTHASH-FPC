unit usamlib;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows,utils,uadvapi32,usid;

type
NTStatus = DWORD;

type tdomainuser=record
     domain_handle:thandle;
     servername:string;
     username:string;
     rid:dword;
end;
pdomainuser=^tdomainuser;

type PWSTR = PWideChar;
type
  _LSA_UNICODE_STRING = record
    Length: USHORT;
    MaximumLength: USHORT;
    {$ifdef CPU64}dummy:dword;{$endif cpu64} //to force/ensure 8 bytes alignement
    Buffer: PWSTR;
  end;
  LSA_UNICODE_STRING=_LSA_UNICODE_STRING;
  PLSA_UNICODE_STRING=  ^_LSA_UNICODE_STRING;

  type _SAMPR_USER_INTERNAL1_INFORMATION =record
   EncryptedNtOwfPassword:tbyte16;
   EncryptedLmOwfPassword:tbyte16;
   NtPasswordPresent:byte;
   LmPasswordPresent:byte;
   PasswordExpired:byte;
   end;
 SAMPR_USER_INTERNAL1_INFORMATION=_SAMPR_USER_INTERNAL1_INFORMATION;
 PSAMPR_USER_INTERNAL1_INFORMATION=^SAMPR_USER_INTERNAL1_INFORMATION;

  type _SAMPR_RID_ENUMERATION =record
     RelativeId:ulong;
     Name:_LSA_UNICODE_STRING;
   end;
   PSAMPR_RID_ENUMERATION=^_SAMPR_RID_ENUMERATION;

//declarations here
//https://github.com/rapid7/meterpreter/blob/master/source/extensions/kiwi/modules/kull_m_samlib.h
//or
//https://doxygen.reactos.org/d2/de6/samlib_8c.html
{
//NTSTATUS NTAPI 	SamConnect (IN OUT PUNICODE_STRING ServerName OPTIONAL, OUT PSAM_HANDLE ServerHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes)
function SamConnect(server:pointer; ServerHandle:phandle;DesiredAccess:dword;reserved:boolean):NTStatus;stdcall;external 'samlib.dll';
function SamConnect2 (serverName:PLSA_UNICODE_STRING;out ServerHandle:handle;DesiredAccess:dword;reserved:boolean):NTStatus;stdcall;external 'samlib.dll' name 'SamConnect';
//NTSTATUS NTAPI 	SamCloseHandle (IN SAM_HANDLE SamHandle)
function SamCloseHandle(SamHandle:thandle):integer;stdcall;external 'samlib.dll';
//NTSTATUS NTAPI 	SamOpenDomain (IN SAM_HANDLE ServerHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT PSAM_HANDLE DomainHandle)
function SamOpenDomain(ServerHandle:thandle;DesiredAccess:dword; DomainId:PSID;DomainHandle:phandle):NTStatus;stdcall;external 'samlib.dll';
//NTSTATUS NTAPI 	SamOpenUser (IN SAM_HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN ULONG UserId, OUT PSAM_HANDLE UserHandle)
function SamOpenUser(DomainHandle:thandle;DesiredAccess:dword;UserId:ulong;UserHandle:phandle):NTStatus;stdcall;external 'samlib.dll';
//NTSTATUS NTAPI 	SamEnumerateDomainsInSamServer (IN SAM_HANDLE ServerHandle, IN OUT PSAM_ENUMERATE_HANDLE EnumerationContext, OUT PVOID *Buffer, IN ULONG PreferedMaximumLength, OUT PULONG CountReturned)                                                                    isNewNTLM:boolean; oldNTLM:array of byte; newNTLM:array of byte):integer;stdcall;external 'samlib.dll';
function SamEnumerateDomainsInSamServer (ServerHandle:thandle; var EnumerationContext:dword; out buffer:PSAMPR_RID_ENUMERATION ;PreferedMaximumLength:ulong;out CountReturned:ulong):NTStatus;stdcall;external 'samlib.dll';

//NTSTATUS NTAPI 	SamLookupDomainInSamServer (IN SAM_HANDLE ServerHandle, IN PUNICODE_STRING Name, OUT PSID *DomainId)
function SamLookupDomainInSamServer (ServerHandle:thandle;Name:PLSA_UNICODE_STRING; OUT DomainId:PSID):NTStatus;stdcall;external 'samlib.dll';

//NTSTATUS NTAPI 	SamEnumerateUsersInDomain (IN SAM_HANDLE DomainHandle, IN OUT PSAM_ENUMERATE_HANDLE EnumerationContext, IN ULONG UserAccountControl, OUT PVOID *Buffer, IN ULONG PreferedMaximumLength, OUT PULONG CountReturned)
function SamEnumerateUsersInDomain(DomainHandle:thandle;var EnumerationContext:dword;UserAccountControl:ulong; OUT Buffer:PSAMPR_RID_ENUMERATION;PreferedMaximumLength:ulong;OUT CountReturned:ulong):NTStatus;stdcall;external 'samlib.dll';

//static extern int SamiChangePasswordUser(IntPtr UserHandle, bool isOldLM, byte[] oldLM, byte[] newLM,
//bool isNewNTLM, byte[] oldNTLM, byte[] newNTLM);
function SamiChangePasswordUser(UserHandle:thandle;
isOldLM:boolean;oldLM:tbyte16; newLM:tbyte16;
isNewNTLM:boolean;oldNTLM:tbyte16;newNTLM:tbyte16):NTStatus;stdcall;external 'samlib.dll';

//NTSTATUS NTAPI 	SamRidToSid (IN SAM_HANDLE ObjectHandle, IN ULONG Rid, OUT PSID *Sid)
function SamRidToSid(UserHandle:thandle;rid:ulong; out Sid:PSID):NTStatus;stdcall;external 'samlib.dll';
//extern NTSTATUS WINAPI SamFreeMemory(IN PVOID Buffer);
function SamFreeMemory(buffer:pointer):NTStatus;stdcall;external 'samlib.dll';

//NTSTATUS NTAPI 	SamQueryInformationUser (IN SAM_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, OUT PVOID *Buffer)
function SamQueryInformationUser (UserHandle:thandle; UserInformationClass:dword; out Buffer:pointer):NTStatus;stdcall;external 'samlib.dll';

//NTSTATUS NTAPI 	SamSetInformationUser (IN SAM_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, IN PVOID Buffer)
function SamSetInformationUser (UserHandle:thandle; UserInformationClass:dword; Buffer:PSAMPR_USER_INTERNAL1_INFORMATION):NTStatus;stdcall;external 'samlib.dll';
}
//*************************************************************************

procedure CreateFromStr (var value:_LSA_UNICODE_STRING; st : string);

function QueryDomains(server:pchar;func:pointer =nil):boolean;

function callback_QueryUser(param:pointer=nil):dword;stdcall;
function callback_QuerySID(param:pointer=nil):dword;stdcall;
function QueryUsers(server,_domain:pchar;func:pointer =nil):boolean;

function SetInfoUser(server,user:string;hash:tbyte16):boolean; //aka setntlm

function ChangeNTLM(server:string;user:string;previousntlm,newntlm:tbyte16):boolean;

var
  //NTSTATUS NTAPI 	SamConnect (IN OUT PUNICODE_STRING ServerName OPTIONAL, OUT PSAM_HANDLE ServerHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes)
 SamConnect:function(server:pointer; ServerHandle:phandle;DesiredAccess:dword;reserved:boolean):NTStatus;stdcall;
 SamConnect2:function (serverName:PLSA_UNICODE_STRING;out ServerHandle:handle;DesiredAccess:dword;reserved:boolean):NTStatus;stdcall;
//NTSTATUS NTAPI 	SamCloseHandle (IN SAM_HANDLE SamHandle)
 SamCloseHandle:function(SamHandle:thandle):integer;stdcall;
//NTSTATUS NTAPI 	SamOpenDomain (IN SAM_HANDLE ServerHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT PSAM_HANDLE DomainHandle)
 SamOpenDomain:function(ServerHandle:thandle;DesiredAccess:dword; DomainId:PSID;DomainHandle:phandle):NTStatus;stdcall;
 SamOpenUser:function(DomainHandle:thandle;DesiredAccess:dword;UserId:ulong;UserHandle:phandle):NTStatus;stdcall;
//NTSTATUS NTAPI 	SamEnumerateDomainsInSamServer (IN SAM_HANDLE ServerHandle, IN OUT PSAM_ENUMERATE_HANDLE EnumerationContext, OUT PVOID *Buffer, IN ULONG PreferedMaximumLength, OUT PULONG CountReturned)                                                                    isNewNTLM:boolean; oldNTLM:array of byte; newNTLM:array of byte):integer;stdcall;external 'samlib.dll';
 SamEnumerateDomainsInSamServer:function (ServerHandle:thandle; var EnumerationContext:dword; out buffer:PSAMPR_RID_ENUMERATION ;PreferedMaximumLength:ulong;out CountReturned:ulong):NTStatus;stdcall;

//NTSTATUS NTAPI 	SamLookupDomainInSamServer (IN SAM_HANDLE ServerHandle, IN PUNICODE_STRING Name, OUT PSID *DomainId)
 SamLookupDomainInSamServer:function (ServerHandle:thandle;Name:PLSA_UNICODE_STRING; OUT DomainId:PSID):NTStatus;stdcall;

//NTSTATUS NTAPI 	SamEnumerateUsersInDomain (IN SAM_HANDLE DomainHandle, IN OUT PSAM_ENUMERATE_HANDLE EnumerationContext, IN ULONG UserAccountControl, OUT PVOID *Buffer, IN ULONG PreferedMaximumLength, OUT PULONG CountReturned)
 SamEnumerateUsersInDomain:function(DomainHandle:thandle;var EnumerationContext:dword;UserAccountControl:ulong; OUT Buffer:PSAMPR_RID_ENUMERATION;PreferedMaximumLength:ulong;OUT CountReturned:ulong):NTStatus;stdcall;

//static extern int SamiChangePasswordUser(IntPtr UserHandle, bool isOldLM, byte[] oldLM, byte[] newLM,
//bool isNewNTLM, byte[] oldNTLM, byte[] newNTLM);
 SamiChangePasswordUser:function(UserHandle:thandle;
isOldLM:boolean;oldLM:tbyte16; newLM:tbyte16;
isNewNTLM:boolean;oldNTLM:tbyte16;newNTLM:tbyte16):NTStatus;stdcall;

//NTSTATUS NTAPI 	SamRidToSid (IN SAM_HANDLE ObjectHandle, IN ULONG Rid, OUT PSID *Sid)
 SamRidToSid:function(UserHandle:thandle;rid:ulong; out Sid:PSID):NTStatus;stdcall;
//extern NTSTATUS WINAPI SamFreeMemory(IN PVOID Buffer);
 SamFreeMemory:function(buffer:pointer):NTStatus;stdcall;

//NTSTATUS NTAPI 	SamQueryInformationUser (IN SAM_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, OUT PVOID *Buffer)
 SamQueryInformationUser:function (UserHandle:thandle; UserInformationClass:dword; out Buffer:pointer):NTStatus;stdcall;

//NTSTATUS NTAPI 	SamSetInformationUser (IN SAM_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, IN PVOID Buffer)
 SamSetInformationUser:function (UserHandle:thandle; UserInformationClass:dword; Buffer:PSAMPR_USER_INTERNAL1_INFORMATION):NTStatus;stdcall;


implementation

const
  SAM_SERVER_CONNECT=$00000001;
  SAM_SERVER_ENUMERATE_DOMAINS=$00000010;
  SAM_SERVER_LOOKUP_DOMAIN=$00000020;
  SAM_SERVER_ALL_ACCESS=$000F003F;
  SAM_SERVER_READ=$00020010;
  SAM_SERVER_WRITE=$0002000E;
  SAM_SERVER_EXECUTE=$00020021;
  SAM_SERVER_SHUTDOWN=$00000002;


procedure CreateFromStr (var value:_LSA_UNICODE_STRING; st : string);
var
  len : Integer;
  wst : WideString;
begin
  len := Length (st);
  Value.Length := len * sizeof (WideChar);
  Value.MaximumLength := (len + 1) * sizeof (WideChar);
  GetMem (Value.buffer, sizeof (WideChar) * (len + 1));
  wst := st;
  lstrcpyw (Value.buffer, PWideChar (wst))
end;

function QueryDomains(server:pchar;func:pointer =nil):boolean;
type fn=function(param:pointer):dword;stdcall;
var
ustr_server : _LSA_UNICODE_STRING;
samhandle_:thandle=thandle(-1);
domainhandle_:thandle=thandle(-1);
UserHandle_:thandle=thandle(-1);
status:ntstatus;
PDomainSID,PUSERSID:PSID;
stringsid:pchar;
domain:string;
rid,i:dword;
ptr:pointer;
domainuser:tdomainuser;
//
buffer:PSAMPR_RID_ENUMERATION=nil;
count:ulong;
//EnumHandle_:thandle=thandle(-1);
EnumHandle_:dword=0;
//unicode_domain:_LSA_UNICODE_STRING;
begin
result:=false;
//
if server<>''  then
   begin
   writeln('server:'+server);
   CreateFromStr (ustr_server,server);
   Status := SamConnect2(@ustr_server, SamHandle_, MAXIMUM_ALLOWED, false); //SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN
   end
else
Status := SamConnect(nil, @samhandle_ , MAXIMUM_ALLOWED {0x000F003F}, false);
if Status <> 0 then
   begin log('SamConnect failed:'+inttohex(status,8),status);exit;end
   else log ('SamConnect ok',status);
//
//0x00000105 MORE_ENTRIES
//not necessary : could go straight to 'Builtin' or even 'S-1-5-32' or to computername ?

status:=SamEnumerateDomainsInSamServer (samhandle_ ,EnumHandle_ ,buffer,100,count);
if (Status <> 0) and (status<>$00000105) then
   begin log('SamEnumerateDomainsInSamServer failed:'+inttohex(status,8));;end
   else log ('SamEnumerateDomainsInSamServer ok');
if (status=0) or (status=$00000105) then
   begin
   log('count='+inttostr(count),0);
   ptr:=buffer;
   for i:=1 to count do
       begin
       log(strpas(PSAMPR_RID_ENUMERATION(ptr).Name.Buffer),1);
       status := SamLookupDomainInSamServer(samhandle_, @PSAMPR_RID_ENUMERATION(ptr).Name, PDomainSID);
       if status=0 then
          begin
          if ConvertSidToStringSidA (PDomainSID ,stringsid)
             then log('sid:'+strpas(stringsid),1);
          end else log('SamLookupDomainInSamServer failed:'+inttostr(status));
       //if func<>nil then fn(func)(@param );
       inc(ptr,sizeof(_SAMPR_RID_ENUMERATION));
       end;
   //log(strpas(buffer.Name.Buffer));
   status:=0;
   SamFreeMemory(buffer);
   end;
//
//ReallocMem (ustr_server.Buffer, 0);
if UserHandle_ <>thandle(-1) then status:=SamCloseHandle(UserHandle_);
if Status <> 0 then
   begin log('SamCloseHandle failed:'+inttostr(status),status);;end
   else log ('SamCloseHandle ok',status);

if DomainHandle_<>thandle(-1) then status:=SamCloseHandle(DomainHandle_);
if Status <> 0 then
   begin log('SamCloseHandle failed:'+inttostr(status),status);;end
   else log('SamCloseHandle ok',status);

if samhandle_<>thandle(-1) then status:=SamCloseHandle(samhandle_ );
if Status <> 0 then
     begin log('SamCloseHandle failed:'+inttostr(status),status);;end
     else log('SamCloseHandle ok',status);
end;

//this function can only called if lsass is "patched"
//SamQueryInformationUser + UserInternal1Information=0x12
//or else you get //c0000003 (STATUS_INVALID_INFO_CLASS)
function QueryInfoUser(server,user:string):boolean;
var
ustr_server : _LSA_UNICODE_STRING;
samhandle_:thandle=thandle(-1);
domainhandle_:thandle=thandle(-1);
UserHandle_:thandle=thandle(-1);
status:ntstatus;
PDomainSID,PUSERSID:PSID;
stringsid:pchar;
domain:string;
rid:dword;
userinfo:PSAMPR_USER_INTERNAL1_INFORMATION;
begin
result:=false;
//
GetAccountSid2(server,widestring(user),pusersid);
if (pusersid<>nil) and (ConvertSidToStringSidA(pusersid,stringsid)) then
   begin
   log('user:'+StringSid,1 );
   SplitUserSID (StringSid ,domain,rid);
   localfree(cardinal(stringsid));
   end
   else
   begin
     log('something wrong with user account...',1);
     exit;
   end;
//
if server<>''  then
   begin
   CreateFromStr (ustr_server,server);
   Status := SamConnect2(@ustr_server, SamHandle_, MAXIMUM_ALLOWED, false);
   end
else
Status := SamConnect(nil, @samhandle_ , MAXIMUM_ALLOWED {0x000F003F}, false);
if Status <> 0 then
   begin log('SamConnect failed:'+inttohex(status,8));;end
   else log ('SamConnect ok');
//
if  ConvertStringSidToSidA(pchar(domain),PDOMAINSID )=false
   then log('ConvertStringSidToSid failed' )
   else log ('ConvertStringSidToSid ok');
//
Status := SamOpenDomain(samhandle_ , {$705}MAXIMUM_ALLOWED, PDomainSID, @DomainHandle_);
if Status <> 0 then
   begin log('SamOpenDomain failed:'+inttohex(status,8));;end
   else log ('SamOpenDomain ok');
//
Status := SamOpenUser(DomainHandle_ , MAXIMUM_ALLOWED , rid , @UserHandle_);
if Status <> 0 then
   begin log('SamOpenUser failed:'+inttohex(status,8));;end
   else log('SamOpenUser ok');
//
status:=SamQueryInformationUser(UserHandle_ ,$12,userinfo);
if Status <> 0 then
   begin log('SamQueryInformationUser failed:'+inttohex(status,8));;end
   else log ('SamQueryInformationUser ok');
if status=0 then
   begin
   if (userinfo^.LmPasswordPresent=1 ) then log('LmPassword:'+ByteToHexaString (tbyte16(userinfo^.EncryptedLmOwfPassword)  ),1);
   if (userinfo^.NtPasswordPresent=1) then log('NTLmPassword:'+ByteToHexaString (tbyte16(userinfo^.EncryptedNtOwfPassword)),1);
   result:=true;
   SamFreeMemory(userinfo);
   end;
//
//ReallocMem (ustr_server.Buffer, 0);
if UserHandle_ <>thandle(-1) then status:=SamCloseHandle(UserHandle_);
if Status <> 0 then
   begin log('SamCloseHandle failed:'+inttostr(status));exit;end
   else log ('SamCloseHandle ok');

if DomainHandle_<>thandle(-1) then status:=SamCloseHandle(DomainHandle_);
if Status <> 0 then
   begin log('SamCloseHandle failed:'+inttostr(status));exit;end
   else log('SamCloseHandle ok');

if samhandle_<>thandle(-1) then status:=SamCloseHandle(samhandle_ );
if Status <> 0 then
     begin log('SamCloseHandle failed:'+inttostr(status));exit;end
     else log('SamCloseHandle ok');
end;

function callback_QueryUser(param:pointer=nil):dword;stdcall;
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
     if (userinfo^.LmPasswordPresent=1 ) then lm:=ByteToHexaString (tbyte16(userinfo^.EncryptedLmOwfPassword)  );
     if (userinfo^.NtPasswordPresent=1) then ntlm:=ByteToHexaString (tbyte16(userinfo^.EncryptedNtOwfPassword )  );
     log(pdomainuser (param).username +':'+inttostr(pdomainuser (param).rid) +':'+lm+':'+ntlm,1);
     result:=1;
     SamFreeMemory(userinfo);
     end;
     //
     end;
end;

function callback_QuerySID(param:pointer=nil):dword;stdcall;
var
  mypsid:psid;
  mystringsid:pchar;
begin
result:=0;
if param<>nil then
     begin
     GetAccountSid2(widestring(pdomainuser (param).servername),widestring(pdomainuser (param).username),mypsid);
     ConvertSidToStringSidA (mypsid,mystringsid);
     log(pdomainuser (param).username+':'+mystringsid,1);
     //
     end;
end;


function QueryUsers(server,_domain:pchar;func:pointer =nil):boolean;
var
ustr_server : _LSA_UNICODE_STRING;
samhandle_:thandle=thandle(-1);
domainhandle_:thandle=thandle(-1);
UserHandle_:thandle=thandle(-1);
status:ntstatus;
PDomainSID,PUSERSID:PSID;
stringsid:pchar;
domain:string;
rid,i:dword;
ptr:pointer;
domainuser:tdomainuser;
//
buffer:PSAMPR_RID_ENUMERATION=nil;
count:ulong;
//EnumHandle_:thandle=thandle(-1);
EnumHandle_:dword=0;
unicode_domain:_LSA_UNICODE_STRING;
begin
result:=false;
//
if server<>''  then
   begin
   writeln('server:'+server);
   CreateFromStr (ustr_server,server);
   Status := SamConnect2(@ustr_server, SamHandle_, MAXIMUM_ALLOWED, false); //SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS | SAM_SERVER_LOOKUP_DOMAIN
   end
else
Status := SamConnect(nil, @samhandle_ , MAXIMUM_ALLOWED {0x000F003F}, false);
if Status <> 0 then
   begin log('SamConnect failed:'+inttohex(status,8),status);exit;end
   else log ('SamConnect ok',status);
//

//
if status=0 then
begin
//could go straight to 'Builtin' or even 'S-1-5-32' or to computername ?
//if a domain is ever passed as a parameter
if _domain<>'' then
   begin
   log('domain:'+_domain,1);
        if  ConvertStringSidToSidA(_domain,PDOMAINSID )=false
        then log('ConvertStringSidToSid domain failed',1 )
        else log ('ConvertStringSidToSid ok',0);
   end;

//Builtin
//CreateFromStr (unicode_domain,'Builtin');
//or local computername
if _domain='' then
   begin
   count:=255;
   getmem(_domain,count);
   if GetComputerName (_domain,count) then log('domain:'+strpas(_domain),1 );
   CreateFromStr (unicode_domain ,strpas(_domain));

   status:=SamLookupDomainInSamServer(samhandle_ , @unicode_domain {@buffer.Name} , PDomainSID );
   if Status <> 0 then
      begin log('SamLookupDomainInSamServer failed:'+inttohex(status,8),1);exit;end
      else log ('SamLookupDomainInSamServer ok',status);
   ReallocMem (unicode_domain.Buffer, 0);
   //0xC00000DF STATUS_NO_SUCH_DOMAIN
end;
{
if status=0 then
   if ConvertSidToStringSid (PDomainSID ,stringsid) then log(stringsid ) ;
}

end;
//
//ConvertStringSidToSid (pchar('S-1-5-21-1453083631-684653683-723175971'),PDOMAINSID);
Status := SamOpenDomain(samhandle_ , {$705}MAXIMUM_ALLOWED, PDomainSID, @DomainHandle_);
if Status <> 0 then
   begin log('SamOpenDomain failed:'+inttohex(status,8),status);;end
   else log ('SamOpenDomain ok',status);

//
EnumHandle_:=0;
if buffer<>nil then SamFreeMemory(buffer);
status:=SamEnumerateUsersInDomain (domainhandle_ ,EnumHandle_ ,0,buffer,1000,count);
if (Status <> 0) and (status<>$00000105) then
   begin log('SamEnumerateUsersInDomain failed:'+inttohex(status,8),status);;end
   else log ('SamEnumerateUsersInDomain ok',status);
   if (status=0) or (status=$00000105) then
      begin
      result:=true;
      log('count='+inttostr(count),0);

      ptr:=buffer;
      for i:=1 to count do
          begin
          if func=nil
             then log(strpas(PSAMPR_RID_ENUMERATION(ptr).Name.Buffer)+':'+inttostr(PSAMPR_RID_ENUMERATION(ptr).RelativeId ),1);
          if func<>nil then
             begin
             domainuser.rid :=PSAMPR_RID_ENUMERATION(ptr).RelativeId ;
             domainuser.domain_handle :=domainhandle_;
             domainuser.servername:=strpas(server);
             domainuser.username :=strpas(PSAMPR_RID_ENUMERATION(ptr).Name.Buffer);
             fn(func)(@domainuser );
             end;
          inc(ptr,sizeof(_SAMPR_RID_ENUMERATION));
          end;
      //log(strpas(buffer.Name.Buffer));
      SamFreeMemory(buffer)
      end;
//
//if buffer<>nil then ReallocMem (ustr_server.Buffer, 0);
if UserHandle_ <>thandle(-1) then status:=SamCloseHandle(UserHandle_);
if Status <> 0 then
   begin log('SamCloseHandle failed:'+inttostr(status),status);exit;end
   else log ('SamCloseHandle ok',status);

if DomainHandle_<>thandle(-1) then status:=SamCloseHandle(DomainHandle_);
if Status <> 0 then
   begin log('SamCloseHandle failed:'+inttostr(status),status);exit;end
   else log('SamCloseHandle ok',status);

if samhandle_<>thandle(-1) then status:=SamCloseHandle(samhandle_ );
if Status <> 0 then
     begin log('SamCloseHandle failed:'+inttostr(status),status);exit;end
     else log('SamCloseHandle ok',status);
end;

function SetInfoUser(server,user:string;hash:tbyte16):boolean;
var
ustr_server : _LSA_UNICODE_STRING;
samhandle_:thandle=thandle(-1);
domainhandle_:thandle=thandle(-1);
UserHandle_:thandle=thandle(-1);
status:ntstatus;
PDomainSID,PUSERSID:PSID;
stringsid:pchar;
domain:string;
rid:dword;
userinfo:PSAMPR_USER_INTERNAL1_INFORMATION;
begin
result:=false;
if user='' then exit;
//
GetAccountSid2(server,widestring(user),pusersid);
if (pusersid<>nil) and (ConvertSidToStringSidA(pusersid,stringsid)) then
   begin
   log('user:'+StringSid,1 );
   SplitUserSID (StringSid ,domain,rid);
   localfree(cardinal(stringsid));
   end
   else
   begin
     log('something wrong with user account...',1);
     exit;
   end;
//
if server<>''  then
   begin
   CreateFromStr (ustr_server,server);
   Status := SamConnect2(@ustr_server, SamHandle_, MAXIMUM_ALLOWED, false);
   end
else
Status := SamConnect(nil, @samhandle_ , MAXIMUM_ALLOWED {0x000F003F}, false);
if Status <> 0 then
   begin log('SamConnect failed:'+inttohex(status,8),status);;end
   else log ('SamConnect ok',status);
//
if  ConvertStringSidToSidA(pchar(domain),PDOMAINSID )=false
   then log('ConvertStringSidToSid failed',status )
   else log ('ConvertStringSidToSid ok',status);
//
Status := SamOpenDomain(samhandle_ , {$705}MAXIMUM_ALLOWED, PDomainSID, @DomainHandle_);
if Status <> 0 then
   begin log('SamOpenDomain failed:'+inttohex(status,8));;end
   else log ('SamOpenDomain ok');
//
Status := SamOpenUser(DomainHandle_ , MAXIMUM_ALLOWED , rid , @UserHandle_);
if Status <> 0 then
   begin log('SamOpenUser failed:'+inttohex(status,8),status);;end
   else log('SamOpenUser ok',status);
//
userinfo:=allocmem(sizeof(_SAMPR_USER_INTERNAL1_INFORMATION));
userinfo^.LmPasswordPresent :=0;
userinfo^.NtPasswordPresent :=1;
userinfo^.PasswordExpired :=0;
userinfo^.EncryptedNtOwfPassword :=tbyte16(hash);

status:=SamSetInformationUser(UserHandle_ ,$12,userinfo);
if Status <> 0 then
   begin log('SamSetInformationUser failed:'+inttohex(status,8),status);;end
   else log('SamSetInformationUser ok',status);
if status=0 then
   begin
   result:=true;
   end;
//
//ReallocMem (ustr_server.Buffer, 0);
if UserHandle_ <>thandle(-1) then status:=SamCloseHandle(UserHandle_);
if Status <> 0 then
   begin log('SamCloseHandle failed:'+inttostr(status),status);;end
   else log ('SamCloseHandle ok',status);

if DomainHandle_<>thandle(-1) then status:=SamCloseHandle(DomainHandle_);
if Status <> 0 then
   begin log('SamCloseHandle failed:'+inttostr(status),status);;end
   else log('SamCloseHandle ok',status);

if samhandle_<>thandle(-1) then status:=SamCloseHandle(samhandle_ );
if Status <> 0 then
     begin log('SamCloseHandle failed:'+inttostr(status),status);;end
     else log('SamCloseHandle ok',status);
end;

function ChangeNTLM(server:string;user:string;previousntlm,newntlm:tbyte16):boolean;
const MAXIMUM_ALLOWED = $02000000;
var
  i:byte;
Status:dword= 0;
ustr_server : _LSA_UNICODE_STRING;
DomainSID_,UserSID_:SID;
rid:dword;
oldlm,newlm:tbyte16;

domain:string;
elements: TStrings;

//Psamhandle:pointer=nil;

samhandle_:thandle=thandle(-1);
domainhandle_:thandle=thandle(-1);
UserHandle_:thandle=thandle(-1);

//enumcontext:thandle=thandle(-1);
//buf:_SAMPR_RID_ENUMERATION;
//CountReturned:ulong=0;

//
  //sidtext: array[0..260] of Char;
  //len:DWORD;
  StringSid: pchar;
  PDOMAINSID:PSID=nil;
  PUSERSID:PSID;
begin
  log('***************************************');
//lets go for the builtin domain
{
DomainSID_.Revision  := SID_REVISION;
DomainSID_.SubAuthorityCount :=1;
DomainSID_.IdentifierAuthority :=SECURITY_NT_AUTHORITY;
DomainSID_.SubAuthority[0] :=SECURITY_BUILTIN_DOMAIN_RID;
}

//lets go for the local DB
//domain sid=user sid minus RID
//lets get PUSERSID
GetAccountSid2(server,widestring(user),pusersid);
if (pusersid<>nil) and (ConvertSidToStringSidA(pusersid,stringsid)) then
   begin
   log('user:'+StringSid );
   //
   SplitUserSID (StringSid ,domain,rid);
   {
   elements := TStringList.Create;
   ExtractStrings(['-'],[],StringSid,elements,false);
   for i:=0 to elements.Count-2 do domain:=domain+'-'+elements[i];
   delete(domain,1,1);
   log('domain:'+domain);
   rid:=strtoint(elements[elements.count-1]);
   log('rid:'+inttostr(rid));
   }
   localfree(cardinal(stringsid));
   //freemem(pusersid);
   end
   else
   begin
     log('something wrong with user account...');
     exit;
   end;

//lets get PDOMAINSID
if  ConvertStringSidToSidA(pchar(domain),PDOMAINSID ) then
    begin
    //log ('ConvertStringSidToSidA:OK');
    if ConvertSidToStringSidA (PDOMAINSID ,StringSid) then
       begin
       //log ('ConvertSidToStringSid:OK');
       //log ('domain:'+StringSid );
       if StringSid <>domain then log('domain mismatch...');
       localfree(cardinal(StringSid) );
       end;
    end
    else
    begin
     //log('ConvertStringSidToSid: NOT OK');
     log('something wrong with the domain...');
     exit;
    end;
    log('***************************************');

//if GetDomainSid (DomainSID_ ) then form1.Memo1.Lines.Add ('GetDomainSid OK') ;

try
if server<>''  then
   begin
   CreateFromStr (ustr_server,server);
   Status := SamConnect2(@ustr_server, SamHandle_, MAXIMUM_ALLOWED, false);
   end
else
Status := SamConnect(nil, @samhandle_ , MAXIMUM_ALLOWED {0x000F003F}, false);
except
  on e:exception do log(e.message );
end;

if Status <> 0 then
   begin log('SamConnect failed:'+inttohex(status,8));;end
   else log ('SamConnect ok');
//showmessage(inttostr(samhandle_ ));
log('***************************************');

if (status=0) and (samhandle_ <>thandle(-1)) then
begin
//https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_lsadump.c
//fillchar(sid_,sizeof(tsid),0);
//sid_:=GetCurrentUserSid ;
//local admin : S-1-5-21-1453083631-684653683-723175971-500

{
//lets check if domain sid is valid
//memory leak below?
getmem(StringSid ,261);
if ConvertSidToStringSid(PDomainSID ,stringsid) then
   begin
   form1.Memo1.Lines.Add ('ConvertSidToStringSid:OK');
   Form1.Memo1.Lines.Add (StringSid );
   end
   else form1.Memo1.Lines.Add ('ConvertSidToStringSid:NOT OK');
if ConvertStringSidToSid(StringSid ,PDOMAINSID)
   then form1.memo1.lines.add('ConvertStringSidToSid: OK');
}
//
//try
//showmessage('SamOpenDomain');
Status := SamOpenDomain(samhandle_ , {$705}MAXIMUM_ALLOWED, PDomainSID, @DomainHandle_);
//except
//  on e:exception do showmessage(e.message );
//end;

//The System can not log you on (C00000DF)
if Status <> 0 then
   begin log('SamOpenDomain failed:'+inttohex(status,8));;end
   else log ('SamOpenDomain ok');
end;
log('***************************************');

if (status=0) and (DomainHandle_<>thandle(-1)) then
begin
//int rid = GetRidFromSid(account);
//Console.WriteLine("rid is " + rid);
//rid = 58599

//rid:=1003; //one local user RID
//rid:=500; //local builtin administrator
//try
//showmessage('SamOpenUser');
Status := SamOpenUser(DomainHandle_ , MAXIMUM_ALLOWED , rid , @UserHandle_);
//except
//  on e:exception do showmessage(e.message );
//end;
//C0000064, user name does not exist.
if Status <> 0 then
   begin log('SamOpenUser failed:'+inttohex(status,8));;end
   else log('SamOpenUser ok');
end;
log('***************************************');

//lets ensure userhandle is working
//side note : enabling the below optional check seems to get rid of some mem leaks?
//if (status=0) and (UserHandle_ <>thandle(-1)) then
if 1=2 then
begin
status:=SamRidToSid(UserHandle_ ,rid,PUSERSID);
if Status <> 0 then
   begin log('SamRidToSid failed:'+inttohex(status,8));;end
   else log('SamRidToSid:OK '+inttostr(rid));
   //memory leak below??
   //if status=0 then
   if 1=2 then
   begin
   //getmem(StringSid ,261);
   if ConvertSidToStringSidA(PUSERSID ,stringsid) then
      begin
      //showmessage(inttostr(PUSERSID^.Revision)) ;
      //showmessage(stringsid);
      log ('ConvertSidToStringSid:OK');
      log (strpas(StringSid) );
      localfree(cardinal(stringsid));
      end
      else log ('ConvertSidToStringSid:NOT OK');
   end;
end;

log('***************************************');
if (status=0) and (UserHandle_ <>thandle(-1)) then
begin

fillchar(oldlm,16,0);
fillchar(newlm,16,0);
//C000006A	STATUS_WRONG_PASSWORD
//C000006B	STATUS_ILL_FORMED_PASSWORD
//C000006C	STATUS_PASSWORD_RESTRICTION

//try
//showmessage('SamiChangePasswordUser');
Status := SamiChangePasswordUser(UserHandle_,
       false, tbyte16(oldLm), tbyte16(newLm),
       true, tbyte16(PreviousNTLM), tbyte16(NewNTLM));
//except
//  on e:exception do showmessage(e.message );
//end;
//showmessage(inttohex(status,8));
if Status <> 0 then
   begin log('SamiChangePasswordUser failed:'+inttohex(status,8));;end
   else log('SamiChangePasswordUser ok');
result:=status=0;
end;
log('***************************************');
//
//ReallocMem (ustr_server.Buffer, 0);
if UserHandle_ <>thandle(-1) then status:=SamCloseHandle(UserHandle_);
if Status <> 0 then
   begin log('SamCloseHandle failed:'+inttostr(status));exit;end
   else log ('SamCloseHandle ok');

if DomainHandle_<>thandle(-1) then status:=SamCloseHandle(DomainHandle_);
if Status <> 0 then
   begin log('SamCloseHandle failed:'+inttostr(status));exit;end
   else log('SamCloseHandle ok');

if samhandle_<>thandle(-1) then status:=SamCloseHandle(samhandle_ );
if Status <> 0 then
     begin log('SamCloseHandle failed:'+inttostr(status));exit;end
     else log('SamCloseHandle ok');
end;

function initAPI:boolean;
  var lib:hmodule=0;
  begin
  //writeln('initapi');
  result:=false;
  try
  //lib:=0;
  if lib>0 then begin {log('lib<>0');} result:=true; exit;end;
      {$IFDEF win64}lib:=loadlibrary('samlib.dll');{$endif}
      {$IFDEF win32}lib:=loadlibrary('samlib.dll');{$endif}
  if lib<=0 then
    begin
    writeln('could not loadlibrary ntdll.dll');
    exit;
    end;
       SamConnect:=getProcAddress(lib,'SamConnect');
       SamConnect2:=getProcAddress(lib,'SamConnect');
       SamCloseHandle:=getProcAddress(lib,'SamCloseHandle');
       SamOpenDomain:=getProcAddress(lib,'SamOpenDomain');
       SamOpenUser:=getProcAddress(lib,'SamOpenUser');
       SamEnumerateDomainsInSamServer:=getProcAddress(lib,'SamEnumerateDomainsInSamServer');
       SamLookupDomainInSamServer:=getProcAddress(lib,'SamLookupDomainInSamServer');
       SamEnumerateUsersInDomain:=getProcAddress(lib,'SamEnumerateUsersInDomain');
       SamiChangePasswordUser:=getProcAddress(lib,'SamiChangePasswordUser');
       SamRidToSid:=getProcAddress(lib,'SamRidToSid');
       SamFreeMemory:=getProcAddress(lib,'SamFreeMemory');
       SamQueryInformationUser:=getProcAddress(lib,'SamQueryInformationUser');
       SamSetInformationUser:=getProcAddress(lib,'SamSetInformationUser');
  result:=true;
  except
  //on e:exception do writeln('init error:'+e.message);
     writeln('init error');
  end;
  //log('init:'+BoolToStr (result,'true','false'));
  end;

initialization
initAPI ;

end.

