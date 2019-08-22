unit uadvapi32;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows;

const
  LOGON_WITH_PROFILE = $00000001;

  //https://github.com/gentilkiwi/mimikatz/blob/master/modules/kull_m_crypto_system.h
  const
  MD4_DIGEST_LENGTH=	16;
  MD5_DIGEST_LENGTH=	16;
  SHA_DIGEST_LENGTH=	20;

  DES_KEY_LENGTH=	7;
  DES_BLOCK_LENGTH=	8;
  AES_128_KEY_LENGTH=	16;
  AES_256_KEY_LENGTH=	32;

  //https://github.com/rapid7/meterpreter/blob/master/source/extensions/kiwi/mimikatz/modules/kuhl_m_lsadump_struct.h
  SYSKEY_LENGTH	=16;
  SAM_KEY_DATA_SALT_LENGTH=	16 ;
  SAM_KEY_DATA_KEY_LENGTH=		16;

type
 tbyte16__=array[0..15] of byte;

type
   TIntegrityLevel = (UnknownIntegrityLevel=0, LowIntegrityLevel, MediumIntegrityLevel, HighIntegrityLevel, SystemIntegrityLevel);


function GenerateNTLMHash(mypassword:string):string;
function GenerateNTLMHashByte(mypassword:string):tbyte16__;
function EnableDebugPriv:boolean;
function enumprivileges:boolean;

function Impersonate(const User, PW: string): Boolean;
function GetCurrUserName: string;

function CreateProcessAsLogon(const User, PW, Application, CmdLine: WideString): LongWord;

function CreateProcessAsSystemW_Vista(
  ApplicationName: PWideChar;
  CommandLine: PWideChar;
  CreationFlags: DWORD;
  Environment: Pointer;
  CurrentDirectory: PWideChar;
  StartupInfo: TStartupInfoW;
  var ProcessInformation: TProcessInformation;
  IntegrityLevel: TIntegrityLevel;
  const pid:cardinal=0): Boolean;

//***************************************************************************


function CreateProcessWithLogonW(
  lpUsername,
  lpDomain,
  lpPassword:PWideChar;
  dwLogonFlags:dword;
  lpApplicationName: PWideChar;
  lpCommandLine: PWideChar;
  dwCreationFlags: DWORD;
  lpEnvironment: Pointer;
  lpCurrentDirectory: PWideChar;
  lpStartupInfo: PStartupInfoW;
  lpProcessInformation: PProcessInformation
): BOOL; stdcall; external 'advapi32.dll';


type
   MD4_CTX  = packed record
    _Buf    : array[0..3] of LongWord;
    _I      : array[0..1] of LongWord;
    input   : array[0..63] of byte;
    digest  : Array[0..15] of Byte;
   end;


Procedure MD4Init(Var Context: MD4_CTX); StdCall;external 'advapi32.dll';
Procedure MD4Update(Var Context: MD4_CTX; const Input; inLen: LongWord); StdCall;external 'advapi32.dll';
Procedure MD4Final(Var Context: MD4_CTX); StdCall;external 'advapi32.dll';
//function MD4_Selftest:Boolean;


type
  MD5_CTX = packed Record
    i:      Array[0.. 1] of LongWord;
    buf:    Array[0.. 3] of LongWord;
    input:  Array[0..63] of Byte;
    digest: Array[0..15] of Byte;
  End;

  type _CRYPTO_BUFFER = packed record
  	 Length:dword;
  	 MaximumLength:dword;
  	 Buffer:PBYTE;
  end;
  PCRYPTO_BUFFER=^_CRYPTO_BUFFER;
  PCCRYPTO_BUFFER=^_CRYPTO_BUFFER; //? to be verified...



//SystemFunction004
//extern NTSTATUS WINAPI RtlEncryptDESblocksECB(IN PCCRYPTO_BUFFER data, IN PCCRYPTO_BUFFER key, OUT PCRYPTO_BUFFER output);
//SystemFunction005
//extern NTSTATUS WINAPI RtlDecryptDESblocksECB(IN PCCRYPTO_BUFFER data, IN PCCRYPTO_BUFFER key, OUT PCRYPTO_BUFFER output);
//SystemFunction032 or SystemFunction033?
//extern NTSTATUS WINAPI RtlEncryptDecryptRC4(IN OUT PCRYPTO_BUFFER data, IN PCCRYPTO_BUFFER key);
function RtlEncryptDecryptRC4(var  data:PCRYPTO_BUFFER;  key:PCRYPTO_BUFFER):dword ;StdCall;external 'advapi32.dll' name 'SystemFunction032';

// The MD5Init function initializes an MD5 message digest context.
Procedure MD5Init(Var Context: MD5_CTX); StdCall;external 'advapi32.dll';
// The MD5Update function updates the MD5 context by using the supplied buffer for the message whose MD5 digest is being generated
Procedure MD5Update(Var Context: MD5_CTX; const Input; inLen: LongWord); StdCall;external 'advapi32.dll';
//The MD5Final function ends an MD5 message digest previously started by a call to the MD5Init function
Procedure MD5Final(Var Context: MD5_CTX); StdCall;external 'advapi32.dll';
//function MD5string(const data : Ansistring):AnsiString;
//function MD5_Selftest:Boolean;

{lets go late binding
function CreateProcessWithTokenW(hToken: THandle;
  dwLogonFlags: DWORD;
  lpApplicationName: PWideChar;
  lpCommandLine: PWideChar;
  dwCreationFlags: DWORD;
  lpEnvironment: Pointer;
  lpCurrentDirectory: PWideChar;
  lpStartupInfo: PStartupInfoW;
  lpProcessInformation: PProcessInformation): BOOL; stdcall;external 'advapi32.dll';
  }

function DuplicateTokenEx(hExistingToken: HANDLE; dwDesiredAccess: DWORD;
  lpTokenAttributes: LPSECURITY_ATTRIBUTES; ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL;
  TokenType: TOKEN_TYPE; var phNewToken: HANDLE): BOOL; stdcall;external 'advapi32.dll';

//function ConvertStringSidToSidA(StringSid: LPCSTR; var Sid: PSID): BOOL; stdcall;
function ConvertStringSidToSidW(StringSid: LPCWSTR; var Sid: PSID): BOOL; stdcall;external 'advapi32.dll';
//function ConvertStringSidToSid(StringSid: LPCTSTR; var Sid: PSID): BOOL; stdcall;
function ConvertStringSidToSidA(StringSid: pchar; var Sid: PSID): BOOL; stdcall;external 'advapi32.dll' name 'ConvertStringSidToSidA';

// SHA1

type
  SHA_CTX = packed record
   	Unknown : array[0..5] of LongWord;
	   State   : array[0..4] of LongWord;
	   Count   : array[0..1] of LongWord;
    	Buffer  : array[0..63] of Byte;
  end;

  SHA_DIG = packed record
	   Dig     : array[0..19] of Byte;
  end;

procedure A_SHAInit(var Context: SHA_CTX); StdCall;external 'advapi32.dll';
procedure A_SHAUpdate(var Context: SHA_CTX; const Input; inlen: LongWord); StdCall;external 'advapi32.dll';
procedure A_SHAFinal(var Context: SHA_CTX; out Digest:SHA_DIG); StdCall;external 'advapi32.dll';

//function SHA_Selftest:Boolean;

implementation

const
  LOW_INTEGRITY_SID: PWideChar = ('S-1-16-4096');
  MEDIUM_INTEGRITY_SID: PWideChar = ('S-1-16-8192');
  HIGH_INTEGRITY_SID: PWideChar = ('S-1-16-12288');
  SYSTEM_INTEGRITY_SID: PWideChar = ('S-1-16-16384');

  SE_GROUP_INTEGRITY = $00000020;


type
  _TOKEN_MANDATORY_LABEL = record
    Label_: SID_AND_ATTRIBUTES;
  end;
  TOKEN_MANDATORY_LABEL = _TOKEN_MANDATORY_LABEL;
  PTOKEN_MANDATORY_LABEL = ^TOKEN_MANDATORY_LABEL;

type PWSTR = PWideChar;
type
  _LSA_UNICODE_STRING = record
    Length: USHORT;
    MaximumLength: USHORT;
    Buffer: PWSTR;
  end;
  PLSA_UNICODE_STRING=  ^_LSA_UNICODE_STRING;

function GenerateNTLMHash(mypassword:string):string;
type
//aka rtldigestntlm
tSystemFunction007 = Function( password:pchar;hash:pointer): integer; stdcall;
var
i:byte;
ret:integer;
lib:thandle;
sysfunc7:tSystemFunction007;
hash:array [0..15] of byte;
strpassword,strHash:string;
data:_LSA_UNICODE_STRING ;
begin
lib:=LoadLibrary('advapi32.dll');
if lib <> 0 then
begin
sysfunc7 := GetProcAddress(lib, 'SystemFunction007');
if Assigned(sysfunc7) then
begin
fillchar(hash,16,0);
strpassword:=mypassword;
//
data.MaximumLength := 4096;
data.Buffer := AllocMem(data.MaximumLength);
data.Length := Length(strpassword) * SizeOf(WideChar);
StringToWideChar(strpassword, data.Buffer,Length(strpassword) + 1);
//
ret:=sysfunc7(@data,@hash[0]);
for i:=0 to 15 do strHash :=strHash +IntToHex ( hash[i],2);
result :=strHash ;
end; //if Assigned(sysfunc6) then
FreeLibrary(lib);
end; //if lib <> 0 then
end;

function GenerateNTLMHashByte(mypassword:string):Tbyte16__;
type
//aka rtldigestlm
tSystemFunction007 = Function( password:pchar;hash:pointer): integer; stdcall;
var
i:byte;
ret:integer;
lib:thandle;
sysfunc7:tSystemFunction007;
hash:tbyte16__;
strpassword:string;
data:_LSA_UNICODE_STRING ;
begin
lib:=LoadLibrary('advapi32.dll');
if lib <> 0 then
begin
sysfunc7 := GetProcAddress(lib, 'SystemFunction007');
if Assigned(sysfunc7) then
begin
fillchar(hash,16,0);
strpassword:=mypassword;
//
data.MaximumLength := 4096;
data.Buffer := AllocMem(data.MaximumLength);
data.Length := Length(strpassword) * SizeOf(WideChar);
StringToWideChar(strpassword, data.Buffer,Length(strpassword) + 1);
//
ret:=sysfunc7(@data,@hash[0]);
result :=Hash ;
end; //if Assigned(sysfunc6) then
FreeLibrary(lib);
end; //if lib <> 0 then
end;


function EnableDebugPriv:boolean;
var
  NewState,prev: TTokenPrivileges;
  luid: TLargeInteger;
  hToken: THandle;
  ReturnLength: DWord;
begin
result:=false;
  //TOKEN_ADJUST_PRIVILEGES is just not enough...
  if OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, hToken) then
  begin
   if LookupPrivilegeValue(nil, PChar('SeDebugPrivilege'), luid) then
   begin
    NewState.PrivilegeCount:= 1;
    NewState.Privileges[0].Luid := luid;
    NewState.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
    fillchar(prev,sizeof(prev),0);
    if AdjustTokenPrivileges(hToken, False, NewState, SizeOf(TTokenPrivileges), prev, ReturnLength) then
    begin
    result:=true;
      {
      if GetLastError = ERROR_NOT_ALL_ASSIGNED then
        WriteLn('Change privilege failed: Not all assigned')
      else
        WriteLn('Privileged');
      }
    end;
    //else writeln(getlasterror);
   end;
    CloseHandle(hToken);
  end;
end;

function GetCurrUserName: string;
var
  Size              : DWORD;
begin
  Size := MAX_COMPUTERNAME_LENGTH + 1;
  SetLength(Result, Size);
  if GetUserName(PChar(Result), Size) then
    SetLength(Result, Size)
  else
    Result := '';
end;

function Impersonate(const User, PW: string): Boolean;
var
 LogonType         : Integer;
 LogonProvider     : Integer;
 TokenHandle       : THandle;
 strAdminUser      : string;
 strAdminDomain    : string;
 strAdminPassword  : string;
begin
 LogonType := LOGON32_LOGON_INTERACTIVE;
 LogonProvider := LOGON32_PROVIDER_DEFAULT;
 strAdminUser := USER;
 strAdminDomain := '';
 strAdminPassword := PW;
 Result := LogonUser(PChar(strAdminUser), nil,
   PChar(strAdminPassword), LogonType, LogonProvider, TokenHandle);
 if Result then
 begin
   Result := ImpersonateLoggedOnUser(TokenHandle);
 end;
end;

function CreateProcessAsLogon(const User, PW, Application, CmdLine: WideString):
  LongWord;
var
  si           : TStartupInfoW;
  pif          : TProcessInformation;
begin
  //writeln(user+':'+pw);
  ZeroMemory(@si, sizeof(si));
  si.cb := sizeof(si);
  si.dwFlags := STARTF_USESHOWWINDOW;
  si.wShowWindow := 1;

  SetLastError(0);
  CreateProcessWithLogonW(PWideChar(User), nil, PWideChar(PW),
    LOGON_WITH_PROFILE, nil, PWideChar(Application+' "'+CmdLine+'"'),
    CREATE_DEFAULT_ERROR_MODE, nil, nil, @si, @pif);
  Result := GetLastError;
end;

function GetWinlogonProcessId: Cardinal;
begin
 //TBD
end;

function CreateProcessAsSystemW_Vista(
  ApplicationName: PWideChar;
  CommandLine: PWideChar;
  CreationFlags: DWORD;
  Environment: Pointer;
  CurrentDirectory: PWideChar;
  StartupInfo: TStartupInfoW;
  var ProcessInformation: TProcessInformation;
  IntegrityLevel: TIntegrityLevel;
  const pid:cardinal=0): Boolean;
type
  TCreateProcessWithTokenW=function(hToken: THandle;
  dwLogonFlags: DWORD;
  lpApplicationName: PWideChar;
  lpCommandLine: PWideChar;
  dwCreationFlags: DWORD;
  lpEnvironment: Pointer;
  lpCurrentDirectory: PWideChar;
  lpStartupInfo: PStartupInfoW;
  lpProcessInformation: PProcessInformation): BOOL; stdcall;
var
  ProcessHandle, TokenHandle, ImpersonateToken: THandle;
  Sid: PSID;
  MandatoryLabel: PTOKEN_MANDATORY_LABEL;
  ReturnLength: DWORD;
  PIntegrityLevel: PWideChar;
  CreateProcessWithTokenW:pointer;
begin
  Result := False;
  CreateProcessWithTokenW:=getprocaddress(loadlibrary('advapi32.dll'),'CreateProcessWithTokenW');
  if (@CreateProcessWithTokenW = nil) then
    Exit;
  try
    if pid=0
      then ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, GetWinlogonProcessId)
      else ProcessHandle := OpenProcess(MAXIMUM_ALLOWED, False, pid);
    if ProcessHandle <> 0 then
    begin
      try
        if OpenProcessToken(ProcessHandle, MAXIMUM_ALLOWED, TokenHandle) then
        begin
          try
            //writeln('OpenProcessToken OK');
            if DuplicateTokenEx(TokenHandle, MAXIMUM_ALLOWED, nil, SecurityImpersonation, TokenPrimary, ImpersonateToken) then
            begin
              try
                //writeln('DuplicateTokenEx OK');
                New(Sid);
                if (not GetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, 0, ReturnLength)) and (GetLastError = ERROR_INSUFFICIENT_BUFFER) then
                begin
                  //writeln('GetTokenInformation OK');
                  MandatoryLabel := nil;
                  GetMem(MandatoryLabel, ReturnLength);
                  if MandatoryLabel <> nil then
                  begin
                    try
                      if GetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, ReturnLength, ReturnLength) then
                      begin
                        //writeln('GetTokenInformation OK');
                        if IntegrityLevel = SystemIntegrityLevel then
                          PIntegrityLevel := (SYSTEM_INTEGRITY_SID)
                        else if IntegrityLevel = HighIntegrityLevel then
                          PIntegrityLevel := (HIGH_INTEGRITY_SID)
                        else if IntegrityLevel = MediumIntegrityLevel then
                          PIntegrityLevel := (MEDIUM_INTEGRITY_SID)
                        else if IntegrityLevel = LowIntegrityLevel then
                          PIntegrityLevel := (LOW_INTEGRITY_SID);
                        writeln(strpas(PIntegrityLevel));
                        if ConvertStringSidToSidw(PIntegrityLevel, Sid) then
                        begin
                          //writeln('ConvertStringSidToSidW OK');
                          MandatoryLabel.Label_.Sid := Sid;
                          MandatoryLabel.Label_.Attributes := SE_GROUP_INTEGRITY;
                          if SetTokenInformation(ImpersonateToken, TTokenInformationClass(TokenIntegrityLevel), MandatoryLabel, SizeOf(TOKEN_MANDATORY_LABEL) + GetLengthSid(Sid)) then
                          begin
                            Result := TCreateProcessWithTokenW(CreateProcessWithTokenW)(ImpersonateToken, 0, ApplicationName, CommandLine, CreationFlags, Environment, CurrentDirectory, @StartupInfo, @ProcessInformation);
                            //writeln(result);
                            SetLastError(0);
                          end;
                        end;
                      end;
                    finally
                      FreeMem(MandatoryLabel);
                    end;
                  end;
                end;
              finally
                CloseHandle(ImpersonateToken);
              end;
            end;
          finally
            CloseHandle(TokenHandle);
          end;
        end;
      finally
        CloseHandle(ProcessHandle);
      end;
    end;
  except
  end;
end;

////////////////////////////////////////////////////////////////////////////////////
// Enumerating privileges held by the current user.
function enumprivileges:boolean;
type
  TPrivilegesArray = array [0..1024] of TLuidAndAttributes;
  PPrivilegesArray = ^TPrivilegesArray;
var
  TokenHandle: THandle;
  Size: Cardinal;
  Privileges: PTokenPrivileges;
  I: Integer;
  Luid: TLuid;
  Name: string;
  Attr: Longword;
  function AttrToString: string;
  begin
    Result := '';
    if (Attr and SE_PRIVILEGE_ENABLED) <> 0 then
       Result := Result + 'Enabled ';
    if (Attr and SE_PRIVILEGE_ENABLED_BY_DEFAULT) <> 0
       then Result := Result + 'EnabledByDefault';
    Result := '[' + Trim(Result) + ']';
  end;
begin
  Win32Check(OpenProcessToken(GetCurrentProcess,
    TOKEN_QUERY, TokenHandle));
  try
    GetTokenInformation(TokenHandle, TokenPrivileges, nil,
      0, Size);
    Privileges := AllocMem(Size);
    Win32Check(GetTokenInformation(TokenHandle, TokenPrivileges, Privileges, Size, Size));
    for I := 0 to Privileges.PrivilegeCount - 1 do
    begin
      Luid := PPrivilegesArray(@Privileges^.Privileges)^[I].Luid;
      Attr := PPrivilegesArray(@Privileges^.Privileges)^[I].Attributes;
      Size := 0;
      LookupPrivilegeName(nil, Luid, nil, Size);
      SetLength(Name, Size);
      LookupPrivilegeName(nil, Luid, PChar(Name), Size);
      writeln(PChar(Name) + ' ' + AttrToString);
    end;
  finally
    CloseHandle(TokenHandle);
  end;
end;

end.

