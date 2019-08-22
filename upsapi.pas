unit upsapi;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows;

type phmodule=^hmodule;

  type
  LPMODULEINFO = ^MODULEINFO;
  {$EXTERNALSYM LPMODULEINFO}
  _MODULEINFO = record
    lpBaseOfDll: LPVOID;
    SizeOfImage: DWORD;
    EntryPoint: LPVOID;
  end;
  {$EXTERNALSYM _MODULEINFO}
  MODULEINFO = _MODULEINFO;
  {$EXTERNALSYM MODULEINFO}
  TModuleInfo = MODULEINFO;
  PModuleInfo = LPMODULEINFO;

  type
    PPROC_THREAD_ATTRIBUTE_LIST = Pointer;

    STARTUPINFOEXW = packed record
      StartupInfo: TStartupInfoW;
      lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST;
    end;

    type PSIZE_T=^SIZE_T;

function GetModuleInformation(hProcess: HANDLE; hModule: HMODULE;
  var lpmodinfo: MODULEINFO; cb: DWORD): BOOL; stdcall;external 'psapi.dll';

  function EnumProcessModules(hProcess: HANDLE; lphModule: PHMODULE; cb: DWORD;
    var lpcbNeeded: DWORD): BOOL; stdcall;external 'psapi.dll';

  function GetModuleFileNameExA(hProcess: HANDLE; hModule: HMODULE; lpFilename: LPSTR;
  nSize: DWORD): DWORD; stdcall;external 'psapi.dll';

  function EnumProcesses(lpidProcess: LPDWORD; cb: DWORD; var cbNeeded: DWORD): BOOL; stdcall;external 'psapi.dll';

  function GetModuleBaseNameA(hProcess: HANDLE; hModule: HMODULE; lpBaseName: LPSTR;
nSize: DWORD): DWORD; stdcall;external 'psapi.dll';

  { WinVista API }
  //let go for late binding so that we can still run on xp
  {
  function InitializeProcThreadAttributeList(lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST; dwAttributeCount, dwFlags: DWORD; var lpSize: Cardinal): Boolean; stdcall;
    external 'kernel32.dll';

  function UpdateProcThreadAttribute(
       lpAttributeList : PPROC_THREAD_ATTRIBUTE_LIST;   //__inout
       dwFlags : DWORD;                                 //__in
       Attribute : DWORD_PTR;                           //__in
       lpValue : pvoid;                                 //__in_bcount_opt(cbSize)
       cbSize : SIZE_T;                                 //__in
       lpPreviousValue : PVOID;                         //__out_bcount_opt(cbSize)
       lpReturnSize : PSIZE_T                           //__in_opt
      ) : BOOL; stdcall; external 'kernel32.dll';

  procedure DeleteProcThreadAttributeList(lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST); stdcall; external 'Kernel32.dll';
  }

  //
  function _EnumProc(search:string=''):dword;
  function _EnumMod(pid:dword;search:string=''):dword;
  function _killproc(pid:dword):boolean;
  function CreateProcessOnParentProcess(pid:dword;ExeName: string):boolean;


implementation

const
  SE_SECURITY_NAME                     = 'SeSecurityPrivilege';
  PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = $00020000;
  EXTENDED_STARTUPINFO_PRESENT         = $00080000;

function _killproc(pid:dword):boolean;
var
  hProcess:thandle;
begin
  result:=false;
       HProcess := OpenProcess(PROCESS_TERMINATE, False, pid);
           if HProcess <> 0 then
           begin
             Result := TerminateProcess(HProcess, 0);
             CloseHandle(HProcess);
           end;
end;

function _EnumMod(pid:dword;search:string=''):dword;
var
  cbneeded:dword;
  count:dword;
  modules:array[0..1023] of thandle;
  hProcess:thandle;
  szModName:array[0..259] of char;
begin
result:=0;
//beware of 32bit process onto 64bits processes...
hProcess := OpenProcess( PROCESS_QUERY_INFORMATION or
                         PROCESS_VM_READ,
                         FALSE, pid );


   if EnumProcessModules (hProcess,@modules[0],SizeOf(hmodule)*1024,cbneeded) then
      begin
      //writeln(cbneeded div sizeof(dword)); //debug
      for count:=0 to cbneeded div sizeof(thandle) - 1 do
          begin

          //EnumProcessModules (hprocess,@modules[0],cb,cbneeded2);
          if GetModuleBaseNameA( hProcess, modules[count], szModName,sizeof(szModName))<>0 then
             begin
             if search='' then writeln(inttohex(modules[count],sizeof(thandle))+ ' '+szModName );
             if lowercase(search)=lowercase(strpas(szModName) ) then
                begin
                result:=modules[count];
                break;
                end; //if lowercase...
             end;// if GetModuleBaseNameA...
             //else writeln(getlasterror);
          end; //for count:=0...
      end;//if EnumProcesses...
   closehandle(hProcess);
end;

function _EnumProc(search:string=''):dword;
var
  cb,cbneeded,cbneeded2:dword;
  count:dword;
  pids,modules:array[0..1023] of dword;
  hProcess:thandle;
  szProcessName:array[0..259] of char;
begin
result:=0;
   cb:=sizeof(dword)*1024;
   if EnumProcesses (@pids[0],cb,cbneeded) then
      begin
      //writeln(cbneeded div sizeof(dword)); //debug
      for count:=0 to cbneeded div sizeof(dword) - 1 do
          begin
          //beware of 32bit process onto 64bits processes...
          hProcess := OpenProcess( PROCESS_QUERY_INFORMATION or
                                   PROCESS_VM_READ,
                                   FALSE, pids[count] );
          //EnumProcessModules (hprocess,@modules[0],cb,cbneeded2);
          if GetModuleBaseNameA( hProcess, 0, szProcessName,sizeof(szProcessName))<>0 then
             begin
             if search='' then writeln(inttostr(pids[count])+ ' '+szProcessName );
             if lowercase(search)=lowercase(strpas(szProcessName) ) then
                begin
                result:=pids[count];
                break;
                end; //if lowercase...
             end;// if GetModuleBaseNameA...
          closehandle(hProcess);
             //else writeln(getlasterror);
          end; //for count:=0...
      end;//if EnumProcesses...
end;

function EnableDebugPrivilege(PrivName: string; CanDebug: Boolean): Boolean;
var
  TP,prev    : Windows.TOKEN_PRIVILEGES;
  Dummy : Cardinal;
  hToken: THandle;
begin
  htoken:=0;
  //OpenProcessToken(GetCurrentProcess, TOKEN_ADJUST_PRIVILEGES, hToken);
  OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, hToken);
  TP.PrivilegeCount := 1;
  LookupPrivilegeValue(nil, pchar(PrivName), TP.Privileges[0].Luid);
  if CanDebug then
    TP.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED
  else
    TP.Privileges[0].Attributes := 0;
  Result                        := AdjustTokenPrivileges(hToken, False, TP, SizeOf(TP), prev, Dummy);
  hToken                        := 0;
end;

function CreateProcessOnParentProcess(pid:dword;ExeName: string):boolean;
type
TInitializeProcThreadAttributeList=function(lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST; dwAttributeCount, dwFlags: DWORD; var lpSize: Cardinal): Boolean; stdcall;
TUpdateProcThreadAttribute=function(
    lpAttributeList : PPROC_THREAD_ATTRIBUTE_LIST;
    dwFlags : DWORD;
    Attribute : DWORD_PTR;
    lpValue : pvoid;
    cbSize : SIZE_T;
    lpPreviousValue : PVOID;
    lpReturnSize : PSIZE_T
    ) : BOOL; stdcall;
TDeleteProcThreadAttributeList=procedure(lpAttributeList: PPROC_THREAD_ATTRIBUTE_LIST); stdcall;
var
  pi         : TProcessInformation;
  si         : STARTUPINFOEXW;
  cbAListSize: Cardinal;
  pAList     : PPROC_THREAD_ATTRIBUTE_LIST;
  hParent    : thandle;
  exitcode:dword;
  ptr:pointer;
begin
  //writeln(pid);
  result:=false;
  if EnableDebugPrivilege(SE_SECURITY_NAME, True)=false
     then writeln('EnableDebugPrivilege NOT OK');


  FillChar(si, SizeOf(si), 0);
  si.StartupInfo.cb          := SizeOf(si);
  si.StartupInfo.dwFlags     := STARTF_USESHOWWINDOW;
  si.StartupInfo.wShowWindow := SW_SHOWDEFAULT;
  si.STARTUPINFO.lpDesktop   :='WinSta0\Default';  //need a desktop? :='' ?
  FillChar(pi, SizeOf(pi), 0);

  cbAListSize := 0;
  ptr:=GetProcAddress (loadlibrary('kernel32.dll'),'InitializeProcThreadAttributeList');
  //InitializeProcThreadAttributeList(nil, 1, 0, cbAListSize);
  TInitializeProcThreadAttributeList(ptr)(nil, 1, 0, cbAListSize);
  pAList := HeapAlloc(GetProcessHeap(), 0, cbAListSize);
  //if InitializeProcThreadAttributeList(pAList, 1, 0, cbAListSize)=false
  if TInitializeProcThreadAttributeList(ptr)(pAList, 1, 0, cbAListSize)=false
      then begin writeln('InitializeProcThreadAttributeList NOT OK');exit;end;
  hParent := OpenProcess(PROCESS_ALL_ACCESS, False, pid);
  if hparent<=0 then begin writeln('OpenProcess NOT OK');exit;end;
  ptr:=GetProcAddress (loadlibrary('kernel32.dll'),'UpdateProcThreadAttribute');
  //if UpdateProcThreadAttribute(pAList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, @hParent, sizeof(thandle), nil, nil)=false
  if tUpdateProcThreadAttribute(ptr)(pAList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, @hParent, sizeof(thandle), nil, nil)=false
     then begin writeln('UpdateProcThreadAttribute NOT OK');exit;end;
  si.lpAttributeList := pAList;

  //need current dir?
  //need env?
  if CreateProcessW(PWideChar(widestring(ExeName)), nil, nil, nil, false, EXTENDED_STARTUPINFO_PRESENT,
  nil, pwidechar(widestring(GetCurrentDir)), si.StartupInfo  , pi) then
  begin
    //if GetExitCodeProcess (pi.hProcess ,exitcode) then writeln(exitcode);
    //WaitForInputIdle(pi.hprocess,5000);
    //sleep(15000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    result:=true;
  end
  else writeln(getlasterror);

  ptr:=GetProcAddress (loadlibrary('kernel32.dll'),'UpdateProcThreadAttribute');
  //DeleteProcThreadAttributeList(pAList);
  TDeleteProcThreadAttributeList(ptr)(pAList);
  HeapFree(GetProcessHeap(), 0, pAList);
end;


end.

