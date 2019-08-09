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

function GetModuleInformation(hProcess: HANDLE; hModule: HMODULE;
  var lpmodinfo: MODULEINFO; cb: DWORD): BOOL; stdcall;external 'psapi.dll';

  function EnumProcessModules(hProcess: HANDLE; lphModule: PHMODULE; cb: DWORD;
    var lpcbNeeded: DWORD): BOOL; stdcall;external 'psapi.dll';

  function GetModuleFileNameExA(hProcess: HANDLE; hModule: HMODULE; lpFilename: LPSTR;
  nSize: DWORD): DWORD; stdcall;external 'psapi.dll';

  function EnumProcesses(lpidProcess: LPDWORD; cb: DWORD; var cbNeeded: DWORD): BOOL; stdcall;external 'psapi.dll';

  function GetModuleBaseNameA(hProcess: HANDLE; hModule: HMODULE; lpBaseName: LPSTR;
nSize: DWORD): DWORD; stdcall;external 'psapi.dll';

  //
  function _FindPid(search:string=''):dword;


implementation

function _FindPid(search:string=''):dword;
var
  cb,cbneeded:dword;
  count:dword;
  pids:array[0..1023] of dword;
  hProcess:thandle;
  hmod:hmodule;
  szProcessName:array[0..254] of char;
begin
result:=0;
   cb:=sizeof(dword)*1024;
   if EnumProcesses (@pids[0],cb,cbneeded) then
      begin
      for count:=0 to cbneeded div sizeof(dword) - 1 do
          begin
          hProcess := OpenProcess( PROCESS_QUERY_INFORMATION or
                                   PROCESS_VM_READ,
                                   FALSE, pids[count] );
          GetModuleBaseNameA( hProcess, 0, szProcessName,sizeof(szProcessName));
          //writeln(inttostr(pids[count])+ ' '+szProcessName );
          closehandle(hProcess);
          if lowercase(search)=lowercase(strpas(szProcessName) ) then
             begin
             result:=pids[count];
             break;
             end;
          end;
      end;
end;


end.

