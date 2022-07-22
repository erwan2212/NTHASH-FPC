unit uimagehlp;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows,
  utils,ntdll;

const
  MiniDumpNormal         = $0000;
  {$EXTERNALSYM MiniDumpNormal}
  MiniDumpWithDataSegs   = $0001;
  {$EXTERNALSYM MiniDumpWithDataSegs}
  MiniDumpWithFullMemory = $0002;
  {$EXTERNALSYM MiniDumpWithFullMemory}
  MiniDumpWithHandleData = $0004;
  {$EXTERNALSYM MiniDumpWithHandleData}
  MiniDumpFilterMemory   = $0008;
  {$EXTERNALSYM MiniDumpFilterMemory}
  MiniDumpScanMemory     = $0010;
  {$EXTERNALSYM MiniDumpScanMemory}
  MiniDumpWithUnloadedModules            = $0020;
  {$EXTERNALSYM MiniDumpWithUnloadedModules}
  MiniDumpWithIndirectlyReferencedMemory = $0040;
  {$EXTERNALSYM MiniDumpWithIndirectlyReferencedMemory}
  MiniDumpFilterModulePaths              = $0080;
  {$EXTERNALSYM MiniDumpFilterModulePaths}
  MiniDumpWithProcessThreadData          = $0100;
  {$EXTERNALSYM MiniDumpWithProcessThreadData}
  MiniDumpWithPrivateReadWriteMemory     = $0200;
  {$EXTERNALSYM MiniDumpWithPrivateReadWriteMemory}

  type
  _MINIDUMP_TYPE = DWORD;
  {$EXTERNALSYM _MINIDUMP_TYPE}
  MINIDUMP_TYPE = _MINIDUMP_TYPE;
  {$EXTERNALSYM MINIDUMP_TYPE}
  TMinidumpType = MINIDUMP_TYPE;


  //function MiniDumpWriteDump(hProcess: HANDLE; ProcessId: DWORD; hFile: HANDLE; DumpType: MINIDUMP_TYPE; ExceptionParam: pointer; UserStreamParam: pointer; CallbackParam: pointer): BOOL; stdcall; external 'Dbghelp.dll';
{$EXTERNALSYM MiniDumpWriteDump}

//
function dumpprocess(pid:dword):boolean;
function dumpprocess2(pid:dword):boolean;

implementation

var
MiniDumpWriteDump:function (hProcess: HANDLE; ProcessId: DWORD; hFile: HANDLE; DumpType: MINIDUMP_TYPE; ExceptionParam: pointer; UserStreamParam: pointer; CallbackParam: pointer): BOOL; stdcall;

function dumpprocess(pid:dword):boolean;
var
  processHandle,hfile:thandle;
  //
  {$IFDEF win32}lib:cardinal;{$endif}
{$IFDEF win64}lib:int64;{$endif}
begin
log('******** dumpprocess ********');
lib:=0;
lib:=loadlibrary(pchar(sysdir+'\dbghelp.dll')); //we go for the default system one
if lib<=0 then
  begin
  raise exception.Create  ('could not loadlibrary:'+inttostr(getlasterror));
  exit;
  end;
MiniDumpWriteDump:=getProcAddress(lib,'MiniDumpWriteDump');
//
processHandle:=thandle(-1);
processHandle := OpenProcess(PROCESS_ALL_ACCESS, false, PID);
if processHandle<>thandle(-1) then
   begin
   hFile := CreateFile(pchar(inttostr(pid)+'.dmp'), GENERIC_ALL, 0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
   result := MiniDumpWriteDump(processHandle, pid, hfile, MiniDumpWithFullMemory, nil, nil, nil);
   if result=false then log('MiniDumpWriteDump failed,'+inttohex(getlasterror,sizeof(dword)));
   closehandle(hfile);
   closehandle(processHandle );
   end
   else log('OpenProcess failed');
 end;

function dumpprocess2(pid:dword):boolean;
var
  status:ntstatus;
  clone,processHandle,hfile:thandle;
  //
  {$IFDEF win32}lib:cardinal;{$endif}
{$IFDEF win64}lib:int64;{$endif}
begin
log('******** dumpprocess2 ********');
lib:=0;
lib:=loadlibrary(pchar(sysdir+'\dbghelp.dll')); //we go for the default system one
if lib<=0 then
  begin
  raise exception.Create  ('could not loadlibrary:'+inttostr(getlasterror));
  exit;
  end;
//
processHandle:=thandle(-1);
processHandle := OpenProcess(PROCESS_CREATE_PROCESS, false, PID);
if processHandle<>thandle(-1) then
   begin
   //
   ZeroMemory(@clone,sizeof(clone));
   status := NtCreateProcessEx(@clone,PROCESS_ALL_ACCESS,nil,processHandle,0,0,0,0,false);
   //
   if clone>0 then
      begin
      hFile := CreateFile(pchar(inttostr(pid)+'.dmp'), GENERIC_ALL, 0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
      MiniDumpWriteDump:=getProcAddress(lib,'MiniDumpWriteDump');
      result := MiniDumpWriteDump(clone, pid, hfile, MiniDumpWithFullMemory, nil, nil, nil);
      if result=false then log('MiniDumpWriteDump failed,'+inttohex(getlasterror,sizeof(dword)));
      closehandle(hfile);
      end else log('NtCreateProcessEx failed');
   closehandle(processHandle );
   TerminateProcess(clone,0);
   closehandle(clone );
   end
   else log('OpenProcess failed');
 end;

//initialization

end.

