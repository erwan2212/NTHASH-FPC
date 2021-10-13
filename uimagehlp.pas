unit uimagehlp;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows,
  utils;

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
   if result=false then log('MiniDumpWriteDump failed,'+inttostr(getlasterror));
   closehandle(hfile);
   closehandle(processHandle );
   end
   else log('OpenProcess failed');
 end;

//initialization

end.

