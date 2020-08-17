library hook;

{ Important note about DLL memory management: ShareMem must be the
  first unit in your library's USES clause AND your project's (select
  Project-View Source) USES clause if your DLL exports any procedures or
  functions that pass strings as parameters or function results. This
  applies to all strings passed to and from your DLL--even those that
  are nested in records and classes. ShareMem is the interface unit to
  the BORLNDMM.DLL shared memory manager, which must be deployed along
  with your DLL. To avoid using BORLNDMM.DLL, pass string information
  using PChar or ShortString parameters. }

uses
  windows  ;
  //uhandles in 'uhandles.pas';

{

procedure main;
var hfile:thandle;
written:cardinal;
p:pointer;
s:string;
begin
  LoadLibrary('kernel32.dll');
  LoadLibrary('user32.dll');
  hFile := CreateFile(pchar('test.txt'), GENERIC_WRITE, 0, nil, CREATE_ALWAYS, 0, 0);
  p:=VirtualAlloc(nil,8,MEM_COMMIT,PAGE_READWRITE);
  //p:=pchar(inttostr(GetCurrentProcessId )); //'12345678';
  s:=(inttostr(GetCurrentProcessId )); //'12345678';
  CopyMemory(p,@s[1],length(s));
  WriteFile(hfile,p^,8,written,nil);
  //
  //if CreateFile('c:\pagefile.sys', GENERIC_READ ,file_share_read or FILE_SHARE_WRITE, nil, OPEN_EXISTING, 0, 0)<>thandle(-1) then s:='ok' else s:='nok';
  //CopyMemory(p,@s[1],length(s));
  //WriteFile(hfile,p^,8,written,nil);
  //
  virtualfree(p,0,MEM_RELEASE);
  CloseHandle(hfile);
end;
}

function dummy(param:pointer):dword;
begin
OutputDebugString('dummy');
end;



procedure DllMain(Reason: Integer);
begin
  case Reason of
  DLL_PROCESS_ATTACH:begin OutputDebugString('DLL_PROCESS_ATTACH');{main};end;
  DLL_PROCESS_DETACH:OutputDebugString('DLL_PROCESS_DETACH');
  DLL_THREAD_ATTACH:OutputDebugString('DLL_THREAD_ATTACH');
  DLL_THREAD_DETACH:OutputDebugString('DLL_THREAD_DETACH');
  end;
end;

exports dummy;


begin
OutputDebugString('BEGIN');
DllProc := DllMain;
DllMain(DLL_PROCESS_ATTACH);
end.
 