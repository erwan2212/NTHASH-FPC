unit uhandles;

{$mode objfpc}{$H+}

interface

uses windows,ntdll,sysutils;

type tobj=record
     h:thandle;
     s:array [0..255] of char;
     end;

type tcallback=function(param:pointer=nil):dword;stdcall;

{
function GetModuleFileNameExA(hProcess : THandle; hModule : THandle;
                             lpFileName : pchar;
                             nSize : DWORD): DWORD; stdcall; external 'psapi.dll';

function GetProcessImageFileNameA(
   hProcess:HANDLE;
    lpImageFileName:LPSTR;
    nSize:DWORD):dword; stdcall; external 'psapi.dll';
}

function QueryFullProcessImageNameA(
   hProcess:HANDLE;
    dwFlags:DWORD;
    lpExeName:LPSTR;
    lpdwSize:PDWORD):bool; stdcall; external 'kernel32.dll';

function gethandles(pid:word=0;type_:string='';func:pointer=nil):boolean;

//var ptr:pointer;

implementation

function mycallback(param:pointer=nil):dword;stdcall;
begin
//do something with duplicatedobject ...
writeln(inttohex(thandle(param^),sizeof(thandle)));
//it should be the responsibility of the callback to close the duplicated handle
//if thandle(param^)<>thandle(-1) then closehandle(thandle(param^));
end;

function queryname(param:pointer):dword;stdcall;
begin
  //retrieve handle from param
  //pass back a string in param
  zeromemory(@tobj(param^).s[0],256);
  tobj(param^).s:=GetObjectInfo(tobj(param^).h,ObjectNameInformation);
  result:=0;
end;

var
  lpid:word=0;
  ltype:string='';


function gethandles(pid:word=0;type_:string='';func:pointer=nil):boolean;
//const PROCESS_QUERY_LIMITED_INFORMATION: DWORD = $1000;
var
  handleinfosize:ulong;
  handleinfo:psystem_handle_information;
  status:ntstatus;
  q:qword;
  _handle:thandle;
  _pid:word;
  strtype,strname,dup:string;
  processHandle,dupHandle:thandle;
  lpszProcess : PChar;
  size:dword;
  obj:tobj;
  hThread:thandle;
  tid:dword;
  ptr:pointer;
begin

   result:=false;
   handleinfosize:=DefaulBUFFERSIZE;
   handleinfo:=virtualalloc(nil,size_t(handleinfosize),mem_commit,page_execute_readwrite);

   status:=ntquerysysteminformation(systemhandleinformation,handleinfo,handleinfosize,nil);
   while status=STATUS_INFO_LENGTH_MISMATCH do
   begin
     handleinfosize*=2;
     if handleinfo<>nil then virtualfree(handleinfo,size_t(handleinfosize),mem_release);
     setlasterror(0);
     handleinfo:=virtualalloc(nil,size_t(handleinfosize),mem_commit,page_execute_readwrite);
     status:=ntquerysysteminformation(systemhandleinformation,handleinfo,handleinfosize,nil);
   end;

   if status<>0 then
   begin
       writeln(pansichar('error getting handle: '+inttohex(status,8)));
       exit;
   end;

   //writeln(handleinfo^.uCount);

   for q:=0 to handleinfo^.uCount-1 do
   begin
     try
       _handle:=thandle(-1);
       _handle:=handleinfo^.handles[q].Handle;
       if (_handle>0) and (handleinfo^.handles[q].uIdProcess<>getcurrentprocessid) then
          begin
          //https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
          //if (handleinfo^.handles[q].GrantedAccess<>$0012019f)
          //and  (handleinfo^.handles[q].GrantedAccess<>$001a019f)
          //and  (handleinfo^.handles[q].GrantedAccess<>$00120189)
          //and  (handleinfo^.handles[q].GrantedAccess<>$00100000)
          //and (handleinfo^.handles[q].GrantedAccess<>$120089) then
           begin
           _pid:=handleinfo^.handles[q].uIdProcess;
           if (pid=0) or (pid=_pid) then
           begin
           //we need to duplicate the handle to be able to query it
           processHandle:=thandle(-1);dupHandle:=thandle(-1);
           processHandle := OpenProcess(PROCESS_DUP_HANDLE   , FALSE, handleinfo^.handles[q].uIdProcess );
           if processhandle<>thandle(-1) then
              begin
              status:=NtDuplicateObject(processHandle,_handle,GetCurrentProcess ,@dupHandle,0,0,DUPLICATE_SAME_ACCESS); //DUPLICATE_SAME_ACCESS
              //if status<>STATUS_SUCCESS then status:=NtDuplicateObject(processHandle,_handle,GetCurrentProcess ,@dupHandle,0,0,0); //DUPLICATE_SAME_ACCESS
              if processhandle<>thandle(-1) then closehandle(processhandle);
              end;
           //
           strtype:='';strname:='???';dup:='';
           if (dupHandle<>thandle(-1)) and (status=STATUS_SUCCESS) then
              begin
              //_handle:=dupHandle;
              dup:='!';
              //end; //if (dupHandle<>thandle(-1)) and (status=STATUS_SUCCESS) then
              strtype:=GetObjectInfo(dupHandle,  ObjectTypeInformation);
              //will lock on file / pipe (getfiletype to get only file_disk?)
              //use a thread here : see https://social.msdn.microsoft.com/Forums/en-US/39dfd967-5c84-410f-9e81-7dd1e597cbc8/list-open-handles-by-a-process?forum=csharpgeneral
              //strname:=GetObjectInfo(dupHandle, ObjectNameInformation);
              if (type_='') or (lowercase(type_)=lowercase(strtype)) then
              begin
              obj.h :=dupHandle;
              hThread := CreateThread(nil, 0, @queryname, @obj, 0, TId);
              if WaitForSingleObject(hThread, 500) = WAIT_TIMEOUT
                 then TerminateThread(hThread, 0)
                 else strName :=strpas(obj.s);

              //
              if (dup='!') and (strtype='Process') and (strname='') then
              begin
              lpszProcess := AllocMem(MAX_PATH);
              size:=MAX_PATH;
              if QueryFullProcessImageNameA(dupHandle,0,lpszProcess ,@size)=true
              //if GetModuleFileNameExA(_handle, 0,lpszProcess, MAX_PATH) <> 0
                 //then processname:=lpszProcess else processname:= 'System Process';
                 then strname:=lpszProcess else strname:= 'System Process';
              end;
              //the callback must close the handme
          if func <>nil
             //then CreateThread (nil,$ffff,callback,@duphandle,0,tid)
             then tcallback(func)(pointer(@dupHandle))
             else
             begin
             writeln(inttostr(_pid)+' '+inttohex(handleinfo^.handles[q].Handle,sizeof(SYSTEM_HANDLE.Handle ))+' '+inttostr(handleinfo^.handles[q].ObjectType )+' '+strtype+' '+strname+' '+inttohex(handleinfo^.handles[q].GrantedAccess,sizeof(dword)));
             if duphandle<>thandle(-1) then closehandle(duphandle);
             end;
          //writeln('duphandle:'+inttohex(duphandle,sizeof(duphandle)));
          end; //if (type_='') or (lowercase(type_)=lowercase(strtype)) then
          end; //if (dupHandle<>thandle(-1)) and (status=STATUS_SUCCESS) then
          end; //if (pid=0) or (pid=_pid) then
          end; //if (handleinfo^.handles[q].GrantedAccess<>$0012019f)
          end; //if (_handle>0) and (handleinfo^.handles[q].uIdProcess<>getcurrentprocessid) then
     result:=true;
     except
         //
       on e:exception do writeln(e.message);
     end;
   end;

   if handleinfo<>nil then virtualfree(handleinfo,size_t(handleinfosize),mem_release);

end;


end.
