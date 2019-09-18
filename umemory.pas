unit umemory;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows,utils;

function WriteMem(hprocess:thandle;offset:nativeint;bytes:array of byte):boolean;
function ReadMem(hprocess:thandle;offset:nativeuint;var bytes:array of byte):boolean;overload;
function ReadMem(hprocess:thandle;offset:nativeuint;bytes:pointer;len:PtrUInt):boolean;overload;
function SearchMem(hprocess:thandle;addr:pointer;sizeofimage:DWORD;pattern:array of byte):nativeint;


implementation

//type tbytes=array of byte;

function WriteMem(hprocess:thandle;offset:nativeint;bytes:array of byte):boolean;
var
  written:cardinal;
begin
log('WriteMem offset:'+inttohex(offset,sizeof(offset))+' len:'+inttostr(length(bytes)));
result:=WriteProcessMemory (hprocess,pointer(offset),@bytes[0],length(bytes),@written);
if written=0 then result:=false;
if result=false then log('WriteMem: written:'+inttostr(written)+' error:'+inttostr(getlasterror));
//ideally should check written against length(bytes) as well...
end;

function ReadMem(hprocess:thandle;offset:nativeuint;var bytes:array of byte):boolean;
var
  read:PtrUInt;
begin
fillchar(bytes,length(bytes),0);
log('ReadMem offset:'+inttohex(offset,sizeof(offset))+' len:'+inttostr(length(bytes)));
result:=ReadProcessMemory (hprocess,pointer(offset),@bytes[0],length(bytes),@read);
if read=0 then result:=false;
if result=false then log('readmem: read:'+inttostr(read)+' error:'+inttostr(getlasterror));
//ideally should check read against length(bytes) as well...
end;

function ReadMem(hprocess:thandle;offset:nativeuint;bytes:pointer;len:PtrUInt):boolean;overload;
var
  read:PtrUInt;
begin
fillchar(bytes^,len,0);
log('ReadMem offset:'+inttohex(offset,sizeof(offset))+' len:'+inttostr(len));
result:=ReadProcessMemory (hprocess,pointer(offset),bytes,len,@read);
if read=0 then result:=false;
if result=false then log('readmem: read:'+inttostr(read)+' error:'+inttostr(getlasterror));
//ideally should check read against length(bytes) as well...
end;

//https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_lsadump.c#L971
//pattern should be a parameter to make this function generic...
function SearchMem(hprocess:thandle;addr:pointer;sizeofimage:DWORD;pattern:array of byte):nativeint;
var
  i:nativeint;
  buffer:array of byte;
  read:cardinal;
begin
result:=0;
setlength(buffer,length(pattern));
//log('Searching...',0);
  for i:=nativeint(addr) to nativeint(addr)+sizeofimage-length(buffer) do
      begin
      //fillchar(buffer,4,0);
      if ReadProcessMemory( hprocess,pointer(i),@buffer[0],length(buffer),@read) then
        begin
        //log(inttohex(i,sizeof(pointer)));
        if CompareMem (@pattern [0],@buffer[0],length(buffer)) then
           begin
           result:=i;
           break;
           end;
        end;//if readprocessmemory...
      end;//for
//log('Done!',0);
end;



end.

