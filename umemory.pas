unit umemory;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows;

function WriteMem(hprocess:thandle;offset:nativeint;bytes:array of byte):boolean;
function ReadMem(hprocess:thandle;offset:nativeint;var bytes:array of byte):boolean;
function SearchMem(hprocess:thandle;addr:pointer;sizeofimage:DWORD;pattern:array of byte):nativeint;


implementation

//type tbytes=array of byte;

function WriteMem(hprocess:thandle;offset:nativeint;bytes:array of byte):boolean;
var
  written:cardinal;
begin
result:=WriteProcessMemory (hprocess,pointer(offset),@bytes[0],length(bytes),@written);
//ideally should check written against length(bytes) as well...
end;

function ReadMem(hprocess:thandle;offset:nativeint;var bytes:array of byte):boolean;
var
  read:cardinal;
begin
fillchar(bytes,length(bytes),0);
result:=ReadProcessMemory (hprocess,pointer(offset),@bytes[0],length(bytes),@read);
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

