unit umemory;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows;

function WriteMem(hprocess:thandle;offset:nativeint;bytes:array of byte):boolean;
function ReadMem(hprocess:thandle;offset:nativeint;var bytes:array of byte):boolean;


implementation

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


end.

