unit uadvapi32;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows;

type
 tbyte16__=array[0..15] of byte;

function GenerateNTLMHash(mypassword:string):string;
function GenerateNTLMHashByte(mypassword:string):tbyte16__;
function EnableDebugPriv:boolean;

implementation

type PWSTR = PWideChar;
type
  _LSA_UNICODE_STRING = record
    Length: USHORT;
    MaximumLength: USHORT;
    Buffer: PWSTR;
  end;
  PLSA_UNICODE_STRING=  ^_LSA_UNICODE_STRING;

function GenerateNTLMHash(mypassword:string):string;
type
tSystemFunction007 = Function( password:pchar;hash:pointer): integer; stdcall;
var
i:byte;
ret:integer;
lib:thandle;
sysfunc7:tSystemFunction007;
hash:array [0..15] of byte;
strpassword,strHash:string;
data:_LSA_UNICODE_STRING ;
begin
lib:=LoadLibrary('advapi32.dll');
if lib <> 0 then
begin
sysfunc7 := GetProcAddress(lib, 'SystemFunction007');
if Assigned(sysfunc7) then
begin
fillchar(hash,16,0);
strpassword:=mypassword;
//
data.MaximumLength := 4096;
data.Buffer := AllocMem(data.MaximumLength);
data.Length := Length(strpassword) * SizeOf(WideChar);
StringToWideChar(strpassword, data.Buffer,Length(strpassword) + 1);
//
ret:=sysfunc7(@data,@hash[0]);
for i:=0 to 15 do strHash :=strHash +IntToHex ( hash[i],2);
result :=strHash ;
end; //if Assigned(sysfunc6) then
FreeLibrary(lib);
end; //if lib <> 0 then
end;

function GenerateNTLMHashByte(mypassword:string):Tbyte16__;
type
tSystemFunction007 = Function( password:pchar;hash:pointer): integer; stdcall;
var
i:byte;
ret:integer;
lib:thandle;
sysfunc7:tSystemFunction007;
hash:tbyte16__;
strpassword:string;
data:_LSA_UNICODE_STRING ;
begin
lib:=LoadLibrary('advapi32.dll');
if lib <> 0 then
begin
sysfunc7 := GetProcAddress(lib, 'SystemFunction007');
if Assigned(sysfunc7) then
begin
fillchar(hash,16,0);
strpassword:=mypassword;
//
data.MaximumLength := 4096;
data.Buffer := AllocMem(data.MaximumLength);
data.Length := Length(strpassword) * SizeOf(WideChar);
StringToWideChar(strpassword, data.Buffer,Length(strpassword) + 1);
//
ret:=sysfunc7(@data,@hash[0]);
result :=Hash ;
end; //if Assigned(sysfunc6) then
FreeLibrary(lib);
end; //if lib <> 0 then
end;


function EnableDebugPriv:boolean;
var
  NewState,prev: TTokenPrivileges;
  luid: TLargeInteger;
  hToken: THandle;
  ReturnLength: DWord;
begin
result:=false;
  //TOKEN_ADJUST_PRIVILEGES is just not enough...
  if OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, hToken) then
  begin
   if LookupPrivilegeValue(nil, PChar('SeDebugPrivilege'), luid) then
   begin
    NewState.PrivilegeCount:= 1;
    NewState.Privileges[0].Luid := luid;
    NewState.Privileges[0].Attributes := SE_PRIVILEGE_ENABLED;
    fillchar(prev,sizeof(prev),0);
    if AdjustTokenPrivileges(hToken, False, NewState, SizeOf(TTokenPrivileges), prev, ReturnLength) then
    begin
    result:=true;
      {
      if GetLastError = ERROR_NOT_ALL_ASSIGNED then
        WriteLn('Change privilege failed: Not all assigned')
      else
        WriteLn('Privileged');
      }
    end;
    //else writeln(getlasterror);
   end;
    CloseHandle(hToken);
  end;
end;
end.

