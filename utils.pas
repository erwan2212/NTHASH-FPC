unit utils;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows;

type
  tbyte16=array[0..15] of byte;
  tbyte32=array[0..31] of byte;

  NTStatus = DWORD;

  type fn=function(param:pointer):dword;stdcall;

  type _KUHL_M_SEKURLSA_ENUM_HELPER =record
	 tailleStruct:nativeint; //SIZE_T
	 offsetToLuid:ULONG;
	 offsetToLogonType:ULONG;
	 offsetToSession:ULONG;
	 offsetToUsername:ULONG;
	 offsetToDomain:ULONG;
	 offsetToCredentials:ULONG;
	 offsetToPSid:ULONG;
	 offsetToCredentialManager:ULONG;
	 offsetToLogonTime:ULONG;
	 offsetToLogonServer:ULONG;
  end;
 KUHL_M_SEKURLSA_ENUM_HELPER=_KUHL_M_SEKURLSA_ENUM_HELPER;
 PKUHL_M_SEKURLSA_ENUM_HELPER=^_KUHL_M_SEKURLSA_ENUM_HELPER;

procedure log(msg:string;status:dword=0);
//function HashByteToString(hash:tbyte16):string;
function HashByteToString(hash:array of byte):string;
function HashStringToByte(hash:string):tbyte16;
Function SplitUserSID(user:pchar;var domain:string;var rid:dword):boolean;
function LeftPad(value: string; length:integer=8; pad:char='0'): string; overload;

var
  verbose:boolean=false;

implementation

//status : success=0
procedure log(msg:string;status:dword=0);
begin
//if (verbose=false) and (status=0) then exit;
if verbose=false then
   if status<>0 then writeln(msg);
if verbose=true then writeln(msg);
//writeln(status);
end;

function LeftPad(value: string; length:integer=8; pad:char='0'): string; overload;
begin
result := RightStr(StringOfChar(pad,length) + value, length );
end;

//function HashByteToString(hash:tbyte16):string;
function HashByteToString(hash:array of byte):string;
var
  i:byte;
  dummy:string='';
begin
  for i:=0 to sizeof(hash)-1 do  dummy:=dummy+inttohex(hash[i],2);
  result:=dummy;
end;

function HashStringToByte(hash:string):tbyte16;
var
  i:byte;
  tmp:string;
begin
i:=1;
  while I<length(hash){sizeof(hash)*2} do
      begin
      tmp:=copy(hash,i,2);
      result[i div 2]:=strtoint('$'+tmp);
      inc(i,2);
      end;
end;


Function SplitUserSID(user:pchar;var domain:string;var rid:dword):boolean;
var
  elements: TStrings;
  i:byte;
begin
elements := TStringList.Create;
   ExtractStrings(['-'],[],user,elements,false);
   for i:=0 to elements.Count-2 do domain:=domain+'-'+elements[i];
   delete(domain,1,1);
   log('domain:'+domain);
   rid:=strtoint(elements[elements.count-1]);
   log('rid:'+inttostr(rid));
elements.Free ;;
end;


end.

