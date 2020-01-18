unit utils;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows,dom,XMLRead;

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

procedure log(msg:string;status:dword=0);overload;
procedure log(msg:dword;status:dword=0);overload;
procedure log(msg:qword;status:dword=0);overload;
//function HashByteToString(hash:tbyte16):string;

function FiletoHexaString(filename:string):boolean;
function HexaStringToFile(filename:string;buffer:tbytes):boolean;

function ByteToHexaString(hash:array of byte):string;overload;
function ByteToHexaString(hash:pbyte;len:dword):string;overload;
function HexaStringToByte(hash:string):tbyte16;
function HexaStringToByte2(hash:string):tbytes;

function BytetoAnsiString(buffer:pbyte;len:dword):string;overload;
function BytetoAnsiString(input:array of byte):string;overload;

function AnsiStringtoByte(input:string;unicode:boolean=false):tbytes;

Function SplitUserSID(user:pchar;var domain:string;var rid:dword):boolean;
function LeftPad(value: string; length:integer=8; pad:char='0'): string; overload;

function ByteSwap64(Value: Int64): Int64;
function ByteSwap32(dw: cardinal): cardinal;
function ByteSwap16(w: word): word;

function MyRegQueryValue(hk:hkey;subkey:pchar;value:pchar;var data:tbytes;server:string=''):boolean;

function parsexml(binary,key:string;var output:string):boolean;


var
  verbose:boolean=false;
  winver,osarch:string;
  debug:boolean=false;

implementation

//status : success=0
procedure log(msg:string;status:dword=0);
begin
//if (verbose=false) and (status=0) then exit;
try
if verbose=false then
   if status<>0 then writeln(msg);
if verbose=true then writeln(msg);
except
on e:exception do writeln('log:'+e.message);
end;
//writeln(status);
end;

procedure log(msg:dword;status:dword=0);overload;
begin
log(inttostr(msg),status);
end;

procedure log(msg:qword;status:dword=0);overload;
begin
log(inttostr(msg),status);
end;

function LeftPad(value: string; length:integer=8; pad:char='0'): string; overload;
begin
result := RightStr(StringOfChar(pad,length) + value, length );
end;

function getoffset(var field;var rec):integer;
begin
  result:=ptrint(pointer(@field)-ptrint(@rec));
end;

function findnodes(list:tdomnodelist;search:string):tdomnode;
//*******************************************
function recursexml(n:tdomnode;search:string):tdomnode;
var
  w:word;
begin
  result:=nil;
  //log(n.ChildNodes.Count);

  if (search<>'') and (lowercase(search)=lowercase(n.NodeName)) then
     begin
     result:=n;
     exit;
     end;

  if n.firstchild.NodeValue<>''
     then log(n.NodeName+':'+n.firstchild.NodeValue )
     else log(n.NodeName);

  if n.FirstChild.nodename<>'#text' then
  for w:=0 to n.ChildNodes.Count-1 do
      begin
      result:=recursexml(n.childnodes[w],search);
      end;

end;
//*******************************************
var
  w:word;
begin
  result:=nil;
  log('search:'+search);

  for w:=0 to list.Count-1 do
      begin
      log('----');
      result:= recursexml(list[w],search);
      if result<>nil then break;
      end;

end;

function parsexml(binary,key:string;var output:string):boolean;

  var
  PassNode: TDOMNode=nil;
  Doc: TXMLDocument;
  w:word;
begin
  result:=false;
  log('binary:'+binary);
  log('key:'+key);
  try
    // Read in xml file from disk
    ReadXMLFile(Doc, binary);
    //log('ReadXMLFile ok');
    // Retrieve the "password" node
    //PassNode := Doc.DocumentElement.FindNode(node);
    //log('FindNode ok');
    passnode:=findnodes(doc.DocumentElement.ChildNodes,key);


    // Write out value of the selected node
    if passnode<>nil then
    begin
    //log(PassNode.NodeValue); // will be blank
    // The text of the node is actually a separate child node
    log(PassNode.FirstChild.NodeValue); // correctly prints "abc"
    output:=PassNode.FirstChild.NodeValue;
    result:=true;
    // alternatively
    //log(PassNode.TextContent);
    end
    else log('passnode=nil');
  finally
    // finally, free the document
    Doc.Free;
  end;
end;


function MyRegQueryValue(hk:hkey;subkey:pchar;value:pchar;var data:tbytes;server:string=''):boolean;
var
  ret:long;
  topkey,rk:thandle;
  cbdata,lptype:dword;
  dwDisposition:dword=0;
begin
log('**** MyRegQueryValue ****');
log('server:'+server);
log('subkey:'+subkey);
log('value:'+value);
result:=false;
topkey:=thandle(-1);
if server<>''
   then
   begin
   SetLastError(0) ;
   ret:=RegConnectRegistry (pchar(server),hk,rk );
   log('RegConnectRegistry:'+inttostr(ret),0);
   //log('RegConnectRegistry:'+inttostr(getlasterror));
   //KEY_QUERY_VALUE or KEY_READ? // KEY_WOW64_32KEY or
   SetLastError(0) ;
   if ret=0 then ret:=RegOpenKeyEx(rk, subkey,0, KEY_READ, topkey);
   //log('RegOpenKeyEx:'+inttostr(getlasterror));
   //if ret=0 then ret := RegCreateKeyEx(rk,subkey,0,nil,REG_OPTION_NON_VOLATILE,KEY_QUERY_VALUE,nil,topKey,@dwDisposition);
   end
   else ret:=RegOpenKeyEx(hk, subkey,0, KEY_READ, topkey);
if ret=0 then
begin
  log('RegOpenKeyEx OK',0);
  cbdata:=1024;
  ret := RegQueryValueex (topkey,value,nil,@lptype,nil,@cbdata);
  if (ret=0) and (cbdata>0) then
     begin
     log('RegQueryValueex OK',0);
     log('cbdata:'+inttostr(cbdata));
     setlength(data,cbdata);
     RegQueryValueex (topkey,value,nil,@lptype,@data[0],@cbdata);
     if (ret=0) and (cbdata>0) then result:=true;
     end;
RegCloseKey(topkey);
end //RegOpenKeyEx
else log('RegOpenKeyEx NOT OK',0);
end;

function FiletoHexaString(filename:string):boolean;
var
  outfile:thandle=0;
  buffer:array[0..1023] of byte;
  bytesread:cardinal;
begin
result:=false;
if not FileExists(filename) then log('filename does not exist');
outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
bytesread:=1;
while bytesread>0 do
begin
result:=readfile(outfile ,buffer,length(buffer),bytesread,nil);
if bytesread>0 then
   begin
   log(ByteToHexaString (@buffer[0],bytesread),1);
   result:=true;
   end;
end;
closehandle(outfile);
end;

function HexaStringToFile(filename:string;buffer:tbytes):boolean;
var
  outfile:thandle=0;
  byteswritten:cardinal;
begin
log('**** HexaStringToFile ****');
result:=false;
outFile := CreateFile(pchar(filename), GENERIC_WRITE, 0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
byteswritten :=0;
log('length(buffer):'+inttostr(length(buffer)));
result:=writefile(outfile ,buffer[0],length(buffer),byteswritten,nil);
log('byteswritten:'+inttostr(byteswritten));
if byteswritten>0 then result:=true;
closehandle(outfile);
end;

function AnsiStringtoByte(input:string;unicode:boolean=false):tbytes;
var
  i:word;
begin
try

if unicode=false then
begin
setlength(result,length(input));
//log('AnsiStringtoByte len:'+inttostr(length(input)));
for i:=1 to length(input) do result[i-1]:=ord(input[i]);
end;

if unicode=true then
begin
setlength(result,length(input)*2);
//log('AnsiStringtoByte len:'+inttostr(length(input)));
for i:=1 to length(input)  do
    begin
    result[(i-1)*2]:=ord(input[i]);
    //Inc(PInteger(@i)^, 1);
    end;
end;

except
on e:exception do log('AnsiStringtoByte'+e.Message );
end;
end;

function BytetoAnsiString(buffer:pbyte;len:dword):string;overload;
var
  tmp:tbytes;
begin
SetLength(tmp,len);
ZeroMemory(@tmp[0],len);
CopyMemory(@tmp[0],buffer,len) ;
result:=BytetoAnsiString(tmp);
end;

function BytetoAnsiString(input:array of byte):string;
var
  i:word;
  dummy:string='';
begin
if sizeof(input)=0 then exit;
try
//writeln(sizeof(input));
  for i:=0 to sizeof(input)-1 do  dummy:=dummy+chr(input[i]);
  result:=dummy;
except
on e:exception do log('AnsiStringtoByte'+e.Message );
end;
end;

function ByteToHexaString(hash:pbyte;len:dword):string;overload;
var
  tmp:tbytes;
begin
SetLength(tmp,len);
ZeroMemory(@tmp[0],len);
CopyMemory(@tmp[0],hash,len) ;
result:=ByteToHexaString(tmp);
end;

//function HashByteToString(hash:tbyte16):string;
function ByteToHexaString(hash:array of byte):string;
var
  i:word;
  dummy:string='';
begin
try
//writeln('sizeof(hash):'+inttostr(sizeof(hash)));
//writeln('length(hash):'+inttostr(length(hash)));
  for i:=0 to sizeof(hash)-1 do  dummy:=dummy+inttohex(hash[i],2);
  result:=dummy;
except
on e:exception do log('AnsiStringtoByte'+e.Message );
end;
end;

function HexaStringToByte(hash:string):tbyte16;
var
  i:word;
  tmp:string;
begin
try
i:=1;
//setlength(result,length(hash));
  while I<min(32,length(hash)){sizeof(hash)*2} do
      begin
      tmp:=copy(hash,i,2);
      result[i div 2]:=strtoint('$'+tmp);
      inc(i,2);
      end;
except
on e:exception do log('AnsiStringtoByte'+e.Message );
end;
end;

function HexaStringToByte2(hash:string):tbytes;
var
  i:word;
  tmp:string;
begin
try
i:=1;
//log('hash:'+hash);
//log('length(hash) div 2:'+inttostr(length(hash) div 2));
setlength(result,length(hash) div 2);
  while I<length(hash) do
      begin
      tmp:=copy(hash,i,2);
      result[i div 2]:=strtoint('$'+tmp);
      inc(i,2);
      end;
except
on e:exception do log('AnsiStringtoByte'+e.Message );
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

{$ifdef fpc}
{$asmmode intel}
{$endif}
//support cpux86 and cpux64
function ByteSwap64(Value: Int64): Int64;
asm
{$IF Defined(CPUX86)}
  mov    edx, [ebp+$08]
  mov    eax, [ebp+$0c]
  bswap  edx
  bswap  eax
{$ELSEIF Defined(CPUX64)}
  mov    rax, rcx
  bswap  rax
//{$ELSE}
//{$Message Fatal 'ByteSwap64 has not been implemented for this architecture.'}
//{$ENDIF}
{$IFEND}
end;

function ByteSwap32(dw: cardinal): cardinal;
asm
  {$IFDEF CPUX64}
  mov rax, rcx
  {$ENDIF}
  bswap eax
end;

function ByteSwap16(w: word): word;
asm
   {$IFDEF CPUX64}
   mov rax, rcx
   {$ENDIF}
   xchg   al, ah
end;


end.

