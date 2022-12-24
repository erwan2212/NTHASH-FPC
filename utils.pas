unit utils;

{$ifdef fpc}{$mode delphi}{$endif fpc}

interface

uses
  Classes, SysUtils,windows,
  inifiles
  {$ifdef fpc},dom,XMLRead{$endif fpc}
  {$ifndef fpc},math{$endif fpc};

  {$ifndef fpc}
  type
  TBytes = array of Byte;
  //PBytes = ^tbytes;
  qword=int64;
  long=longint;
  PSTR = PAnsiChar;
  GUID = tguid;
  ULONGLONG = Int64;
  LPCVOID = Pointer;
  LPVOID = Pointer;
  lpbyte=PBYTE;
  PVOID = Pointer;
  ULONG_PTR = Longword;
  SIZE_T = ULONG_PTR;
  PtrUInt = NativeUInt;
  {$endif fpc}

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

procedure writeini(section,ident,value:string;config:string='');
function readini(section,ident,default:string;config:string=''):string;

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
function MyRegEnumKeys(hk:hkey;subkey:pchar;server:string=''):boolean;

{$ifdef fpc}
function parsexml(binary,key:string;var output:string):boolean;
{$endif fpc}


var
  verbose:boolean=false;
  lsass_pid:dword=0;
  winver,osarch:string;
  sysdir:pchar;
  debugpriv:boolean=false;
  symmode:boolean=false;
  console_output_type:dword;
  //
  system_hive:string='system.sav';
  security_hive:string='security.sav';
  sam_hive:string='sam.sav';

implementation

function readini(section,ident,default:string;config:string=''):string;
var
ini:tinifile;
currentdir,fname:string;
begin
log('*********** readini **********');
//currentdir:=upsapi.GetCurrentExeDir;
//if currentdir='' then currentdir:=lib.CurrentExeDir ;
if config<>'' then fname:=config else fname:=getcurrentdir + '\config.INI';
if FileExists(fname) then
  begin
    ini:=tinifile.Create (fname);
    result:=ini.ReadString (section,ident,default  );
    freeandnil(ini);
  end
  else result:=default;

end;

procedure writeini(section,ident,value:string;config:string='');
var
ini:tinifile;
Attrs:word;
{currentdir,}fname:string;
begin
log('*********** writeini **********');
//currentdir:=upsapi.GetCurrentExeDir;
//if currentdir='' then currentdir:=lib.CurrentExeDir ;
if config<>'' then fname:=config else fname:=getcurrentdir + '\config.INI';
if FileExists(fname) then
  begin
  Attrs := FileGetAttr(fname);
  if Attrs and fareadonly <> 0 then exit;
  end;

//if FileExists(GetCurrentDir + '\config.INI')=false then exit;
try
  ini:=tinifile.Create (fname);
  ini.WriteString(section,ident,value);
finally
  freeandnil(ini);
end;
end;

//status : success=0
procedure log(msg:string;status:dword=0);
begin
//if (verbose=false) and (status=0) then exit;
//writeln('length(msg):'+inttostr(length(msg)));
try
if verbose=false then
   if status<>0 then writeln(msg);
if (verbose=true) and (console_output_type<>FILE_TYPE_PIPE) then writeln(msg);
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
{$ifdef fpc} //no delphi for now
result := RightStr(StringOfChar(pad,length) + value, length );
{$endif fpc}
end;

function getoffset(var field;var rec):integer;
begin
{$ifdef fpc} //no delphi for now
  result:=ptrint(pointer(@field)-ptrint(@rec));
{$endif fpc}
end;

{$ifdef fpc} //no delphi for now
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
{$endif fpc}

{$ifdef fpc} //no delphi for now
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
{$endif fpc}

function MyRegEnumKeys(hk:hkey;subkey:pchar;server:string=''):boolean;
var
  ret:long;
  topkey,rk:hkey;
  cbdata,lptype,index:dword;
  dwDisposition:dword{$ifdef fpc}=0{$endif fpc};
  lpname:pchar;
begin
log('**** MyRegEnumKeys ****');
log('server:'+server);
log('subkey:'+subkey);
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
  getmem(lpname,1024);
  index:=0;ret:=0;
  while ret=0 do
      begin
      ret:= RegEnumKey (topkey ,index,lpname,cbdata);
      if ret=0 then log(lpname,1);
      inc(index);
      end;

RegCloseKey(topkey);
end //RegOpenKeyEx
else log('RegOpenKeyEx NOT OK:'+inttostr(ret),0);
end;


function MyRegQueryValue(hk:hkey;subkey:pchar;value:pchar;var data:tbytes;server:string=''):boolean;
var
  ret:long;
  topkey,rk:hkey;
  cbdata,lptype:dword;
  dwDisposition:dword{$ifdef fpc}=0{$endif fpc};
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
else log('RegOpenKeyEx '+strpas(subkey)+' NOT OK:'+inttostr(ret),1);
end;

function FiletoHexaString(filename:string):boolean;
var
  outfile:thandle{$ifdef fpc}=0{$endif fpc};
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
  outfile:thandle{$ifdef fpc}=0{$endif fpc};
  byteswritten:cardinal;
begin
log('**** HexaStringToFile ****');
result:=false;
outFile := CreateFile(pchar(filename), GENERIC_WRITE, 0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
byteswritten :=0;
log('length:'+inttostr(length(buffer)));
result:=writefile(outfile ,buffer[0],length(buffer),byteswritten,nil);
log('byteswritten:'+inttostr(byteswritten));
if byteswritten>0 then result:=true;
closehandle(outfile);
end;

function AnsiStringtoByte(input:string;unicode:boolean=false):tbytes;
var
  i:dword;
begin
log('**** AnsiStringtoByte ****');
input:=stringreplace(input,'\0',#0,[]);
//log('input:->'+input+'<-');
log('length:'+inttostr(length(input)));
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
on e:exception do log('AnsiStringtoByte:'+e.Message );
end;
end;

function BytetoAnsiString(buffer:pbyte;len:dword):string;overload;
var
  tmp:tbytes;
begin
if len=0 then exit;
SetLength(tmp,len);
ZeroMemory(@tmp[0],len);
CopyMemory(@tmp[0],buffer,len) ;
result:=BytetoAnsiString(tmp);
end;

function BytetoAnsiString(input:array of byte):string;
var
  i:dword;
  dummy:string{$ifdef fpc}=''{$endif fpc};
begin
log('**** BytetoAnsiString ****');
log('sizeof:'+inttostr(sizeof(input)));
if sizeof(input)=0 then exit;
try
//writeln(sizeof(input));
  for i:=0 to sizeof(input)-1 do  dummy:=dummy+chr(input[i]);
  result:=dummy;
except
on e:exception do log('BytetoAnsiString:'+e.Message );
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
  i:dword;
  dummy:string{$ifdef fpc}=''{$endif fpc};
begin
log('**** ByteToHexaString ****');
log('sizeof:'+inttostr(sizeof(hash)));
//setlength(dummy,sizeof(hash)*2);
try
//writeln('sizeof(hash):'+inttostr(sizeof(hash)));
//writeln('length(hash):'+inttostr(length(hash)));
  for i:=0 to sizeof(hash)-1 do  dummy:=dummy+inttohex(hash[i],2);
  result:=dummy;
except
on e:exception do log('ByteToHexaString:'+e.Message );
end;
end;

function HexaStringToByte(hash:string):tbyte16;
var
  i:dword;
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
on e:exception do log('HexaStringToByte:'+e.Message );
end;
end;

function HexaStringToByte2(hash:string):tbytes;
var
  i:dword;
  tmp:string;
  b:longint;
begin
log('**** HexaStringToByte2 ****');
log('length:'+inttostr(length(hash)));
try
i:=1;
//log('hash:'+hash);
//log('length(hash) div 2:'+inttostr(length(hash) div 2));
setlength(result,length(hash) div 2);
  while I<length(hash) do
      begin
      tmp:=copy(hash,i,2);
      if TryStrToInt ('$'+tmp,b) then result[i div 2]:=b;
      //result[i div 2]:=strtoint('$'+tmp);
      inc(i,2);
      //write('.');
      end;
except
on e:exception do log('HexaStringToByte2:'+e.Message );
end;
end;


Function SplitUserSID(user:pchar;var domain:string;var rid:dword):boolean;
var
  elements: TStrings;
  i:byte;
begin
elements := TStringList.Create;
{$ifdef fpc}ExtractStrings(['-'],[],user,elements,false);{$endif fpc}
{$ifndef fpc}ExtractStrings(['-'],[],user,elements);{$endif fpc}
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

