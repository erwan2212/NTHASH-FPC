unit uofflinereg;

{$mode delphi}

interface

uses
  Windows,Classes, SysUtils;

function init:boolean;



type
PCWSTR=pwidechar;
PWSTR=pwidechar;
PVOID=Pointer;

var
//http://msdn.microsoft.com/en-us/library/ee210756%28v=VS.85%29.aspx
ORCreateHive: function(var ORHKEY :tHandle):dword;stdcall;
OROpenHive: function (lpHivePath:PCWSTR;var phkResult:thandle):dword;stdcall;
ORCloseHive:function (ORHKEY:tHandle):dword;stdcall;
OROpenKey:function (ORHKEY:tHandle;lpSubKeyName:PCWSTR;var phkResult:thandle):DWORD;stdcall;
ORCloseKey:function(ORHKEY:tHandle):DWORD;stdcall;
ORGetValue:function(ORHKEY:tHandle;lpSubKey:PCWSTR;lpValue:PCWSTR; pdwType:PDWORD; pvData:PVOID; pcbData:PDWORD):DWORD;stdcall;
ORSetValue:function(ORHKEY:tHandle;lpValueName:PCWSTR;dwType:dword;lpData:pvoid;cbData:dword):dword;stdcall;
ORGetVersion:procedure( var pdwMajorVersion:dword; var pdwMinorVersion:dword);stdcall;
ORSaveHive:function(ORHKEY:tHandle;lpHivePath:PCWSTR;dwOsMajorVersion:dword;dwOsMinorVersion:dword):dword;stdcall;
ORDeleteValue:function(ORHKEY:tHandle;lpValueName:PCWSTR):DWORD;stdcall;
ORDeleteKey:function(ORHKEY:tHandle;lpSubKey:PCWSTR):DWORD;stdcall;
ORCreateKey:function(
  ORHKEY:tHandle;
  lpSubKey:PCWSTR;
  lpClass:PWSTR;
  dwOptions:DWORD;
  pSecurityDescriptor:PSECURITY_DESCRIPTOR;
  phkResult:pointer;
  pdwDisposition:PDWORD):DWORD;stdcall;
OREnumKey:function(
  ORHKEY:tHandle;
  dwIndex:dword;
  lpName:pwstr;
  lpcName:pdword;
  lpClass:PWSTR;
  lpcClass:PDWORD;
  lpftLastWriteTime:PFILETIME):dWORD;stdcall;
 OREnumValue:function(
  ORHKEY:tHandle;
  dwIndex:DWORD;
  lpValueName:PWSTR;
  lpcValueName:PDWORD;
  lpType:PDWORD;
  lpData:PBYTE;
  lpcbData:PDWORD):WORD;stdcall;
  ORQueryInfoKey:function(
       ORHKEY:tHandle;
       lpClass:PWSTR;
       lpcClass:PDWORD;
       lpcSubKeys:PDWORD;
       lpcMaxSubKeyLen:PDWORD;
       lpcMaxClassLen:PDWORD;
       lpcValues:PDWORD;
       lpcMaxValueNameLen:PDWORD;
       lpcMaxValueLen:PDWORD;
       lpcbSecurityDescriptor:PDWORD;
       lpftLastWriteTime:PFILETIME):WORD;stdcall;

implementation

  var lib:hmodule=0;

  function init:boolean;
  //var lib:hmodule;
  begin
  result:=false;
  try
  //lib:=0;
  if lib<>0 then exit;
      {$IFDEF win64}lib:=loadlibrary('offreg64.dll');{$endif}
      {$IFDEF win32}lib:=loadlibrary('offreg.dll');{$endif}
  if lib<=0 then
    begin
    writeln('could not loadlibrary:'+inttostr(getlasterror));
    exit;
    end;
  ORGetVersion:=getProcAddress(lib,'ORGetVersion');
  ORCreateHive:=getProcAddress(lib,'ORCreateHive');
  OROpenHive:=getProcAddress(lib,'OROpenHive');
  ORCloseHive:=getProcAddress(lib,'ORCloseHive');
  ORSaveHive:=getProcAddress(lib,'ORSaveHive');
  OROpenKey:=getProcAddress(lib,'OROpenKey');
  ORCloseKey:=getProcAddress(lib,'ORCloseKey');
  ORGetValue:=getProcAddress(lib,'ORGetValue');
  ORSetValue:=getProcAddress(lib,'ORSetValue');
  ORDeleteValue:=getProcAddress(lib,'ORDeleteValue');
  ORDeleteKey:=getProcAddress(lib,'ORDeleteKey');
  ORCreateKey:=getProcAddress(lib,'ORCreateKey');
  OREnumKey:=getProcAddress(lib,'OREnumKey');
  OREnumValue:=getProcAddress(lib,'OREnumValue');
  ORQueryInfoKey:=getProcAddress(lib,'ORQueryInfoKey');
  result:=true;
  except
  on e:exception do writeln('init error:'+e.message);
  end;
  end;

  function getvaluePTR(key:thandle;svaluename:string;var data:pointer):integer;
var
ret:dword;
wvaluename:array[0..255] of widechar;
pvdata:pointer;
pdwtype,pcbData:pdword;
b:array of byte;
begin
result:=-1;
try
fillchar(wvaluename,sizeof(wvaluename),#0);
StringToWideChar(svaluename, wvaluename, length(svaluename)+1);
getmem(pdwType,sizeof(dword));

getmem(pcbdata,sizeof(dword));pcbdata^:=0;
pvdata:=nil;
ret:=ORGetValue (key,nil,wvaluename,pdwtype,pvdata,pcbData);
if ret<>0 then raise exception.Create('ORGetValue failed:'+inttostr(ret)+':'+SysErrorMessage(ret));
if pcbData^=0 then
    begin
    result:=0;
    exit;
    end;

getmem(pvdata,pcbdata^);
ret:=ORGetValue (key,nil,wvaluename,pdwtype,pvdata,pcbData);
if ret<>0
  then raise exception.Create('ORGetValue failed:'+inttostr(ret)+':'+SysErrorMessage(ret))
  else
  begin
  result:=pcbdata^;
  if pdwtype^=reg_binary then
    begin
    getmem(data,pcbdata^);
    CopyMemory(data,pvdata,pcbdata^);
    end;
  end;
freemem(pdwtype);
freemem(pvdata);
freemem(pcbdata);
except
on e:exception do raise exception.Create('getvalue error:'+e.message);
end;
end;

end.

