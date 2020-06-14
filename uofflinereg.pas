unit uofflinereg;

{$mode delphi}

interface

uses
  Windows,Classes, SysUtils,utils;

function init:boolean;
function MyOrQueryValue(hive:string;subkey:string;value:string;var data:tbytes):boolean;
function MyOrEnumKeys(hive:string;subkey:string):boolean;
function getvaluePTR(key:thandle;svaluename:string;var data:pointer):longword;


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
  log('**** uofflinereg.init ****');
  result:=false;
  try
  //lib:=0;
  if lib>0 then begin {log('lib<>0');} result:=true; exit;end;
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
  //log('init:'+BoolToStr (result,'true','false'));
  end;

  function getvaluePTR(key:thandle;svaluename:string;var data:pointer):longword;
var
ret:dword;
wvaluename:array[0..255] of widechar;
pvdata:pointer=nil;
//pdwtype,pcbData:pdword;
pdwtype,pcbdata:dword;
//b:array of byte;
begin
result:=0;
try

fillchar(wvaluename,sizeof(wvaluename),#0);
StringToWideChar(svaluename, wvaluename, length(svaluename)+1);

pcbdata:=0;

ret:=ORGetValue (key,nil,wvaluename,@pdwtype,nil,@pcbData);
if ret<>0 then raise exception.Create('ORGetValue '+svaluename+' NOT OK:'+inttostr(ret)+':'+SysErrorMessage(ret));

if (pcbData=0) then
    begin
    log('pcbData=0');
    exit;
    end;

getmem(data,pcbdata );
ret:=ORGetValue (key,nil,wvaluename,@pdwtype,data,@pcbData);
if ret<>0 then raise exception.Create('ORGetValue failed:'+inttostr(ret)+':'+SysErrorMessage(ret))
  else
  begin

  log('pdwtype:'+inttostr(pdwtype));
  log('pcbData:'+inttostr(pcbData));


  if data=nil then
    begin
    log('data=nil');
    exit;
    end;

  if (pdwtype=reg_binary) or (pdwtype=reg_none) then
    begin
    result:=pcbdata;
    end
    else result:=0;
  end;

except
on e:exception do raise exception.Create('getvalue error:'+e.message);
end;
end;

function MyOrQueryValue(hive:string;subkey:string;value:string;var data:tbytes):boolean;
var
  ret:word;
  hkey,hkresult:thandle;
  cbdata:longword;
  ptr:pointer=nil;
begin
log('**** MyOrQueryValue ****');
result:=false;

if not uofflinereg.init then exit;

log('hive:'+hive);
ret:=OROpenHive(pwidechar(widestring(hive)),hkey);
if ret<>0 then begin log('OROpenHive '+hive+' NOT OK',1);exit;end;

log('subkey:'+subkey);
ret:=OROpenKey (hkey,pwidechar(widestring(subkey)),hkresult);
if ret<>0 then begin log('OROpenKey '+subkey+' NOT OK',1);exit;end;

log('value:'+value);
cbdata:=getvaluePTR (hkresult,value,ptr);
if cbdata<>0 then
   begin
   setlength(data,cbdata);
   copymemory(@data[0],ptr,cbdata);
   result:=true;
   end
   else log('cbdata:'+inttostr(cbdata));
if ptr<>nil then freemem(ptr);


try if hkresult>0 then ret:=ORcloseKey (hkresult);except end;
try if hkey>0 then ret:=ORCloseHive (hkey);except end;

//ugly try/except as it seems to crash randomly

end;

function MyOrEnumKeys(hive:string;subkey:string):boolean;
var
ret:dword;
lpname:pwidechar;
lpcname:pdword;
idx:word;
ws:widestring;
hkey,hkresult:thandle;
begin
//
log('**** MyOrEnumKeys ****');
result:=false;

if not uofflinereg.init then exit;

log('hive:'+hive);
ret:=OROpenHive(pwidechar(widestring(hive)),hkey);
if ret<>0 then begin log('OROpenHive '+hive+' NOT OK',0);exit;end;

log('subkey:'+subkey);
ret:=OROpenKey (hkey,pwidechar(widestring(subkey)),hkresult);
if ret<>0 then begin log('OROpenKey '+subkey+' NOT OK',0);exit;end;
//
try
idx:=0;
getmem(lpname,256);
getmem(lpcname ,sizeof(dword));
ret:=0;
while ret=0 do
  begin
  lpcname^:=256;
  ret:=OREnumKey(hkresult,idx,lpname,lpcname,nil,nil,nil);
  if ret=0 then
    begin
    setlength(ws,lpcname^);
    copymemory(@ws[1],lpname,lpcname^*2);
    //list.Add (string(ws));
    log(string(ws),1);
    inc(idx);
    end;//if ret=0 then
  end;//while ret=0 do
if idx>0 then result:=true else log('OREnumKey failed:'+inttostr(ret)+':'+SysErrorMessage(ret));
except
on e:exception do log('EnumKeys error:'+e.message);
end;

try if hkresult>0 then ret:=ORcloseKey (hkresult);except end;
try if hkey>0 then ret:=ORCloseHive (hkey);except end;

end;

end.

