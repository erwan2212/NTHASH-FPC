unit usid;

{$mode delphi}

interface

uses
  windows,Classes, SysUtils,utils,uofflinereg;

//type tbytes=array of byte;



//function createbinaryform(sid:psid;buffer:tbytes;var len:dword):bool;

function GetCurrentUserTextSid: string;
function GetCurrentUserSid: TSID;
function GetAccountSid2(const Server, User: WideString; var Sid: PSID): DWORD;
function getsids(hive:string):boolean;



const
 HEAP_ZERO_MEMORY = $00000008;
SID_REVISION     = 1; // Current revision level



implementation

function ConvertSidToStringSid(SID: PSID; var StringSid: pchar): Boolean; stdcall;
    external 'advapi32.dll' name 'ConvertSidToStringSidA';

function ConvertStringSidToSid(StringSid: pchar; var Sid: PSID): BOOL; stdcall;
    external 'advapi32.dll' name 'ConvertStringSidToSidA';


//void CreateFromBinaryForm (IntPtr binaryForm, int length)
		{
			int revision = Marshal.ReadByte (binaryForm, 0);
			int numSubAuthorities = Marshal.ReadByte (binaryForm, 1);
			if (revision != 1 || numSubAuthorities > 15)
				throw new ArgumentException ("Value was invalid.");
			if (length < (8 + (numSubAuthorities * 4)))
				throw new ArgumentException ("offset");

			buffer = new byte[8 + (numSubAuthorities * 4)];
			Marshal.Copy (binaryForm, buffer, 0, buffer.Length);
		}
//https://github.com/mono/mono/blob/master/mcs/class/corlib/System.Security.Principal/SecurityIdentifier.cs
function createbinaryform(sid:psid;buffer:tbytes;var len:dword):bool;
var
  numSubAuthorities:BYTE;
  authority:ulong;
  subAuthority:uint;
  i,offset:integer;
  elements: TStrings;
  sid_:pchar;
begin
  numSubAuthorities:=sid^.SubAuthorityCount;
  setlength(buffer,8 + ( numSubAuthorities* 4));

  //string[] elements = sid.ToUpperInvariant ().Split ('-');
  ConvertSidToStringSid(sid ,sid_);
  elements := TStringList.Create;
  ExtractStrings(['-'],[],sid_,elements,false);
  authority:=strtoint(elements[2]);
buffer[0] := 1;
buffer[1] := byte(numSubAuthorities);
buffer[2] := byte((authority shr 40) and $FF);
buffer[3] := byte((authority shr 32) and $FF);
buffer[4] := byte((authority shr 24) and $FF);
buffer[5] := byte((authority shr 16) and $FF);
buffer[6] := byte((authority shr 8) and $FF);
buffer[7] := byte((authority shr 0) and $FF);

for i:=0 to numSubAuthorities-1 do
begin

  subAuthority:= strtoint(elements[i + 3]);

// Note sub authorities little-endian!
offset := 8 + (i * 4);
buffer[offset + 0] := byte(subAuthority shr 0);
buffer[offset + 1] := byte(subAuthority shr 8);
buffer[offset + 2] := byte(subAuthority shr 16);
buffer[offset + 3] := byte(subAuthority shr 24);
end;

end;

function ConvertSidtoString(Sid: PSID; pszSidText: PChar; var dwBufferLen: DWORD): BOOL;
var
  psia: PSIDIdentifierAuthority;
  dwSubAuthorities: DWORD;
  dwSidRev: DWORD;
  dwCounter: DWORD;
  dwSidSize: DWORD;
begin
  Result := False;

  dwSidRev := SID_REVISION;

  if not IsValidSid(Sid) then Exit;

  psia := GetSidIdentifierAuthority(Sid);

  dwSubAuthorities := GetSidSubAuthorityCount(Sid)^;

  dwSidSize := (15 + 12 + (12 * dwSubAuthorities) + 1) * SizeOf(Char);

  if (dwBufferLen < dwSidSize) then
  begin
    dwBufferLen := dwSidSize;
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    Exit;
  end;

  StrFmt(pszSidText, 'S-%u-', [dwSidRev]);

  if (psia.Value[0] <> 0) or (psia.Value[1] <> 0) then
    StrFmt(pszSidText + StrLen(pszSidText),
      '0x%.2x%.2x%.2x%.2x%.2x%.2x',
      [psia.Value[0], psia.Value[1], psia.Value[2],
      psia.Value[3], psia.Value[4], psia.Value[5]])
  else
    StrFmt(pszSidText + StrLen(pszSidText),
      '%u',
      [DWORD(psia.Value[5]) +
      DWORD(psia.Value[4] shl 8) +
      DWORD(psia.Value[3] shl 16) +
      DWORD(psia.Value[2] shl 24)]);

  dwSidSize := StrLen(pszSidText);

  for dwCounter := 0 to dwSubAuthorities - 1 do
  begin
    StrFmt(pszSidText + dwSidSize, '-%u',
      [GetSidSubAuthority(Sid, dwCounter)^]);
    dwSidSize := StrLen(pszSidText);
  end;

  Result := True;
end;

function ObtainSid(hToken: THandle; Sid_: TSID): BOOL;
var
  dwReturnLength: DWORD;
  dwTokenUserLength: DWORD;
  tic: TTokenInformationClass;
  ptu: Pointer;
begin
  Result := False;
  dwReturnLength := 0;
  dwTokenUserLength := 0;
  tic := TokenUser;
  ptu := nil;

  if not GetTokenInformation(hToken, tic, ptu, dwTokenUserLength,
    dwReturnLength) then
  begin
    if GetLastError = ERROR_INSUFFICIENT_BUFFER then
    begin
      ptu := HeapAlloc(GetProcessHeap, HEAP_ZERO_MEMORY, dwReturnLength);
      if ptu = nil then Exit;
      dwTokenUserLength := dwReturnLength;
      dwReturnLength    := 0;

      if not GetTokenInformation(hToken, tic, ptu, dwTokenUserLength,
        dwReturnLength) then Exit;
    end
    else
      Exit;
  end;

  sid_:=(PTokenUser(ptu).User).Sid^;

  if not HeapFree(GetProcessHeap, 0, ptu) then Exit;

  Result := True;
end;

function ObtainTextSid(hToken: THandle; pszSid: PChar;
  var dwBufferLen: DWORD): BOOL;
var
  dwReturnLength: DWORD;
  dwTokenUserLength: DWORD;
  tic: TTokenInformationClass;
  ptu: Pointer;
begin
  Result := False;
  dwReturnLength := 0;
  dwTokenUserLength := 0;
  tic := TokenUser;
  ptu := nil;

  if not GetTokenInformation(hToken, tic, ptu, dwTokenUserLength,
    dwReturnLength) then
  begin
    if GetLastError = ERROR_INSUFFICIENT_BUFFER then
    begin
      ptu := HeapAlloc(GetProcessHeap, HEAP_ZERO_MEMORY, dwReturnLength);
      if ptu = nil then Exit;
      dwTokenUserLength := dwReturnLength;
      dwReturnLength    := 0;

      if not GetTokenInformation(hToken, tic, ptu, dwTokenUserLength,
        dwReturnLength) then Exit;
    end
    else
      Exit;
  end;

  if not ConvertSidtoString((PTokenUser(ptu).User).Sid, pszSid, dwBufferLen) then Exit;

  if not HeapFree(GetProcessHeap, 0, ptu) then Exit;

  Result := True;
end;

function GetCurrentUserTextSid: string;
var
  hAccessToken: THandle;
  bSuccess: BOOL;
  dwBufferLen: DWORD;
  szSid: array[0..260] of Char;
begin
  Result := '';

  bSuccess := OpenThreadToken(GetCurrentThread, TOKEN_QUERY, True,
    hAccessToken);
  if not bSuccess then
  begin
    if GetLastError = ERROR_NO_TOKEN then
      bSuccess := OpenProcessToken(GetCurrentProcess, TOKEN_QUERY,
        hAccessToken);
  end;
  if bSuccess then
  begin
    ZeroMemory(@szSid, SizeOf(szSid));
    dwBufferLen := SizeOf(szSid);

    if ObtainTextSid(hAccessToken, szSid, dwBufferLen) then
      Result := szSid;
    CloseHandle(hAccessToken);
  end;
end;

function GetCurrentUserSid: TSID;
var
  hAccessToken: THandle;
  bSuccess: BOOL;
  dwBufferLen: DWORD;
  sid_:tsid;
begin
  Result.revision:=255;

  bSuccess := OpenThreadToken(GetCurrentThread, TOKEN_QUERY, True,
    hAccessToken);
  if not bSuccess then
  begin
    if GetLastError = ERROR_NO_TOKEN then
      bSuccess := OpenProcessToken(GetCurrentProcess, TOKEN_QUERY,
        hAccessToken);
  end;
  if bSuccess then
  begin

    if ObtainSid(hAccessToken, sid_) then
      Result := sid_;
    CloseHandle(hAccessToken);
  end;
end;

function GetAccountSid2(const Server, User: WideString; var Sid: PSID): DWORD;
var
  dwDomainSize, dwSidSize: DWord;
  R                 : LongBool;
  wDomain           : WideString;
  Use               : SID_NAME_USE; //DWord;
begin
  Result := 0;
  SetLastError(0);
  dwSidSize := 0;
  dwDomainSize := 0;
  R := LookupAccountNameW(PWideChar(Server), PWideChar(User), nil, dwSidSize,
    nil, dwDomainSize, Use);
  if (not R) and (GetLastError = ERROR_INSUFFICIENT_BUFFER) then
  begin
    SetLength(wDomain, dwDomainSize);
    Sid := GetMemory(dwSidSize);
    R := LookupAccountNameW(PWideChar(Server), PWideChar(User), Sid,
      dwSidSize, PWideChar(wDomain), dwDomainSize, Use);
    if not R then
    begin
      FreeMemory(Sid);
      Sid := nil;
    end;
  end
  else
    Result := GetLastError;
end;

procedure ConvertStringToSid (const sidName : string; sid : PSid; sidLen :DWORD);
var
  ps : PChar;
  pn : PChar;
  p : PChar;
  pa : PChar;
  valueStr : string;
  psia : PSIDIdentifierAuthority;
  i : DWORD;
  d : DWORD;
  authorityCount : DWORD;
begin
(*
typedef struct _SID {
   BYTE  Revision;
   BYTE  SubAuthorityCount;
   SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
#ifdef MIDL_PASS
   [size_is(SubAuthorityCount)] DWORD SubAuthority[*];
#else // MIDL_PASS
   DWORD SubAuthority[ANYSIZE_ARRAY];
*)
  if not ((Length (sidName) > 3) and (sidName [1] = 'S') and (sidName
[2] = '-')) then raise Exception.Create ('Bad SID');
  if sidLen < sizeof (_SID_IDENTIFIER_AUTHORITY) + 2 then raise Exception.Create ('Bad SID');
  ps := PChar (sid);
  pn := PChar (sidName);
  Inc (pn, 2);
  p := StrScan (pn, '-');
  if not Assigned (p) then raise Exception.Create ('Bad SID');
  p^ := #0;
  ps^ := char (StrToInt (pn)); // Revision
  Inc (ps);
  pa := ps;             // Save authority count position
  Inc (ps);
  pn := p + 1;
  p := StrScan (pn, '-');
  if not Assigned (p) then
    raise Exception.Create ('Bad SID');
  p^ := #0;
  valueStr := pn;
  if Length (valueStr) < 1 then
    raise Exception.Create ('Bad SID');
  psia := PSIDIdentifierAuthority (ps);
  Inc (ps, sizeof (_SID_IDENTIFIER_AUTHORITY));
  Dec (sidLen, 2 + sizeof (_SID_IDENTIFIER_AUTHORITY));
  if valueStr [1] = 'x' then
  begin
    if Length (valueStr) <> 14 then
      raise Exception.Create ('Bad SID');
    psia^.value [0] := StrToInt ('$' + Copy (valueStr, 3, 2));
    psia^.value [1] := StrToInt ('$' + Copy (valueStr, 5, 2));
    psia^.value [2] := StrToInt ('$' + Copy (valueStr, 7, 2));
    psia^.value [3] := StrToInt ('$' + Copy (valueStr, 9, 2));
    psia^.value [4] := StrToInt ('$' + Copy (valueStr, 11, 2));
    psia^.value [5] := StrToInt ('$' + Copy (valueStr, 13, 2))
  end
  else
  begin
    psia^.value [0] := 0;
    psia^.value [1] := 0;
    i := StrToInt (valueStr);
    d := i shl 24;
    psia^.value [2] := d and $ff;
    d := i shl 16;
    psia^.value [3] := d and $ff;
    d := i shl 8;
    psia^.value [4] := d and $ff;
    psia^.value [5] := i and $ff;
  end;
  pn := p + 1;
  authorityCount := 0;
  while lstrlen (pn) > 0 do
  begin
    p := StrScan (pn, '-');
    if Assigned (p) then
    begin
      p^ := #0;
      i := StrToInt (pn);
      pn := p + 1
    end
    else
    begin
      i := StrToInt (pn);
      pn := pn + lstrlen (pn)
    end;
    if sidLen < sizeof (DWORD) then
      raise Exception.Create ('Bad SID');
    PDWORD (ps)^ := i;
    Inc (ps, sizeof (DWORD));
    Dec (sidLen, sizeof (DWORD));
    Inc (authorityCount);
  end;
  pa^ := char (authorityCount);
  if not IsValidSID (sid) then
    raise Exception.Create ('Bad SID');
end;

function getsids(hive:string):boolean;
var
ret:dword;
lpname:pwidechar;
lpcname:pdword;
idx:word;
ws:widestring;
hkey,hkresult,hkresult2:thandle;
subkey:string;
data:pointer;
pdwtype,pcbdata:dword;
begin
subkey:='Microsoft\Windows NT\CurrentVersion\ProfileList';
pcbdata:=0;
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
    //log(string(ws),1);
      if ORGetValue (hkresult,pwidechar(ws),pwidechar(widestring('ProfileImagePath')),@pdwtype,nil,@pcbData)=0 then
        begin
        getmem(data,pcbdata );
        if ORGetValue (hkresult,pwidechar(ws),pwidechar(widestring('ProfileImagePath')),@pdwtype,data,@pcbData)=0 then
          begin
          log(ExtractFilename (stringreplace( BytetoAnsiString (data,pcbdata),chr(0),'',[rfReplaceAll]))+':'+string(ws),1);
          end;
        end;
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

