unit uvaults;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows,utils;

type _VAULT_BYTE_BUFFER =record
	 Length:DWORD;
	 Value:PBYTE;
        end;
PVAULT_BYTE_BUFFER=^_VAULT_BYTE_BUFFER;

type _VAULT_ITEM_TYPE =record
	 ItemType:GUID;
	 FriendlyName:PVOID;
	 unk1:PVOID;
	 unk2:PVOID;
	 unk3:PVOID;
	 cbUnk:DWORD;
	 Unk:PVOID;
end;
PVAULT_ITEM_TYPE=^ _VAULT_ITEM_TYPE;

type _VAULT_ITEM_DATA =record
	 SchemaElementId:DWORD;
	 unk0:DWORD;
	 Type_:_VAULT_ITEM_TYPE;
	 unk1:DWORD;
	//union of different types...
	 String_:LPWSTR;
end;
PVAULT_ITEM_DATA=^_VAULT_ITEM_DATA;

type _VAULT_ITEM_8 =record
	 SchemaId:GUID;
	 FriendlyName:PWIDECHAR; //PWSTR;
	 Ressource:pointer; //PVAULT_ITEM_DATA;
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
VAULTENUMERATEVAULTS:function ( unk0:DWORD; cbVault:PDWORD; out vaultguids:LPGUID):dword;stdcall;
VAULTFREE:function (memory:pvoid):dword;
VAULTOPENVAULT:function (vaultGUID:guid; unk0:dword; out vault:phandle):dword;stdcall;
VAULTCLOSEVAULT:function (vault:PHANDLE):dword;stdcall;
VAULTGETINFORMATION:function ( vault:handle; unk0:dword;  informations:pointer{PVAULT_INFORMATION}):dword;stdcall;
VAULTENUMERATEITEMS:function (vault:phandle; unk0:dword;  cbItems:PDWORD; out items:PVOID):dword;stdcall;
VAULTENUMERATEITEMTYPES:function (vault:handle; unk0:dword; cbItemTypes:PDWORD;itemTypes:PVAULT_ITEM_TYPE):dword;stdcall;
VAULTGETITEM7:function (vault:handle; SchemaId:LPGUID; Resource:pointer{PVAULT_ITEM_DATA};Identity:pointer{PVAULT_ITEM_DATA}; hWnd:hwnd;  Flags:dword;  pItem:pointer {PVAULT_ITEM_7}):dword;stdcall;
VAULTGETITEM8:function (vault:handle; SchemaId:LPGUID; Resource:pointer{PVAULT_ITEM_DATA};Identity:pointer{PVAULT_ITEM_DATA}; PackageSid:pointer{PVAULT_ITEM_DATA}; hWnd:hwnd;  Flags:dword;  pItem:pointer {PVAULT_ITEM_8}):dword;stdcall;

function Init:boolean;
function enum:boolean;

implementation

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


function Init:boolean;
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
    if result=false then log('vault init=false');
end;

//check against vaultcmd

function enum:boolean;
var
  i,j,cbvaults,cbItems:dword;
  //vaults:array [0..254] of lpguid;
  status:dword;
  //hvault:handle;
  hvault:phandle;
  //items:array[0..254] of pvoid;
  pvaults,pitems,ptr,ptr2:pointer;
  pitem8:PVAULT_ITEM_8 ;
begin
    //fillchar(vaults,sizeof(vaults),0);
    //status := VaultEnumerateVaults(0, @cbVaults, @vaults[0]);
    status := VaultEnumerateVaults(0, @cbVaults, pvaults);
		if(status = 0) then
                begin
                ptr:=pvaults;
                log('VaultEnumerateVaults OK, '+inttostr(cbvaults));
                for i:= 0 to cbVaults-1 do
                    begin
                    log('item:'+inttostr(i));
                    log(GUIDToString ( tguid(ptr^)));
                    begin
                    //if VaultOpenVault(vaults[i]^, 0, @hVault)=0 then
                    if VaultOpenVault(tguid(ptr^), 0, hVault)=0 then
                       begin
                       log('VaultOpenVault OK');
                       //if VaultEnumerateItems(hVault, $200, @cbItems, @items[0])=0 then
                       if VaultEnumerateItems(hVault, $200, @cbItems, pitems)=0 then
                          begin
                          log('VaultEnumerateItems OK, '+inttostr(cbitems));
                          ptr2:=pitems;
                          for j:=0 to cbItems -1 do
                              begin
                              //log( PVAULT_ITEM_8(ptr).FriendlyName  );
                              {
                              if VaultGetItem8(hVault, PVAULT_ITEM_8(ptr).SchemaId, PVAULT_ITEM_8(ptr).Ressource, PVAULT_ITEM_8(ptr).Identity, PVAULT_ITEM_8(ptr).PackageSid,0, 0, pItem8);
                                 then log('GetItemW8 OK')
                                 else log('GetItemW8 NOT OK');
                              }
                              end; //for j
                          inc(ptr2);
                          //VaultFree(@items[0]);
                          end; //VaultEnumerateItems
                       VaultCloseVault(hVault);
                       end//VaultOpenVault
                       else log('VaultOpenVault NOT OK, '+inttostr(getlasterror));
                    end; //if nativeuint(vaults[i])<>0 then
                    inc(nativeuint(ptr));
                    end; //for i
                VaultFree(pvaults);
                end //VaultEnumerateVaults
                else log('VaultEnumerateVaults NOT OK')

end;

end.

