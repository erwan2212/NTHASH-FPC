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

var
VAULTENUMERATEVAULTS:function ( unk0:DWORD; cbVault:PDWORD; vaultguids:LPGUID):dword;stdcall;
VAULTFREE:function (memory:pvoid):dword;
VAULTOPENVAULT:function (vaultGUID:guid; unk0:dword; vault:phandle):dword;stdcall;
VAULTCLOSEVAULT:function ( vault:PHANDLE):dword;stdcall;
VAULTGETINFORMATION:function ( vault:handle; unk0:dword;  informations:pointer{PVAULT_INFORMATION}):dword;stdcall;
VAULTENUMERATEITEMS:function (vault:handle; unk0:dword;  cbItems:PDWORD; items:PVOID):dword;stdcall;
VAULTENUMERATEITEMTYPES:function (vault:handle; unk0:dword; cbItemTypes:PDWORD;itemTypes:PVAULT_ITEM_TYPE):dword;stdcall;
VAULTGETITEM7:function (vault:handle; SchemaId:LPGUID; Resource:pointer{PVAULT_ITEM_DATA};Identity:pointer{PVAULT_ITEM_DATA}; hWnd:hwnd;  Flags:dword;  pItem:pointer {PVAULT_ITEM_7}):dword;stdcall;
VAULTGETITEM8:function (vault:handle; SchemaId:LPGUID; Resource:pointer{PVAULT_ITEM_DATA};Identity:pointer{PVAULT_ITEM_DATA}; PackageSid:pointer{PVAULT_ITEM_DATA}; hWnd:hwnd;  Flags:dword;  pItem:pointer {PVAULT_ITEM_8}):dword;stdcall;

function Init:boolean;
function enum:boolean;

implementation

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
end;


function enum:boolean;
var
  i,cbvaults,cbItems:dword;
  vaults:array [0..254] of guid;
  status:dword;
  hvault:handle;
  items:pvoid;
begin

    status := VaultEnumerateVaults(0, @cbVaults, @vaults);
		if(status = 0) then
                begin
                log('VaultEnumerateVaults OK');
                for i:= 0 to cbVaults-1 do
                    begin
                    if VaultOpenVault(vaults[i], 0, @hVault)=0 then
                       begin
                       if VaultEnumerateItems(hVault, $200, @cbItems, items)=0 then
                          begin

                          end; //VaultEnumerateItems
                       end;//VaultOpenVault
                    end; //for
                end //VaultEnumerateVaults
                else log('VaultEnumerateVaults NOT OK')

end;

end.

