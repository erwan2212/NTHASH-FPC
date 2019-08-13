unit ucryptoapi;

{$mode delphi}

interface



uses
  Classes, SysUtils,JwaWinCrypt;

const
PROV_RSA_AES = 24;

implementation

procedure doSomeEncryption();
var
  HASHOBJ: HCRYPTHASH;
  hProv: HCRYPTPROV;
  bHash: tBytes;
  dwHashBytes: DWORD;
begin
  if not CryptAcquireContext(hProv, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) then
    raiseLastOsError;

  if not CryptCreateHash(hProv, CALG_SHA, 0, 0, HASHOBJ) then
    raiseLastOsError;

  // Your encrypt stuff here
  //CryptEncrypt(yourHKey, HASHOBJ, ...) //

  setLength(bHash, 255);  // Allocate the buffer
  if CryptGetHashParam(HASHOBJ, HP_HASHVAL, @bHash[0], dwHashBytes, 0) then
  begin
    setLength(bHash, dwHashBytes);  // bHash now contains the hash bytes
  end
  else
    setLength(bHash, 0);

  //  Release HASHOBJ
  CryptDestroyHash(HASHOBJ);

  //  Release Provider Context
  CryptReleaseContext(hProv, 0);

end;

{
function crypto_genericAES128Decrypt(pKey,pIV,pData:pointer;dwDataLen:dword;pOut:pointer;var dwOutLen:dword):boolean;

  var
	 status:boolean = FALSE;
	 hProv:HCRYPTPROV;
	 hKey:HCRYPTKEY;
	 mode :DWORD= CRYPT_MODE_CBC;
 begin
	if(CryptAcquireContext(hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) then
	begin
		if(kull_m_crypto_hkey(hProv, CALG_AES_128, pKey, 16, 0, &hKey, NULL))
		begin
			if(CryptSetKeyParam(hKey, KP_MODE, (LPCBYTE) &mode, 0))
			begin
				if(CryptSetKeyParam(hKey, KP_IV, (LPCBYTE) pIV, 0))
				begin
					if (pOut = LocalAlloc(LPTR, dwDataLen))
					begin
						*dwOutLen = dwDataLen;
						RtlCopyMemory(pOut, pData, dwDataLen);
						if(!(status = CryptDecrypt(hKey, 0, TRUE, 0, (PBYTE) *pOut, dwOutLen)))
						begin
							writeln('CryptDecrypt");
							*pOut = LocalFree(pOut);
							*dwOutLen = 0;
						end
					end
				end
				else writeln('CryptSetKeyParam (IV)');
			end
			else writeln('CryptSetKeyParam (MODE)');
			CryptDestroyKey(hKey);
		end
		else writeln('kull_m_crypto_hkey');
		CryptReleaseContext(hProv, 0);
	end
	else writeln('CryptAcquireContext');
	return status;
end;
}

end.

