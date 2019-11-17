unit ucryptoapi;

{$mode delphi}

interface



uses
  windows,Classes, SysUtils,JwaWinCrypt,jwabcrypt,utils;


function DecryptAES128(const Key: tbyte16;const IV:array of byte;const data: tbyte16;var output:tbyte16): boolean;
function EnCryptDecrypt(algid:dword;key: string;var buffer:tbytes;const decrypt:boolean=false):boolean;

function bdecrypt(algo:lpcwstr;encryped:array of byte;output:pointer;const gKey,initializationVector:array of byte):ULONG;
function bencrypt(algo:lpcwstr;decrypted:array of byte;output:pointer;const gKey,initializationVector:array of byte):ULONG;

function CryptProtectData_(dataBytes:array of byte;var output:tbytes):boolean;overload;
function CryptProtectData_(dataBytes:array of byte;filename:string):boolean;overload;

function CryptUnProtectData_(filename:string;var dataBytes:tbytes;const AdditionalEntropy: string=''):boolean;overload;
function CryptUnProtectData_(buffer:tbytes;var output:tbytes;const AdditionalEntropy: string=''):boolean;overload;

function decodeblob(filename:string):boolean;
function decodemk(filename:string):boolean;

function crypto_hash(algid:alg_id;data:lpbyte;dataLen:DWORD; var output:tbytes;hashWanted:DWORD):boolean;

type
 PCREDENTIAL_ATTRIBUTEW = ^_CREDENTIAL_ATTRIBUTEW;
  _CREDENTIAL_ATTRIBUTEW = record
    Keyword: LPWSTR;
    Flags: DWORD;
    ValueSize: DWORD;
    Value: LPBYTE;
  end;


  PCREDENTIALW = ^_CREDENTIALW;
  _CREDENTIALW = record
    Flags: DWORD;
    Type_: DWORD;
    TargetName: LPWSTR;
    Comment: LPWSTR;
    LastWritten: FILETIME;
    CredentialBlobSize: DWORD;
    dummy : dword;
    CredentialBlob: LPBYTE;
    Persist: DWORD;
    AttributeCount: DWORD;
    Attributes: PCREDENTIAL_ATTRIBUTEW;
    TargetAlias: LPWSTR;
    UserName: LPWSTR;
  end;

PCredentialArray = array of PCREDENTIALW;

//https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id
const
  CALG_RC2 =    $00006602;
  CALG_RC4=	$00006801;
  CALG_RC5=     $0000660d;
  CALG_DES=	$00006601;
  CALG_DESX=	$00006604;
  CALG_3DES=	$00006603;
  CALG_AES=	$00006611;
  CALG_AES_128=	$0000660e;
  CALG_AES_192=	$0000660f;
  CALG_AES_256=	$00006610;
  //hash
  CALG_HMAC=	$00008009;
  CALG_MAC=	$00008005;

implementation



type _NT6_CLEAR_SECRET =record
	SecretSize:DWORD;
	unk0:DWORD;
	unk1:DWORD;
	unk2:DWORD;
	Secret:array[0..0] of byte;
        end;
NT6_CLEAR_SECRET=_NT6_CLEAR_SECRET;
PNT6_CLEAR_SECRET=^NT6_CLEAR_SECRET;

//#define LAZY_NT6_IV_SIZE	32
//#define ANYSIZE_ARRAY 1
type _NT6_HARD_SECRET =record
	version:DWORD;
	KeyId:GUID;
	algorithm:DWORD;
	flag:DWORD;
	lazyiv:array [0..32-1] of byte;
	//union
	clearSecret:NT6_CLEAR_SECRET;
	encryptedSecret:array [0..0] of byte;
        end;
 NT6_HARD_SECRET=_NT6_HARD_SECRET;
 PNT6_HARD_SECRET=^NT6_HARD_SECRET;

 type _PUBLICKEYSTRUC =record
            bType:BYTE;
            bVersion:BYTE;
            reserved:WORD;
            aiKeyAlg:ALG_ID;
 end;
 BLOBHEADER=_PUBLICKEYSTRUC;
 PUBLICKEYSTRUC=_PUBLICKEYSTRUC;

 type _GENERICKEY_BLOB =record
	 Header:BLOBHEADER;
	 dwKeyLen:DWORD;
end;
   GENERICKEY_BLOB=_GENERICKEY_BLOB;
   PGENERICKEY_BLOB=^GENERICKEY_BLOB;

type
  //{$align 8}
  _MY_BLOB = record
    cbData: DWORD;
    pbData: LPBYTE;
  end;

const
PROV_RSA_AES = 24;
const
BCRYPT_CHAIN_MODE_CBC_:widestring       = 'ChainingModeCBC';
BCRYPT_CHAIN_MODE_ECB_:widestring       = 'ChainingModeECB';
BCRYPT_CHAIN_MODE_CFB_:widestring       = 'ChainingModeCFB';
BCRYPT_CHAINING_MODE_:widestring        = 'ChainingMode';


procedure RtlCopyMemory(Destination: PVOID; Source: PVOID; Length: SIZE_T); stdcall;
begin
  Move(Source^, Destination^, Length);
end;


//https://stackoverflow.com/questions/13145112/secure-way-to-store-password-in-windows

function CryptProtectData_(dataBytes:array of byte;var output:tbytes):boolean;overload;
var
  plainBlob,encryptedBlob:DATA_BLOB;
begin
  fillchar(plainBlob,sizeof(DATA_BLOB),0);
  fillchar(encryptedBlob,sizeof(DATA_BLOB),0);

  plainBlob.pbData := dataBytes;
  plainBlob.cbData := sizeof(dataBytes);

  result:=CryptProtectData(@plainBlob, nil, nil, nil, nil, 0 {CRYPTPROTECT_LOCAL_MACHINE}, @encryptedBlob);
  if result=true then
     begin
     setlength(output,encryptedBlob.cbData);
     CopyMemory (@output[0],encryptedBlob.pbData,encryptedBlob.cbData);
     end;
end;

function CryptProtectData_(dataBytes:array of byte;filename:string):boolean;overload;
var
  plainBlob,encryptedBlob:_MY_BLOB;
  outfile:thandle=0;
  byteswritten:dword=0;
  //
  text:string;

begin
  result:=false;
  fillchar(plainBlob,sizeof(plainBlob),0);
  fillchar(encryptedBlob,sizeof(encryptedBlob),0);

  outFile := CreateFile(pchar(filename), GENERIC_WRITE, 0, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if outfile<=0 then exit;

  plainBlob.pbData := @dataBytes[0];
  plainBlob.cbData := length(dataBytes);
  log('length in:'+inttostr(length(dataBytes)));

  //test
  {
  text:='password';
  plainBlob.cbData := SizeOf(Char)*Length(Text);
  plainBlob.pbData := Pointer(LocalAlloc(LPTR, plainBlob.cbData));
  Move(Pointer(Text)^, plainBlob.pbData^, plainBlob.cbData);
  }

  result:=CryptProtectData(@plainBlob, nil, nil, nil, nil, 0 {CRYPTPROTECT_LOCAL_MACHINE}, @encryptedBlob);
  log('cbData:'+inttostr(encryptedBlob.cbData) );
  if result=true then
     begin
     result:=WriteFile(outFile, encryptedBlob.pbData^, encryptedBlob.cbData, byteswritten, nil);
     log('byteswritten:'+inttostr(byteswritten));
     end;

  closehandle(outfile);

end;

function decodemk(filename:string):boolean;
var
  buffer:array[0..4095] of byte;
  outfile:thandle=0;
  bytesread:cardinal;
  MasterKeyLen,offset:word;
  dw:dword;
  pw:pwidechar;
  bytes:tbytes;
begin
  //
  outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
  if outfile=thandle(-1) then log('CreateFile:'+inttostr(getlasterror));
  if outfile=thandle(-1) then exit;
  bytesread:=0;
  result:=readfile(outfile ,buffer,4096,bytesread,nil);
  closehandle(outfile);
  //
  offset:=0;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwVersion:'+inttohex(dw,4));
  inc(offset,4);
  //
  inc(offset,8); //dummy
  //
  pw:=AllocMem ($48);
  CopyMemory(pw,@buffer[offset],$48);
  writeln('szGuid:'+string(widestring(pw)));
  inc(offset,$48);
  //
  inc(offset,8); //dummy
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwFlags:'+inttohex(dw,4));
  inc(offset,4);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwMasterKeyLen:'+inttohex(dw,4));
  inc(offset,4);
  MasterKeyLen:=dw-32;
  //
  inc(offset,4); //dummy
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwBackupKeyLen:'+inttohex(dw,4));
  inc(offset,4);
  //
  inc(offset,4); //dummy
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwCredHistLen:'+inttohex(dw,4));
  inc(offset,4);
  //
  inc(offset,4); //dummy
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwDomainKeyLen:'+inttohex(dw,4));
  inc(offset,4);
  //
  inc(offset,4); //dummy
  //
  writeln('MasterKey');
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwVersion:'+inttohex(dw,4));
  inc(offset,4);
  //
  SetLength(bytes,16);;
  CopyMemory (@bytes[0],@buffer[offset],16);
  writeln('Salt:'+ByteToHexaString(bytes));
  inc(offset,16);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('rounds:'+inttohex(dw,4));
  inc(offset,4);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('algHash:'+inttohex(dw,4));
  inc(offset,4);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('algCrypt:'+inttohex(dw,4));
  inc(offset,4);
  //
  SetLength(bytes,MasterKeyLen);;
  CopyMemory (@bytes[0],@buffer[offset],MasterKeyLen);
  writeln('pbKey:'+ByteToHexaString(bytes));
  inc(offset,MasterKeyLen);
  //
end;

function decodeblob(filename:string):boolean;
const
marker:array[0..15] of byte=($D0,$8C,$9D,$DF,$01,$15,$D1,$11,$8C,$7A,$00,$C0,$4F,$C2,$97,$EB);
var
  buffer:array[0..4095] of byte;
  outfile:thandle=0;
  bytesread:cardinal;
  i,offset:word;
  guid:tguid;
  dw:dword;
  pw:pwidechar;
  bytes:tbytes;
begin
  //
  outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
  if outfile=thandle(-1) then log('CreateFile:'+inttostr(getlasterror));
  if outfile=thandle(-1) then exit;
  bytesread:=0;
  result:=readfile(outfile ,buffer,4096,bytesread,nil);
  closehandle(outfile);
  if result=false then exit;
  if bytesread=0 then exit;
  //
  offset:=0;
  for i:=0 to 32 do
      begin
        if CompareMem (@buffer[i],@marker[0],16) then begin offset:=i;break;end;
      end;
  if offset=0 then exit;
  //
  CopyMemory( @dw,@buffer[offset-4],sizeof(dw));
  writeln('dwVersion:'+inttohex(dw,4));
  //
  CopyMemory( @guid,@buffer[offset],sizeof(guid));
  writeln('GuidProvider:'+GUIDToString(guid));
  inc(offset,16);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwMasterKeyVersion:'+inttohex(dw,4));
  inc(offset,4);
  //
  CopyMemory( @guid,@buffer[offset],sizeof(guid));
  writeln('GuidMasterKey:'+GUIDToString(guid));
  inc(offset,16);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwFlags:'+inttohex(dw,4));
  inc(offset,4);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwDescriptionLen:'+inttostr(dw));
  inc(offset,4);
  if dw>0 then
     begin
     pw:=AllocMem (dw);
     copymemory(pw,@buffer[offset],dw);
     //writeln('szDescription:'+(  StringReplace ( string(widestring(pw)),'#13#10','',[]) ));
     writeln('szDescription:'+(  string(widestring(pw)) ));
     inc(offset,dw);
     end;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('algCrypt:'+inttohex(dw,sizeof(dw)));
  inc(offset,4);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwAlgCryptLen:'+inttohex(dw,sizeof(dw)));
  inc(offset,4);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwSaltLen:'+inttohex(dw,sizeof(dw)));
  inc(offset,4);
  if dw>0 then
     begin
     SetLength(bytes,dw);;
     CopyMemory (@bytes[0],@buffer[offset],dw);
     writeln('pbSalt:'+ByteToHexaString(bytes));
     inc(offset,dw);
     end;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwHmacKeyLen:'+inttohex(dw,sizeof(dw)));
  inc(offset,4);
  if dw>0 then
     begin
     SetLength(bytes,dw);;
     CopyMemory (@bytes[0],@buffer[offset],dw);
     writeln('pbHmackKey:'+ByteToHexaString(bytes));
     inc(offset,dw);
     end;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('algHash:'+inttohex(dw,sizeof(dw)));
  inc(offset,4);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('algHadwAlgHashLensh:'+inttohex(dw,sizeof(dw)));
  inc(offset,4);
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwHmac2KeyLen:'+inttohex(dw,sizeof(dw)));
  inc(offset,4);
  if dw>0 then
     begin
     SetLength(bytes,dw);;
     CopyMemory (@bytes[0],@buffer[offset],dw);
     writeln('pbHmack2Key:'+ByteToHexaString(bytes));
     inc(offset,dw);
     end;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwDataLen:'+inttohex(dw,sizeof(dw)));
  inc(offset,4);
  if dw>0 then
     begin
     SetLength(bytes,dw);;
     CopyMemory (@bytes[0],@buffer[offset],dw);
     writeln('pbData:'+ByteToHexaString(bytes));
     inc(offset,dw);
     end;
  //
  CopyMemory( @dw,@buffer[offset],sizeof(dw));
  writeln('dwSignLen:'+inttohex(dw,sizeof(dw)));
  inc(offset,4);
  if dw>0 then
     begin
     SetLength(bytes,dw);;
     CopyMemory (@bytes[0],@buffer[offset],dw);
     writeln('pbSign:'+ByteToHexaString(bytes));
     inc(offset,dw);
     end;
end;

{
function crypto_hash_hmac(calgid:DWORD; key:LPCVOID;keyLen:DWORD; message:LPCVOID; messageLen:DWORD; hash:LPVOID;hashWanted:DWORD ):boolean;
var
	 status:BOOL = FALSE;
	 hashLen:DWORD;
	 hProv:HCRYPTPROV;
	 hKey:HCRYPTKEY;
	 hHash:HCRYPTHASH;
	 HmacInfo:HMAC_INFO; // = (calgid, nil, 0, nil, 0);
	 buffer:PBYTE;
begin
  fillchar(HmacInfo ,sizeof(HmacInfo ),0);
  HmacInfo.HashAlgid :=calgid ;
	if CryptAcquireContext(hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
	begin
		if(kull_m_crypto_hkey(hProv, CALG_RC2, key, keyLen, CRYPT_IPSEC_HMAC_KEY, &hKey, NULL)) then
		begin
			if(CryptCreateHash(hProv, CALG_HMAC, hKey, 0, hHash))
			begin
				if(CryptSetHashParam(hHash, HP_HMAC_INFO, (LPCBYTE) &HmacInfo, 0)) then
					if(CryptHashData(hHash, (LPCBYTE) message, messageLen, 0)) then
                                        begin
						if(CryptGetHashParam(hHash, HP_HASHVAL, NULL, &hashLen, 0)) then
						begin
							if(buffer = (PBYTE) LocalAlloc(LPTR, hashLen)) then
							begin
								status = CryptGetHashParam(hHash, HP_HASHVAL, buffer, &hashLen, 0);
								RtlCopyMemory(hash, buffer, min(hashLen, hashWanted));
								LocalFree(buffer);
							end; //if buffer
						end;//CryptGetHashParam
						CryptDestroyHash(hHash);
                                                end; //CryptHashData
			end; //CryptCreateHash
			CryptDestroyKey(hKey);
		end; //kull_m_crypto_hkey
		CryptReleaseContext(hProv, 0);
	end; //CryptAcquireContext
	return status;
end;
}

function crypto_hash(algid:alg_id;data:lpbyte;dataLen:DWORD;  var output:tbytes;hashWanted:DWORD):boolean;
var
  hProv:HCRYPTPROV;
  hashLen:DWORD;
  buffer:PBYTE;
  status:bool = FALSE;
  hHash: HCRYPTHASH;
begin
  //writeln(inttohex(CALG_SHA1,4));writeln(inttohex(CALG_MD4,4));writeln(inttohex(CALG_MD5,4));
  result:=false;
  if CryptAcquireContext(hProv, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
  	begin
        log('CryptAcquireContext OK');
  		if CryptCreateHash(hProv, algid, 0, 0, hHash) then
  		begin
                log('CryptCreateHash OK');
  			if CryptHashData(hHash, data, dataLen, 0) then
  			begin
                        log('CryptHashData OK');
  				if CryptGetHashParam(hHash, HP_HASHVAL, nil, hashLen, 0) then
  				begin
                                log('CryptGetHashParam OK:'+inttostr(hashLen));
                                buffer:=Pointer(LocalAlloc(LPTR, hashLen));
  					if buffer<>nil  then
  					begin
                                        log('LocalAlloc OK');
  						result := CryptGetHashParam(hHash, HP_HASHVAL, buffer, hashLen, 0);
                                                log('CryptGetHashParam:'+BoolToStr(result,true));
                                                //RtlCopyMemory(pointer(hash), buffer, min(hashLen, hashWanted));
                                                log('hashLen:'+inttostr(hashLen));
                                                log('hashashWantedhLen:'+inttostr(hashWanted));
                                                //log(inttohex(hHash,sizeof(pointer)));
                                                setlength(output,min(hashLen, hashWanted));
                                                CopyMemory (@output[0], buffer, min(hashLen, hashWanted));
                                                //log('HASH:'+ByteToHexaString (buffer^),1);
                                                //
                                                LocalFree(thandle(buffer));
  					end;//if(buffer = (PBYTE) LocalAlloc(LPTR, hashLen))
  				end; //CryptGetHashParam
  			end; //CryptHashData
  			CryptDestroyHash(hHash);
  		end; //CryptCreateHash
  		CryptReleaseContext(hProv, 0);
        end; //CryptAcquireContext

end;

function CryptUnProtectData_(filename:string;var dataBytes:tbytes;const AdditionalEntropy: string=''):boolean;overload;
var
  plainBlob,decryptedBlob:_MY_BLOB;
  outfile:thandle=0;
  byteswritten:dword=0;
  //
  text:string;
  buffer:array[0..4095] of byte;
  bytesread:cardinal;
  //
  entropyBlob: DATA_BLOB;
  pEntropy: Pointer;
begin
  result:=false;
  fillchar(plainBlob,sizeof(plainBlob),0);
  fillchar(decryptedBlob,sizeof(decryptedBlob),0);

  if not FileExists(filename) then log('filename does not exist');

  outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL , 0);
  //if outfile=thandle(-1) then outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL or FILE_ATTRIBUTE_HIDDEN , 0);
  //if outfile=thandle(-1) then outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL or FILE_ATTRIBUTE_HIDDEN or FILE_ATTRIBUTE_ARCHIVE, 0);
  //if outfile=thandle(-1) then outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL or FILE_ATTRIBUTE_HIDDEN or FILE_ATTRIBUTE_ARCHIVE or FILE_ATTRIBUTE_SYSTEM, 0);
  if outfile=thandle(-1) then log('CreateFile:'+inttostr(getlasterror));
  if outfile=thandle(-1) then exit;
  result:=readfile(outfile ,buffer,4096,bytesread,nil);
  if (result=false) or (bytesread=0) then log('readfile:'+inttostr(getlasterror)+' '+inttostr(outfile));
  log('bytesread:'+inttostr(bytesread));

  if AdditionalEntropy <> '' then
    begin
        entropyBlob.pbData := Pointer(AdditionalEntropy);
        entropyBlob.cbData := Length(AdditionalEntropy)*SizeOf(Char);
        pEntropy := @entropyBlob;
    end
    else
        pEntropy := nil;

  plainBlob.pbData := @buffer[0];
  //plainBlob.pbData:=getmem(bytesread);
  //copymemory(plainBlob.pbData,@buffer[0],bytesread);
  plainBlob.cbData := bytesread;
  log('plainBlob.cbData:'+inttostr(plainBlob.cbData) );

  //test
  {
  text:='password';
  plainBlob.cbData := SizeOf(Char)*Length(Text);
  plainBlob.pbData := Pointer(LocalAlloc(LPTR, plainBlob.cbData));
  Move(Pointer(Text)^, plainBlob.pbData^, plainBlob.cbData);
  }

  decryptedBlob.pbData :=nil; //getmem(4096); //@databytes[0];

  //3rd param is entropy
  //5th param is password
  result:=CryptunProtectData(@plainBlob, nil, pEntropy, nil, nil, 0{CRYPTPROTECT_LOCAL_MACHINE}, @decryptedBlob);
  if result=false then result:=CryptunProtectData(@plainBlob, nil, pEntropy, nil, nil, CRYPTPROTECT_LOCAL_MACHINE, @decryptedBlob);

  log('decryptedBlob.cbData:'+inttostr(decryptedBlob.cbData) );
  //log(strpas(pchar(decryptedBlob.pbData)));
  if result=true then
    begin
    setlength(databytes,decryptedBlob.cbData);
    CopyMemory(@databytes[0],decryptedBlob.pbData,decryptedBlob.cbData);
    end;
  if result=false then log('CryptUnProtectData_ lasterror:'+inttostr(getlasterror));

  closehandle(outfile);

end;

function CryptUnProtectData_(buffer:tbytes;var output:tbytes;const AdditionalEntropy: string=''):boolean;overload;
var
  plainBlob,decryptedBlob:_MY_BLOB;
  byteswritten:dword=0;
  //
  text:string;
  //buffer:array[0..4095] of byte;
  //
  entropyBlob: DATA_BLOB;
  pEntropy: Pointer;
begin
  result:=false;

  fillchar(plainBlob,sizeof(plainBlob),0);
  fillchar(decryptedBlob,sizeof(decryptedBlob),0);

  if AdditionalEntropy <> '' then
    begin
        entropyBlob.pbData := Pointer(AdditionalEntropy);
        entropyBlob.cbData := Length(AdditionalEntropy)*SizeOf(Char);
        pEntropy := @entropyBlob;
    end
    else
        pEntropy := nil;


  plainBlob.pbData := @buffer[0];
  //plainBlob.pbData:=getmem(bytesread);
  //copymemory(plainBlob.pbData,@buffer[0],bytesread);
  plainBlob.cbData := length(buffer);
  log('plainBlob.cbData:'+inttostr(plainBlob.cbData) );

  //test
  {
  text:='password';
  plainBlob.cbData := SizeOf(Char)*Length(Text);
  plainBlob.pbData := Pointer(LocalAlloc(LPTR, plainBlob.cbData));
  Move(Pointer(Text)^, plainBlob.pbData^, plainBlob.cbData);
  }

  decryptedBlob.pbData :=nil; //getmem(4096); //@databytes[0];
  //3rd param entropy
  result:=CryptunProtectData(@plainBlob, nil, pEntropy, nil, nil, 0{CRYPTPROTECT_LOCAL_MACHINE}, @decryptedBlob);
  if result=false then result:=CryptunProtectData(@plainBlob, nil, pEntropy, nil, nil, CRYPTPROTECT_LOCAL_MACHINE, @decryptedBlob);

  log('decryptedBlob.cbData:'+inttostr(decryptedBlob.cbData) );
  if result=true then
    begin
    setlength(output,decryptedBlob.cbData);
    CopyMemory(@output[0],decryptedBlob.pbData,decryptedBlob.cbData);
    end;
  if result=false then log('CryptUnProtectData_ lasterror:'+inttostr(getlasterror));


end;

function bencrypt(algo:lpcwstr;decrypted:array of byte;output:pointer;const gKey,initializationVector:array of byte):ULONG;
var
  hProvider:BCRYPT_ALG_HANDLE=0;
  encrypted:array[0..1023] of byte;
  hkey:BCRYPT_KEY_HANDLE=0;
  status:NTSTATUS;
  encryptedPassLen,cbiv:ULONG;
  //gInitializationVector:array[0..15] of uchar;
begin
  result:=0;
  cbiv:=0;
  log('algo:'+strpas(algo) );
  {
  log('encrypted size:'+inttostr(sizeof(encryped) ));
  log('decrypted size:'+inttostr(sizeof(decrypted) ));
  log('decrypted length:'+inttostr(length(decrypted) ));
  log('sizeof(gkey):'+inttostr(sizeof(gkey)));
  log('sizeof(iv):'+inttostr(sizeof(initializationVector )));
  }
  status:=BCryptOpenAlgorithmProvider(hProvider, algo, nil, 0);
  //log('hProvider:'+inttostr(hProvider));
  if status<>0 then begin log('BCryptOpenAlgorithmProvider NOT OK');exit;end;
  if algo=BCRYPT_AES_ALGORITHM then
     begin
       status:=BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE_), @BCRYPT_CHAIN_MODE_CFB_[1], sizeof(BCRYPT_CHAIN_MODE_CFB_), 0);
       cbiv:=sizeof(initializationVector );
     end;
  if algo=BCRYPT_3DES_ALGORITHM then
     begin
       status:=BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE_), @BCRYPT_CHAIN_MODE_CBC_[1], sizeof(BCRYPT_CHAIN_MODE_CBC_), 0);
       cbiv:=sizeof(initializationVector ) div 2;
     end;
  //writeln('cbiv:'+inttostr(cbiv));
  if status<>0 then begin log('BCryptSetProperty NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  status:=BCryptGenerateSymmetricKey(hProvider, hkey, nil, 0, @gKey[0], sizeof(gKey), 0);
  if status<>0 then begin log('BCryptGenerateSymmetricKey NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  //writeln('hkey:'+inttostr(hkey));
  //fillchar(decrypted,sizeof(decrypted ),0);
  fillchar(encrypted,length(encrypted ),0);
  if length(initializationVector)>0
     then status := BCryptEncrypt(hkey, @decrypted[0], sizeof(decrypted), 0, @initializationVector[0], cbiv, @encrypted[0], length(encrypted), result, 0)
     else status := BCryptEncrypt(hkey, @decrypted[0], sizeof(decrypted), 0, nil, 0, @encrypted[0], length(encrypted), result, 0);
  if status<>0 then begin log('BCryptDecrypt NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  log('resultlen:'+inttostr(result));
  log('encrypted:'+ByteToHexaString  (encrypted  ));
  //log(strpas (pwidechar(@decrypted[0]) ));
  copymemory(output,@encrypted[0],result);
  //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
  //0xC0000023  STATUS_BUFFER_TOO_SMALL
end;


function bdecrypt(algo:lpcwstr;encryped:array of byte;output:pointer;const gKey,initializationVector:array of byte):ULONG;
var
  hProvider:BCRYPT_ALG_HANDLE=0;
  decrypted:array[0..1023] of byte;
  hkey:BCRYPT_KEY_HANDLE=0;
  status:NTSTATUS;
  decryptedPassLen,cbiv:ULONG;
  //gInitializationVector:array[0..15] of uchar;
begin
  result:=0;
  cbiv:=0;
  log('algo:'+strpas(algo) );
  {
  log('encrypted size:'+inttostr(sizeof(encryped) ));
  log('decrypted size:'+inttostr(sizeof(decrypted) ));
  log('decrypted length:'+inttostr(length(decrypted) ));
  log('sizeof(gkey):'+inttostr(sizeof(gkey)));
  log('sizeof(iv):'+inttostr(sizeof(initializationVector )));
  }
  status:=BCryptOpenAlgorithmProvider(hProvider, algo, nil, 0);
  //log('hProvider:'+inttostr(hProvider));
  if status<>0 then begin log('BCryptOpenAlgorithmProvider NOT OK');exit;end;
  if algo=BCRYPT_AES_ALGORITHM then
     begin
       status:=BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE_), @BCRYPT_CHAIN_MODE_CFB_[1], sizeof(BCRYPT_CHAIN_MODE_CFB_), 0);
       cbiv:=sizeof(initializationVector );
     end;
  if algo=BCRYPT_3DES_ALGORITHM then
     begin
       status:=BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE_), @BCRYPT_CHAIN_MODE_CBC_[1], sizeof(BCRYPT_CHAIN_MODE_CBC_), 0);
       cbiv:=sizeof(initializationVector ) div 2;
     end;
  //writeln('cbiv:'+inttostr(cbiv));
  if status<>0 then begin log('BCryptSetProperty NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  status:=BCryptGenerateSymmetricKey(hProvider, hkey, nil, 0, @gKey[0], sizeof(gKey), 0);
  if status<>0 then begin log('BCryptGenerateSymmetricKey NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  //writeln('hkey:'+inttostr(hkey));
  //fillchar(decrypted,sizeof(decrypted ),0);
  fillchar(decrypted,length(decrypted ),0);
  //status := BCryptDecrypt(hkey, @encryped[0], sizeof(encryped), 0, @initializationVector[0], cbiv, @decrypted[0], sizeof(decrypted), result, 0);
  status := BCryptDecrypt(hkey, @encryped[0], sizeof(encryped), 0, @initializationVector[0], cbiv, @decrypted[0], length(decrypted), result, 0);
  if status<>0 then begin log('BCryptDecrypt NOT OK:'+inttohex(status,sizeof(status)));exit;end;
  log('resultlen:'+inttostr(result));
  log('decrypted:'+ByteToHexaString  (decrypted ));
  //log(strpas (pwidechar(@decrypted[0]) ));
  if output=nil then output:=allocmem(result);
  copymemory(output,@decrypted[0],result);
  //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
  //0xC0000023  STATUS_BUFFER_TOO_SMALL
end;

function _bdecryptDES(encrypedPass:array of byte;gDesKey,initializationVector:array of byte):ULONG;
var
  hDesProvider:BCRYPT_ALG_HANDLE;
  decryptedPass:array[0..1023] of byte; //puchar;
  hDes:BCRYPT_KEY_HANDLE;
  status:NTSTATUS;
  //decryptedPassLen:ULONG;
  //gInitializationVector:array[0..15] of uchar;
begin
   //3des
  BCryptOpenAlgorithmProvider(hDesProvider, pwidechar(BCRYPT_3DES_ALGORITHM), nil, 0);
  BCryptSetProperty(hDesProvider, pwidechar(BCRYPT_CHAINING_MODE_), @BCRYPT_CHAIN_MODE_CBC_[1], sizeof(BCRYPT_CHAIN_MODE_CBC_), 0);
  BCryptGenerateSymmetricKey(hDesProvider, hDes, nil, 0, @gDesKey[0], sizeof(gDesKey), 0);
  status := BCryptDecrypt(hDes, @encrypedPass[0], sizeof(encrypedPass), 0, @initializationVector[0], sizeof(initializationVector ) div 2, @decryptedPass[0], sizeof(decryptedPass), result, 0);

end;


function _bdecryptAES(encrypedPass:array of byte;gAesKey,initializationVector:array of byte):ULONG;
var
  hprovider:BCRYPT_ALG_HANDLE;
  decryptedPass:array[0..1023] of byte; //puchar;
  hAes:BCRYPT_KEY_HANDLE;
  status:NTSTATUS;
  //decryptedPassLen:ULONG;
  //gInitializationVector:array[0..15] of uchar;
begin
  //aes
  BCryptOpenAlgorithmProvider(hProvider, pwidechar(BCRYPT_AES_ALGORITHM), nil, 0);
  BCryptSetProperty(hProvider, pwidechar(BCRYPT_CHAINING_MODE), @BCRYPT_CHAIN_MODE_CFB_[1], sizeof(BCRYPT_CHAIN_MODE_CFB_), 0);
  BCryptGenerateSymmetricKey(hProvider, hAes, nil, 0, @gAesKey[0], sizeof(gAesKey), 0);
  status := BCryptDecrypt(hAes, @encrypedPass[0], sizeof(encrypedPass), 0, @initializationVector[0], sizeof(initializationVector ) div 2, @decryptedPass[0], sizeof(decryptedPass), result, 0);

end;

//similar to kull_m_crypto_genericAES128Decrypt in mimikatz
function DecryptAES128(const Key: tbyte16;const IV:array of byte;const data: tbyte16;var output:tbyte16): boolean;
var
  pbData: PByte;
  hCryptProvider: HCRYPTPROV;
  KeyBlob: packed record
    Header: BLOBHEADER;
    Size: DWORD;
    Data: array[0..15] of Byte;
  end;
  hKey, hDecryptKey: HCRYPTKEY;
  dwKeyCypherMode: DWORD;
  ResultLen: DWORD;
//const
  //PROV_RSA_AES = 24;
  //CALG_AES_128 = $0000660e;
  //AESFinal = True;
begin
  Result := false;
  // MS_ENH_RSA_AES_PROV
  if CryptAcquireContext(hCryptProvider, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
  begin
    log('CryptAcquireContext OK',0);
    KeyBlob.Header.bType := PLAINTEXTKEYBLOB;
    keyBlob.Header.bVersion := CUR_BLOB_VERSION;
    keyBlob.Header.reserved := 0;
    keyBlob.Header.aiKeyAlg := CALG_AES_128;
    keyBlob.Size := Length(Key);
    CopyMemory(@keyBlob.Data[0], @Key[0], keyBlob.Size);

    if CryptImportKey(hCryptProvider, @KeyBlob, SizeOf(KeyBlob), 0, 0, hKey) then
    begin
      log('CryptImportKey OK',0);
      if CryptDuplicateKey(hKey, nil, 0, hDecryptKey) then
      begin
        log('CryptDuplicateKey OK',0);
        dwKeyCypherMode := CRYPT_MODE_CBC; //CRYPT_MODE_CBC or CRYPT_MODE_ECB
        if CryptSetKeyParam(hDecryptKey, KP_MODE, @dwKeyCypherMode, 0)=false then log('CryptSetKeyParam NOT OK',0);
        if CryptSetKeyParam(hDecryptKey, KP_IV, @IV[0], 0)=false then log('CryptSetKeyParam NOT OK',0);

        {
        output:=value;
        pbData := @output[0];
        }
        ResultLen :=sizeof(output);
        CopyMemory(@output[0],@data[0],sizeof(output));

        // the calling application sets the DWORD value to the number of bytes to be decrypted. Upon return, the DWORD value contains the number of bytes of the decrypted plaintext.
        if CryptDecrypt(hDecryptKey, 0, true, 0, @output[0]{pbData}, ResultLen) then
        begin
          log('CryptDecrypt OK',0);
          //SetLength(Result, ResultLen);
          result:=true;
        end
        else
        begin
          //NT_BAD_DATA (0x80090005)
          log('ResultLen:'+inttostr(ResultLen),0);
          if ResultLen >0 then result:=true else result:=false;
          log('CryptDecrypt NOT OK '+ IntTohex(GetLastError,4),0);
          Result := true;
        end;

        CryptDestroyKey(hDecryptKey);
      end;

      CryptDestroyKey(hKey);
    end;

    CryptReleaseContext(hCryptProvider, 0);
  end;
end;

function crypto_hkey(hProv:HCRYPTPROV; calgid:ALG_ID; key:LPCVOID; keyLen:DWORD; flags:DWORD; var hKey:HCRYPTKEY; var hSessionProv:HCRYPTPROV):boolean;
var
  status:BOOL = FALSE;
  keyBlob:PGENERICKEY_BLOB;
  szBlob:DWORD;
begin

        szBlob := sizeof(GENERICKEY_BLOB) + keyLen;

	if(calgid <> CALG_3DES) then
	begin
          keyBlob:=Pointer(LocalAlloc(LPTR, szBlob));
		if(keyBlob <>nil) then
		begin
			keyBlob^.Header.bType := PLAINTEXTKEYBLOB;
			keyBlob^.Header.bVersion := CUR_BLOB_VERSION;
			keyBlob^.Header.reserved := 0;
			keyBlob^.Header.aiKeyAlg := calgid;
			keyBlob^.dwKeyLen := keyLen;
			//RtlCopyMemory((PBYTE) keyBlob + sizeof(GENERICKEY_BLOB), key, keyBlob->dwKeyLen);
                        CopyMemory(pointer(nativeuint(keyBlob) + sizeof(GENERICKEY_BLOB)),key,keyBlob^.dwKeyLen);
                        status := CryptImportKey(hProv, pbyte(keyBlob), szBlob, 0, flags, hKey);
			LocalFree(thandle(keyBlob));
		end;
	//}
	//else if(hSessionProv)
	//	status = kull_m_crypto_hkey_session(calgid, key, keyLen, flags, hKey, hSessionProv);
        //end;
        end;

	result:= status;
end;

//hardSecretBlob = PNT6_HARD_SECRET
function lsadump_sec_aes256(hardSecretBlob:tbytes; hardSecretBlobSize:dword;lazyiv:tbytes;sysKey:tbytes):boolean;
const
  CALG_SHA_256 = $0000800c;
  CALG_SHA_384 = $0000800d;
  CALG_SHA_512 = $0000800e;
  LAZY_NT6_IV_SIZE=32;
  AES_256_KEY_SIZE=256 div 8;
  //CALG_SHA_256 = (ALG_CLASS_HASH or ALG_TYPE_ANY or 12);
  CALG_AES_128 = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or 14);
  CALG_AES_192 = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or 15);
  CALG_AES_256 = (ALG_CLASS_DATA_ENCRYPT or ALG_TYPE_BLOCK or 16);

var
 hContext:HCRYPTPROV;
 hHash:HCRYPTHASH;
 hKey:HCRYPTKEY;
 pKey:PBYTE = nil;
 i, szNeeded:DWORD;
 keyBuffer:array [0..AES_256_KEY_SIZE-1] of byte;
 status:BOOL = FALSE;
 hSessionProv:HCRYPTPROV=0;
begin

//pKey = sysKey;
//szNeeded = SYSKEY_LENGTH;

  if(CryptAcquireContext(hContext, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) then
		begin
			if(CryptCreateHash(hContext, CALG_SHA_256, 0, 0, hHash)) then
			begin
				CryptHashData(hHash, pKey, szNeeded, 0);
				for i:= 0 to 1000-1 do	CryptHashData(hHash, @lazyiv[0], LAZY_NT6_IV_SIZE, 0);

				szNeeded := sizeof(keyBuffer);
				if(CryptGetHashParam(hHash, HP_HASHVAL, keyBuffer, &szNeeded, 0)) then
				begin
					if (crypto_hkey(hContext, CALG_AES_256, @keyBuffer[0], sizeof(keyBuffer), 0, hKey, hSessionProv)) then
                                        //if 1=1 then
                                        begin
						i := CRYPT_MODE_ECB;
						if(CryptSetKeyParam(hKey, KP_MODE, @i, 0)) then
						begin
							szNeeded := hardSecretBlobSize - PtrUInt(@NT6_HARD_SECRET(Nil^).encryptedSecret); //FIELD_OFFSET(NT6_HARD_SECRET, encryptedSecret);
							status := CryptDecrypt(hKey, 0, FALSE, 0, pointer(PNT6_HARD_SECRET(@hardSecretBlob[0])^.encryptedSecret [0]), szNeeded);
							if(status=false) then log('CryptDecrypt not ok');
						end
						else log('CryptSetKeyParam not ok');
						CryptDestroyKey(hKey);
					end
					else log('kull_m_crypto_hkey not ok');
				end;
				CryptDestroyHash(hHash);
			end;
			CryptReleaseContext(hContext, 0);
		end;

end;

//------------------------------------------------------------------------------
function _AES128ECB_Decrypt(const Value: RawByteString; const Key: RawByteString): RawByteString;
var
  pbData: PByte;
  hCryptProvider: HCRYPTPROV;
  KeyBlob: packed record
    Header: BLOBHEADER;
    Size: DWORD;
    Data: array[0..15] of Byte;
  end;
  hKey, hDecryptKey: HCRYPTKEY;
  dwKeyCypherMode: DWORD;
  ResultLen: DWORD;
const
  PROV_RSA_AES = 24;
  CALG_AES_128 = $0000660e;
  AESFinal = True;
begin
  Result := '';
  // MS_ENH_RSA_AES_PROV
  if CryptAcquireContext(hCryptProvider, nil, nil, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) then
  begin
    KeyBlob.Header.bType := PLAINTEXTKEYBLOB;
    keyBlob.Header.bVersion := CUR_BLOB_VERSION;
    keyBlob.Header.reserved := 0;
    keyBlob.Header.aiKeyAlg := CALG_AES_128;
    keyBlob.Size := Length(Key);
    CopyMemory(@keyBlob.Data[0], @Key[1], keyBlob.Size);

    if CryptImportKey(hCryptProvider, @KeyBlob, SizeOf(KeyBlob), 0, 0, hKey) then
    begin
      if CryptDuplicateKey(hKey, nil, 0, hDecryptKey) then
      begin
        dwKeyCypherMode := CRYPT_MODE_ECB; //CRYPT_MODE_CBC
        CryptSetKeyParam(hDecryptKey, KP_MODE, @dwKeyCypherMode, 0);

        Result := Value;
        pbData := Pointer(Result);
        ResultLen := Length(Result);

        // the calling application sets the DWORD value to the number of bytes to be decrypted. Upon return, the DWORD value contains the number of bytes of the decrypted plaintext.
        if CryptDecrypt(hDecryptKey, 0, AESFinal, 0, pbData, ResultLen) then
        begin
          SetLength(Result, ResultLen);
        end
        else
        begin
          Result := '';
        end;

        CryptDestroyKey(hDecryptKey);
      end;

      CryptDestroyKey(hKey);
    end;

    CryptReleaseContext(hCryptProvider, 0);
  end;
end;

//------------------------------------------------------------------------------
 function _Encrypt(algid:longword;const Value: RawByteString; const Key: RawByteString): RawByteString;
var
  pbData: PByte;
  hCryptProvider: HCRYPTPROV;
  KeyBlob: packed record
    Header: BLOBHEADER;
    Size: DWORD;
    Data: array[0..15] of Byte;
  end;
  hKey, hEncryptKey: HCRYPTKEY;
  dwKeyCypherMode: DWORD;
  InputLen, ResultLen: DWORD;
const
  PROV_RSA_AES = 24;
  AESFinal = True;
begin
  Result := '';
  // MS_ENH_RSA_AES_PROV
  if CryptAcquireContext(hCryptProvider, nil, nil{MS_ENHANCED_PROV}, PROV_RSA_AES, CRYPT_VERIFYCONTEXT{PROV_RSA_FULL}) then
  begin
    log('CryptAcquireContext OK');
    KeyBlob.Header.bType := PLAINTEXTKEYBLOB;
    keyBlob.Header.bVersion := CUR_BLOB_VERSION;
    keyBlob.Header.reserved := 0;
    keyBlob.Header.aiKeyAlg := algid; //CALG_AES_128
    keyBlob.Size := Length(Key);
    CopyMemory(@keyBlob.Data[0], @Key[1], keyBlob.Size);

    if CryptImportKey(hCryptProvider, @KeyBlob, SizeOf(KeyBlob), 0, 0, hKey) then
    begin
      log('CryptImportKey OK');
      if CryptDuplicateKey(hKey, nil, 0, hEncryptKey) then
      begin
        log('CryptDuplicateKey OK');
        dwKeyCypherMode := CRYPT_MODE_CBC;
        CryptSetKeyParam(hEncryptKey, KP_MODE, @dwKeyCypherMode, 0);

        InputLen := Length(Value);
        ResultLen := InputLen;

        // nil dans pbData => If this parameter contains NULL, this function will calculate the required size for the ciphertext and place that in the value pointed to by the pdwDataLen parameter.
        if CryptEncrypt(hEncryptKey, 0, AESFinal, 0, nil, ResultLen, 0) then
        begin
          log('CryptEncrypt OK');
          SetLength(Result, ResultLen);
          Move(Value[1], Result[1], Length(Value));
          pbData := Pointer(PAnsiChar(Result));
          if not CryptEncrypt(hEncryptKey, 0, AESFinal, 0, pbData, InputLen, ResultLen) then
          begin
            Result := '';
            {$IFDEF DEBUG_SLT_CRYPT}
            OutputDebugCRYPT('TSLTAES128ECB.Encrypt ' + IntToStr(GetLastError()));
            {$ENDIF DEBUG_SLT_CRYPT}
          end;
        end
        else
        begin
          Result := '';
          {$IFDEF DEBUG_SLT_CRYPT}
          OutputDebugCRYPT('TSLTAES128ECB.Pre-Encrypt ' + IntToStr(GetLastError()));
          {$ENDIF DEBUG_SLT_CRYPT}
        end;

        CryptDestroyKey(hEncryptKey);
      end;

      CryptDestroyKey(hKey);
    end;

    CryptReleaseContext(hCryptProvider, 0);
  end;
end;

 //beware of stream cipher vs block cipher
 function EnCryptDecrypt(algid:dword;key: string;var buffer:tbytes;const decrypt:boolean=false):boolean;
 const
   CRYPT_EXPORTABLE = $00000001;
   CRYPT_NO_SALT    = $10;
   AES_KEY_SIZE =16; //also AES_BLOCK_SIZE  ? look at https://stackoverflow.com/questions/9091108/cryptencrypt-aes-256-fails-at-encrypting-last-block
 var
  hProv: HCRYPTPROV;
  hash: HCRYPTHASH;
  hkey: HCRYPTKEY;

  //Buffer: PByte;
  datalen,buflen: dWord;
  dwKeyCypherMode,dwsize,dwBLOCKLEN,dwKEYLEN,hash_len: DWORD;
  hash_buffer,data:tbytes;

  MS_ENH_RSA_AES_PROV:pchar='Microsoft Enhanced RSA and AES Cryptographic Provider'+#0;
begin
  result:=false;
  if decrypt=false
     then log('buffer:'+BytetoAnsiString(buffer))
     else log('buffer:'+ByteToHexaString (buffer));
  log('key:'+key);
  log('ALG_ID:'+inttohex(algid,sizeof(algid )));
  log('buffer length:'+inttostr(length(buffer)));
  log('key length:'+inttostr(length(key))); // The secret key must equal the size of the key.
  {get context for crypt default provider}
  //if fail then try again with CRYPT_NEWKEYSET
  //if CryptAcquireContext(hProv, nil, nil, {PROV_RSA_AES} PROV_RSA_FULL, 0{CRYPT_VERIFYCONTEXT}) then
  if CryptAcquireContext(hProv, nil, MS_ENH_RSA_AES_PROV, PROV_RSA_AES {PROV_RSA_FULL}, 0{CRYPT_VERIFYCONTEXT}) then
  begin
  log('CryptAcquireContext');
  {create hash-object (MD5 algorithm)}
  if CryptCreateHash(hProv, CALG_MD5, 0, 0, hash) then
  begin
  log('CryptCreateHash');
  {get hash from password}
  if CryptHashData(hash, @key[1], Length(key), 0) then
  begin
  log('CryptHashData');
  hash_len:=16;
  setlength(hash_buffer,hash_len );
  if CryptGetHashParam(hash, HP_HASHVAL, @hash_buffer[0], hash_len, 0)
     then log('CryptGetHashParam OK:'+ByteToHexaString (hash_buffer) )
     else log('CryptGetHashParam NOT OK');
  {create key from hash by RC4 algorithm}
  if CryptDeriveKey(hProv, algid, hash, 0 or CRYPT_EXPORTABLE{CRYPT_NO_SALT}, hkey) then
  begin
  log('CryptDeriveKey');
  {
  AES is a block cipher, and like all block ciphers it can be used in one of several modes,
  such as ECB, CBC, OCB, CTR.
  Only the first of these modes - ECB, or electronic code book, which is the fundamental block encryption mode -
  allows a single block of output to result from the encryption of a single input block.
  The others are geared towards encoding multiple blocks of input data,
  and involve additional data (the IV) which means the output is longer than the input.
  }
  //if (algid =CALG_AES) or (algid =CALG_AES_128) or (algid=CALG_RC2) then
  //below only applies to block ciphers
  //An initialization vector is required if using CBC mode
  if 1=1 then
  begin
  dwKeyCypherMode := CRYPT_MODE_CFB;    //dcrypt2 default is CBC //ms default is CRYPT_MODE_CBC
  log('KP_MODE:'+inttostr(dwKeyCypherMode));
  if CryptSetKeyParam(hkey, KP_MODE, @dwKeyCypherMode, 0)=true
     then log('CryptSetKeyParam KP_MODE OK')
     else log('CryptSetKeyParam KP_MODE NOT OK,'+inttostr(getlasterror));
  end;
  //
  //look at KP_PADDING, KP_ALGID
  //
  dwsize:=sizeof(dwBLOCKLEN);
  dwBLOCKLEN:=0;
  //KP_BLOCKLEN size in bits
  //we get the block length as we can only encrypt up to that size, per pass
  if CryptGetKeyParam (hkey,KP_BLOCKLEN ,@dwBLOCKLEN,dwsize,0)=true
     then log('CryptGetKeyParam KP_BLOCKLEN OK,'+inttostr(dwBLOCKLEN div 8))
     else log('CryptGetKeyParam KP_BLOCKLEN NOT OK');
  dwsize:=sizeof(dwKEYLEN);
  dwKEYLEN:=0;
  if CryptGetKeyParam (hkey,KP_MODE ,@dwKEYLEN,dwsize,0)=true
     then log('CryptGetKeyParam KP_MODE OK,'+inttostr(dwKEYLEN ))
     else log('CryptGetKeyParam KP_MODE NOT OK');
  dwsize:=sizeof(dwKEYLEN);
  dwKEYLEN:=0;
  if CryptGetKeyParam (hkey,KP_KEYLEN ,@dwKEYLEN,dwsize,0)=true
     then log('CryptGetKeyParam KP_KEYLEN OK,'+inttostr(dwKEYLEN div 8))
     else log('CryptGetKeyParam KP_KEYLEN NOT OK');
  dwsize:=sizeof(dwKEYLEN);
  dwKEYLEN:=0;
  if CryptGetKeyParam (hkey,KP_EFFECTIVE_KEYLEN ,@dwKEYLEN,dwsize,0)=true
     then log('CryptGetKeyParam KP_EFFECTIVE_KEYLEN OK,'+inttostr(dwKEYLEN div 8))
     else log('CryptGetKeyParam KP_EFFECTIVE_KEYLEN NOT OK');
  dwsize:=sizeof(dwKEYLEN);
  dwKEYLEN:=0;
  if CryptGetKeyParam (hkey,KP_PADDING ,@dwKEYLEN,dwsize,0)=true
     then log('CryptGetKeyParam KP_PADDING OK,'+inttostr(dwKEYLEN ))
     else log('CryptGetKeyParam KP_PADDING NOT OK');
  {
  dwKEYLEN:=PKCS5_PADDING; //only one supported...
  if CryptSetKeyParam(hkey, KP_PADDING, @dwKEYLEN, 0)=true
     then log('CryptSetKeyParam KP_PADDING OK')
     else log('CryptSetKeyParam KP_PADDING NOT OK,'+inttostr(getlasterror));
  }
  {destroy hash-object}
  CryptDestroyHash(hash);
  log('CryptDestroyHash');

        buflen := length(buffer);

        if decrypt =false then
        begin
        datalen:=buflen;
        if CryptEncrypt(hkey, 0, true, 0, nil, datalen, 0)
           then log('CryptEncrypt OK')
           else log('CryptEncrypt:NOT OK'+inttostr(getlasterror));

        //lets create a buffer big enough to hold the encrypted data
        if dwBLOCKLEN<>0 then datalen:=((length(buffer) + dwBLOCKLEN -1) div dwBLOCKLEN) *dwBLOCKLEN ;
        log('datalen:'+inttostr(datalen));
        setlength(data,datalen);
        ZeroMemory(@data[0],datalen);
        copymemory(@data[0],@buffer[0],buflen);

        {crypt buffer}
        //https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptencrypt
        result:= CryptEncrypt(hkey, 0, true, 0, @data[0], buflen, datalen);
        if result
           then log('CryptEncrypt:'+inttostr(buflen))
           else log('CryptEncrypt:NOT OK,'+inttostr(buflen)+','+inttostr(getlasterror));

        //lets push the encrypted buffer back
        if result=true then
           begin
           setlength(buffer,buflen);
           copymemory(@buffer[0],@data[0],buflen);
           end;
        end
        else //if decrypt =false then
        begin
        {decrypt buffer}
        datalen:=buflen*2;
        setlength(data,datalen);
        ZeroMemory(@data[0],datalen);
        copymemory(@data[0],@buffer[0],buflen);
        result:=CryptDecrypt(hkey, 0, true, 0, @data[0], buflen);
          if result
             then log('CryptDecrypt:'+inttostr(buflen))
             else log('CryptDecrypt:NOT OK,'+inttostr(buflen)+','+inttostr(getlasterror));
        //lets push the decrypted buffer back
        if result=true then
           begin
           setlength(buffer,buflen);
           copymemory(@buffer[0],@data[0],buflen);
           end;

        end;
  end // if CryptDeriveKey
  else log('CryptDeriveKey NOT OK,'+inttostr(getlasterror)); //0x80090008 | 2148073480 NTE_BAD_ALGID
  end //if CryptHashData
  else log('CryptHashData NOT OK');
  end //if CryptCreateHash
  else log('CryptCreateHash NOT OK');
  {release the context for crypt default provider}
  CryptReleaseContext(hProv, 0);
  log('CryptReleaseContext');

  end //if CryptAcquireContext
  else log('CryptAcquireContext NOT OK,'+inttostr(getlasterror));
end;
//------------------------------------------------------------------------------


procedure _doSomeEncryption();
var
  HASHOBJ: HCRYPTHASH;
  hProv: HCRYPTPROV;
  bHash: tBytes;
  dwHashBytes: DWORD;
begin
  if not CryptAcquireContext(hProv, nil, nil, PROV_RSA_FULL , CRYPT_VERIFYCONTEXT) then
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






end.

