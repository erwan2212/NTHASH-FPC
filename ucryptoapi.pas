unit ucryptoapi;

{$mode delphi}

interface



uses
  windows,Classes, SysUtils,JwaWinCrypt,jwabcrypt,utils;


function DecryptAES128(const Key: tbyte16;const IV:array of byte;const data: tbyte16;var output:tbyte16): boolean;

//function bdecrypt(algo:lpcwstr;encryped:array of byte;const gKey,initializationVector:array of byte):ULONG;
function bdecrypt(algo:lpcwstr;encryped:array of byte;output:pointer;const gKey,initializationVector:array of byte):ULONG;
//function bdecryptDES(encrypedPass:puchar;encryptedPassLen:ulong;gDesKey,initializationVector:puchar):ULONG;
//function bdecryptAES(encrypedPass:puchar;encryptedPassLen:ulong;gAesKey,initializationVector:puchar):ULONG;

function CryptProtectData_(dataBytes:array of byte;var output:tbytes):boolean;overload;
function CryptProtectData_(dataBytes:array of byte;filename:string):boolean;overload;

function CryptUnProtectData_(var dataBytes:tbytes;filename:string):boolean;overload;

function CredEnum:boolean;



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

implementation

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

function CredEnum:boolean;
var
  Credentials: array of pointer; //PCredentialArray;
  ptr:pointer;
  Credential: PCREDENTIALW;
  UserName: WideString;
  i: integer;
  dwCount: DWORD;
  bytes:array[0..1023] of byte;
begin
  //setlength(Credentials ,1024);
    if CredEnumerateW(nil{PChar('TERM*')}, 0, dwCount, Credentials) then
    begin
      writeln(dwcount);
      //ptr:=credentials;
      for i:= 0 to dwCount - 1  do
        begin
          log('*************************************',1);
          CopyMemory(@bytes[0],Credentials[i],sizeof(_CREDENTIALW)) ;
          //log('Hexa:'+ByteToHexaString (bytes),1);
          log('Flags:'+inttostr(PCREDENTIALW(Credentials[i])^.Flags)  ,1);
          log('Type_:'+inttostr(PCREDENTIALW(Credentials[i])^.Type_   ),1);
          log('TargetName:'+widestring(PCREDENTIALW(Credentials[i])^.TargetName ),1);
          log('Comment:'+widestring(PCREDENTIALW(Credentials[i])^.Comment ),1);
          log('TargetAlias:'+widestring(PCREDENTIALW(Credentials[i])^.TargetAlias ),1);
          log('UserName:'+widestring(PCREDENTIALW(Credentials[i])^.UserName ),1);
          //writeln(PCREDENTIALW(Credentials[i])^.CredentialBlobSize);
          if PCREDENTIALW(Credentials[i])^.CredentialBlobSize >0 then
             begin
               //we could use entropy/salt + CryptUnprotectData
               CopyMemory (@bytes[0],PCREDENTIALW(Credentials[i])^.CredentialBlob,PCREDENTIALW(Credentials[i])^.CredentialBlobSize);
               log('CredentialBlob:'+copy(BytetoAnsiString (bytes),1,PCREDENTIALW(Credentials[i])^.CredentialBlobSize),1);
             end;
          //inc(ptr,sizeof(pointer));
          {
            if CredReadW(Credentials[i].TargetName, Credentials[i].Type_, 0, Credential) then
            begin
              writeln(widestring(Credential.UserName));
              UserName:= Credential.UserName;
              log(Credentials[i].TargetName + ' :: ' + UserName + ' >> ' + IntToStr(Credentials[i].Type_));
              log(IntToStr(Credential.CredentialBlobSize));
            end; // if CredReadW
            }
        end; //for i:= 0 to dwCount - 1  do
    credfree(Credentials);
    end; //if CredEnumerateW
end;

function CryptProtectData_(dataBytes:array of byte;var output:tbytes):boolean;overload;
var
  plainBlob,encryptedBlob:DATA_BLOB;
begin
  fillchar(plainBlob,sizeof(DATA_BLOB),0);
  fillchar(encryptedBlob,sizeof(DATA_BLOB),0);

  plainBlob.pbData := dataBytes;
  plainBlob.cbData := sizeof(dataBytes);

  result:=CryptProtectData(@plainBlob, nil, nil, nil, nil, CRYPTPROTECT_LOCAL_MACHINE, @encryptedBlob);
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
  //writeln(length(dataBytes));

  //test
  {
  text:='password';
  plainBlob.cbData := SizeOf(Char)*Length(Text);
  plainBlob.pbData := Pointer(LocalAlloc(LPTR, plainBlob.cbData));
  Move(Pointer(Text)^, plainBlob.pbData^, plainBlob.cbData);
  }

  result:=CryptProtectData(@plainBlob, nil, nil, nil, nil, CRYPTPROTECT_LOCAL_MACHINE, @encryptedBlob);
  log('cbData:'+inttostr(encryptedBlob.cbData) );
  if result=true then
     begin
     result:=WriteFile(outFile, encryptedBlob.pbData^, encryptedBlob.cbData, byteswritten, nil);
     log('byteswritten:'+inttostr(byteswritten));
     end;

  closehandle(outfile);

end;

function CryptUnProtectData_(var dataBytes:tbytes;filename:string):boolean;overload;
var
  plainBlob,decryptedBlob:_MY_BLOB;
  outfile:thandle=0;
  byteswritten:dword=0;
  //
  text:string;
  buffer:array[0..4095] of byte;
  bytesread:cardinal;
begin
  result:=false;
  fillchar(plainBlob,sizeof(plainBlob),0);
  fillchar(decryptedBlob,sizeof(decryptedBlob),0);

  outFile := CreateFile(pchar(filename), GENERIC_READ, 0, nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  if outfile<=0 then exit;
  result:=readfile(outfile ,buffer,4096,bytesread,nil);
  log('bytesread:'+inttostr(bytesread));

  plainBlob.pbData := @buffer[0];
  //plainBlob.pbData:=getmem(bytesread);
  //copymemory(plainBlob.pbData,@buffer[0],bytesread);
  plainBlob.cbData := bytesread;
  //writeln(length(dataBytes));

  //test
  {
  text:='password';
  plainBlob.cbData := SizeOf(Char)*Length(Text);
  plainBlob.pbData := Pointer(LocalAlloc(LPTR, plainBlob.cbData));
  Move(Pointer(Text)^, plainBlob.pbData^, plainBlob.cbData);
  }

  decryptedBlob.pbData :=getmem(4096); //@databytes[0];
  result:=CryptunProtectData(@plainBlob, nil, nil, nil, nil, CRYPTPROTECT_LOCAL_MACHINE, @decryptedBlob);
  //writeln('CryptunProtectData:'+booltostr(result));
  log('cbData:'+inttostr(decryptedBlob.cbData) );
  //log(strpas(pchar(decryptedBlob.pbData)));
  if result=true then
    begin
    setlength(databytes,decryptedBlob.cbData);
    CopyMemory(@databytes[0],decryptedBlob.pbData,decryptedBlob.cbData);
    end;
  //if result=false then writeln('lasterror:'+inttostr(getlasterror));



  closehandle(outfile);

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
  log(ByteToHexaString  (decrypted ));
  log(strpas (pwidechar(@decrypted[0]) ));
  copymemory(output,@decrypted[0],result);
  //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
  //0xC0000023  STATUS_BUFFER_TOO_SMALL
end;

function bdecryptDES(encrypedPass:array of byte;gDesKey,initializationVector:array of byte):ULONG;
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


function bdecryptAES(encrypedPass:array of byte;gAesKey,initializationVector:array of byte):ULONG;
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
const
  PROV_RSA_AES = 24;
  CALG_AES_128 = $0000660e;
  AESFinal = True;
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
        if CryptDecrypt(hDecryptKey, 0, AESFinal, 0, @output[0]{pbData}, ResultLen) then
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

//------------------------------------------------------------------------------
function AES128ECB_Decrypt(const Value: RawByteString; const Key: RawByteString): RawByteString;
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
 function AES128ECB_Encrypt(const Value: RawByteString; const Key: RawByteString): RawByteString;
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
      if CryptDuplicateKey(hKey, nil, 0, hEncryptKey) then
      begin
        dwKeyCypherMode := CRYPT_MODE_ECB;
        CryptSetKeyParam(hEncryptKey, KP_MODE, @dwKeyCypherMode, 0);

        InputLen := Length(Value);
        ResultLen := InputLen;

        // nil dans pbData => If this parameter contains NULL, this function will calculate the required size for the ciphertext and place that in the value pointed to by the pdwDataLen parameter.
        if CryptEncrypt(hEncryptKey, 0, AESFinal, 0, nil, ResultLen, 0) then
        begin
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
//------------------------------------------------------------------------------


procedure doSomeEncryption();
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

procedure RtlCopyMemory(Destination: PVOID; Source: PVOID; Length: SIZE_T); stdcall;
begin
  Move(Source^, Destination^, Length);
end;




end.

