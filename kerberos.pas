unit kerberos;

{$mode delphi}

interface

uses
  windows,SysUtils,
  ntdll,utils;

const
  	//kerberosPackageName:STRING = {8, 9, MICROSOFT_KERBEROS_NAME_A};
	g_AuthenticationPackageId_Kerberos:DWORD = 0;
	g_isAuthPackageKerberos:BOOL = FALSE;
	g_hLSA:HANDLE = 0;

implementation

 type

  //https://www.rdos.net/svn/tags/V9.2.5/watcom/bld/w32api/include/ntsecapi.mh
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

    type KERB_PURGE_TKT_CACHE_REQUEST =record
       MessageType:KERB_PROTOCOL_MESSAGE_TYPE;
       LogonId:LUID;
       ServerName:UNICODE_STRING;
       RealmName:UNICODE_STRING;
    end;
    PKERB_PURGE_TKT_CACHE_REQUEST=^KERB_PURGE_TKT_CACHE_REQUEST;

    KERB_CRYPTO_KEY32 =record
    KeyType:LONG;
    Length:ULONG;
    Offset:ULONG;
end;
    PKERB_CRYPTO_KEY32=^KERB_CRYPTO_KEY32;

    KERB_SUBMIT_TKT_REQUEST =record
     MessageType: KERB_PROTOCOL_MESSAGE_TYPE;
     LogonId: LUID;
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

const
STATUS_HANDLE_NO_LONGER_VALID=$C0190028;
STATUS_UNSUCCESSFUL=$c0000001;

function LsaCallKerberosPackage( ProtocolSubmitBuffer:PVOID;  SubmitBufferLength:ULONG; ProtocolReturnBuffer:PPVOID;  ReturnBufferLength:PULONG; ProtocolStatus:PNTSTATUS):ntstatus;
var
  status:NTSTATUS;
begin

	 status:= STATUS_HANDLE_NO_LONGER_VALID;
	//if(g_hLSA && g_isAuthPackageKerberos)
	            status := LsaCallAuthenticationPackage(g_hLSA, g_AuthenticationPackageId_Kerberos, ProtocolSubmitBuffer, SubmitBufferLength, ProtocolReturnBuffer, ReturnBufferLength, ProtocolStatus);
	result:= status;
end;

function kuhl_m_kerberos_use_ticket(fileData:PBYTE;fileSize:DWORD):LONG;
var
status:NTSTATUS = STATUS_UNSUCCESSFUL;
packageStatus:NTSTATUS;
submitSize, responseSize:DWORD;
pKerbSubmit:PKERB_SUBMIT_TKT_REQUEST;
dumPtr:PVOID;
begin



	submitSize := sizeof(KERB_SUBMIT_TKT_REQUEST) + fileSize;
        pKerbSubmit := AllocMem(submitSize);
	if pKerbSubmit <>nil then
        begin

		pKerbSubmit^.MessageType := KerbSubmitTicketMessage;
		pKerbSubmit^.KerbCredSize := fileSize;
		pKerbSubmit^.KerbCredOffset := sizeof(KERB_SUBMIT_TKT_REQUEST);
		//RtlCopyMemory((PBYTE) pKerbSubmit + pKerbSubmit->KerbCredOffset, fileData, pKerbSubmit->KerbCredSize);
                CopyMemory(pointer(nativeuint(pKerbSubmit)+ pKerbSubmit^.KerbCredOffset),fileData,pKerbSubmit^.KerbCredSize);

		status := LsaCallKerberosPackage(pKerbSubmit, submitSize, @dumPtr, @responseSize, @packageStatus);
		if status=STATUS_SUCCESS then
		begin
			if packageStatus=STATUS_SUCCESS then
			begin
				log('Ticket successfully submitted for current session',1);
				status := STATUS_SUCCESS;
                        end
			else log('LsaCallAuthenticationPackage KerbSubmitTicketMessage / Package : '+inttostr( packageStatus));
                end
		else log('LsaCallAuthenticationPackage KerbSubmitTicketMessage : '+inttostr( status),1);

		freemem(pKerbSubmit);
	end;

	result:= status;
end;

function kuhl_m_kerberos_purge_ticket:NTSTATUS;
var
status, packageStatus:NTSTATUS;
kerbPurgeRequest:KERB_PURGE_TKT_CACHE_REQUEST; //= (KerbPurgeTicketCacheMessage, (0, 0), (0, 0, nil), (0, 0, nil));
 dumPtr:PVOID;
 responseSize:DWORD;
begin

 fillchar(kerbPurgeRequest ,sizeof(kerbPurgeRequest),0);
 kerbPurgeRequest.MessageType :=KerbPurgeTicketCacheMessage;


	status := LsaCallKerberosPackage(@kerbPurgeRequest, sizeof(KERB_PURGE_TKT_CACHE_REQUEST), @dumPtr, @responseSize, @packageStatus);
	if status=STATUS_SUCCESS then
	begin
		if packageStatus=STATUS_SUCCESS
                then log('Ticket(s) purge for current session is OK',1)
		else log('LsaCallAuthenticationPackage KerbPurgeTicketCacheMessage / Package : '+inttostr(packageStatus),1);
	end
	else log('LsaCallAuthenticationPackage KerbPurgeTicketCacheMessage : ' +inttostr(status),1);

	result:= STATUS_SUCCESS;
end;



end.

