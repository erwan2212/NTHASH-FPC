unit usamlib;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows;

type
NTStatus = DWORD;

type
 tbyte16_=array[0..15] of byte;
 tbyte=array of byte;

type PWSTR = PWideChar;
type
  _LSA_UNICODE_STRING = record
    Length: USHORT;
    MaximumLength: USHORT;
    Buffer: PWSTR;
  end;
  PLSA_UNICODE_STRING=  ^_LSA_UNICODE_STRING;

  type _SAMPR_USER_INTERNAL1_INFORMATION =record
   EncryptedNtOwfPassword:tbyte16_;
   EncryptedLmOwfPassword:tbyte16_;
   NtPasswordPresent:byte;
   LmPasswordPresent:byte;
   PasswordExpired:byte;
   end;
 SAMPR_USER_INTERNAL1_INFORMATION=_SAMPR_USER_INTERNAL1_INFORMATION;
 PSAMPR_USER_INTERNAL1_INFORMATION=^SAMPR_USER_INTERNAL1_INFORMATION;

  type _SAMPR_RID_ENUMERATION =record
     RelativeId:ulong;
     Name:_LSA_UNICODE_STRING;
   end;
   PSAMPR_RID_ENUMERATION=^_SAMPR_RID_ENUMERATION;

//declarations here
//https://github.com/rapid7/meterpreter/blob/master/source/extensions/kiwi/modules/kull_m_samlib.h
//or
//https://doxygen.reactos.org/d2/de6/samlib_8c.html

//NTSTATUS NTAPI 	SamConnect (IN OUT PUNICODE_STRING ServerName OPTIONAL, OUT PSAM_HANDLE ServerHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes)
function SamConnect(server:pointer; ServerHandle:phandle;DesiredAccess:dword;reserved:boolean):NTStatus;stdcall;external 'samlib.dll';
function SamConnect2 (serverName:PLSA_UNICODE_STRING;out ServerHandle:handle;DesiredAccess:dword;reserved:boolean):NTStatus;stdcall;external 'samlib.dll' name 'SamConnect';
//NTSTATUS NTAPI 	SamCloseHandle (IN SAM_HANDLE SamHandle)
function SamCloseHandle(SamHandle:thandle):integer;stdcall;external 'samlib.dll';
//NTSTATUS NTAPI 	SamOpenDomain (IN SAM_HANDLE ServerHandle, IN ACCESS_MASK DesiredAccess, IN PSID DomainId, OUT PSAM_HANDLE DomainHandle)
function SamOpenDomain(ServerHandle:thandle;DesiredAccess:dword; DomainId:PSID;DomainHandle:phandle):NTStatus;stdcall;external 'samlib.dll';
//NTSTATUS NTAPI 	SamOpenUser (IN SAM_HANDLE DomainHandle, IN ACCESS_MASK DesiredAccess, IN ULONG UserId, OUT PSAM_HANDLE UserHandle)
function SamOpenUser(DomainHandle:thandle;DesiredAccess:dword;UserId:ulong;UserHandle:phandle):NTStatus;stdcall;external 'samlib.dll';
//NTSTATUS NTAPI 	SamEnumerateDomainsInSamServer (IN SAM_HANDLE ServerHandle, IN OUT PSAM_ENUMERATE_HANDLE EnumerationContext, OUT PVOID *Buffer, IN ULONG PreferedMaximumLength, OUT PULONG CountReturned)                                                                    isNewNTLM:boolean; oldNTLM:array of byte; newNTLM:array of byte):integer;stdcall;external 'samlib.dll';
function SamEnumerateDomainsInSamServer (ServerHandle:thandle; var EnumerationContext:dword; out buffer:PSAMPR_RID_ENUMERATION ;PreferedMaximumLength:ulong;out CountReturned:ulong):NTStatus;stdcall;external 'samlib.dll';

//NTSTATUS NTAPI 	SamLookupDomainInSamServer (IN SAM_HANDLE ServerHandle, IN PUNICODE_STRING Name, OUT PSID *DomainId)
function SamLookupDomainInSamServer (ServerHandle:thandle;Name:PLSA_UNICODE_STRING; OUT DomainId:PSID):NTStatus;stdcall;external 'samlib.dll';

//NTSTATUS NTAPI 	SamEnumerateUsersInDomain (IN SAM_HANDLE DomainHandle, IN OUT PSAM_ENUMERATE_HANDLE EnumerationContext, IN ULONG UserAccountControl, OUT PVOID *Buffer, IN ULONG PreferedMaximumLength, OUT PULONG CountReturned)
function SamEnumerateUsersInDomain(DomainHandle:thandle;var EnumerationContext:dword;UserAccountControl:ulong; OUT Buffer:PSAMPR_RID_ENUMERATION;PreferedMaximumLength:ulong;OUT CountReturned:ulong):NTStatus;stdcall;external 'samlib.dll';

//static extern int SamiChangePasswordUser(IntPtr UserHandle, bool isOldLM, byte[] oldLM, byte[] newLM,
//bool isNewNTLM, byte[] oldNTLM, byte[] newNTLM);
function SamiChangePasswordUser(UserHandle:thandle;
isOldLM:boolean;oldLM:tbyte16_; newLM:tbyte16_;
isNewNTLM:boolean;oldNTLM:tbyte16_;newNTLM:tbyte16_):NTStatus;stdcall;external 'samlib.dll';

//NTSTATUS NTAPI 	SamRidToSid (IN SAM_HANDLE ObjectHandle, IN ULONG Rid, OUT PSID *Sid)
function SamRidToSid(UserHandle:thandle;rid:ulong; out Sid:PSID):NTStatus;stdcall;external 'samlib.dll';
//extern NTSTATUS WINAPI SamFreeMemory(IN PVOID Buffer);
function SamFreeMemory(buffer:pointer):NTStatus;stdcall;external 'samlib.dll';

//NTSTATUS NTAPI 	SamQueryInformationUser (IN SAM_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, OUT PVOID *Buffer)
function SamQueryInformationUser (UserHandle:thandle; UserInformationClass:dword; out Buffer:pointer):NTStatus;stdcall;external 'samlib.dll';

//NTSTATUS NTAPI 	SamSetInformationUser (IN SAM_HANDLE UserHandle, IN USER_INFORMATION_CLASS UserInformationClass, IN PVOID Buffer)
function SamSetInformationUser (UserHandle:thandle; UserInformationClass:dword; Buffer:PSAMPR_USER_INTERNAL1_INFORMATION):NTStatus;stdcall;external 'samlib.dll';


implementation


end.

