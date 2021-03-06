unit usecur32;

{$mode delphi}

interface

uses
  Classes, SysUtils,windows,utils;

  procedure GetActiveUserNames();

implementation

type
  PTOKEN_USER = ^TOKEN_USER;
  _TOKEN_USER = record
    User: TSidAndAttributes;
  end;
  TOKEN_USER = _TOKEN_USER;

  USHORT = word;

  _LSA_UNICODE_STRING = record
    Length: USHORT;
    MaximumLength: USHORT;
    Buffer: LPWSTR;
  end;
  LSA_UNICODE_STRING = _LSA_UNICODE_STRING;

  PLuid = ^LUID;
  _LUID = record
    LowPart: DWORD;
    HighPart: LongInt;
  end;
  LUID = _LUID;

  _SECURITY_LOGON_TYPE = (
    seltFiller0, seltFiller1,
    Interactive,
    Network,
    Batch,
    Service,
    Proxy,
    Unlock,
    NetworkCleartext,
    NewCredentials,
    RemoteInteractive,
    CachedInteractive,
    CachedRemoteInteractive);
  SECURITY_LOGON_TYPE = _SECURITY_LOGON_TYPE;

  PSECURITY_LOGON_SESSION_DATA = ^SECURITY_LOGON_SESSION_DATA;
  _SECURITY_LOGON_SESSION_DATA = record
    Size: ULONG;
    LogonId: LUID;
    UserName: LSA_UNICODE_STRING;
    LogonDomain: LSA_UNICODE_STRING;
    AuthenticationPackage: LSA_UNICODE_STRING;
    LogonType: SECURITY_LOGON_TYPE;
    Session: ULONG;
    Sid: PSID;
    LogonTime: LARGE_INTEGER;
    LogonServer: LSA_UNICODE_STRING;
    DnsDomainName: LSA_UNICODE_STRING;
    Upn: LSA_UNICODE_STRING;
  end;
  SECURITY_LOGON_SESSION_DATA = _SECURITY_LOGON_SESSION_DATA;

  function LsaGetLogonSessionData(LogonId: PLUID;
     var ppLogonSessionData: PSECURITY_LOGON_SESSION_DATA): LongInt; stdcall;
     external 'Secur32.dll';

  function LsaNtStatusToWinError(Status: cardinal): ULONG; stdcall;
     external 'Advapi32.dll';

  function LsaEnumerateLogonSessions(Count: PULONG; List: PLUID): LongInt;
     stdcall; external 'Secur32.dll';

  function LsaFreeReturnBuffer(Buffer: pointer): Integer; stdcall;external 'secur32.dll';

  function FileTimeToDateTime(const FileTime: Int64): TDateTime; // Change the Filetime type to Int64 as FileTime is passed to me Int64 already

  const
  FileTimeBase      = -109205.0;
  FileTimeStep: Extended = 24.0 * 60.0 * 60.0 * 1000.0 * 1000.0 * 10.0; // 100 nSek per Day
begin
  Result := (FileTime) / FileTimeStep; // Remove the Int64 conversion as FileTime arrives as Int64 already
  Result := Result + FileTimeBase;
end;

procedure GetActiveUserNames();
var
   Count: cardinal;
   List: PLUID;
   sessionData: PSECURITY_LOGON_SESSION_DATA;
   i1: integer;
   SizeNeeded, SizeNeeded2: DWORD;
   OwnerName, DomainName: PChar;
   OwnerType: SID_NAME_USE;
   //pBuffer: Pointer;
   //pBytesreturned: DWord;
   sUser : string;
   LocalFileTime: TFileTime;
   LogonTime:tdatetime;
begin
   //result:= '';
   //Listing LogOnSessions
   i1:= lsaNtStatusToWinError(LsaEnumerateLogonSessions(@Count, @List));
   try
      if i1 = 0 then
      begin
          i1:= -1;
          if Count > 0 then
          begin
              log('user'#9'authpackage'#9'logonserver'#9'logonid'#9'session'#9'logontime',1);
              repeat
                inc(i1);
                LsaGetLogonSessionData(List, sessionData);
                //Checks if it is an interactive session
                sUser := sessionData.UserName.Buffer;
                if (sessionData.LogonType = Interactive)
                  or (sessionData.LogonType = RemoteInteractive)
                  or (sessionData.LogonType = CachedInteractive)
                  or (sessionData.LogonType = CachedRemoteInteractive) then
                begin
                    //
                    SizeNeeded := MAX_PATH;
                    SizeNeeded2:= MAX_PATH;
                    GetMem(OwnerName, MAX_PATH);
                    GetMem(DomainName, MAX_PATH);
                    try
                    if LookupAccountSID(nil, sessionData.SID, OwnerName,
                                       SizeNeeded, DomainName,SizeNeeded2,
                                       OwnerType) then
                    begin
                      if integer(OwnerType) = 1 then  //This is a USER account SID (SidTypeUser=1)
                      begin
                        sUser := AnsiUpperCase(sessionData.LogonDomain.Buffer);
                        sUser := sUser + '\';
                        sUser := sUser + AnsiUpperCase(sessionData.UserName.Buffer);
                        if FileTimeToLocalFileTime(TFileTime(sessionData.LogonTime),LocalFileTime)
                          then LogonTime:=FileTimeToDateTime(LARGE_INTEGER(LocalFileTime).QuadPart );
                        log(suser+#9
                            +sessionData.AuthenticationPackage.Buffer+#9
                            +sessionData.LogonServer.Buffer +#9
                            +inttohex(LARGE_INTEGER(sessionData.LogonId).QuadPart,8)+#9
                            +inttostr(sessionData.Session )+#9
                            +datetimetostr(logontime),1);
                       end;
                    end;
                    finally
                    FreeMem(OwnerName);
                    FreeMem(DomainName);
                    end;
                end;
                inc(List);
                try
                    LSAFreeReturnBuffer(sessionData);
                except
                end;
            until (i1 = Count-1);// or (result <> '');
          end;
      end;
   finally
      LSAFreeReturnBuffer(List);
   end;
end;

end.

