//function WinStationQueryInformationW; external 'winsta.dll' Name 'WinStationQueryInformationW';
unit winsta;

interface

uses windows;

type
HANDLE = THandle;
PVOID = Pointer;

_WINSTATIONQUERYINFORMATIONW = record
    Reserved1: array[0..71] of byte;
//    Res1: array[0..3] of byte;
//    WinStationName: array[0..12] of WideChar;
//    Res2: array[0..13] of byte;
//    ClientName: array[0..12] of WideChar;
//    Res3: array[0..1] of byte;
//    Reserved1: array[0..35] of WideChar;
    SessionId: Longint;
    Reserved2: array[0..3] of byte;
    ConnectTime: FILETIME;
    DisconnectTime: FILETIME;
    LastInputTime: FILETIME;
    LoginTime: FILETIME;
    Reserved3: array[0..1095] of byte;
//    Reserved3: array[0..548] of byte;
    CurrentTime: FILETIME;
  end;


var

  WinStationQueryInformationW:function(hServer: HANDLE; SessionId: ULONG;
  WinStationInformationClass: Cardinal; pWinStationInformation: PVOID;
  WinStationInformationLength: ULONG; var pReturnLength: ULONG):
  Boolean; stdcall;

  WinStationServerPing: function(hServer: HANDLE) :BOOLEAN; stdcall;

  function GetWTSLogonIdleTime(hServer: HANDLE; SessionID: ULong; var sLogonTime: String; var sIdleTime: String): Boolean;

implementation

uses sysutils,dateutils;

const
  apilib = 'winsta.dll';

var
 HApi: THandle = 0;

function InitAPI: Boolean;
begin
  Result := False;
  if Win32Platform <> VER_PLATFORM_WIN32_NT then Exit;
  if HApi = 0 then HApi := LoadLibrary(apilib);
  if HApi > HINSTANCE_ERROR then
  begin
    @WinStationQueryInformationW:= GetProcAddress(HApi, 'WinStationQueryInformationW');
    @WinStationServerPing:=getprocaddress(HApi,'WinStationServerPing');
    Result := True;
  end;
end;

procedure FreeAPI;
begin
  if HApi <> 0 then FreeLibrary(HApi);
  HApi := 0;
end;

function FileTime2DateTime(FileTime: FileTime): TDateTime;
var
   LocalFileTime: TFileTime;
   SystemTime: TSystemTime;
begin
   FileTimeToLocalFileTime(FileTime, LocalFileTime) ;
   FileTimeToSystemTime(LocalFileTime, SystemTime) ;
   Result := SystemTimeToDateTime(SystemTime) ;
end;



function GetWTSLogonIdleTime(hServer: HANDLE; SessionID: ULong; var sLogonTime: String; var sIdleTime: String): Boolean;
var uReturnLength: ULONG;
  info: _WINSTATIONQUERYINFORMATIONW;
  CurrentTime: TDateTime;
  LastInputTime: TDateTime;
  IdleTime: TDateTime;
  LogonTime: TDateTime;
  Days, Hours, Minutes: Word;
  fs: TFormatSettings;
begin
  GetLocaleFormatSettings(LOCALE_SYSTEM_DEFAULT, fs);
  uReturnLength := 0;
  try
    Result := WinStationQueryInformationW(hServer, SessionID, 8, @info,
              sizeof(info), uReturnLength);
    if Result then
    begin
      LogonTime := FileTime2DateTime(Info.LoginTime);
      if YearOf(LogonTime) = 1601 then
      begin
        sLogonTime := '';
      end
      else
      begin
        sLogonTime := DateTimeToStr(LogonTime, fs);
      end;
      { from Usenet post by Chuck Chopp
        http://groups.google.com/group/microsoft.public.win32.programmer.kernel/browse_thread/thread/c6dd86e7df6d26e4/3cf53e12a3246e25?lnk=st&q=WinStationQueryInformationa+group:microsoft.public.*&rnum=1&hl=en#3cf53e12a3246e25
        2)  The system console session cannot go into an idle/disconnected state.
            As such, the LastInputTime value will always math CurrentTime for the
            console session.
        3)  The LastInputTime value will be zero if the session has gone
            disconnected.  In that case, use the DisconnectTime value in place of
            LastInputTime when calculating the current idle time for a disconnected session.
        4)  All of these time values are GMT time values.
        5)  The disconnect time value will be zero if the sesson has never been
            disconnected.}
      CurrentTime := FileTime2DateTime(Info.CurrentTime);
      LastInputTime := FileTime2DateTime(Info.LastInputTime);

      // Disconnected session = idle since DisconnectTime
      if YearOf(LastInputTime) = 1601 then begin
        LastInputTime := FileTime2DateTime(Info.DisconnectTime);
      end;

//      IdleTime := LastInputTime - CurrentTime;
      IdleTime := CurrentTime - LastInputTime;
      Days := Trunc(IdleTime);
      Hours := HourOf(IdleTime);
      Minutes := MinuteOf(IdleTime);
      if Days > 0 then
      begin
        sIdleTime := Format('%d + %d:%1.2d', [Days, Hours, Minutes]);
      end
      else if Hours > 0 then
      begin
        sIdleTime := Format('%d:%1.2d', [Hours, Minutes]);
      end
      else if Minutes > 0 then
      begin
        sIdleTime := IntToStr(Minutes);
      end
      else
      begin
        sIdleTime := '-';
      end;
    end;
  except
    on E: Exception do
    begin
      Result := False;
    end;
  end;
end;


initialization InitAPI;
finalization FreeAPI;

end.

