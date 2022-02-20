//https://theroadtodelphi.com/category/wmi/

unit uwmi;

{$mode delphi}

interface

uses
  windows,SysUtils,ActiveX,ComObj,Variants,utils;

function _EnumProc(const computer,username,password:widestring):boolean;
function _Create(const computer,command,username,password:widestring):boolean;
Function _Killproc(const server,username,password:widestring;pid:dword=0):boolean;
function _reboot(const computer,username,password:widestring):boolean;

procedure  _ListFolder(Const Computer,WbemUser,WbemPassword,Path:widestring);
function  _CopyFile(const computer,username,password,SourceFileName,DestFileName:widestring):integer;

implementation

const
  //Impersonation Level Constants
  //http://msdn.microsoft.com/en-us/library/ms693790%28v=vs.85%29.aspx
  RPC_C_AUTHN_LEVEL_DEFAULT   = 0;
  RPC_C_IMP_LEVEL_ANONYMOUS   = 1;
  RPC_C_IMP_LEVEL_IDENTIFY    = 2;
  RPC_C_IMP_LEVEL_IMPERSONATE = 3;
  RPC_C_IMP_LEVEL_DELEGATE    = 4;

  //Authentication Service Constants
  //http://msdn.microsoft.com/en-us/library/ms692656%28v=vs.85%29.aspx
  RPC_C_AUTHN_WINNT      = 10;
  RPC_C_AUTHN_LEVEL_CALL = 3;
  RPC_C_AUTHN_DEFAULT    = $FFFFFFFF;
  EOAC_NONE              = 0;

  //Authorization Constants
  //http://msdn.microsoft.com/en-us/library/ms690276%28v=vs.85%29.aspx
  RPC_C_AUTHZ_NONE       = 0;
  RPC_C_AUTHZ_NAME       = 1;
  RPC_C_AUTHZ_DCE        = 2;
  RPC_C_AUTHZ_DEFAULT    = $FFFFFFFF;

  //Authentication-Level Constants
  //http://msdn.microsoft.com/en-us/library/aa373553%28v=vs.85%29.aspx
  RPC_C_AUTHN_LEVEL_PKT_PRIVACY   = 6;

  SEC_WINNT_AUTH_IDENTITY_ANSI    = 1;
  SEC_WINNT_AUTH_IDENTITY_UNICODE = 2;

function WbemTimeToDateTime(const V : OleVariant): TDateTime;
var
  Dt : OleVariant;
begin
  Result:=0;
  if VarIsNull(V) then exit;
  Dt:=CreateOleObject('WbemScripting.SWbemDateTime');
  Dt.Value := V;
  Result:=Dt.GetVarDate;
end;

function IsEmptyOrNull(const Value: Variant): Boolean;
begin
  Result := VarIsClear(Value) or VarIsEmpty(Value) or VarIsNull(Value) or (VarCompareValue(Value, Unassigned) = vrEqual);
  if (not Result) and VarIsStr(Value) then
    Result := Value = '';
end;

Function _Killproc(const server,username,password:widestring;pid:dword=0):boolean;
const
  wbemFlagForwardOnly = $00000020;
var
  FSWbemLocator : OLEVariant;
  FWMIService   : OLEVariant;
  FWbemObjectSet: OLEVariant;
  FWbemObject   : OLEVariant;
  oEnum         : IEnumvariant;
  iValue        : LongWord;
begin;
  result:=false;
  if pid=0 then exit;
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  FWMIService   := FSWbemLocator.ConnectServer(server, 'root\CIMV2', username, password);
  //FWbemObjectSet:= FWMIService.ExecQuery('SELECT name FROM Win32_Process Where ProcessId='+inttostr(pid),'WQL',wbemFlagForwardOnly);
  FWbemObjectSet:= FWMIService.ExecQuery(widestring('SELECT name FROM Win32_Process Where processid="'+inttostr(pid)+'"'),'WQL',wbemFlagForwardOnly);
  oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
  while oEnum.Next(1, FWbemObject, iValue) = 0 do
  begin
    if FWbemObject.Terminate()=0 then result:=true else result:=false;
    FWbemObject:=Unassigned;
  end;
  writeln(BoolToStr (result));
end;

//check https://github.com/RRUZ/wmi-delphi-code-creator/wiki/DelphiDevelopers
function _Create(const computer,command,username,password:widestring):boolean;
const
  wbemFlagForwardOnly = $00000020;
  HIDDEN_WINDOW       = 0;
var
  FSWbemLocator : OLEVariant;
  FWMIService   : OLEVariant;
  FWbemObject   : OLEVariant;
  objProcess    : OLEVariant;
  objConfig     : OLEVariant;
  ProcessID     : Integer;
begin;
  result:=false;
  if command='' then exit;
  writeln('computer:'+computer);
  writeln('command:'+command);
  writeln('username:'+username);
  writeln('password:'+password);
  //writeln(process);
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  //if computer='' then ...
  //if Failed(CoInitializeSecurity(nil, -1, nil, nil, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY, nil, EOAC_NONE, nil))
  //if computer<>'' then ...
  //if Failed(CoInitializeSecurity(nil, -1, nil, nil, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY, nil, EOAC_NONE, nil))
  //  then log('failed CoInitializeSecurity');
  FWMIService   := FSWbemLocator.ConnectServer(computer, 'root\CIMV2', username, password);
  FWbemObject   := FWMIService.Get('Win32_ProcessStartup');
  objConfig     := FWbemObject.SpawnInstance_;
  objConfig.ShowWindow := SW_hide ;
  objProcess    := FWMIService.Get('Win32_Process');
  objProcess.Create(widestring(command), null, objConfig, ProcessID);
  Writeln(Format('Pid %d',[ProcessID]));
  result:=true;
end;

function _reboot(const computer,username,password:widestring):boolean;
const
  wbemFlagForwardOnly = $00000020;
  wbemPrivilegeShutdown = $00000012;
  wbemCimtypeSint32 = 3;
var

  FSWbemLocator : OLEVariant;
  FWMIService   : OLEVariant;
  FWbemObject   : OLEVariant;
  FWbemObjectSet: OLEVariant;

  ShutdownMethod_inParameters,ShutdownMethod,Shutdown,WmiProperty,PropertyReboot:      OLEVariant;

  oEnum         : IEnumvariant;
  iValue        : LongWord;
begin


  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
   //Permet aux objets d'utiliser l'identité de l'appelant.
   //C'est le niveau d'usurpation d'identité recommandé pour l'appel d'API de scripting WMI.
  //WMILocator.Security_.Set_ImpersonationLevel(wbemImpersonationLevelImpersonate );
  //WMI utilise la configuration d'authentification par défaut de Windows.
  //WMILocator.Security_.Set_AuthenticationLevel(wbemAuthenticationLevelDefault);

  FWMIService   := FSWbemLocator.ConnectServer(computer, 'root\CIMV2', username, password);

  //Ajoute au process appelant le privilège wbemPrivilegeShutdown (SE_SHUTDOWN_NAME)
  FWMIService.Security_.Privileges.Add(wbemPrivilegeShutdown, True);

  FWbemObjectSet:= FWMIService.ExecQuery('SELECT * FROM Win32_OperatingSystem WHERE Primary=True','WQL', wbemFlagForwardOnly);

  oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;

  while oEnum.Next(1, FWbemObject, iValue) = 0 do
  begin



    {
    ShutdownMethod:= FWbemObject.Methods_.Item('Win32Shutdown', 0);
    ShutdownMethod_inParameters:= ShutdownMethod.InParameters;
    Shutdown:= ShutdownMethod_inParameters.SpawnInstance_(0);

    WmiProperty := Shutdown.Properties_.Add('Flags', wbemCimtypeSint32, False, 0);
    PropertyReboot:= EWX_REBOOT; // ou EWX_REBOOT;
    wmiProperty.Set_Value(PropertyReboot);
    }

    //if FWbemObject.Win32Shutdown(2+4,0)=S_OK then result:=true else result:=false;
    if FWbemObject.reboot()=S_OK then result:=true else result:=false;
    //FWbemObject.ExecMethod_('Win32Shutdown', shutdown, 0);
    FWbemObject:=Unassigned;
  end;
  writeln(BoolToStr (result));

  //if oEnum.Next(1, FWbemObject, iValue) = 0 then  FWbemObject.Win32Shutdown(1);
end;

function _EnumProc(const computer,username,password:widestring):boolean;
const
  wbemFlagForwardOnly = $00000020;
var
  FSWbemLocator : OLEVariant;
  FWMIService   : OLEVariant;
  FWbemObjectSet: OLEVariant;
  FWbemObject   : OLEVariant;
  oEnum         : IEnumvariant;
  iValue        : LongWord;
  NameOfUser    : OleVariant;
  UserDomain    : OleVariant;
  tmp:string;
begin;
  writeln('computer:'+computer);
  writeln('username:'+username);
  writeln('password:'+password);
  result:=false;
  //
  //if computer<>'' then  if Failed(CoInitializeSecurity(nil, -1, nil, nil, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IDENTIFY, nil, EOAC_NONE, nil)) then exit;
  //
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  FWMIService   := FSWbemLocator.ConnectServer(computer, 'root\CIMV2', username, password);
  //  FWbemObjectSet:= FWMIService.ExecQuery(Format('SELECT Name, CommandLine FROM Win32_Process Where Name="%s" or Name="%s"',['cscript.exe','wscript.exe']),'WQL',wbemFlagForwardOnly);
//  FWbemObjectSet:= FWMIService.ExecQuery('SELECT Name, CommandLine FROM Win32_Process','WQL',wbemFlagForwardOnly);
FWbemObjectSet:= FWMIService.ExecQuery('SELECT Name, ProcessID FROM Win32_Process','WQL',wbemFlagForwardOnly);
  oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
  while oEnum.Next(1, FWbemObject, iValue) = 0 do
  begin
    //Writeln(Format('Name         %s',[String(FWbemObject.Name)]));
    FWbemObject.GetOwner(NameOfUser, UserDomain);
    if (IsEmptyOrNull(NameOfUser)=false) and (IsEmptyOrNull(UserDomain)=false)
       then tmp:=string(userdomain)+'\'+string(NameOfUser) else tmp:='';
    Writeln(string(FWbemObject.Name)+#9+string(FWbemObject.ProcessID)+#9+tmp );
    {
    if IsEmptyOrNull(FWbemObject.CommandLine)=false
       then  Writeln(Format('Command Line %s',[String(FWbemObject.CommandLine)]));
    }
    FWbemObject:=Unassigned;
  end;
  result:=true;
end;

//list the files and folders of a specified Path (non recursive)
procedure  _ListFolder(Const Computer,WbemUser,WbemPassword,Path:widestring);
const
  wbemFlagForwardOnly = $00000020;
var
  FSWbemLocator : OLEVariant;
  FWMIService   : OLEVariant;
  FWbemObjectSet: OLEVariant;
  FWbemObject   : OLEVariant;
  oEnum         : IEnumvariant;
  iValue        : LongWord;
  WmiPath       : widestring;
  Drive         : widestring;
begin;
  //Extract the drive from the Path
  Drive   :=ExtractFileDrive(Path);
  writeln('computer:'+computer);
  writeln('drive:'+drive);

  //add a back slash to the end of the folder
  WmiPath :=IncludeTrailingPathDelimiter(Copy(Path,3,Length(Path)));
  //escape the folder name
  WmiPath :=StringReplace(WmiPath,'\','\\',[rfReplaceAll]);
  writeln('WmiPath:'+WmiPath);

  Writeln('Connecting');
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  //establish the connection
  FWMIService   := FSWbemLocator.ConnectServer(Computer, 'root\CIMV2', WbemUser, WbemPassword);

  //Writeln('Folders');
  //get the folders
  //FWbemObjectSet:= FWMIService.ExecQuery(Format('SELECT * FROM CIM_Directory Where Drive="%s" AND Path="%s"',[Drive,WmiPath]),'WQL',wbemFlagForwardOnly);
  FWbemObjectSet:= FWMIService.ExecQuery('SELECT * FROM CIM_Directory Where Drive="'+drive+'" AND Path="'+wmipath+'"','WQL',wbemFlagForwardOnly);
  oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
  while oEnum.Next(1, FWbemObject, iValue) = 0 do
  begin
    Writeln('['+Format('%s',[FWbemObject.Name])+']');// String
    FWbemObject:=Unassigned;
  end;

  //Writeln('Files');
  //get the files
  //FWbemObjectSet:= FWMIService.ExecQuery(Format('SELECT * FROM CIM_DataFile Where Drive="%s" AND Path="%s"',[Drive,WmiPath]),'WQL',wbemFlagForwardOnly);
  FWbemObjectSet:= FWMIService.ExecQuery('SELECT * FROM CIM_DataFile Where Drive="'+drive+'" AND Path="'+wmipath+'"','WQL',wbemFlagForwardOnly);
  oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
  while oEnum.Next(1, FWbemObject, iValue) = 0 do
  begin
    Writeln(Format('%s',[FWbemObject.Name]));// String
    FWbemObject:=Unassigned;
  end;
end;

function  _CopyFile(const computer,username,password,SourceFileName,DestFileName:widestring):integer;
var
  FSWbemLocator : OLEVariant;
  FWMIService   : OLEVariant;
  FWbemObject   : OLEVariant;
  source,dest:widestring;
begin;
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  FWMIService   := FSWbemLocator.ConnectServer(computer, 'root\CIMV2', username, password);
  //FWbemObject   := FWMIService.Get(Format('CIM_DataFile.Name="%s"',[StringReplace(SourceFileName,'\','\\',[rfReplaceAll])]));
  writeln('computer:'+computer);
  source:=StringReplace(SourceFileName,'\','\\',[rfReplaceAll]);
  dest:=StringReplace(DestFileName,'\','\\',[rfReplaceAll]);
  writeln('source:'+source);
  writeln('DestFileName:'+dest);
  FWbemObject   := FWMIService.Get('CIM_DataFile.Name="'+source+'"');
  writeln('get ok');
  Result:=FWbemObject.Copy(dest);
  writeln('copy ok');
end;



end.

