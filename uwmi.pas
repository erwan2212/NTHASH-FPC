//https://theroadtodelphi.com/category/wmi/

unit uwmi;

{$mode delphi}

interface

uses
  windows,SysUtils,ActiveX,ComObj,Variants;

function _EnumProc(computer:widestring=''):boolean;
function _Create(computer:string='';command:string=''):boolean;
Function _Killproc(server:string='';pid:dword=0):boolean;

procedure  _ListFolder(Const Computer,WbemUser,WbemPassword,Path:widestring);
function  _CopyFile(const computer,SourceFileName,DestFileName:widestring):integer;

implementation

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

Function _Killproc(server:string='';pid:dword=0):boolean;
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
  FWMIService   := FSWbemLocator.ConnectServer(widestring(server), 'root\CIMV2', '', '');
  //FWbemObjectSet:= FWMIService.ExecQuery('SELECT name FROM Win32_Process Where ProcessId='+inttostr(pid),'WQL',wbemFlagForwardOnly);
  FWbemObjectSet:= FWMIService.ExecQuery(widestring('SELECT name FROM Win32_Process Where processid="'+inttostr(pid)+'"'),'WQL',wbemFlagForwardOnly);
  oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
  while oEnum.Next(1, FWbemObject, iValue) = 0 do
  begin
    FWbemObject.Terminate();
    FWbemObject:=Unassigned;
  end;
  result:=true;
end;

function _Create(computer:string='';command:string=''):boolean;
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
  //writeln(process);
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  FWMIService   := FSWbemLocator.ConnectServer(widestring(computer), 'root\CIMV2', '', '');
  FWbemObject   := FWMIService.Get('Win32_ProcessStartup');
  objConfig     := FWbemObject.SpawnInstance_;
  objConfig.ShowWindow := SW_HIDE ;
  objProcess    := FWMIService.Get('Win32_Process');
  objProcess.Create(widestring(command), null, objConfig, ProcessID);
  Writeln(Format('Pid %d',[ProcessID]));
  result:=true;
end;

function _EnumProc(computer:widestring=''):boolean;
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
  result:=false;
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  FWMIService   := FSWbemLocator.ConnectServer(computer, 'root\CIMV2', '', '');
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

function  _CopyFile(const computer,SourceFileName,DestFileName:widestring):integer;
var
  FSWbemLocator : OLEVariant;
  FWMIService   : OLEVariant;
  FWbemObject   : OLEVariant;
begin;
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  FWMIService   := FSWbemLocator.ConnectServer(computer, 'root\CIMV2', '', '');
  //FWbemObject   := FWMIService.Get(Format('CIM_DataFile.Name="%s"',[StringReplace(SourceFileName,'\','\\',[rfReplaceAll])]));
  writeln('computer:'+computer);
  writeln('source:'+StringReplace(SourceFileName,'\','\\',[rfReplaceAll]));
  writeln('DestFileName:'+StringReplace(DestFileName,'\','\\',[rfReplaceAll]));
  FWbemObject   := FWMIService.Get('CIM_DataFile.Name="'+widestring(StringReplace(SourceFileName,'\','\\',[rfReplaceAll]))+'"');
  Result:=FWbemObject.Copy(widestring(StringReplace(DestFileName,'\','\\',[rfReplaceAll])));
end;

end.

