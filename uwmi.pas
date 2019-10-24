unit uwmi;

{$mode delphi}

interface

uses
  windows,SysUtils,ActiveX,ComObj,Variants;

function _EnumProc(server:string=''):boolean;
function _Create(server:string='';process:string=''):boolean;
Function _Killproc(server:string='';pid:dword=0):boolean;

implementation

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

function _Create(server:string='';process:string=''):boolean;
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
  if process='' then exit;
  //writeln(process);
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  FWMIService   := FSWbemLocator.ConnectServer(widestring(server), 'root\CIMV2', '', '');
  FWbemObject   := FWMIService.Get('Win32_ProcessStartup');
  objConfig     := FWbemObject.SpawnInstance_;
  objConfig.ShowWindow := SW_HIDE ;
  objProcess    := FWMIService.Get('Win32_Process');
  objProcess.Create(widestring(process), null, objConfig, ProcessID);
  Writeln(Format('Pid %d',[ProcessID]));
  result:=true;
end;

function _EnumProc(server:string=''):boolean;
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
  FSWbemLocator := CreateOleObject('WbemScripting.SWbemLocator');
  FWMIService   := FSWbemLocator.ConnectServer(widestring(server), 'root\CIMV2', '', '');
//  FWbemObjectSet:= FWMIService.ExecQuery(Format('SELECT Name, CommandLine FROM Win32_Process Where Name="%s" or Name="%s"',['cscript.exe','wscript.exe']),'WQL',wbemFlagForwardOnly);
  FWbemObjectSet:= FWMIService.ExecQuery('SELECT Name, CommandLine FROM Win32_Process','WQL',wbemFlagForwardOnly);
  oEnum         := IUnknown(FWbemObjectSet._NewEnum) as IEnumVariant;
  while oEnum.Next(1, FWbemObject, iValue) = 0 do
  begin
    Writeln(Format('Name         %s',[String(FWbemObject.Name)]));
    {
    if IsEmptyOrNull(FWbemObject.CommandLine)=false
       then  Writeln(Format('Command Line %s',[String(FWbemObject.CommandLine)]));
    }
    FWbemObject:=Unassigned;
  end;
  result:=true;
end;

end.

