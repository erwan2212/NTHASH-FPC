unit untdll;

{$mode delphi}

interface

uses
  windows,Classes, SysUtils;

type TOSVersionInfoExW = record
       dwOSVersionInfoSize: DWORD;
       dwMajorVersion: DWORD;
       dwMinorVersion: DWORD;
       dwBuildNumber: DWORD;
       dwPlatformId: DWORD;
       szCSDVersion: array[0..127] of WideChar; { Maintenance string for PSS usage }
       wServicePackMajor: Word;
       wServicePackMinor: Word;
       wSuiteMask: Word;
       wProductType: Byte;
       wReserved: byte;
     end;

 //function RtlGetVersion (var lpVersionInformation: TOSVERSIONINFOEXW): DWORD; stdcall; external 'ntdll.dll' name 'RtlGetVersion';

//
function GetWindowsVer:string;

implementation

//https://www.lifewire.com/windows-version-numbers-2625171
function GetWindowsVer:string;
var
  osver:TOSVersionInfoExW ;
  RtlGetVersion:function(var lpVersionInformation: TOSVERSIONINFOEXW): DWORD; stdcall;
begin
{
windows 10's
version buildnumber
1507	10240
1511	10586
1607	14393
1703	15063
1709	16299
1803	17134
1809	17763
1903	18362
1909    18362
}
//
RtlGetVersion:=getProcAddress(loadlibrary('ntdll.dll'),'RtlGetVersion');
//
   RtlGetVersion(osver ) ;
   result:=(inttostr(osver.dwMajorVersion)
             +'.'+inttostr(osver.dwMinorVersion)
             +'.'+inttostr(osver.dwBuildNumber) );
if osver.dwMajorVersion =10 then
   begin
        case osver.dwBuildNumber of
        10240:result:=result+'-1507'; //ok
        10586:result:=result+'-1511';
        14393:result:=result+'-1607';
        15063:result:=result+'-1703'; //ok
        16299:result:=result+'-1709'; //ok
        17134:result:=result+'-1803'; //OK
        17763:result:=result+'-1809'; //ok
        18362:result:=result+'-1903';
        18823:result:=result+'-1909';
        19041:result:=result+'-2004';
        19042:result:=result+'-20H2';
        20180:result:=result+'-21H1';
        end;
   end;

end;

end.

