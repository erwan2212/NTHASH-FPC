unit uXor;

{$mode delphi}

interface

uses
   sysutils,utils,windows;

function xorfilev2(filein,fileout:string;encrypt:boolean=true):boolean;
function xorfile(filein,fileout:string):boolean;

function xorbytes(buffer:pointer;size:integer):boolean;


implementation

function xorbytes(buffer:pointer;size:integer):boolean;
var
  c:dword;
  pIn:^byte;
begin
  log('**** xorbytes ****');
  log('size:'+inttostr(size));
  //xor buffer here
  pIn:=buffer;
  for c:=0 to size {length(buffer)} -1 do
    begin
    pIn^:=pIn^ xor 255;  //too easy, virustotal can id the file...
    inc(pIn);
    end;
end;

function xorfilev2(filein,fileout:string;encrypt:boolean=true):boolean;
var
  dwread:dword=0;
  dwwrite:dword=0;
  c:dword;
  dwFileSize:dword;
  hfilein,hfileout:thandle;
  bufferIn,bufferOut:pointer;
  pIn,pOut:^byte;
  //
  key:array [0..2] of word=($400,$1000,$4000);
begin
  log('********* xorfilev2 **************');
  hFilein := CreateFile(pchar(filein),GENERIC_READ,0,nil,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
  if hFilein=thandle(-1) then exit;
  hFileout := CreateFile(pchar(fileout),GENERIC_WRITE,0,nil,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
  if hFileout=thandle(-1) then exit;
  //
  dwFileSize := GetFileSize(hFilein,nil);
  log('dwFileSize:'+inttostr(dwFileSize));
  if dwFileSize = INVALID_FILE_SIZE then exit;
  bufferIn := AllocMem(dwFileSize);bufferOut := AllocMem(dwFileSize);
  while 1=1 do
  begin
  ReadFile(hFilein,bufferIn^,dwFileSize,dwRead,nil);
  if dwread=0 then break;
  //xor buffer here
  pIn:=bufferIn;pOut:=bufferOut;
  for c:=0 to dwread -1 do
    begin
    pOut^ := pIn^ xor (Key[2] shr 8);
    if encrypt
       then Key[2] := Byte(pIn^ + Key[2]) * Key[0] + Key[1]
       else Key[2] := byte(pOut^ + Key[2]) * Key[0] + Key[1];
    inc(pIn);inc(pOut);
    end;
  //
  //result:=WriteFile(hFileout, bufferIn^, dwread, dwwrite, nil);
  result:=WriteFile(hFileout, bufferOut^, dwread, dwwrite, nil);
  end;
  //
  if bufferIn<>nil then freemem(bufferIn);
  if bufferOut<>nil then freemem(bufferOut);
  closehandle(hFilein);
  closehandle(hFileout);
  log('done');
end;

function xorfile(filein,fileout:string):boolean;
var
  dwread:dword=0;
  dwwrite:dword=0;
  c:dword;
  dwFileSize:dword;
  hfilein,hfileout:thandle;
  buffer:pointer;
  pIn:pbyte;
begin
  result:=false;
  log('********* xorfile **************');
  hFilein := CreateFile(pchar(filein),GENERIC_READ,0,nil,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
  if hFilein=thandle(-1) then exit;
  hFileout := CreateFile(pchar(fileout),GENERIC_WRITE,0,nil,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
  if hFileout=thandle(-1) then exit;
  //
  dwFileSize := GetFileSize(hFilein,nil);
  log('dwFileSize:'+inttostr(dwFileSize));
  if dwFileSize = INVALID_FILE_SIZE then exit;
  buffer := AllocMem(dwFileSize);
  while 1=1 do
  begin
  ReadFile(hFilein,buffer^,dwFileSize,dwRead,nil);
  if dwread=0 then break;
  //xor buffer here
  pIn:=buffer;
  for c:=0 to dwread -1 do
    begin
    pIn^:=pIn^ xor 255;  //too easy, virustotal can id the file...
    inc(pIn);
    end;
  //
  //result:=WriteFile(hFileout, bufferIn^, dwread, dwwrite, nil);
  result:=WriteFile(hFileout, buffer^, dwread, dwwrite, nil);
  end;
  //
  if buffer<>nil then freemem(buffer);
  closehandle(hFilein);
  closehandle(hFileout);
  result:=true;
  log('done');
end;

end.

