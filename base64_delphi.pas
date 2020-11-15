unit base64_delphi; 

{$ifdef fpc}{$mode delphi}{$endif fpc}

interface

uses
  SysUtils;

function EncodeStringBase64(const S: string): string;
function DecodeStringBase64(const S: string): string;  

implementation

const
  B64Table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function EncodeStringBase64(const S: string): string;
var
  InBuf : array[0..2] of Byte;
  OutBuf: array[0..3] of Char;
  iI, iJ: Integer;
begin
  SetLength(Result, ((Length(S) + 2) div 3) * 4);
  for iI := 1 to ((Length(S) + 2) div 3) do
  begin
    if Length(S) < (iI * 3) then Move(S[(iI - 1) * 3 + 1], InBuf, Length(S) - (iI - 1) * 3)
    else  Move(S[(iI - 1) * 3 + 1], InBuf, 3);
    OutBuf[0] := B64Table[((InBuf[0] and $FC) shr 2) + 1];
    OutBuf[1] := B64Table[(((InBuf[0] and $3) shl 4) or ((InBuf[1] and $F0) shr 4)) + 1];
    OutBuf[2] := B64Table[(((InBuf[1] and $F) shl 2) or ((InBuf[2] and $C0) shr 6)) + 1];
    OutBuf[3] := B64Table[(InBuf[2] and $3F) + 1];
    Move(OutBuf, Result[(iI - 1) * 4 + 1], 4);
  end; //for iI := 1 to ((Length(S) + 2) div 3) do
  if Length(S) mod 3 = 1 then
  begin
    Result[Length(Result) - 1] := '=';
    Result[Length(Result)] := '=';
  end
  else if Length(S) mod 3 = 2 then Result[Length(Result)] := '=';
end;


function DecodeStringBase64(const S: string): string;
var
  OutBuf: array[0..2] of Byte;
  InBuf : array[0..3] of Byte;
  iI, iJ: Integer;
begin
  if Length(S) mod 4 <> 0 then raise Exception.Create('Base64: Incorrect string format');
  SetLength(Result, ((Length(S) div 4) - 1) * 3);
  for iI := 1 to (Length(S) div 4) - 1 do
  begin
   Move(S[(iI - 1) * 4 + 1], InBuf, 4);
    for iJ := 0 to 3 do
      case InBuf[iJ] of
        43: InBuf[iJ] := 62;
        48..57: Inc(InBuf[iJ], 4);
        65..90: Dec(InBuf[iJ], 65);
        97..122: Dec(InBuf[iJ], 71);
      else
        InBuf[iJ] := 63;
      end;
    OutBuf[0] := (InBuf[0] shl 2) or ((InBuf[1] shr 4) and $3);
    OutBuf[1] := (InBuf[1] shl 4) or ((InBuf[2] shr 2) and $F);
    OutBuf[2] := (InBuf[2] shl 6) or (InBuf[3] and $3F);
    Move(OutBuf, Result[(iI - 1) * 3 + 1], 3);
  end; //for
  if Length(S) <> 0 then
  begin
    Move(S[Length(S) - 3], InBuf, 4);
    if InBuf[2] = 61 then
    begin
      for iJ := 0 to 1 do
        case InBuf[iJ] of
          43: InBuf[iJ] := 62;
          48..57: Inc(InBuf[iJ], 4);
          65..90: Dec(InBuf[iJ], 65);
          97..122: Dec(InBuf[iJ], 71);
        else
          InBuf[iJ] := 63;
        end; //case
      OutBuf[0] := (InBuf[0] shl 2) or ((InBuf[1] shr 4) and $3);
      Result := Result + Char(OutBuf[0]);
    end //if InBuf[2] = 61 then
    else if InBuf[3] = 61 then
    begin
      for iJ := 0 to 2 do
        case InBuf[iJ] of
          43: InBuf[iJ] := 62;
          48..57: Inc(InBuf[iJ], 4);
          65..90: Dec(InBuf[iJ], 65);
          97..122: Dec(InBuf[iJ], 71);
        else
          InBuf[iJ] := 63;
        end; //case
      OutBuf[0] := (InBuf[0] shl 2) or ((InBuf[1] shr 4) and $3);
      OutBuf[1] := (InBuf[1] shl 4) or ((InBuf[2] shr 2) and $F);
      Result := Result + Char(OutBuf[0]) + Char(OutBuf[1]);
    end //else if InBuf[3] = 61 then
    else
    begin
      for iJ := 0 to 3 do
        case InBuf[iJ] of
          43: InBuf[iJ] := 62;
          48..57: Inc(InBuf[iJ], 4);
          65..90: Dec(InBuf[iJ], 65);
          97..122: Dec(InBuf[iJ], 71);
        else
          InBuf[iJ] := 63;
        end; //case
      OutBuf[0] := (InBuf[0] shl 2) or ((InBuf[1] shr 4) and $3);
      OutBuf[1] := (InBuf[1] shl 4) or ((InBuf[2] shr 2) and $F);
      OutBuf[2] := (InBuf[2] shl 6) or (InBuf[3] and $3F);
      Result := Result + Char(OutBuf[0]) + Char(OutBuf[1]) + Char(OutBuf[2]);
    end;
  end;
end;


end.