unit uchrome;

{$mode delphi}
{.$define static}

interface

uses
  sysutils,windows,
  //static
  {$ifdef static}synsqlite3static,{$endif}
  //or dynamic
  {$ifndef static}SynSQLite3,{$endif}
  syndb,syndbsqlite3,
  shlobj,
  ucryptoapi,utils;

function decrypt_chrome:boolean;

implementation


function GetSpecialFolder(const CSIDL: integer) : string;
var
  RecPath : pChar;
begin
  RecPath := StrAlloc(MAX_PATH);
    try
    FillChar(RecPath^, MAX_PATH, 0);
    if SHGetSpecialFolderPath(0, RecPath, CSIDL, false)
      then result := RecPath
      else result := '';
    finally
      StrDispose(RecPath);
    end;
end;

function decrypt_chrome:boolean;
var
Props: TSQLDBSQLite3ConnectionProperties ;
  //
  p:pointer;
  //b:array of byte;
  b,output:tbytes;
  path,tmp:string;
  //li:TListItem ;
  Rows: ISQLDBRows;
begin
  result:=false;
//C:\Users\xxx\AppData\Local\Google\Chrome\User Data\Default
path:=(GetSpecialFolder($1c));  //CSIDL_LOCAL_APPDATA
path:=path+'\Google\Chrome\User Data\Default';

  if not FileExists(path+'\login data') then
  begin
    writeln('The database does not exist. Please create one.');
    Exit;
  end;

  {$i-}DeleteFile(pchar(path+'\login data.db'));{$i+}
  copyfile(pchar(path+'\login data'),pchar(path+'\login data.db'),false);

  try
    //if dynamic
    {$ifndef static}
    sqlite3 := TSQLite3LibraryDynamic.Create(SQLITE_LIBRARY_DEFAULT_NAME);
    {$endif}
    //
    props:=TSQLDBSQLite3ConnectionProperties.Create(pchar(path+'\login data.db'),'','','');

    setlength(b,230);
    try
    rows:= props.Execute('SELECT origin_url,username_value,password_value,length(password_value) from logins',[]);
    result:=true;
    while rows.step do
      begin

      tmp:=''; //for i:=0 to length(b)-1 do b[i]:=0;
      b:=rows.ColumnBlobBytes('password_value');
      //CryptUnprotect(b,tmp);
      if CryptUnProtectData_(b,output)=true then
         begin
         if length(output)<255 then
         begin
         {
         writeln(rows['origin_url']);
         writeln((rows['username_value']));
         writeln(BytetoAnsiString(output));
         }
         writeln(rows['origin_url']+';'+rows['username_value']+';'+BytetoAnsiString(output));
         end;
         end;
      end;
    finally
      //rows._Release ;
    end;
  finally
    //props.FreeInstance ;
  end;
{$i-}DeleteFile(pchar(path+'\login data.db'));{$i+}
end;

end.

