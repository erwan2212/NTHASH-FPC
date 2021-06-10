unit uchrome;

{$ifdef fpc}{$mode delphi}{$endif fpc}
{.$define static}
{$ifndef fpc}{$define nodpapi}{$endif fpc}

interface

uses
  sysutils,windows,
  //static
  {$ifdef static}synsqlite3static,{$endif}
  //or dynamic
  {$ifndef static}SynSQLite3,{$endif}
  syndb,syndbsqlite3,
  //shlobj,
  ucryptoapi,utils,
  {$ifndef nodpapi}udpapi,{$endif nodpapi}
  uLkJSON,variants,
  {$ifdef fpc}base64;{$endif fpc}
  {$ifndef fpc}base64_delphi;{$endif fpc}


function decrypt_chrome(db:string='';mk:pointer=nil):boolean;
function decrypt_cookies(db:string=''):boolean;

var
  SHGetSpecialFolderPath:function(HWND:hwnd;pszpath: LPSTR; csidl:Longint;fcreate:bool):bool;StdCall; //external 'shell32' name 'SHGetSpecialFolderPathA';

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

function decrypt_chrome(db:string='';mk:pointer=nil):boolean;
const
  DPAPI_CHROME_UNKV10 : array[0..2] of char = ('v', '1', '0');
var
Props: TSQLDBSQLite3ConnectionProperties ;
  //
  p:pointer;
  //b:array of byte;
  b,output:tbytes;
  path,tmp:string;
  //li:TListItem ;
  Rows: ISQLDBRows;
  //
  blob_:tdpapi_blob;
  guidMasterKey:string{$ifdef fpc}=''{$endif fpc};
  ptr_:pointer;
  dw:dword;
  pwd:string;
  //
  js:TlkJSONobject;
  T: TextFile;
  s:string;
  bytes,key,iv,encrypted:tbytes;
begin

  result:=false;
//C:\Users\xxx\AppData\Local\Google\Chrome\User Data\Default
if db='' then
   begin
   path:=(GetSpecialFolder($1c));  //CSIDL_LOCAL_APPDATA
   path:=path+'\Google\Chrome\User Data\Default';
     if not FileExists(path+'\login data') then
     begin
       writeln('The database does not exist. Please create one.');
       Exit;
     end;
   {$i-}DeleteFile(pchar(path+'\login data.db'));{$i+}
   copyfile(pchar(path+'\login data'),pchar(path+'\login data.db'),false);
   end; //if db='' then

if db<>'' then
   begin
   path:= ExtractFileDir (db);
   {$i-}DeleteFile(pchar(path+'\login data.db'));{$i+}
   copyfile(pchar(db),pchar(path+'\login data.db'),false);
   end; //if db<>'' then

writeln('path:'+path);
writeln('db:'+path+'\login data.db');

if (db<>'') and (fileexists(db)=false) then begin writeln('db does not exist');exit;end;

if (db<>'') and (mk=nil) then
   begin
   getmem(mk,1);
   end;

//
if (db='') and  (FileExists (GetSpecialFolder($1c)+'\Google\Chrome\User Data\local state')) then
   begin
   {
   New Chrome version (v80.0 & higher) uses Master Key based encryption to store your web login passwords.
   First 32-byte random data is generated.
   Then it is encrypted using Windows DPAPI (“CryptProtectData”) function.
   To this encrypted key, it inserts signature “DPAPI” (RFBBUEk) in the beginning for identification.
   Finally this key is encoded using Base64 and stored in “Local State” file in above “User Data” folder.
   }
   //writeln('found '+GetSpecialFolder($1c)+'\Google\Chrome\User Data\local state');
   {
   AssignFile(t, GetSpecialFolder($1c)+'\Google\Chrome\User Data\local state');
   Reset(t);
   Readln(t, s); //while not eof... ?
   CloseFile(t);
   }
   //js := TlkJSON.ParseText(s) as TlkJSONobject;
   js:=TlkJSONstreamed.loadfromfile(GetSpecialFolder($1c)+'\Google\Chrome\User Data\local state') as TlkJsonObject;
   if assigned(js) then
      begin
      //writeln('assigned(js)');
      s:=vartostr(js.Field['os_crypt'].Field['encrypted_key'].Value);
      //writeln(s);
      {$ifdef fpc}bytes:=AnsiStringtoByte (base64.DecodeStringBase64 (s,true));{$endif fpc}
      {$ifndef fpc}bytes:=AnsiStringtoByte (base64_delphi.DecodeStringBase64 (s));{$endif fpc}
      s:=ByteToHexaString(bytes);
      delete(s,1,10); //remove 'DPAPI'
      //writeln(s);
      //writeln(length(s));
      if CryptUnProtectData_(HexaStringToByte2(s),key)= true
        then writeln('os_crypt:encrypted_key:'+ByteToHexaString(key))
        else writeln('no os_crypt:encrypted_key');
      js.Free;
      end;
   end;
//

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

    guidMasterKey:='{00000000-0000-0000-0000-000000000000}';

    while rows.step do
      begin
      tmp:=''; //for i:=0 to length(b)-1 do b[i]:=0;
      b:=tbytes(rows.ColumnBlobBytes('password_value'));

      //if a decrypted MK is provided...
      {$ifndef nodpapi}
      if mk<>nil then
         begin
         if (CompareMem (@b[0],@DPAPI_CHROME_UNKV10[0] ,3)=false) then
         begin
         //
         //lets get our encrypted blob
         guidMasterKey:='{00000000-0000-0000-0000-000000000000}';
         if decodeblob (b,@blob_)
           then guidMasterKey:=GUIDToString (blob_.guidMasterKey);
           //else guidMasterKey:='{00000000-0000-0000-0000-000000000000}';
         //
         if dpapi_unprotect_blob(@blob_,mk ,20,nil,0,nil,ptr_,dw) then
            begin
            //20=sha1_length
            if dw>0 then
               begin
               SetLength(pwd,dw);
               zeromemory(@pwd[1],dw);
               copymemory(@pwd[1],ptr_,dw);
               writeln(rows['origin_url']+';'+rows['username_value']+';'+pwd+';'+guidMasterKey);
               end;
            end //if dpapi_unprotect_blob(@blob_,mk ,20,nil,0,nil,ptr_,dw) then
            else writeln(rows['origin_url']+';'+rows['username_value']+';'+'SCRAMBLEDOFF'+';'+guidMasterKey);
         end; //if (CompareMem...
         //chrome 80...
         if (CompareMem (@b[0],@DPAPI_CHROME_UNKV10[0] ,3)) and (length(key)=0)
            then //writeln(rows['origin_url']+';'+rows['username_value']+';'+'SCRAMBLEDOFF'+';*');
            begin
            setlength(key,32);
            CopyMemory(@key[0],mk,32);
            end;
         if (CompareMem (@b[0],@DPAPI_CHROME_UNKV10[0] ,3)) and (length(key)<>0) //TODO
            then
            begin
            //writeln(rows['origin_url']+';'+rows['username_value']+';'+'SCRAMBLEDOFF'+';*');
            setlength(iv,12);
            CopyMemory (@iv[0],@b[0+3],length(iv));
            setlength(encrypted,length(b)-12-3); //contains also the TAG
            CopyMemory (@encrypted[0],@b[0+3+12],length(encrypted));
            setlength(output,length(encrypted)-16); //-16=TAG length
            //writeln('length(key):'+inttostr(length(key)));
            if bdecrypt_gcm('AES', encrypted, @output[0], key, iv)<>0
              then writeln(rows['origin_url']+';'+rows['username_value']+';'+BytetoAnsiString (output)+';*')
              else writeln(rows['origin_url']+';'+rows['username_value']+';'+'SCRAMBLEDOFF'+';*');
            end;
      end;   //if mk<>nil then
      {$endif nodpapi}

      if mk=nil then
      begin
         //
         if (CompareMem (@b[0],@DPAPI_CHROME_UNKV10[0] ,3)=false) then
         begin
         if (CryptUnProtectData_(b,output)=true) then
         begin
            if length(output)<255 then writeln(rows['origin_url']+';'+rows['username_value']+';'+BytetoAnsiString(output));
         end
         else writeln(rows['origin_url']+';'+rows['username_value']+';'+'SCRAMBLEDON');
         end; // if (CompareMem ...
         //chrome 80...
         if (CompareMem (@b[0],@DPAPI_CHROME_UNKV10[0] ,3)) and (length(key)=0)
            then writeln(rows['origin_url']+';'+rows['username_value']+';'+'SCRAMBLEDON'+';*');
         //chrome 80...
         if (CompareMem (@b[0],@DPAPI_CHROME_UNKV10[0] ,3)) and (length(key)>0) then
            begin
            {
   	    BYTE signature[3] = "v10";
   	    BYTE iv[12];
   	    BYTE encPassword[...]
            }
            {
            writeln('signature:'+'v10');
            writeln('iv:'+ByteToHexaString (@b[0+3],12));
            writeln('encrypted key:'+ByteToHexaString (@b[0+3+12],length(b)-12-3)); // -16? id tag...
            }
            setlength(iv,12);
            CopyMemory (@iv[0],@b[0+3],length(iv));
            setlength(encrypted,length(b)-12-3); //contains also the TAG
            CopyMemory (@encrypted[0],@b[0+3+12],length(encrypted));
            setlength(output,length(encrypted)-16); //-16=TAG length
            //writeln('length(key):'+inttostr(length(key)));
            if bdecrypt_gcm('AES', encrypted, @output[0], key, iv)<>0
              then writeln(rows['origin_url']+';'+rows['username_value']+';'+BytetoAnsiString (output)+';*')
              else writeln(rows['origin_url']+';'+rows['username_value']+';'+'SCRAMBLEDON'+';*');
         end; //if (CompareMem ...
      //
      end; //if mk=nil then

      end; //while rows.step do
    finally
      //rows._Release ;
    end;
  finally
    //props.FreeInstance ;
  end;
{$i-}DeleteFile(pchar(path+'\login data.db'));{$i+}
end;

function decrypt_cookies(db:string=''):boolean;
const
  DPAPI_CHROME_UNKV10 : array[0..2] of char = ('v', '1', '0');
var
Props: TSQLDBSQLite3ConnectionProperties ;
  //
  p:pointer;
  //b:array of byte;
  b,output:tbytes;
  path,tmp:string;
  //li:TListItem ;
  Rows: ISQLDBRows;
  //
  js:TlkJSONobject;
  s:string;
  bytes,key,iv,encrypted:tbytes;
begin
  result:=false;
//C:\Users\xxx\AppData\Local\Google\Chrome\User Data\Default
if db='' then
   begin
   path:=(GetSpecialFolder($1c));  //CSIDL_LOCAL_APPDATA
   path:=path+'\Google\Chrome\User Data\Default';
   //
   if not FileExists(path+'\cookies') then
   begin
     writeln('The database does not exist. Please create one.');
     Exit;
   end;
   {$i-}DeleteFile(pchar(path+'\cookies.db'));{$i+}
   copyfile(pchar(path+'\cookies'),pchar(path+'\cookies.db'),false);
   end;

if db<>'' then
   begin
   path:= ExtractFileDir (db);
   {$i-}DeleteFile(pchar(path+'\cookies.db'));{$i+}
   copyfile(pchar(db),pchar(path+'\cookies.db'),false);
   end;

writeln('path:'+path);
writeln('db:'+path+'\cookies.db');

if (db<>'') and (fileexists(db)=false) then begin writeln('db does not exist');exit;end;

if (db='') and  (FileExists (GetSpecialFolder($1c)+'\Google\Chrome\User Data\local state')) then
   begin
   js:=TlkJSONstreamed.loadfromfile(GetSpecialFolder($1c)+'\Google\Chrome\User Data\local state') as TlkJsonObject;
   if assigned(js) then
      begin
      //writeln('assigned(js)');
      s:=vartostr(js.Field['os_crypt'].Field['encrypted_key'].Value);
      //writeln(s);
      {$ifdef fpc}bytes:=AnsiStringtoByte (base64.DecodeStringBase64 (s,true));{$endif fpc}
      {$ifndef fpc}bytes:=AnsiStringtoByte (base64_delphi.DecodeStringBase64 (s));{$endif fpc}
      s:=ByteToHexaString(bytes);
      delete(s,1,10); //remove 'DPAPI'
      //writeln(s); //writeln(length(s));
      if CryptUnProtectData_(HexaStringToByte2(s),key)= true
        then writeln('os_crypt:encrypted_key:'+ByteToHexaString(key))
        else writeln('no os_crypt:encrypted_key');
      js.Free;
      end;
   end;
//

  try
    //if dynamic
    {$ifndef static}
    sqlite3 := TSQLite3LibraryDynamic.Create(SQLITE_LIBRARY_DEFAULT_NAME);
    {$endif}
    //
    props:=TSQLDBSQLite3ConnectionProperties.Create(pchar(path+'\cookies.db'),'','','');

    setlength(b,230);
    try
    rows:= props.Execute('SELECT datetime(creation_utc/1000000-11644473600,''unixepoch'') as creation_utc,host_key,name,encrypted_value,cast(is_secure as TEXT) as is_secure,cast(is_httponly as TEXT) as is_httponly,length(encrypted_value) from cookies order by creation_utc desc',[]);
    result:=true;

    writeln('creation_utc;host_key;name;value;is_secure;is_httponly');
    while rows.step do
      begin
      tmp:=''; //for i:=0 to length(b)-1 do b[i]:=0;
      b:=tbytes(rows.ColumnBlobBytes('encrypted_value'));
      //CryptUnprotect(b,tmp);
      if (CompareMem (@b[0],@DPAPI_CHROME_UNKV10[0] ,3)=false) then
      begin

         if CryptUnProtectData_(b,output)=true then
         begin
         if length(output)<255 then
         begin
         writeln(rows['creation_utc']+';'+rows['host_key']+';'+rows['name']+';'+BytetoAnsiString(output)+';'+rows['is_secure']+';'+rows['is_httponly']);
         end; //if length(output)<255 then
         end; //if CryptUnProtectData_(b,output)=true then

      end
      else  //if (CompareMem (@b[0],@DPAPI_CHROME_UNKV10[0] ,3)=false) then
      begin

            setlength(iv,12);
            CopyMemory (@iv[0],@b[0+3],length(iv));
            setlength(encrypted,length(b)-12-3); //contains also the TAG
            CopyMemory (@encrypted[0],@b[0+3+12],length(encrypted));
            setlength(output,length(encrypted)-16); //-16=TAG length
            if bdecrypt_gcm('AES', encrypted, @output[0], key, iv)<>0
              then writeln(rows['creation_utc']+';'+rows['host_key']+';'+rows['name']+';'+BytetoAnsiString(output)+';'+rows['is_secure']+';'+rows['is_httponly'])
              else writeln(rows['creation_utc']+';'+rows['host_key']+';'+rows['name']+';'+'SCRAMBLED'+';'+rows['is_secure']+';'+rows['is_httponly']);
      end;

      end; //while
    finally
      //rows._Release ;
    end;
  finally
    //props.FreeInstance ;
  end;
{$i-}DeleteFile(pchar(path+'\login data.db'));{$i+}
end;

function initAPI:boolean;
  var lib:hmodule{$IFDEF fpc}=0{$endif};
  begin
  {$IFnDEF fpc}lib:=0{$endif};
  //writeln('initapi');
  result:=false;
  try
  //lib:=0;
  if lib>0 then begin {log('lib<>0');} result:=true; exit;end;
      {$IFDEF win64}lib:=loadlibrary('shell32.dll');{$endif}
      {$IFDEF win32}lib:=loadlibrary('shell32.dll');{$endif}
  if lib<=0 then
    begin
    writeln('could not loadlibrary ntdll.dll');
    exit;
    end;
       SHGetSpecialFolderPath:=getProcAddress(lib,'SHGetSpecialFolderPathA');
  result:=true;
  except
  //on e:exception do writeln('init error:'+e.message);
     writeln('init error');
  end;
  //log('init:'+BoolToStr (result,'true','false'));
  end;

initialization
initAPI ;

end.

