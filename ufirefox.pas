unit ufirefox;

{$mode delphi}
{.$define static}

interface

uses
  windows,Classes, SysUtils,base64,
  uLkJSON,
  //shfolder,
  //static
  {$ifdef static}synsqlite3static,{$endif}
  //or dynamic
  {$ifndef static}SynSQLite3,{$endif}
  syndb,syndbsqlite3;

procedure decrypt_firefox(db:string='');
procedure decrypt_cookies(db:string='');

var
   SHGetFolderPath:Function (Ahwnd: HWND; Csidl: longint; Token: THandle; Flags: DWord; Path: PChar): HRESULT; stdcall; //external LibName name 'SHGetFolderPathA';

implementation

type
  TSECItem =  record //stay away from packed...
  SECItemType: dword;
  SECItemData: pansichar;
  SECItemLen: dword;
  end;
  PSECItem = ^TSECItem;

{$ifndef fpc} //
    tbytes=array of byte;
  {$endif fpc}

  //typedef enum SECItemType
    const
    siBuffer = 0;
    siClearDataBuffer = 1;
    siCipherDataBuffer = 2;
    siDERCertBuffer = 3;
    siEncodedCertBuffer = 4;
    siDERNameBuffer = 5;
    siEncodedNameBuffer = 6;
    siAsciiNameString = 7;
    siAsciiString = 8;
    siDEROID = 9;
    siUnsignedInteger = 10;
    siUTCTime = 11;
    siGeneralizedTime = 12 ;

    const
     CSIDL_PROFILE = $28;
     CSIDL_PROGRAM_FILES = $26;
     CSIDL_PROGRAM_FILES_COMMON = $2B;
     CSIDL_PROGRAM_FILES_COMMONX86 = $2C;
     CSIDL_PROGRAM_FILESX86 = $2A;
     CSIDL_PROGRAMS = $2;
     CSIDL_APPDATA = $1A;

    var
      //the below is legacy but still works if NSSBase64_DecodeBuffer is not available
      ATOB_AsciiToData                                       : function(input:pchar;var lenp:uint):pointer;cdecl;
      //the below has been dropped in latest ff editions
      NSSBase64_DecodeBuffer                                 : function(arenaOpt: pointer; outItemOpt: PSECItem; inStr: pchar; inLen: dword): dword; cdecl;
      NSS_Init                                               : function(configdir: pchar): dword; cdecl;
      PK11_GetInternalKeySlot                                : function: pointer; cdecl;
      PK11_Authenticate                                      : function(slot: pointer; loadCerts: boolean; wincx: pointer): dword; cdecl;
      PK11SDR_Decrypt                                        : function(data: PSECItem;  res: PSECItem; cx: pointer): dword; cdecl;
      NSS_Shutdown                                           : procedure; cdecl;
      PK11_FreeSlot                                          : procedure(slot: pointer); cdecl;
      GetUserProfileDirectory                                : function(hToken: THandle; lpProfileDir: pchar; var lpcchSize: dword): longbool; stdcall;

      function FolderPath(folder : integer) : string;
      const
      SHGFP_TYPE_CURRENT = 0;
      var
        path: array [0..MAX_PATH] of char;
      begin
      if SUCCEEDED(SHGetFolderPath(0,folder,0,SHGFP_TYPE_CURRENT,@path[0])) then
      Result := path
      else
      Result := '';
      end;

procedure decrypt(value:string;var decrypted:string);
var
EncryptedSECItem,DecryptedSECItem                       : TSECItem;
//DecryptedSECItem:PSECItem;
p:pchar;
output:string;
lenp:uint;
bytes:tbytes;
begin
fillchar(EncryptedSECItem,sizeof(TSECItem),0);
fillchar(DecryptedSECItem,sizeof(TSECItem),0);
//DecryptedSECItem :=allocmem(sizeof(tsecitem));
//writeln('decrypt 0');
if nativeuint(@NSSBase64_DecodeBuffer) <>0
   then NSSBase64_DecodeBuffer(nil, @EncryptedSECItem, pchar(Value), Length(Value))
   else
   begin
   //writeln(value);
   //writeln(length(value));
   lenp:=0;

   {
   //using legacy ATOB_AsciiToData //to eventually keep compatibility with good ol' delphi7
   p:=ATOB_AsciiToData(pchar(value),lenp);
   EncryptedSECItem.SECItemData :=p;
   EncryptedSECItem.SECItemLen :=lenp;
   if EncryptedSECItem.SECItemData=nil then writeln('EncryptedSECItem.SECItemData=nil');
   //writeln(strpas(EncryptedSECItem.SECItemData)+' - '+inttostr(lenp));
   }

   {
   //using indy10 base64decode
   bytes:=Base64Decode (value,lenp);
   EncryptedSECItem.SECItemData :=pchar(@bytes[0]); //pchar(output);
   EncryptedSECItem.SECItemLen :=lenp; //(length(value) div 4 * 3) - 1;
   }

   //or using FPC base64
   output:=DecodeStringBase64(value);
   EncryptedSECItem.SECItemData :=pchar(@output[1]);
   EncryptedSECItem.SECItemLen :=length(output);
   //or
   //EncryptedSECItem.SECItemData:=allocmem(8192);
   //EncryptedSECItem.SECItemLen :=lenp; //8192;
   //copymemory(EncryptedSECItem.SECItemData,@bytes[0],lenp);
   if EncryptedSECItem.SECItemData=nil then writeln('EncryptedSECItem.SECItemData=nil');
   //writeln(strpas(EncryptedSECItem.SECItemData)+' - '+inttostr(EncryptedSECItem.SECItemLen));

   end;

if PK11SDR_Decrypt(@EncryptedSECItem, @DecryptedSECItem, nil) = 0 then
            begin
            decrypted := strpas(DecryptedSECItem.SECItemData);
            SetLength(decrypted, DecryptedSECItem.SECItemLen);
            end;
end;

procedure decode_cookies(MainProfilePath:pchar);
const
SQLITE_ROW        = 100; //in sqlite3.pas
var
 value,res1,res2:string;
 //
  //DB: TSQLite3Database;
  //Stmt  : TSQLite3Statement;
  Props: TSQLDBSQLite3ConnectionProperties ;
  Rows: ISQLDBRows;
begin
  //DB := TSQLite3Database.Create;
//if dynamic
{$ifndef static}
sqlite3 := TSQLite3LibraryDynamic.Create(SQLITE_LIBRARY_DEFAULT_NAME);
{$endif}
//
  props:=TSQLDBSQLite3ConnectionProperties.Create(MainProfilePath,'','','');
  try
    //DB.Open(MainProfilePath);
    //Stmt := DB.Prepare('SELECT hostname,encryptedUsername,encryptedPassword,length(encryptedPassword) from moz_logins');
    rows:= props.Execute('SELECT datetime(creationTime/1000000-11644473600,''unixepoch'') as creationTime,baseDomain,name,value,cast(issecure as TEXT) as issecure,cast(ishttponly as TEXT) as ishttponly from moz_cookies order by creationTime desc',[]);
    try
      //while Stmt.Step = SQLITE_ROW do
      writeln('creationTime;baseDomain;name;value;issecure;ishttponly');
      while rows.step do
      begin
      writeln(rows.ColumnString (0)+';'+rows.ColumnString (2)+';'+rows.ColumnString (3)+';'+rows.ColumnString (4)+';'+rows.ColumnString (5));
      end;
    finally
      //Stmt.Free;
    end;
  finally
    //DB.Free;
  end;
end;


procedure decrypt_sqlite(MainProfilePath:pchar);
const
SQLITE_ROW        = 100; //in sqlite3.pas
var
 value,res1,res2:string;
 //
  //DB: TSQLite3Database;
  //Stmt  : TSQLite3Statement;
  Props: TSQLDBSQLite3ConnectionProperties ;
  Rows: ISQLDBRows;
begin
  //DB := TSQLite3Database.Create;
//if dynamic
{$ifndef static}
sqlite3 := TSQLite3LibraryDynamic.Create(SQLITE_LIBRARY_DEFAULT_NAME);
{$endif}
//
  props:=TSQLDBSQLite3ConnectionProperties.Create(MainProfilePath,'','','');
  try
    //DB.Open(MainProfilePath);
    //Stmt := DB.Prepare('SELECT hostname,encryptedUsername,encryptedPassword,length(encryptedPassword) from moz_logins');
    rows:= props.Execute('SELECT hostname,encryptedUsername,encryptedPassword,length(encryptedPassword) from moz_logins',[]);
    try
      //while Stmt.Step = SQLITE_ROW do
      while rows.step do
      begin
      //value:=Stmt.ColumnText (1); //user
      value:=rows.ColumnString (1); //user
      decrypt(value,res1);
      //value:=Stmt.ColumnText (2);  //password
      value:=rows.ColumnString (2);  //password
      decrypt(value,res2);
      //writeln(Stmt.ColumnText (0)+';'+res1+';'+res2);
      writeln(rows.ColumnString (0)+';'+res1+';'+res2);
      end;
    finally
      //Stmt.Free;
    end;
  finally
    //DB.Free;
  end;
end;

procedure decrypt_json(MainProfilePath:pchar);
var
 value,res1,res2:string;
 //
  js,xs:TlkJSONobject;
  xl:TlkJSONlist ;
  ws: TlkJSONstring;
  s: String;
  i: Integer;
  sl:TStrings ;
begin
      sl:=TStringList.Create ;
      sl.LoadFromFile(MainProfilePath);
      s:=sl.Text ;
      sl.free;
      js := TlkJSON.ParseText(s) as TlkJSONobject;
      try
      if not assigned(js) then
        begin
        writeln('error: xs not assigned!');
        exit;
        end;//if not assigned(js) then
      xl := js.Field['logins'] as TlkJSONlist;
      writeln('logins count:'+inttostr(xl.Count));
      for i:=0 to xl.Count -1 do
        begin
        xs:=xl.Child [i] as TlkJSONobject;
        value:=xs.getString('encryptedUsername');
        decrypt(value,res1);
        value:=xs.getString('encryptedPassword');
        decrypt(value,res2);
        writeln(xs.getString('hostname')+';'+res1+';'+res2);
        end; //for
      except
      on e:exception do writeln(e.Message );
      end;
end;

procedure decrypt_txt(MainProfilePath:pchar);
var
 //
 CurrentEntry, Site, Name, Value, Passwords,configdir,res        : string;
 PasswordFileSize, BytesRead                 : dword;
 PasswordFile              : THandle;
 PasswordFileData       : pchar;
 EncryptedSECItem, DecryptedSECItem                          : TSECItem;
begin
try
      PasswordFile := CreateFile(MainProfilePath, GENERIC_READ, FILE_SHARE_READ, nil, OPEN_EXISTING, 0, 0);
      PasswordFileSize := GetFileSize(PasswordFile, nil);
      GetMem(PasswordFileData, PasswordFileSize);
      ReadFile(PasswordFile, PasswordFileData^, PasswordFileSize, BytesRead, nil);
      CloseHandle(PasswordFile);
      Passwords := PasswordFileData;
      FreeMem(PasswordFileData);
      Delete(Passwords, 1, Pos('.' + #13#10, Passwords) + 2);
        while Length(Passwords) <> 0 do
        begin
          CurrentEntry := Copy(Passwords, 1, Pos('.' + #13#10, Passwords) - 1);
          Delete(Passwords, 1, Length(CurrentEntry) + 3);
          Site := Copy(CurrentEntry, 1, Pos(#13#10, CurrentEntry) - 1);
          Delete(CurrentEntry, 1, Length(Site) + 2);
          while Length(CurrentEntry) <> 0 do
          begin
            Name := Copy(CurrentEntry, 1, Pos(#13#10, CurrentEntry) - 1);
            if Length(Name) = 0 then Name := '(unnamed value)';
            Delete(CurrentEntry, 1, Length(Name) + 2);
            Value := Copy(CurrentEntry, 1, Pos(#13#10, CurrentEntry) - 1);
            decrypt(value,res);
            Delete(CurrentEntry, 1, Length(Value) + 2);
          end; //while Length(CurrentEntry) <> 0 do
        writeln(site+';'+name+';'+res);
        end;//while Length(Passwords) <> 0 do
except
on e:exception do writeln(e.Message );
end;
end;


procedure decrypt_firefox(db:string='');


var
  NSSModule,glueLib, UserenvModule, hToken              : THandle;
  ProfilePath, MainProfile,isrelative                         : array [0..MAX_PATH] of char;
  ProfilePathLen                  : dword;
  FirefoxProfilePath, database       : pchar;
  ProgramPath:string;
  configdir        : string;
  KeySlot                                                     : pointer;
  //

begin
  //

  //

ProgramPath:=FolderPath(CSIDL_PROGRAM_FILES)+ '\Mozilla Firefox\';
if not FileExists (ProgramPath  + 'nss3.dll') then ProgramPath :=FolderPath(CSIDL_PROGRAM_FILES) +' (x86)\Mozilla Firefox\' ;
//ProgramPath:='e:\FirefoxPortable\App\Firefox\'; //WORKS X32
//ProgramPath:='E:\FirefoxPortable\App\Firefox64\'; //WORKS X64
writeln(ProgramPath);
  //LoadLibrary(pchar(ProgramPath  + 'mozcrt19.dll'));
  //LoadLibrary(pchar(ProgramPath  + 'sqlite3.dll'));
  //LoadLibrary(pchar(ProgramPath  + 'mozutils.dll')); //added
  glueLib:=0;
  glueLib:=LoadLibrary(pchar(ProgramPath + 'mozglue.dll')); //added //***
  if glueLib=0 then writeln('glueLib:='+inttostr(getlasterror));
  //LoadLibrary(pchar(ProgramPath + 'mozsqlite3.dll')); //added
  //LoadLibrary(pchar(ProgramPath + 'nspr4.dll'));
  //LoadLibrary(pchar(ProgramPath + 'plc4.dll'));
  //LoadLibrary(pchar(ProgramPath + 'plds4.dll'));
  //LoadLibrary(pchar(ProgramPath + 'nssutil3.dll'));
  //LoadLibrary(pchar(ProgramPath + 'softokn3.dll'));
  NSSModule:=0;
  NSSModule := LoadLibrary(pchar(ProgramPath + 'nss3.dll'));
  if NSSModule=0 then writeln('NSSModule:='+inttostr(getlasterror));
  //LoadLibrary(pchar(ProgramPath + 'softokn3.dll'));
  @NSS_Init:=nil;
  @NSS_Init := GetProcAddress(NSSModule, 'NSS_Init');
  if nativeuint(@NSS_Init )=0 then writeln('NSS_Init:='+inttostr(getlasterror));
  if @nss_init=nil then
    begin
    writeln('abort, modules missing');
    exit;
    end;
  @NSSBase64_DecodeBuffer:=nil;
  @NSSBase64_DecodeBuffer := GetProcAddress(NSSModule, 'NSSBase64_DecodeBuffer');
  if nativeuint(@NSSBase64_DecodeBuffer )=0 then
     begin
     writeln('NSSBase64_DecodeBuffer:='+inttostr(getlasterror));
     @ATOB_AsciiToData:=0;
     @ATOB_AsciiToData:= GetProcAddress(NSSModule, 'ATOB_AsciiToData');
     if nativeuint(@ATOB_AsciiToData )=0 then writeln('ATOB_AsciiToData:='+inttostr(getlasterror));
     end;
  //@PL_Base64Decode:= GetProcAddress(NSSModule, 'PL_Base64Decode');
  //if nativeuint(@PL_Base64Decode )=0 then writeln('PL_Base64Decode:='+inttostr(getlasterror));
  @PK11_GetInternalKeySlot := GetProcAddress(NSSModule, 'PK11_GetInternalKeySlot');
  @PK11_Authenticate:=0;
  @PK11_Authenticate := GetProcAddress(NSSModule, 'PK11_Authenticate');
  if nativeuint(@PK11_Authenticate )=0 then writeln('PK11_Authenticate:='+inttostr(getlasterror));
  @PK11SDR_Decrypt:=0;
  @PK11SDR_Decrypt := GetProcAddress(NSSModule, 'PK11SDR_Decrypt');
  if nativeuint(@PK11SDR_Decrypt )=0 then writeln('PK11SDR_Decrypt:='+inttostr(getlasterror));
  @NSS_Shutdown := GetProcAddress(NSSModule, 'NSS_Shutdown');
  @PK11_FreeSlot := GetProcAddress(NSSModule, 'PK11_FreeSlot');

  database:='';

  if database='' then
  begin
  UserenvModule := LoadLibrary('userenv.dll');
  @GetUserProfileDirectory := GetProcAddress(UserenvModule, 'GetUserProfileDirectoryA');
  OpenProcessToken(GetCurrentProcess, TOKEN_QUERY, hToken);
  ProfilePathLen := MAX_PATH;
  ZeroMemory(@ProfilePath, MAX_PATH);
  GetUserProfileDirectory(hToken, @ProfilePath, ProfilePathLen);
  FirefoxProfilePath := pchar(FolderPath(CSIDL_APPDATA) + '\Mozilla\Firefox\'  + 'profiles.ini');
  GetPrivateProfileString('Profile0', 'Path', '', MainProfile, MAX_PATH, FirefoxProfilePath);
  GetPrivateProfileString('Profile0', 'isrelative', '', isrelative, MAX_PATH, FirefoxProfilePath);
  if strpas(isrelative)='0'
    then configdir:=MainProfile
    else configdir:=FolderPath(CSIDL_APPDATA) + '\Mozilla\Firefox\'  +  MainProfile;
  end;

  if db<>'' then configdir :=ExtractFileDir (db);
  if (db<>'') and (fileexists(db)=false) then begin writeln('db does not exist');exit;end;
  if configdir<>'' then writeln('configdir:'+configdir);
  //readln;

//**************  signongs3.txt ****************************
  if strpas(isrelative)='0'
    then database :=pchar(MainProfile+ '\signons3.txt')
    else database := pchar(FolderPath(CSIDL_APPDATA) + '\Mozilla\Firefox\' + MainProfile  + '\signons3.txt');
 if (db<>'') and (pos('.txt',lowercase(db))>0) then database:=pchar(db);
 if FileExists(database) then
 begin
  writeln('db:'+database);
  if NSS_Init(pchar(configdir)) = 0 then
  begin
    KeySlot := PK11_GetInternalKeySlot;
    if KeySlot <> nil then
    begin
      if PK11_Authenticate(KeySlot, True, nil) = 0 then
      begin
      decrypt_txt(database );
      end; //if PK11_Authenticate(KeySlot, True, nil) = 0 then
      PK11_FreeSlot(KeySlot);
    end; //if KeySlot <> nil then
    NSS_Shutdown;
  end; //if NSS_Init(pchar(configdir)) = 0 then
  exit;
  end; //if FileExists(MainProfilePath) then


  //************* JSON **********************************************
  if strpas(isrelative)='0'
  then database :=pchar(MainProfile+ '\logins.json')
  else database := pchar(FolderPath(CSIDL_APPDATA) + '\Mozilla\Firefox\' + MainProfile  + '\logins.json');
  if (db<>'') and (pos('.json',lowercase(db))>0) then database:=pchar(db);
  if fileexists(database) then
  begin
  writeln('db:'+database);
  if NSS_Init(pchar(configdir)) = 0 then
  begin
    KeySlot := PK11_GetInternalKeySlot;
    if KeySlot <> nil then
    begin
      if PK11_Authenticate(KeySlot, True, nil) = 0 then
      //will fail is there is a master password
      //then use PK11_CheckUserPassword(keyslot, password)
      begin
      decrypt_json(database);
      end; //if PK11_Authenticate(KeySlot, True, nil) = 0 then
      PK11_FreeSlot(KeySlot);
    end; //if KeySlot <> nil then
    NSS_Shutdown;
  end;//if NSS_Init(pchar(configdir)) = 0 then
  exit;
  end;

  //*************  sqlite *******************************************
  if strpas(isrelative)='0'
  then database :=pchar(MainProfile+ '\signons.sqlite')
  else database := pchar(FolderPath(CSIDL_APPDATA) + '\Mozilla\Firefox\' + MainProfile  + '\signons.sqlite');
  if (db<>'') and (pos('.sqlite',lowercase(db))>0) then database:=pchar(db);
  if fileexists(database) then
  begin
  writeln('db:'+database);
  if NSS_Init(pchar(configdir)) = 0 then
  begin
    KeySlot := PK11_GetInternalKeySlot;
    if KeySlot <> nil then
    begin
      if PK11_Authenticate(KeySlot, True, nil) = 0 then
      begin
      decrypt_sqlite(database );
      end;//if PK11_Authenticate(KeySlot, True, nil)
  PK11_FreeSlot(KeySlot);
  end;//if KeySlot <> nil then
  NSS_Shutdown;
  end;//if NSS_Init(pchar(configdir)) = 0 then
  exit;
  end; //sqlite
//*******************************************************************

  end;

procedure decrypt_cookies(db:string='');


var
  UserenvModule, hToken              : THandle;
  ProfilePath, MainProfile,isrelative                         : array [0..MAX_PATH] of char;
  ProfilePathLen                  : dword;
  FirefoxProfilePath,database       : pchar;

  configdir        : string;
  //

begin
  //
  database:='';
  //


  if database='' then
  begin
  writeln('ok0');
  UserenvModule := LoadLibrary('userenv.dll');
  writeln('ok1');
  @GetUserProfileDirectory := GetProcAddress(UserenvModule, 'GetUserProfileDirectoryA');
  OpenProcessToken(GetCurrentProcess, TOKEN_QUERY, hToken);
  ProfilePathLen := MAX_PATH;
  ZeroMemory(@ProfilePath, MAX_PATH);
  GetUserProfileDirectory(hToken, @ProfilePath, ProfilePathLen);
  FirefoxProfilePath := pchar(FolderPath(CSIDL_APPDATA) + '\Mozilla\Firefox\'  + 'profiles.ini');
  GetPrivateProfileString('Profile0', 'Path', '', MainProfile, MAX_PATH, FirefoxProfilePath);
  GetPrivateProfileString('Profile0', 'isrelative', '', isrelative, MAX_PATH, FirefoxProfilePath);
  if strpas(isrelative)='0'
    then configdir:=MainProfile
    else configdir:=FolderPath(CSIDL_APPDATA) + '\Mozilla\Firefox\'  +  MainProfile;
  end;

  if db<>'' then configdir :=ExtractFileDir (db);
  if (db<>'') and (fileexists(db)=false) then begin writeln('db does not exist');exit;end;
  if configdir<>'' then writeln('configdir:'+configdir);
  //readln;


  //*************  sqlite *******************************************
  if strpas(isrelative)='0'
  then database :=pchar(MainProfile+ '\cookies.sqlite')
  else database := pchar(FolderPath(CSIDL_APPDATA) + '\Mozilla\Firefox\' + MainProfile  + '\cookies.sqlite');
  if (db<>'') and (pos('.sqlite',lowercase(db))>0) then database:=pchar(db);
  if fileexists(database) then
  begin
  writeln('db:'+database);

  decode_cookies(database );
  end; //sqlite
//*******************************************************************

  end;

function initAPI:boolean;
  var lib:hmodule=0;
  begin
  //writeln('initapi');
  result:=false;
  try
  //lib:=0;
  if lib>0 then begin {log('lib<>0');} result:=true; exit;end;
      {$IFDEF win64}lib:=loadlibrary('shfolder.dll');{$endif}
      {$IFDEF win32}lib:=loadlibrary('shfolder.dll');{$endif}
  if lib<=0 then
    begin
    writeln('could not loadlibrary ntdll.dll');
    exit;
    end;
       SHGetFolderPath:=getProcAddress(lib,'SHGetFolderPathA');
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

