program vaults;

uses uvaults,utils;

begin
   if uvaults.VaultInit=false then begin log('VaultInit failed',1);exit; end;
   uvaults.Vaultenum ;

end.

