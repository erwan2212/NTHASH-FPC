unit memfuncs;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

uses windows,utils,math;

Type TMemoryRegion = record
{$ifdef CPU32}BaseAddress: dword; {$endif CPU32}
{$ifdef CPU64}BaseAddress: nativeint; {$endif CPU64}
  MemorySize: dword;
  IsChild: boolean;  //means there is a region before it
  startaddress: pointer; //pointer to a spot in the whole memory copy, it means the start of this region
  Protect : DWORD; //added ELC
  _type : DWORD; //added ELC
  end;
type TMemoryRegions = array of TMemoryRegion;
type PMemoryRegions = ^TMemoryRegions;

procedure getexecutablememoryregionsfromregion(hprocess:thandle;start: ptrUint; stop:ptrUint; var memoryregions: tmemoryregions);
function getallmemoryregions(hprocess:thandle;var memoryregions: tmemoryregions): dword;
function rewritecode(processhandle: thandle; address:ptrUint; buffer: pointer; var size:dword; force: boolean=false): boolean;

implementation

//CE
function rewritedata(processhandle: thandle; address:ptrUint; buffer: pointer; var size:dword): boolean;
var original,a: dword;
    s: PtrUInt;
begin
  //make writable, write, restore, flush
{$IFnDEF FPC}
  VirtualProtectEx(processhandle,  pointer(address),size,PAGE_EXECUTE_READWRITE,original);
  result:=writeprocessmemory(processhandle,pointer(address),buffer,size,s);
  size:=s;
  VirtualProtectEx(processhandle,pointer(address),size,original,a);
  {$else}
  VirtualProtectEx(processhandle,  pointer(address),size,PAGE_EXECUTE_READWRITE,@original);
  result:=writeprocessmemory(processhandle,pointer(address),buffer,size,s);
  size:=s;
  VirtualProtectEx(processhandle,pointer(address),size,original,@a);
  {$endif}
end;

function rewritecode(processhandle: thandle; address:ptrUint; buffer: pointer; var size:dword; force: boolean=false): boolean;
var
  init: dword;
  bytesleft: dword;
  chunk: dword;
begin
  if force then
  begin
    result:=true;

    bytesleft:=size;
    size:=0;
    init:=4096-(address and $fff); //init now contains the number of bytes needed to write to get to the first boundary
    init:=min(init, bytesleft);
    chunk:=init;
    if rewritedata(processhandle, address, buffer, init)=false then
      result:=false;

    size:=size+init;

    address:=address+chunk;
    ptruint(buffer):=ptruint(buffer)+chunk;

    dec(bytesleft, chunk);
    //address now contains the base address of a page so go from here
    while (bytesleft>0) do
    begin
      chunk:=4096;
      if rewritedata(processhandle, address, buffer, chunk)=false then
        result:=false;

      size:=size+chunk;
      address:=address+4096;
      ptruint(buffer):=ptruint(buffer)+4096;
    end;



  end
  else
  begin
    result:=rewritedata(processhandle,address,buffer,size);

    FlushInstructionCache(processhandle,pointer(address),size);
  end;

end;

//https://www.freepascal.org/docs-html/ref/refsu4.html
function getallmemoryregions(hprocess:thandle;var memoryregions: tmemoryregions): dword; //qword
var address: ptrUint;
    mbi: memory_basic_information;
    stop: ptruint;
begin
  result:=0;

  setlength(memoryregions,0);
  address:=0;
  {if processhandler.is64Bit then
    stop:=$7fffffffffffffff
  else
    stop:=$7fffffff;
  }

  {$ifdef CPU32}stop:=$7fffffff;{$endif CPU32}
  {$ifdef CPU64}stop:=$7fffffffffffffff;{$endif CPU64}

  while (address<stop) and (VirtualQueryEx(hProcess ,pointer(address),mbi,sizeof(mbi))<>0) and ((address+mbi.RegionSize)>address) do
  begin
    if (mbi.state=MEM_COMMIT) and //mbi.state<>MEM_FREE
       ((mbi.Protect and PAGE_NOACCESS)<>PAGE_NOACCESS) and
       ((mbi.Protect and PAGE_GUARD)<>PAGE_GUARD) and
       ((mbi.Protect and PAGE_NOCACHE)<>PAGE_NOCACHE) then
    begin
      //readable
      setlength(memoryregions,length(memoryregions)+1);
      memoryregions[length(memoryregions)-1].BaseAddress:=ptrUint(mbi.baseaddress);
      memoryregions[length(memoryregions)-1].MemorySize:=mbi.RegionSize;
      memoryregions[length(memoryregions)-1].protect:=mbi.Protect;
      memoryregions[length(memoryregions)-1]._type:=mbi._type; //image...private...mapped...
      inc(result, mbi.RegionSize);
    end;

    inc(address,mbi.RegionSize);
  end;
end;

procedure getexecutablememoryregionsfromregion(hprocess:thandle;start: ptrUint; stop:ptrUint; var memoryregions: tmemoryregions);
var address: ptrUint;
    mbi: memory_basic_information;
begin
  setlength(memoryregions,0);
  address:=start;
  while (address<stop) and (VirtualQueryEx(hProcess ,pointer(address),mbi,sizeof(mbi))<>0) and ((address+mbi.RegionSize)>address) do
  begin
    if (mbi.state=MEM_COMMIT) and
    (
       ((mbi.Protect and PAGE_EXECUTE)=PAGE_EXECUTE) or
       ((mbi.Protect and PAGE_EXECUTE_READ)=PAGE_EXECUTE_READ) or
       ((mbi.Protect and PAGE_EXECUTE_READWRITE)=PAGE_EXECUTE_READWRITE) or
       ((mbi.Protect and PAGE_EXECUTE_WRITECOPY)=PAGE_EXECUTE_WRITECOPY)
    )
    then
    begin
      //executable
      setlength(memoryregions,length(memoryregions)+1);
      memoryregions[length(memoryregions)-1].BaseAddress:=ptrUint(mbi.baseaddress);
      memoryregions[length(memoryregions)-1].MemorySize:=mbi.RegionSize;
    end;

    inc(address,mbi.RegionSize);
  end;
end;


end.
