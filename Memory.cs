using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

internal static class Memory {

#region Imports
[DllImport("kernel32.dll")]
internal static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

[DllImport("kernel32.dll")] 
internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesWritten);
[DllImport("kernel32.dll")] 
internal static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int dwSize, out int lpNumberOfBytesWritten);

[DllImport("kernel32.dll", SetLastError = true)]
internal static extern bool ReadProcessMemory(IntPtr hProcess,IntPtr lpBaseAddress,IntPtr lpBuffer,int dwSize,out int lpNumberOfBytesRead);

[DllImport("kernel32.dll")]
internal static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("kernel32.dll")]
internal static extern bool CloseHandle(IntPtr hObject);

[DllImport("kernel32.dll", SetLastError=true)]
internal static extern void GetSystemInfo(ref SYSTEM_INFO Info);

[DllImport("kernel32.dll")]
internal static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

[DllImport("kernel32.dll", SetLastError = true)]
internal static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);


[MethodImpl(MethodImplOptions.AggressiveInlining)]
public static unsafe bool Write<T>(IntPtr Handle, long Address,T value) where T:unmanaged=>
Write(Handle, (IntPtr) Address,value);

[MethodImpl(MethodImplOptions.AggressiveInlining)]
public static unsafe bool Write<T>(IntPtr Handle, IntPtr Address,T value) where T:unmanaged{
var Size=Marshal.SizeOf<T>();
return WriteProcessMemory(Handle, Address, (IntPtr)(T*)&value, Size,out Size);
}

[MethodImpl(MethodImplOptions.AggressiveInlining)]
public static unsafe bool WriteBytes(IntPtr Handle, IntPtr Address,byte[] value){
return WriteProcessMemory(Handle, Address, value, value.Length,out int Size);
}


[MethodImpl(MethodImplOptions.AggressiveInlining)]
public static unsafe T Read<T>(IntPtr Handle, long Address,int ArraySize=1) where T:unmanaged=>
Read<T>(Handle, (IntPtr) Address,ArraySize);

[MethodImpl(MethodImplOptions.AggressiveInlining)]
public static unsafe T Read<T>(IntPtr Handle, IntPtr Address,int ArraySize=1) where T:unmanaged{
T Out=default(T);
int Size = (int)sizeof(T);
ReadProcessMemory(Handle, Address, (IntPtr)(T*)&Out, Size,out Size);
return Out;
}


[MethodImpl(MethodImplOptions.AggressiveInlining)]
public static unsafe string ReadString(IntPtr Handle, long Address,int Size,Encoding Encoding){
IntPtr Alloc=Marshal.AllocHGlobal(Size);
ReadProcessMemory(Handle, (IntPtr)Address, Alloc, Size,out Size);
var Out=Encoding.GetString((byte*)Alloc,Size);
Marshal.FreeHGlobal(Alloc);
return Out;
}


/// <summary>Find Method / Function / Export By Name</summary>
/// <param name="hModule"></param>
/// <param name="procName"></param>
/// <returns></returns>
[DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
internal static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

/// <summary>Read A X64bit Offset From Assembly Code (This Is Very Much Needed)</summary>
/// <param name="hProcess"></param>
/// <param name="Address"></param>
/// <param name="Offset"></param>
/// <returns></returns>
internal static IntPtr ReadRef(IntPtr hProcess,IntPtr Address,int Offset){
return (IntPtr)((long)Address + Read<int>(hProcess,Address + Offset) + (Offset + 0x4));
}
/// <summary>Create A X64bit Offset To Static Address From Assembly Address (This Is Very Much Needed)</summary>
/// <param name="TO"></param>
/// <param name="INSRUCTION_Address"></param>
/// <param name="Offset"></param>
/// <returns></returns>
internal static int CreateRef(long TO, long INSRUCTION_Address, int Offset) { 
Offset+=0x4;
return (int)(TO> INSRUCTION_Address?
((TO-Offset)- INSRUCTION_Address):
(TO-(INSRUCTION_Address-Offset)-(Offset*2)));
}
internal static bool WriteRef(IntPtr hProcess,IntPtr INSRUCTION_Address,long TO,int offset){ 
return WriteBytes(hProcess,INSRUCTION_Address+offset,BitConverter.GetBytes(CreateRef(TO,INSRUCTION_Address,offset)));
}

#endregion

internal static Process LastProcess=null;
internal const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
internal static int GetProcessId(string processName){
try{
Process[] processes = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(processName));
if (processes.Length > 0)
return (LastProcess=processes[0]).Id;
}catch (Exception ex){
Console.WriteLine($"Ошибка при получении PID: {ex.Message}");
}
return -1;
}


public static PatternMask NullPatternMask { get; } =new PatternMask();
public struct PatternMask {
public string[] stringByteArray;
public byte[] aobPattern;
public byte[] mask;
}
public static PatternMask AobToPatternMask(string search){
var D= new PatternMask();
D.stringByteArray = search.Trim(' ').Split(' ');
D.aobPattern = new byte[D.stringByteArray.Length];
D.mask = new byte[D.stringByteArray.Length];
string ba =null;
for (var i = 0; i < D.stringByteArray.Length; i++){
ba = D.stringByteArray[i];
if (ba == "??" || (ba.Length == 1 && ba == "?")){
D.mask[i] = 0x00;
D.stringByteArray[i] = "0x00";
}else if (Char.IsLetterOrDigit(ba[0]) && ba[1] == '?'){
D.mask[i] = 0xF0;
D.stringByteArray[i] = ba[0] + "0";
}else if (Char.IsLetterOrDigit(ba[1]) && ba[0] == '?'){
D.mask[i] = 0x0F;
D.stringByteArray[i] = "0" + ba[1];
}else
D.mask[i] = 0xFF;
}
for (int i = 0; i < D.stringByteArray.Length; i++)
D.aobPattern[i] = (byte)(Convert.ToByte(D.stringByteArray[i], 16) & D.mask[i]);
return D;
}



[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_INFO{
public ushort wProcessorArchitecture;
public ushort wReserved;
public uint dwPageSize;
public IntPtr lpMinimumApplicationAddress;
public IntPtr lpMaximumApplicationAddress;
public UIntPtr dwActiveProcessorMask;
public uint dwNumberOfProcessors;
public uint dwProcessorType;
public uint dwAllocationGranularity;
public ushort wProcessorLevel;
public ushort wProcessorRevision;
};

[StructLayout(LayoutKind.Sequential)]
public struct MemoryRegionResult{
public IntPtr CurrentBaseAddress { get; set; }
public long RegionSize { get; set; }
public IntPtr RegionBase { get; set; }
}

[StructLayout(LayoutKind.Sequential)]
public struct MEMORY_BASIC_INFORMATION{
public IntPtr BaseAddress;
public IntPtr AllocationBase;
public uint AllocationProtect;
public ulong RegionSize;
public uint State;
public uint Protect;
public uint Type;
}

public enum MemState : uint{
COMMIT = 0x1000,
FREE = 0x10000,
RESERVE = 0x2000
}
public enum MemType : uint{
IMAGE = 0x1000000,
MAPPED = 0x40000,
PRIVATE = 0x20000
}
[Flags]
public enum PageProtection : uint{
EXECUTE = 0x00000010,
EXECUTE_READ = 0x00000020,
EXECUTE_READWRITE = 0x00000040,
EXECUTE_WRITECOPY = 0x00000080,
NOACCESS = 0x00000001,
READONLY = 0x00000002,
READWRITE = 0x00000004,
WRITECOPY = 0x00000008,
GUARD = 0x00000100,
NOCACHE = 0x00000200,
WRITECOMBINE = 0x00000400,
TARGETS_INVALID = 0x40000000,
TARGETS_NO_UPDATE = 0x40000000,
}

public static List<MemoryRegionResult> GetMemoryRegionResult(IntPtr Handle, long start, long end, bool readable, bool writable, bool executable){
var memRegionList = new List<MemoryRegionResult>();
SYSTEM_INFO sys_info = new SYSTEM_INFO();
 GetSystemInfo(ref sys_info);

IntPtr proc_min_address = sys_info.lpMinimumApplicationAddress;
IntPtr proc_max_address = sys_info.lpMaximumApplicationAddress;

if (start < (long)proc_min_address)
start = (long)proc_min_address;

if (end > (long)proc_max_address)
end = (long)proc_max_address;

IntPtr currentBaseAddress = (IntPtr)start;

MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();
bool REX(){ 
var D=(long)VirtualQueryEx(Handle, currentBaseAddress, out memInfo,(uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());

if((long)currentBaseAddress<(long)0x7ff000000000)
if(D==0)
return false;
else
return true;

return D!=0;
}


while (
REX()
&&
(long)currentBaseAddress < end && (long)currentBaseAddress + 
(long)memInfo.RegionSize > (long)currentBaseAddress){
bool isValid = memInfo.State == (uint)MemState.COMMIT;
isValid &= ((long)memInfo.BaseAddress) < ((long)proc_max_address) ;
isValid &= ((memInfo.Protect & (uint)PageProtection.GUARD) == 0);
isValid &= ((memInfo.Protect & (uint)PageProtection.NOACCESS) == 0);
isValid &= (memInfo.Type == (uint)MemType.PRIVATE) || (memInfo.Type == (uint)MemType.IMAGE);

if (isValid){
bool isReadable = (memInfo.Protect & (uint)PageProtection.READONLY) > 0;
bool isWritable = ((memInfo.Protect & (uint)PageProtection.READWRITE) > 0) || ((memInfo.Protect & (uint)PageProtection.WRITECOPY) > 0) || ((memInfo.Protect & (uint)PageProtection.EXECUTE_READWRITE) > 0) || ((memInfo.Protect & (uint)PageProtection.EXECUTE_WRITECOPY) > 0);
bool isExecutable = ((memInfo.Protect & (uint)PageProtection.EXECUTE) > 0) || ((memInfo.Protect & (uint)PageProtection.EXECUTE_READ) > 0) || ((memInfo.Protect & (uint)PageProtection.EXECUTE_READWRITE) > 0) || ((memInfo.Protect & (uint)PageProtection.EXECUTE_WRITECOPY) > 0);
isReadable &= readable;
isWritable &= writable;
isExecutable &= executable;
isValid &= isReadable || isWritable || isExecutable;
}

if (!isValid){
currentBaseAddress = (IntPtr)(((ulong)memInfo.BaseAddress) + memInfo.RegionSize);
continue;
}

MemoryRegionResult memRegion = new MemoryRegionResult{
CurrentBaseAddress = currentBaseAddress,
RegionSize = (long)memInfo.RegionSize,
RegionBase = memInfo.BaseAddress
};

currentBaseAddress = (IntPtr)((ulong)memInfo.BaseAddress + memInfo.RegionSize);

//Console.WriteLine("SCAN start:" + memRegion.RegionBase.ToString() + " end:" + currentBaseAddress.ToString());

if (memRegionList.Count > 0){
var previousRegion = memRegionList[memRegionList.Count - 1];

if ((long)previousRegion.RegionBase + previousRegion.RegionSize == (long)memInfo.BaseAddress){
memRegionList[memRegionList.Count - 1] = new MemoryRegionResult{
CurrentBaseAddress = previousRegion.CurrentBaseAddress,
RegionBase = previousRegion.RegionBase,
RegionSize = previousRegion.RegionSize + (long)memInfo.RegionSize
};

continue;
}
}

memRegionList.Add(memRegion);
}
return memRegionList;
}


public static unsafe int FindPattern(byte* body, int bodyLength, byte[] pattern, byte[] masks, int start = 0){
int foundIndex = -1;
if (bodyLength <= 0 || pattern.Length <= 0 || start > bodyLength - pattern.Length || pattern.Length > bodyLength)
return foundIndex;

for (int index = start; index <= bodyLength - pattern.Length; index++){
if (((body[index] & masks[0]) == (pattern[0] & masks[0]))){
var match = true;
for (int index2 = pattern.Length - 1; index2 >= 1; index2--){
if ((body[index + index2] & masks[index2]) == (pattern[index2] & masks[index2])) 
continue;
match = false;
break;
}
if (!match)
continue;
foundIndex = index;
break;
}
}
return foundIndex;
}

public static long[] CompareScan(IntPtr Handle,MemoryRegionResult item, byte[] aobPattern, byte[] mask,bool FindSingleResult=false){
if (mask.Length != aobPattern.Length)
throw new ArgumentException($"AOB Mask Creator Broke! {nameof(aobPattern)}.Length != {nameof(mask)}.Length");
IntPtr buffer = Marshal.AllocHGlobal((int)item.RegionSize);

int bytesRead= (int)item.RegionSize;
ReadProcessMemory(Handle, item.CurrentBaseAddress, buffer,bytesRead,out bytesRead);
int result = 0 - aobPattern.Length;
List<long> ret = new List<long>();
unsafe{
do{
result = FindPattern((byte*)buffer.ToPointer(), (int)bytesRead, aobPattern, mask, result + aobPattern.Length);
if (result >= 0){
ret.Add((long)item.CurrentBaseAddress + result);
if(FindSingleResult)
break;}
} while (result != -1);
}
Marshal.FreeHGlobal(buffer);
return ret.ToArray();
}

#pragma warning disable CS8619 // Nullability of reference types in value doesn't match target type.
public static Task<List<long>> AoBScan(IntPtr Handle,List<MemoryRegionResult> memRegionList, string search, bool OnlyFindOne=false)=>Task.Run(() =>{
if(Handle==IntPtr.Zero|| memRegionList==null?true: memRegionList.Count==0)
return null;
var O= AobToPatternMask(search);
ConcurrentBag<long> bagResult = new ConcurrentBag<long>();
var F = true;

Parallel.ForEach(memRegionList, (item, parallelLoopState, index) =>{
if(F){
long[] compareResults = CompareScan(Handle, item, O.aobPattern, O.mask, OnlyFindOne);
foreach (long result in compareResults){
bagResult.Add(result);
if (OnlyFindOne?!(F=!F):false){
parallelLoopState.Break();
break;
}
}
compareResults=null;
}else
parallelLoopState.Break();
});
O= NullPatternMask;
return bagResult.ToList();
});
#pragma warning restore CS8619 // Nullability of reference types in value doesn't match target type.


 [DllImport("dbghelp.dll", CharSet = CharSet.Ansi)]
private static extern int UnDecorateSymbolName(
[In][MarshalAs(UnmanagedType.LPStr)] string DecoratedName,
[In]IntPtr UnDecoratedName, 
[In][MarshalAs(UnmanagedType.U4)] int UndecoratedLength,
[In][MarshalAs(UnmanagedType.U4)] UnDecorateFlags Flags);
public static int UnDecorateSymbolName(string DecoratedName,out string UnDecoratedName,int UndecoratedLength,UnDecorateFlags Flags){
var M=Marshal.AllocHGlobal(UndecoratedLength+1);
var D=UnDecorateSymbolName(DecoratedName,M, UndecoratedLength, Flags);
byte[] bytes=new byte[D];
Marshal.Copy(M,bytes,0,D);
UnDecoratedName=Encoding.ASCII.GetString(bytes);
Marshal.FreeHGlobal(M);
return D;
}
public static string UnDecorateSymbolName(string DecoratedName, UnDecorateFlags UnDecorateFlags = UnDecorateFlags.NAME_ONLY){
if (DecoratedName.Contains("@@")){
var DECORATIONS = DecoratedName.Replace("@@", "\0").Split('\0').Length;
if (DecoratedName.Replace("@@", "\a").Contains("@"))
DECORATIONS += DecoratedName.Replace("@@", "\a").Split('@').Length;
if (DecoratedName.Contains("@V?$"))
DECORATIONS += DecoratedName.Replace("@V?$", "\0").Split('\0').Length;
if (DECORATIONS <= 2)
return DecoratedName.Trim().Trim('?').Trim().Replace("@@", "");
}
var DEC = UnDecorateSymbolName(DecoratedName,out string builder, 256, UnDecorateFlags);
return builder;
}


[Flags]
public enum UnDecorateFlags{
COMPLETE = (0x0000),  // Enable full undecoration
NO_LEADING_UNDERSCORES = (0x0001),  // Remove leading underscores from MS extended keywords
NO_MS_KEYWORDS = (0x0002),  // Disable expansion of MS extended keywords
NO_FUNCTION_RETURNS = (0x0004),  // Disable expansion of return type for primary declaration
NO_ALLOCATION_MODEL = (0x0008),  // Disable expansion of the declaration model
NO_ALLOCATION_LANGUAGE = (0x0010),  // Disable expansion of the declaration language specifier
NO_MS_THISTYPE = (0x0020),  // NYI Disable expansion of MS keywords on the 'this' type for primary declaration
NO_CV_THISTYPE = (0x0040),  // NYI Disable expansion of CV modifiers on the 'this' type for primary declaration
NO_THISTYPE = (0x0060),  // Disable all modifiers on the 'this' type
NO_ACCESS_SPECIFIERS = (0x0080),  // Disable expansion of access specifiers for members
NO_THROW_SIGNATURES = (0x0100),  // Disable expansion of 'throw-signatures' for functions and pointers to functions
NO_MEMBER_TYPE = (0x0200),  // Disable expansion of 'static' or 'virtual'ness of members
NO_RETURN_UDT_MODEL = (0x0400),  // Disable expansion of MS model for UDT returns
_32_BIT_DECODE = (0x0800),  // Undecorate 32-bit decorated names
NAME_ONLY = (0x1000),  // Crack only the name for primary declaration;
NO_ARGUMENTS = (0x2000),  // Don't undecorate arguments to function
NO_SPECIAL_SYMS = (0x4000),  // Don't undecorate special names (v-table, vcall, vector xxx, metatype, etc)
}

public static IntPtr GetExportedFromModule(IntPtr ProcessHandle,IntPtr ModuleAddress,string FunctionName){ 
IntPtr FunctionAddress = IntPtr.Zero;
///Todo Fix This As Its Detected In Yara Rules
try{
// Traverse the PE header in memory
Int32 PeHeader = Read<Int32>(ProcessHandle,ModuleAddress + 0x3C);
Int16 OptHeaderSize = Read<Int16>(ProcessHandle,ModuleAddress + PeHeader + 0x14);
Int64 OptHeader = ModuleAddress + PeHeader + 0x18;
Int16 Magic = Read<Int16>(ProcessHandle,(IntPtr)OptHeader);
Int64 pExport = 0;
if (Magic == 0x010b)
pExport = OptHeader + 0x60;
else
pExport = OptHeader + 0x70;

// Read -> IMAGE_EXPORT_DIRECTORY
Int32 ExportRVA = Read<Int32>(ProcessHandle,(IntPtr)pExport);
Int32 OrdinalBase = Read<Int32>(ProcessHandle,(IntPtr)(ModuleAddress + ExportRVA + 0x10));
Int32 NumberOfFunctions =  Read<Int32>(ProcessHandle,(IntPtr)(ModuleAddress + ExportRVA + 0x14));
Int32 NumberOfNames = Read<Int32>(ProcessHandle,(IntPtr)(ModuleAddress + ExportRVA + 0x18));
Int32 FunctionsRVA = Read<Int32>(ProcessHandle,(IntPtr)(ModuleAddress + ExportRVA + 0x1C));
Int32 NamesRVA = Read<Int32>(ProcessHandle,(IntPtr)(ModuleAddress + ExportRVA + 0x20));
Int32 OrdinalsRVA = Read<Int32>(ProcessHandle,(IntPtr)(ModuleAddress + ExportRVA + 0x24));

string FunctionNameExp=null;
// Loop the array of export name RVA's
for (int i = 0; i < NumberOfNames; i++){
FunctionNameExp = ReadString(ProcessHandle,(ModuleAddress + Read<Int32>(ProcessHandle,(IntPtr)(ModuleAddress + NamesRVA + i * 4))),256,Encoding.ASCII);
if(FunctionNameExp.StartsWith("?"))
FunctionNameExp=UnDecorateSymbolName(FunctionNameExp,UnDecorateFlags.NAME_ONLY|UnDecorateFlags.NO_FUNCTION_RETURNS|UnDecorateFlags.NO_RETURN_UDT_MODEL|UnDecorateFlags.NO_ALLOCATION_MODEL|UnDecorateFlags.NO_ACCESS_SPECIFIERS);
if (FunctionNameExp.Equals(FunctionName, StringComparison.OrdinalIgnoreCase)||
FunctionNameExp.Equals(FunctionName+"A", StringComparison.OrdinalIgnoreCase)){
Int32 FunctionOrdinal = Read<Int16>(ProcessHandle,(ModuleAddress + OrdinalsRVA + i * 2)) + OrdinalBase;
Int32 FunctionRVA = Read<Int32>(ProcessHandle,(ModuleAddress + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
FunctionAddress = (IntPtr)((Int64)ModuleAddress + FunctionRVA);
break;
}
}
}catch (Exception E){
throw new InvalidOperationException("PE Exports:",E);
}
return FunctionAddress;
}


}