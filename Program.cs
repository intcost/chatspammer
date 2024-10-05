using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using static Memory;
class Program{

private static string[] FinnishPhrases;
private static double interval;
private static string lastCommand = string.Empty; // Переменная для хранения последней фразы

static async Task Main(string[] args){
LoadSettings();

#region Find Process
int pid = GetProcessId("cs2.exe");
if (pid == -1){
Console.WriteLine("Процесс cs2.exe не найден.");
goto EndOfMain;
}
#endregion

#region Open/Connect Process
IntPtr processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
if (processHandle == IntPtr.Zero){
Console.WriteLine("Не удалось открыть процесс.");
goto EndOfMain;
}
#endregion

#region Find Addresses In Games Memory
ProcessModule ClientModule=null;
ProcessModule Engine2Module=null;
ProcessModule Tier0Module=null;
foreach(ProcessModule module in LastProcess.Modules)
if(module.ModuleName.ToLower()=="client.dll")
ClientModule=module;
else if(module.ModuleName.ToLower()=="engine2.dll")
Engine2Module=module;
else if(module.ModuleName.ToLower()=="tier0.dll")
Tier0Module=module;

var ClientModuleRegion=GetMemoryRegionResult(processHandle,(long)ClientModule.BaseAddress,(long)ClientModule.BaseAddress+ClientModule.ModuleMemorySize,true,true,true);
var Engine2ModuleRegion=GetMemoryRegionResult(processHandle,(long)Engine2Module.BaseAddress,(long)Engine2Module.BaseAddress+Engine2Module.ModuleMemorySize,true,true,true);
var Tier0ModuleRegion=GetMemoryRegionResult(processHandle,(long)Tier0Module.BaseAddress,(long)Tier0Module.BaseAddress+Tier0Module.ModuleMemorySize,true,true,true);


var Engine2CommandBufferInstruction=await AoBScan(processHandle,Engine2ModuleRegion,"4C 8D 3D ?? ?? ?? ?? 0F 29 B4 24 ?? ?? ?? ?? F2 0F 10 35",true);
if(Engine2CommandBufferInstruction==null?true:Engine2CommandBufferInstruction.Count==0)
Engine2CommandBufferInstruction=await AoBScan(processHandle,Engine2ModuleRegion,"48 8D 05 ?? ?? ?? ?? 48 C7 44 24 30 00 00 00 00 45 33 C9",true);
if(Engine2CommandBufferInstruction==null?true:Engine2CommandBufferInstruction.Count==0)
Engine2CommandBufferInstruction=await AoBScan(processHandle,Engine2ModuleRegion,"48 8D 1D ?? ?? ?? ?? 0F 11 05 ?? ?? ?? ?? 4C 89 3D ?? ?? ?? ?? 8B F7",true);
IntPtr EngineCCommandBuffer=ReadRef(processHandle,(IntPtr)Engine2CommandBufferInstruction[0],3);



IntPtr InjectedCommandExecFunction = VirtualAllocEx(processHandle, (IntPtr)null, (IntPtr)0x1000, (0x1000 | 0x2000), 0X40);
Console.WriteLine("InjectedCommandExecFunction: 0x"+InjectedCommandExecFunction.ToString("X2"));
byte[] InjectedBytes=new byte[]{
//push rbp
0x55,
//sub rsp,70
0x48,0x83,0xEC,0x70,
//lea rdx,[CommandToExecute]
0x48,0x8D,0x15,0,0,0,0,
//cmp dword ptr [rdx],00 { 0 }
0x83,0x3A,0x00,
//je +41
0x0F,0x84,0x41,0x00,0x00,0x00,
//mov rcx,[CommandBufferPtr]
0x48,0x8B,0x0D,0,0,0,0,
//call qword ptr [CommandBuffer_Create] { ->tier0.CCommandBuffer::CCommandBuffer }
0xFF,0x15,0,0,0,0,
//mov rcx,[CommandBufferPtr]
0x48,0x8B,0x0D,0,0,0,0,
//lea rdx,[CommandToExecute]
0x48,0x8D,0x15,0,0,0,0,
// xor rax,rax
0x48,0x31,0xC0,
//xor r9d,r9d
0x45,0x31,0xC9,
//xor r8d,r8d
0x45,0x31,0xC0,
//call qword ptr [CommandBuffer_AddText] { ->tier0.CCommandBuffer::AddText }
0xFF,0x15,0,0,0,0,
//mov rdx,rax
0x48,0x8B,0xD0,
//mov rcx,[CommandBufferPtr]
0x48,0x8B,0x0D,0,0,0,0,
//call qword ptr [CommandBuffer_BeginProcessingCommands] { ->tier0.CCommandBuffer::BeginProcessingCommands }
0xFF,0x15,0,0,0,0,
//mov [CommandToExecute],rbx { (0) }
0x48,0x89,0x1D,0,0,0,0,
//add rsp,70 { 112 }
0x48,0x83,0xC4,0x70,
//pop rbp
0x5D,
//ret
0xC3
};
WriteBytes(processHandle,InjectedCommandExecFunction,InjectedBytes);
IntPtr InjectedCommandExecVars=InjectedCommandExecFunction+0x248;
int ICEV_O=0;
IntPtr ICEV_CommandBufferPtr=(InjectedCommandExecVars+ICEV_O);ICEV_O+=8;
Write(processHandle,ICEV_CommandBufferPtr,EngineCCommandBuffer);
WriteRef(processHandle,InjectedCommandExecFunction+0x15,ICEV_CommandBufferPtr,3);
WriteRef(processHandle,InjectedCommandExecFunction+0x22,ICEV_CommandBufferPtr,3);
WriteRef(processHandle,InjectedCommandExecFunction+0x42,ICEV_CommandBufferPtr,3);

IntPtr ICEV_AddText=(InjectedCommandExecVars+ICEV_O);ICEV_O+=8;
Write(processHandle,ICEV_AddText,GetExportedFromModule(processHandle,Tier0Module.BaseAddress,"CCommandBuffer::AddText"));
WriteRef(processHandle,InjectedCommandExecFunction+0x39,ICEV_AddText,2);

IntPtr ICEV_BeginProcessingCommands=(InjectedCommandExecVars+ICEV_O);ICEV_O+=8;
Write(processHandle,ICEV_BeginProcessingCommands,GetExportedFromModule(processHandle,Tier0Module.BaseAddress,"CCommandBuffer::BeginProcessingCommands"));
WriteRef(processHandle,InjectedCommandExecFunction+0x49,ICEV_BeginProcessingCommands,2);

IntPtr ICEV_CreateCommandBuffer=(InjectedCommandExecVars+ICEV_O);ICEV_O+=8;
Write(processHandle,ICEV_CreateCommandBuffer,GetExportedFromModule(processHandle,Tier0Module.BaseAddress,"CCommandBuffer::CCommandBuffer"));
WriteRef(processHandle,InjectedCommandExecFunction+0x1C,ICEV_CreateCommandBuffer,2);

IntPtr ICEV_CommandBufferInputText=(InjectedCommandExecVars+ICEV_O);ICEV_O+=8;
WriteRef(processHandle,InjectedCommandExecFunction+0x5,ICEV_CommandBufferInputText,3);
WriteRef(processHandle,InjectedCommandExecFunction+0x29,ICEV_CommandBufferInputText,3);
WriteRef(processHandle,InjectedCommandExecFunction+0x4F,ICEV_CommandBufferInputText,3);

/*CommandExecuteInjection      - 55                    - push rbp
7FF805AF0001                   - 48 83 EC 70           - sub rsp,70 { 112 }
7FF805AF0005                   - 48 8D 15 64020000     - lea rdx,[CommandToExecute] { (0) }
7FF805AF000C                   - 83 3A 00              - cmp dword ptr [rdx],00 { 0 }
7FF805AF000F                   - 0F84 41000000         - je 7FF805AF0056
7FF805AF0015                   - 48 8B 0D 4C020000     - mov rcx,[CommandBufferPtr] { (7FF89D3DC168) }
7FF805AF001C                   - FF 15 3E020000        - call qword ptr [CommandBuffer_Create] { ->tier0.CCommandBuffer::CCommandBuffer }
7FF805AF0022                   - 48 8B 0D 3F020000     - mov rcx,[CommandBufferPtr] { (7FF89D3DC168) }
7FF805AF0029                   - 48 8D 15 40020000     - lea rdx,[CommandToExecute] { (0) }
7FF805AF0030                   - 48 31 C0              - xor rax,rax
7FF805AF0033                   - 45 31 C9              - xor r9d,r9d
7FF805AF0036                   - 45 31 C0              - xor r8d,r8d
7FF805AF0039                   - FF 15 11020000        - call qword ptr [CommandBuffer_AddText] { ->tier0.CCommandBuffer::AddText }
7FF805AF003F                   - 48 8B D0              - mov rdx,rax
7FF805AF0042                   - 48 8B 0D 1F020000     - mov rcx,[CommandBufferPtr] { (7FF89D3DC168) }
7FF805AF0049                   - FF 15 09020000        - call qword ptr [CommandBuffer_BeginProcessingCommands] { ->tier0.CCommandBuffer::BeginProcessingCommands }
7FF805AF004F                   - 48 89 1D 1A020000     - mov [CommandToExecute],rbx { (0) }
7FF805AF0056                   - 48 83 C4 70           - add rsp,70 { 112 }
7FF805AF005A                   - 5D                    - pop rbp
7FF805AF005B                   - C3                    - ret
*/

#endregion

#region While Connected
    try {
            while (true){
                string command;
                if (FinnishPhrases == null || FinnishPhrases.Length == 0)
                {
                    Console.WriteLine("Фразы не инициализированы или пусты.");
                    FinnishPhrases = new string[] { "Free Github project github.com/intcost/chatspammer", "Chat Spammer CS2 | dr NHA & intcost", "Open source CS2 ChatSpammer Github: intcost/chatspammer" };

                }

                // Генерация новой фразы, пока она не будет отличаться от предыдущей
                do
                    command = "say " + FinnishPhrases[new Random().Next(FinnishPhrases.Length)];
                while (command == lastCommand); // Проверка на повтор

                lastCommand = command; // Обновляем последнюю фразу

                byte[] encodedString = Encoding.UTF8.GetBytes(command + "\0");
                int bytesWritten;

                Console.Write($"\r--Chat Spammer-- Текущие оффсеты: addr: 0x{ICEV_CommandBufferInputText.ToInt64():X} x exec: 0x{InjectedCommandExecFunction.ToInt64():X} | Текущий текст: {command}   ");

                if (!WriteProcessMemory(processHandle, ICEV_CommandBufferInputText, encodedString, encodedString.Length, out bytesWritten))
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    Console.WriteLine($"\nОшибки: Не удалось записать в память. Код ошибки: {errorCode}.");
                    break;
                }

                IntPtr threadHandle = CreateRemoteThread(processHandle, IntPtr.Zero, 0, InjectedCommandExecFunction, IntPtr.Zero, 0, IntPtr.Zero);
                if (threadHandle == IntPtr.Zero)
                {
                    Console.WriteLine($"\nОшибки: Не удалось создать удаленный поток. Код ошибки: {Marshal.GetLastWin32Error()}");
                    break;
                }

                await Task.Delay(TimeSpan.FromSeconds(interval));
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nОшибка: {ex.Message}");
        }
        finally
        {
            CloseHandle(processHandle);
        }
    #endregion

EndOfMain:
Console.WriteLine("\nНажмите любую клавишу для выхода...");
Console.ReadKey();
}

private static string fileName = "settings.txt";
    private static string filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, fileName);

    private static void SaveSettings()
    {
        var settings = new Settings { phrases = FinnishPhrases, interval = interval };
        string settingsString = $"phrases={string.Join(",", settings.phrases)};interval={settings.interval}";
        File.WriteAllText(filePath, settingsString);
    }

    private class Settings
    {
        public string[] phrases { get; set; }
        public double interval { get; set; }
    }


    private static void LoadSettings()
    {
        try
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine($"Файл '{filePath}' не найден.");
                FinnishPhrases = new string[] { "Free Github project https://github.com/intcost/chatspammer", "Chat Spammer CS2 | dr NHA & intcost", "Open source CS2 ChatSpammer Github: intcost/chatspammer" };
                interval = 0.5;
                SaveSettings();
                return;
            }

            string settingsString = File.ReadAllText(filePath);
            var settings = new Settings();
            var parts = settingsString.Split(';');

            foreach (var part in parts)
            {
                var keyValue = part.Split('=');
                if (keyValue[0] == "phrases")
                    settings.phrases = keyValue[1].Split(',');
                if (keyValue[0] == "interval")
                    settings.interval = double.Parse(keyValue[1]);
            }

            FinnishPhrases = settings.phrases;
            interval = settings.interval;
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка при загрузке настроек: {ex.Message}");
            FinnishPhrases = new string[0];
            interval = 0.5;
        }
    }
}
