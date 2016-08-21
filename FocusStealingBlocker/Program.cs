using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Hook3;
using Hook3.WinApiFunctions;

namespace FocusStealingBlocker
{
    class Program
    {
        static void Main(string[] args)
        {
            var processRegex = ConfigurationManager.AppSettings["processRegex"];
            foreach (var process in Process.GetProcesses().Where(x => Regex.IsMatch(x.ProcessName, processRegex)))
            {
                try
                {
                    Console.WriteLine($"[{process.Id}] {process.ProcessName} ({process.MainModule.FileName})");

                    var modules = EnumProcessModules((uint) process.Id);
                    var kernel32module = modules.First(x => x.szModule?.ToLower() == "kernel32.dll");

                    var is32bit = process.IsX86();
                    var kernel32pe = new PeNet.PeFile(kernel32module.szExePath);
                    var loadLibraryFileAddr = kernel32pe.ExportedFunctions.First(x => x?.Name == "LoadLibraryA").Address;
                    var loadLibraryAddr = kernel32module.hModule + (int) loadLibraryFileAddr;

                    var injectionDllPath = AppDomain.CurrentDomain.BaseDirectory + $"InjectionDll_{(is32bit ? "x86" : "x64")}.dll";
                    if (!File.Exists(injectionDllPath))
                        throw new Exception("Injection dll is not found!");

                    //var hKernel32 = WinApi.LoadLibrary("kernel32.dll");
                    //var hLoadLibrary = WinApi.GetProcAddress(hKernel32, "LoadLibraryA");
                    var memMan = new RemoteMemoryManager(process.Handle);
                    var injDllRemoteAddr = memMan.Copy(injectionDllPath);

                    uint threadId;
                    var hThread = WinApi.CreateRemoteThread(process.Handle, IntPtr.Zero, 0, loadLibraryAddr, injDllRemoteAddr, 0, out threadId);
                    WinApi.WaitForSingleObject(hThread, (uint) WaitForSingleObjectTimeout.Infinite);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static public extern bool CloseHandle(IntPtr hHandle);

        [DllImport("kernel32.dll")]
        static public extern bool Module32First(IntPtr hSnapshot, ref ModuleEntry32 lpme);

        [DllImport("kernel32.dll")]
        static public extern bool Module32Next(IntPtr hSnapshot, ref ModuleEntry32 lpme);

        [DllImport("kernel32.dll", SetLastError = true)]
        static public extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);

        public const short INVALID_HANDLE_VALUE = -1;

        [Flags]
        public enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = 0x0000001F
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ModuleEntry32
        {
            public uint dwSize;
            public uint th32ModuleID;
            public uint th32ProcessID;
            public uint GlblcntUsage;
            public uint ProccntUsage;
            public IntPtr modBaseAddr;
            public uint modBaseSize;
            public IntPtr hModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szModule;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExePath;

            public override string ToString()
            {
                return $"{szModule} (0x{hModule:X8})";
            }
        };

        static ModuleEntry32[] EnumProcessModules(uint procIDDDDDDDDDDDDD)
        {
            var snapshot = CreateToolhelp32Snapshot(SnapshotFlags.Module | SnapshotFlags.Module32, procIDDDDDDDDDDDDD);
            ModuleEntry32 mod = new ModuleEntry32() { dwSize = (uint)Marshal.SizeOf(typeof(ModuleEntry32)) };
            if (!Module32First(snapshot, ref mod))
                return null;

            var modules = new List<ModuleEntry32>();
            do
            {
                modules.Add(mod);
            }
            while (Module32Next(snapshot, ref mod));

            return modules.ToArray();
        }

        //[DllImport("psapi.dll", SetLastError = true)]
        //public static extern bool EnumProcessModules(IntPtr hProcess,
        //[MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] IntPtr[] lphModule, uint cb, [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);
        //
        //[DllImport("psapi.dll", SetLastError = true)]
        //public static extern bool EnumProcessModulesEx(IntPtr hProcess,
        //[MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] IntPtr[] lphModule, uint cb, [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded, uint dwFilterFlag);
        //
        //[DllImport("psapi.dll")]
        //static extern uint GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, [In] [MarshalAs(UnmanagedType.U4)] int nSize);
        //
        //static void GetProcessModules(Process process)
        //{
        //    // Setting up the variable for the second argument for EnumProcessModules
        //    IntPtr[] hMods = new IntPtr[1024];
        //
        //    //GCHandle gch = GCHandle.Alloc(hMods, GCHandleType.Pinned); // Don't forget to free this later
        //    //IntPtr pModules = gch.AddrOfPinnedObject();
        //
        //    // Setting up the rest of the parameters for EnumProcessModules
        //    uint uiSize = (uint)(Marshal.SizeOf(typeof(IntPtr)) * (hMods.Length));
        //    uint cbNeeded = 0;
        //
        //    if (EnumProcessModulesEx(process.Handle, hMods, uiSize, out cbNeeded, 3 /* LIST_MODULES_ALL */))
        //    {
        //        Int32 uiTotalNumberofModules = (Int32)(cbNeeded / (Marshal.SizeOf(typeof(IntPtr))));
        //
        //        for (int i = 0; i < (int)uiTotalNumberofModules; i++)
        //        {
        //            StringBuilder strbld = new StringBuilder(1024);
        //
        //            GetModuleFileNameEx(process.Handle, hMods[i], strbld, strbld.Capacity);
        //            Console.WriteLine($"[0x{hMods[i]:x8}] {strbld}");
        //        }
        //        Console.WriteLine("Number of Modules: " + uiTotalNumberofModules);
        //        Console.WriteLine();
        //    }
        //
        //    // Must free the GCHandle object
        //    //gch.Free();
        //}
    }

    static class ExtensionMethods
    {
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);

        public static bool IsX86(this Process process)
        {
            if ((Environment.OSVersion.Version.Major > 5)
                || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1)))
            {
                bool retVal;

                return IsWow64Process(process.Handle, out retVal) && retVal;
            }

            return false; // not on 64-bit Windows Emulator
        }
    }
}
