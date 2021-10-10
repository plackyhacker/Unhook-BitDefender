# Unhook Bit Defender
A C# application that unhooks **Bit Defender** from **ntdll.dll** to help run malicious code undetected.

# Introduction
This C# code is based upon one of the techniques demonstrated in the RED TEAM Operator: Windows Evasion Course from [Sektor7](https://institute.sektor7.net), the original is written in C/C++. I would recommend any of the malware development courses, there is a lot of great stuff to learn about creating malware in C/C++.

When Windows creates a new process Bit Defender injects the **atcuf64.dll** DLL into the process and hooks many of the **ntdll.dll** syscalls. If, for example, `NtCreateProcess` is called by malicious code Bit Defender is able to intercept the call, do it's anti-malware magic, then return execution to the thread (or kill the process if it is malicious).

The code maps another version of **ntdll.dll** in memory, finds the `.text` section, and copies it over the hoooked version.

# Proof of Concept in x64dbg

The following image shows the `ZwCreateProcess` function when Bit Defender is not present:

![No Bit Defender](https://github.com/plackyhacker/UnhookBitDefender/blob/main/NoBitDef.png?raw=true)

The following image shows the `ZwCreateProcess` function when Bit Defender has hooked into **ntdll.dll**

![No Bit Defender](https://github.com/plackyhacker/UnhookBitDefender/blob/main/BitDefHooks.png?raw=true)

And finally, this image shows the `ZwCreateProcess` function after being unhooked:

![No Bit Defender](https://github.com/plackyhacker/UnhookBitDefender/blob/main/BitDefUnhooked.png?raw=true)

# Example
 
Execution of the code is shown below:

```
[+] Mapping Ntdll...
[+] Original Ntdll address is 0x7FFE23450000
[+] Mapped Ntdll address is 0x2C17E3B0000
[+] Mapped Ntdll is a valid image.
[+] e_lfanew equals 0xE8
[+] NT_HEADERS address is 0x2C17E3B00E8
[+] Mapped Ntdll NT Headers is valid.
[+] Sections to enumerate is 10
[+] First section is .text
[+] First section is at 0x2C17E3B01F0
[+] Analysing section .text
[+] .text section is at 0x2C17E3B01F0
[+] VirtualProtect Ntdll to PAGE_EXECUTE_READWRITE...
[+] Unhooking Ntdll by copying mapped data...
[+] VirtualProtect Ntdll to PAGE_EXECUTE_WRITECOPY...
[+] Done! Have a nice day!
```

# Notes
I haven't tested the code with anything malicious yet to see if it bypasses Bit Defender. I will post my findings when I do.
