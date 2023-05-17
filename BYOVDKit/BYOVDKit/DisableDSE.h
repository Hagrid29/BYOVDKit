#pragma once

#include <Windows.h>
#include <winternl.h>

// defs
#ifndef IN_REGION
#define IN_REGION(x, Base, Size) (((ULONG_PTR)(x) >= (ULONG_PTR)(Base)) && ((ULONG_PTR)(x) <= (ULONG_PTR)(Base) + (ULONG_PTR)(Size)))
#endif
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_OPEN_IF 0x00000003
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_IMAGE_ALREADY_LOADED 0xC000010EL
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035L
#define STATUS_OBJECT_NAME_EXISTS 0x4000000L
#define PAGE_SIZE 0x1000ull
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#define STATUS_BUFFER_OVERFLOW 0x80000005L
#define STATUS_PROCEDURE_NOT_FOUND 0xC000007AL
#define VM_LOCK_1 0x0001
#define FILE_OPEN 0x00000001
#define STATUS_INSUFFICIENT_RESOURCES 0xC000009AL





typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


typedef NTSTATUS(NTAPI* RtlGetVersion_t)(_Out_ PRTL_OSVERSIONINFOW lpVersionInformation);
typedef NTSTATUS(NTAPI* LdrFindEntryForAddress_t)(PVOID, PLDR_DATA_TABLE_ENTRY*);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
    _In_        HANDLE ProcessHandle,
    _Inout_     PVOID* BaseAddress,
    _In_        ULONG_PTR ZeroBits,
    _Inout_     PSIZE_T RegionSize,
    _In_        ULONG AllocationType,
    _In_        ULONG Protect
);
typedef NTSTATUS(NTAPI* NtLockVirtualMemory_t)(
    IN HANDLE ProcessHandle,
    IN PVOID* BaseAddress,
    IN OUT PULONG NumberOfBytesToLock,
    IN ULONG LockOption
);
typedef NTSTATUS(NTAPI* NtUnlockVirtualMemory_t)(
    IN HANDLE ProcessHandle,
    IN PVOID* BaseAddress,
    IN OUT PULONG NumberOfBytesToUnlock,
    IN ULONG LockType
);
typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(
    IN HANDLE ProcessHandle,
    IN PVOID* BaseAddress,
    IN OUT PULONG RegionSize,
    IN ULONG FreeType
);

typedef enum DSE_MODE
{
    Disable = 0x0,
    Enable = 0x6,
    Test = 0x8,
    Error = 0x999
};

ULONG GetBuildNumber();
ULONG_PTR AnalyzeCi();
bool SetDSE(DSE_MODE mode);
DSE_MODE GetDSE();
