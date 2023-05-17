#pragma once


typedef struct Offsets {
	DWORD PsInitialSystemProcessOffset;
	DWORD UniqueProcessIdOffset;
	DWORD ActiveProcessLinksOffset;
	DWORD ObjectTableOffset;
	DWORD TokenOffset;
	DWORD ProtectionOffset;
	DWORD SignatureLevelOffset;
	DWORD EtwThreatIntProvRegHandleOffset;
};


void InitOffsets();
Offsets GetOffsets();


BOOL GetProcessKernelAddress(DWORD Pid, PULONG_PTR Addr);
DWORD64 GetHandleTableEntryAddress(DWORD64 HandleTable, ULONGLONG Handle);
ULONG_PTR GetKernelBaseAddress();

typedef struct _CTRL_PROCESS_ENTRY
{
	ULONG_PTR KernelAddress;
	DWORD Pid;
} CTRL_PROCESS_ENTRY, * PCTRL_PROCESS_ENTRY;

typedef struct _CTRL_PROCESS_INFO
{
	DWORD NumberOfEntries;
	CTRL_PROCESS_ENTRY Entries[ANYSIZE_ARRAY];
} CTRL_PROCESS_INFO, * PCTRL_PROCESS_INFO;
