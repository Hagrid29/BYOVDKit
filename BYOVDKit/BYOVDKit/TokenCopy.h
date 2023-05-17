#pragma once

typedef struct _EX_FAST_REF
{
	union
	{
		PVOID Object;
		ULONG RefCnt : 3;
		ULONG Value;
	};
} EX_FAST_REF, * PEX_FAST_REF;

bool CopyToken(DWORD SrcPid, DWORD DstPid);