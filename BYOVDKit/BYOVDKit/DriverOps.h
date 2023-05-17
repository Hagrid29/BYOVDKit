#pragma once
#include <iostream>
#include <Windows.h>
#include <winternl.h>



typedef enum DRIVER_OPTION{
	undefined = 0,
	DBUtil_2_3 = 1,
	RTCore64 = 2,
	GIO = 3
};

struct DEFINE_DRIVER {
	PCWSTR serviceName;
	PCWSTR displayName;
	PCWSTR driverPath;
};

//DBUtil_2_3
static const DWORD DBUTIL_READ_IOCTL = 0x9B0C1EC4;
static const DWORD DBUTIL_WRITE_IOCTL = 0x9B0C1EC8;
struct DBUTIL_READ_BUFFER {
    unsigned long long pad1 = 0x4141414141414141;
    unsigned long long Address;
    unsigned long long three1 = 0x0000000000000000;
    unsigned long long value = 0x0000000000000000;
};
struct DBUTIL_WRITE_BUFFER {
    unsigned long long pad1 = 0x4141414141414141;
    unsigned long long Address;
    unsigned long long three1 = 0x0000000000000000;
    unsigned long long Value = 0x0000000000000000;
};

//RTCore64
#define RTC_MEMORY_READ RTC64_MEMORY_READ
struct RTC64_MEMORY_READ {
	BYTE Pad0[8];
	DWORD64 Address;
	BYTE Pad1[8];
	DWORD Size;
	DWORD Value;
	BYTE Pad3[16];
};
#define RTC_MEMORY_WRITE RTC64_MEMORY_WRITE
struct RTC64_MEMORY_WRITE {
	BYTE Pad0[8];
	DWORD64 Address;
	BYTE Pad1[8];
	DWORD Size;
	DWORD Value;
	BYTE Pad3[16];
};
#define RTC64_IOCTL_MEMORY_READ 0x80002048
#define RTC64_IOCTL_MEMORY_WRITE 0x8000204c
#define RTC_IOCTL_MEMORY_READ RTC64_IOCTL_MEMORY_READ
#define RTC_IOCTL_MEMORY_WRITE RTC64_IOCTL_MEMORY_WRITE



// GIO
typedef struct _GIOMemcpyInput
{
	ULONG_PTR Dst;
	ULONG_PTR Src;
	ULONG Size;
} GIOMemcpyInput, * PGIOMemcpyInput;
#define FILE_DEVICE_GIO				(0xc350)
#define IOCTL_GIO_MEMCPY			CTL_CODE(FILE_DEVICE_GIO, 0xa02, METHOD_BUFFERED, FILE_ANY_ACCESS)


bool ServiceInstall(DRIVER_OPTION device_option, PCWSTR binPath, PCWSTR serviceName = NULL);
bool ServiceUninstall(DRIVER_OPTION device_option, PCWSTR serviceName = NULL);
bool InitDriver(DRIVER_OPTION dev_opt);
void CloseDriverHandle();
BOOL Read8(ULONG_PTR Address, PBYTE Value);
BOOL Read16(ULONG_PTR Address, PWORD Value);
BOOL Read32(ULONG_PTR Address, PDWORD Value);
BOOL Read64(ULONG_PTR Address, PDWORD64 Value);
BOOL ReadPtr(ULONG_PTR Address, PULONG_PTR Value);
BOOL Write8(ULONG_PTR Address, BYTE Value);
BOOL Write16(ULONG_PTR Address, WORD Value);
BOOL Write32(ULONG_PTR Address, DWORD Value);
BOOL Write64(ULONG_PTR Address, DWORD64 Value);




