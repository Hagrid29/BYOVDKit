#pragma once

BOOL GetProcessProtectionFromAddress(ULONG_PTR Addr, PUCHAR Protection);
BOOL GetProcessSignatureLevelFromAddress(ULONG_PTR Addr, PUCHAR SignatureLevel);
//BOOL GetProcessSectionSignatureLevelFromAddress(ULONG_PTR Addr, PUCHAR SectionSignatureLevel);
UCHAR GetProtectionLevel(UCHAR Protection);
UCHAR GetSignerType(UCHAR Protection);
BOOL GetProcessProtection(DWORD Pid);

BOOL SetProcessProtectionFromAddress(ULONG_PTR Addr, UCHAR Protection);
BOOL SetProcessProtection(DWORD Pid, LPCWSTR ProtectionLevel, LPCWSTR SignerType);
BOOL UnprotectProcess(DWORD Pid);


typedef enum _PS_PROTECTED_TYPE
{
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER
{
    PsProtectedSignerNone = 0,      // 0
    PsProtectedSignerAuthenticode,  // 1
    PsProtectedSignerCodeGen,       // 2
    PsProtectedSignerAntimalware,   // 3
    PsProtectedSignerLsa,           // 4
    PsProtectedSignerWindows,       // 5
    PsProtectedSignerWinTcb,        // 6
    PsProtectedSignerWinSystem,     // 7
    PsProtectedSignerApp,           // 8
    PsProtectedSignerMax            // 9
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;