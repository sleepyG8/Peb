#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "User32.lib")

// this is key for dealing with peb structure in C
typedef struct _MY_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID ImageBaseAddress; // Base address of the process
} MY_PEB, *PMY_PEB;

// Define a custom PROCESS_BASIC_INFORMATION structure to avoid conflicts
typedef struct _MY_PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PMY_PEB PebBaseAddress; // Address of the PEB
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} MY_PROCESS_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

void GetPEBFromAnotherProcess(HANDLE hProcess) {
    HMODULE hNtDll = GetModuleHandle("ntdll.dll");
    if (!hNtDll) {
        printf("Failed to load ntdll.dll\n");
        return;
    }

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        printf("Failed to get NtQueryInformationProcess\n");
        return;
    }

    MY_PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(hProcess, 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), NULL);
    if (status != 0) {
        printf("NtQueryInformationProcess failed (Status 0x%08X)\n", status);
        return;
    }

    printf("PEB Address of the target process: %p\n", pbi.PebBaseAddress);

    MY_PEB peb;
    if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        printf("Image Base Address of the target process: %p\n", peb.ImageBaseAddress);
    } else {
        printf("Failed to read PEB from the target process (Error %lu)\n", GetLastError());
    }
}

int main() {
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    if (CreateProcess(
            "C:\\Windows\\System32\\notepad.exe",
            NULL,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            NULL,
            &si,
            &pi)) {
        printf("Notepad opened successfully.\n");

        WaitForInputIdle(pi.hProcess, INFINITE);
        GetPEBFromAnotherProcess(pi.hProcess);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("Failed to open Notepad. Error: %lu\n", GetLastError());
    }

    return 0;
}
