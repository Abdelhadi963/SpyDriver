#pragma once
#include "prototypes.h"
#include "common.h"


// ---------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------
PVOID GetKernelModuleBase(const char* moduleName)
{
    PVOID moduleBase = NULL;
    ULONG bufferSize = 0;

    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (bufferSize == 0) {
        DbgPrint("[-] ZwQuerySystemInformation failed to get size\n");
        return NULL;
    }

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(
        NonPagedPool, bufferSize, 'IppY');
    if (!modules) {
        DbgPrint("[-] Memory allocation failed\n");
        return NULL;
    }

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation,
        modules, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] ZwQuerySystemInformation failed: 0x%X\n", status);
        ExFreePoolWithTag(modules, 'IppY');
        return NULL;
    }

    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        RTL_PROCESS_MODULE_INFORMATION* mod = &modules->Modules[i];
        char* fileName = (char*)mod->FullPathName + mod->OffsetToFileName;

        if (_stricmp(fileName, moduleName) == 0) {
            moduleBase = mod->ImageBase;
            DbgPrint("[+] Found %s at 0x%p\n", moduleName, moduleBase);
            break;
        }
    }

    ExFreePoolWithTag(modules, 'IppY');
    return moduleBase;
}

// Helper: Get driver name from callback address
VOID GetDriverNameFromAddress(PVOID address, PCHAR outName, ULONG outSize)
{
    if (!address || !MmIsAddressValid(address)) {
        RtlStringCbCopyA(outName, outSize, "Invalid");
        return;
    }

    ULONG bufferSize = 0;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (bufferSize == 0) {
        RtlStringCbCopyA(outName, outSize, "Unknown");
        return;
    }

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(
        NonPagedPool, bufferSize, 'IppY');
    if (!modules) {
        RtlStringCbCopyA(outName, outSize, "Unknown");
        return;
    }

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation,
        modules, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, 'IppY');
        RtlStringCbCopyA(outName, outSize, "Unknown");
        return;
    }

    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        RTL_PROCESS_MODULE_INFORMATION* mod = &modules->Modules[i];
        ULONG_PTR start = (ULONG_PTR)mod->ImageBase;
        ULONG_PTR end = start + mod->ImageSize;

        if ((ULONG_PTR)address >= start && (ULONG_PTR)address < end) {
            char* fileName = (char*)mod->FullPathName + mod->OffsetToFileName;
            RtlStringCbCopyA(outName, outSize, fileName);
            found = TRUE;
            break;
        }
    }

    if (!found) {
        RtlStringCbCopyA(outName, outSize, "Unknown");
    }

    ExFreePoolWithTag(modules, 'IppY');
}


// ---------------------------------------------------------------
// Process callback enumeration IOCTL handler
// ---------------------------------------------------------------
NTSTATUS SpyIoEnumerateProcessCallbacks(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
)
{
    DbgPrint("[*] Process callback enumeration initiated\n");

    char* out = (char*)outputBuffer;
    ULONG offset = 0;
    NTSTATUS status;
    size_t writtenBytes = 0;

    /*status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[*] Enumerating PspCreateProcessNotifyRoutine Callbacks:\n");
    if (!NT_SUCCESS(status)) {
        *bytesReturned = 0;
        return status;
    }
    status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    offset += (ULONG)writtenBytes;*/

    PVOID ntosBase = GetKernelModuleBase("ntoskrnl.exe");
    if (!ntosBase) {
        DbgPrint("[-] Failed to get ntoskrnl base\n");
        status = RtlStringCbPrintfA(out + offset, outputLength - offset,
            "[-] Failed to locate kernel base\n");
        RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
        offset += (ULONG)writtenBytes;
        *bytesReturned = offset;
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrint("[+] ntoskrnl.exe base: 0x%p\n", ntosBase);

	// append kernel base info to output
    /*status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[+] ntoskrnl.exe base: 0x%p\n", ntosBase);
    RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    offset += (ULONG)writtenBytes;*/

    PEX_CALLBACK_ROUTINE_BLOCK* callbackArray =
        (PEX_CALLBACK_ROUTINE_BLOCK*)((ULONG_PTR)ntosBase + 0xCFFC00);

    DbgPrint("[+] Callback array at: 0x%p\n", callbackArray);

    status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[+] PspCreateProcessNotifyRoutine array at: 0x%p\n", callbackArray);
    RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    offset += (ULONG)writtenBytes;

    ULONG callbackCount = 0;
    for (ULONG i = 0; i < 64; i++) {
        PEX_CALLBACK_ROUTINE_BLOCK block = callbackArray[i];

        if (!block) continue;

        /*PVOID callbackFunc = (PVOID)((ULONG_PTR)block & 0xFFFFFFFFFFFFFFF8);*/
        PVOID callbackFunc = *((PVOID*)((ULONG_PTR)block & 0xFFFFFFFFFFFFFFF8));

        if (!callbackFunc || !MmIsAddressValid(callbackFunc)) continue;

        callbackCount++;

        CHAR driverName[256] = "Unknown";
        GetDriverNameFromAddress(callbackFunc, driverName, sizeof(driverName));

        DbgPrint("[%02lu] 0x%p -> %s\n", i, callbackFunc, driverName);

        status = RtlStringCbPrintfA(out + offset, outputLength - offset,
            "[%02lu] 0x%p -> %s\n", i, callbackFunc, driverName);
        if (!NT_SUCCESS(status)) break;

        RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
        offset += (ULONG)writtenBytes;
    }

    status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[+] Found %lu active callbacks\n", callbackCount);
    RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    offset += (ULONG)writtenBytes;

    *bytesReturned = offset;
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------
//  Thread callback enumeration IOCTL handler
// ---------------------------------------------------------------

NTSTATUS SpyIoEnumerateThreadCallbacks(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
)
{
    DbgPrint("[*] Thread callback enumeration initiated\n");

    char* out = (char*)outputBuffer;
    ULONG offset = 0;
    NTSTATUS status;
    size_t writtenBytes = 0;

    /*status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[*] Enumerating PspCreateThreadNotifyRoutine Callbacks:\n");
    if (!NT_SUCCESS(status)) {
        *bytesReturned = 0;
        return status;
    }
    status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    offset += (ULONG)writtenBytes;*/

    PVOID ntosBase = GetKernelModuleBase("ntoskrnl.exe");
    if (!ntosBase) {
        DbgPrint("[-] Failed to get ntoskrnl base\n");
        status = RtlStringCbPrintfA(out + offset, outputLength - offset,
            "[-] Failed to locate kernel base\n");
        RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
        offset += (ULONG)writtenBytes;
        *bytesReturned = offset;
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrint("[+] ntoskrnl.exe base: 0x%p\n", ntosBase);

	// append kernel base info to output
    /*status = RtlStringCbPrintfA(out + offset, outputLength - offset,
		"[+] ntoskrnl.exe base: 0x%p\n", ntosBase);
	RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
	offset += (ULONG)writtenBytes;*/

    PEX_CALLBACK_ROUTINE_BLOCK* callbackArray =
        (PEX_CALLBACK_ROUTINE_BLOCK*)((ULONG_PTR)ntosBase + 0xCFFE00);

    DbgPrint("[+] Callback array at: 0x%p\n", callbackArray);

    status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[+] PspCreateThreadNotifyRoutine array at: 0x%p\n", callbackArray);
    RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    offset += (ULONG)writtenBytes;

    ULONG callbackCount = 0;
    for (ULONG i = 0; i < 64; i++) {
        PEX_CALLBACK_ROUTINE_BLOCK block = callbackArray[i];

        if (!block) continue;

        /*PVOID callbackFunc = (PVOID)((ULONG_PTR)block & 0xFFFFFFFFFFFFFFF8);*/
        PVOID callbackFunc = *((PVOID*)((ULONG_PTR)block & 0xFFFFFFFFFFFFFFF8));

        if (!callbackFunc || !MmIsAddressValid(callbackFunc)) continue;

        callbackCount++;

        CHAR driverName[256] = "Unknown";
        GetDriverNameFromAddress(callbackFunc, driverName, sizeof(driverName));

        DbgPrint("[%02lu] 0x%p -> %s\n", i, callbackFunc, driverName);

        status = RtlStringCbPrintfA(out + offset, outputLength - offset,
            "[%02lu] 0x%p -> %s\n", i, callbackFunc, driverName);
        if (!NT_SUCCESS(status)) break;

        RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
        offset += (ULONG)writtenBytes;
    }

    status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[+] Found %lu active callbacks\n", callbackCount);
    RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    offset += (ULONG)writtenBytes;

    *bytesReturned = offset;
    return STATUS_SUCCESS;
}