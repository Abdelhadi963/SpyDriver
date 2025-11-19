#pragma once
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