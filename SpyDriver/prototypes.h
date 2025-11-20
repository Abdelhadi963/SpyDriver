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


// System module information structures
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

//typedef struct _EX_RUNDOWN_REF {
//    ULONG_PTR Count;
//} EX_RUNDOWN_REF;

typedef struct _EX_CALLBACK_ROUTINE_BLOCK {
    EX_RUNDOWN_REF RundownProtect;
    PVOID Function;
    PVOID Context;
} EX_CALLBACK_ROUTINE_BLOCK, * PEX_CALLBACK_ROUTINE_BLOCK;

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

NTSTATUS SpyIoSetProcessProtection(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
);

NTSTATUS SpyIoRemoveProcessProtection(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
);

// ---------------------------------------------------------------
// External kernel functions
NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
    IN ULONG SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

// System information classes
#define SystemModuleInformation 11

// Helper function prototypes
PVOID GetKernelModuleBase(const char* moduleName);

VOID GetDriverNameFromAddress(PVOID address, PCHAR outName, ULONG outSize);

// Callback enumeration IOCTL handler
NTSTATUS SpyIoEnumerateProcessCallbacks(
    PVOID outputBuffer,
    ULONG outputLength,
    PULONG_PTR bytesReturned
);