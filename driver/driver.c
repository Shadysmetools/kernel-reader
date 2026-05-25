#include <ntifs.h>
#include <ntddk.h>
#include "../shared/ioctl_shared.h"

NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID     SourceAddress,
    PEPROCESS TargetProcess,
    PVOID     TargetAddress,
    SIZE_T    BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T   ReturnSize
);

PDEVICE_OBJECT g_DeviceObject = NULL;

DRIVER_UNLOAD   DriverUnload;
DRIVER_DISPATCH DispatchCreateClose;
DRIVER_DISPATCH DispatchIoctl;

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS ReadTargetProcessMemory(
    HANDLE  Pid,
    PVOID   SourceAddress,
    PVOID   DestBuffer,
    SIZE_T  Size,
    PSIZE_T BytesRead)
{
    PEPROCESS targetProcess = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(Pid, &targetProcess);
    if (!NT_SUCCESS(status)) return status;

    status = MmCopyVirtualMemory(
        targetProcess,
        SourceAddress,
        PsGetCurrentProcess(),
        DestBuffer,
        Size,
        KernelMode,
        BytesRead);

    ObDereferenceObject(targetProcess);
    return status;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status          = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information    = 0;

    const ULONG code   = stack->Parameters.DeviceIoControl.IoControlCode;
    const ULONG inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    const ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID sysBuffer    = Irp->AssociatedIrp.SystemBuffer;

    switch (code) {
    case IOCTL_READ_PROCESS_MEMORY: {
        if (inLen < sizeof(READ_MEMORY_REQUEST) || sysBuffer == NULL) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        READ_MEMORY_REQUEST req = *(PREAD_MEMORY_REQUEST)sysBuffer;

        if (req.Size == 0 || req.Size > outLen) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        SIZE_T bytesRead = 0;
        status = ReadTargetProcessMemory(
            (HANDLE)(ULONG_PTR)req.ProcessId,
            (PVOID)(ULONG_PTR)req.TargetAddress,
            sysBuffer,
            (SIZE_T)req.Size,
            &bytesRead);

        information = NT_SUCCESS(status) ? bytesRead : 0;
        break;
    }
    default:
        break;
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(DEVICE_NAME_DOS);
    IoDeleteSymbolicLink(&symlink);
    if (g_DeviceObject) IoDeleteDevice(g_DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME_NT);
    UNICODE_STRING symlink = RTL_CONSTANT_STRING(DEVICE_NAME_DOS);

    NTSTATUS status = IoCreateDevice(
        DriverObject, 0, &devName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE,
        &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&symlink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
    DriverObject->DriverUnload                          = DriverUnload;

    return STATUS_SUCCESS;
}
