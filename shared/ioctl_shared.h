#pragma once

// IOCTL code shared between driver and user-mode client.
//   DeviceType  0x8000 = vendor-defined range
//   Function    0x800  = vendor-defined range
//   METHOD_BUFFERED    = I/O manager copies user buffers to/from kernel
//   FILE_ANY_ACCESS    = no special access on the handle
#define IOCTL_READ_PROCESS_MEMORY \
    CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define DEVICE_NAME_NT    L"\\Device\\KernelReader"
#define DEVICE_NAME_DOS   L"\\DosDevices\\KernelReader"
#define DEVICE_PATH_USER  L"\\\\.\\KernelReader"

#pragma pack(push, 1)
typedef struct _READ_MEMORY_REQUEST {
    unsigned long long ProcessId;
    unsigned long long TargetAddress;
    unsigned long long Size;
} READ_MEMORY_REQUEST, *PREAD_MEMORY_REQUEST;
#pragma pack(pop)
