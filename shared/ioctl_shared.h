#pragma once

// Single dispatch IOCTL. The kernel switches on REQUEST_TYPE in the input
// buffer to pick a handler. This mirrors Valthrun's single-IOCTL pattern.
#define IOCTL_DISPATCH \
    CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Kept for backward compat with the old single-handler design — same code.
#define IOCTL_READ_PROCESS_MEMORY IOCTL_DISPATCH

#define DEVICE_NAME_NT    L"\\Device\\KernelReader"
#define DEVICE_NAME_DOS   L"\\DosDevices\\KernelReader"
#define DEVICE_PATH_USER  L"\\\\.\\KernelReader"

// Request discriminator — first 4 bytes of every input buffer.
typedef enum _REQUEST_TYPE {
    REQ_READ_MEMORY        = 1,
    REQ_PROCESS_LIST       = 2,
    REQ_MODULE_LIST        = 3,
    REQ_MODULE_BY_NAME     = 4,
} REQUEST_TYPE;

#pragma pack(push, 1)

// All requests start with a 4-byte type tag. The driver reads the tag,
// then re-interprets the buffer as the matching request struct.
typedef struct _REQUEST_HEADER {
    unsigned int Type; // REQUEST_TYPE
} REQUEST_HEADER, *PREQUEST_HEADER;

// REQ_READ_MEMORY
typedef struct _REQ_READ_MEMORY_IN {
    REQUEST_HEADER Header;
    unsigned int   _pad;
    unsigned long long ProcessId;
    unsigned long long TargetAddress;
    unsigned long long Size;
} REQ_READ_MEMORY_IN, *PREQ_READ_MEMORY_IN;

// REQ_PROCESS_LIST — no extra input fields beyond the header.
typedef struct _REQ_PROCESS_LIST_IN {
    REQUEST_HEADER Header;
} REQ_PROCESS_LIST_IN, *PREQ_PROCESS_LIST_IN;

typedef struct _PROCESS_ENTRY {
    unsigned long long ProcessId;
    wchar_t            Name[260]; // ImageFileName, NUL-terminated
} PROCESS_ENTRY, *PPROCESS_ENTRY;

// Output buffer layout: u32 count, then `count` PROCESS_ENTRY records.
typedef struct _PROCESS_LIST_OUT {
    unsigned int  Count;
    unsigned int  _pad;
    // PROCESS_ENTRY Entries[];  // variable length
} PROCESS_LIST_OUT, *PPROCESS_LIST_OUT;

// REQ_MODULE_LIST
typedef struct _REQ_MODULE_LIST_IN {
    REQUEST_HEADER Header;
    unsigned int   _pad;
    unsigned long long ProcessId;
} REQ_MODULE_LIST_IN, *PREQ_MODULE_LIST_IN;

typedef struct _MODULE_ENTRY {
    unsigned long long BaseAddress;
    unsigned long long Size;
    wchar_t            Name[260];
} MODULE_ENTRY, *PMODULE_ENTRY;

typedef struct _MODULE_LIST_OUT {
    unsigned int  Count;
    unsigned int  _pad;
    // MODULE_ENTRY Entries[];
} MODULE_LIST_OUT, *PMODULE_LIST_OUT;

// REQ_MODULE_BY_NAME
typedef struct _REQ_MODULE_BY_NAME_IN {
    REQUEST_HEADER Header;
    unsigned int   _pad;
    unsigned long long ProcessId;
    wchar_t            Name[260];
} REQ_MODULE_BY_NAME_IN, *PREQ_MODULE_BY_NAME_IN;

typedef struct _MODULE_BY_NAME_OUT {
    unsigned long long BaseAddress;
    unsigned long long Size;
} MODULE_BY_NAME_OUT, *PMODULE_BY_NAME_OUT;

#pragma pack(pop)

// Convenience: largest possible output we'll ever ask the I/O manager for.
// Keep modest — METHOD_BUFFERED allocates this much in non-paged pool.
#define KR_MAX_OUTPUT_BYTES (1024 * 1024) // 1 MiB
