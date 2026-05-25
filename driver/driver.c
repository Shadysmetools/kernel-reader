#include <ntifs.h>
#include <ntddk.h>
#include "../shared/ioctl_shared.h"

// ───────── Forward declarations of undocumented/private kernel APIs ─────────

NTSTATUS NTAPI MmCopyVirtualMemory(
    PEPROCESS SourceProcess, PVOID SourceAddress,
    PEPROCESS TargetProcess, PVOID TargetAddress,
    SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);

#define SystemProcessInformationClass 5

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime, UserTime, KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    // rest unused
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

// PEB / Ldr layout (x64). Stable across Win10/11.
typedef struct _PEB_LDR_DATA_X64 {
    ULONG  Length;
    UCHAR  Initialized;
    PVOID  SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA_X64, *PPEB_LDR_DATA_X64;

typedef struct _LDR_DATA_TABLE_ENTRY_X64 {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UCHAR _pad[4];
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_X64, *PLDR_DATA_TABLE_ENTRY_X64;

typedef struct _PEB_X64 {
    UCHAR _pad[0x18];
    PPEB_LDR_DATA_X64 Ldr;
} PEB_X64, *PPEB_X64;

// ───────── Globals ─────────

PDEVICE_OBJECT g_DeviceObject = NULL;

// ───────── Forward decls ─────────

DRIVER_UNLOAD   DriverUnload;
DRIVER_DISPATCH DispatchCreateClose;
DRIVER_DISPATCH DispatchIoctl;

// ───────── Create/close (required so user-mode CreateFile succeeds) ─────────

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ───────── Handler: REQ_READ_MEMORY ─────────

static NTSTATUS HandleReadMemory(PVOID sysbuf, ULONG inLen, ULONG outLen, PULONG_PTR information) {
    if (inLen < sizeof(REQ_READ_MEMORY_IN)) return STATUS_BUFFER_TOO_SMALL;
    REQ_READ_MEMORY_IN req = *(PREQ_READ_MEMORY_IN)sysbuf;
    if (req.Size == 0 || req.Size > outLen) return STATUS_INVALID_PARAMETER;

    PEPROCESS target = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.ProcessId, &target);
    if (!NT_SUCCESS(status)) return status;

    SIZE_T copied = 0;
    status = MmCopyVirtualMemory(
        target, (PVOID)(ULONG_PTR)req.TargetAddress,
        PsGetCurrentProcess(), sysbuf,
        (SIZE_T)req.Size, KernelMode, &copied);
    ObDereferenceObject(target);

    if (NT_SUCCESS(status)) *information = copied;
    return status;
}

// ───────── Handler: REQ_PROCESS_LIST ─────────

static NTSTATUS HandleProcessList(PVOID sysbuf, ULONG inLen, ULONG outLen, PULONG_PTR information) {
    UNREFERENCED_PARAMETER(inLen);
    if (outLen < sizeof(PROCESS_LIST_OUT)) return STATUS_BUFFER_TOO_SMALL;

    // Discover required size, then allocate.
    ULONG needed = 0;
    NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformationClass, NULL, 0, &needed);
    if (needed == 0) return STATUS_UNSUCCESSFUL;

    needed += 0x4000; // headroom — process set changes between calls
    PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, 'rKsR');
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(SystemProcessInformationClass, buf, needed, &needed);
    if (!NT_SUCCESS(status)) { ExFreePool(buf); return status; }

    PPROCESS_LIST_OUT outHdr = (PPROCESS_LIST_OUT)sysbuf;
    PPROCESS_ENTRY    entries = (PPROCESS_ENTRY)((PUCHAR)sysbuf + sizeof(PROCESS_LIST_OUT));
    ULONG maxEntries = (outLen - sizeof(PROCESS_LIST_OUT)) / sizeof(PROCESS_ENTRY);
    ULONG count = 0;

    PSYSTEM_PROCESS_INFORMATION info = (PSYSTEM_PROCESS_INFORMATION)buf;
    while (count < maxEntries) {
        if (info->UniqueProcessId != NULL) {
            entries[count].ProcessId = (ULONG_PTR)info->UniqueProcessId;
            RtlZeroMemory(entries[count].Name, sizeof(entries[count].Name));
            if (info->ImageName.Buffer && info->ImageName.Length > 0) {
                USHORT bytes = info->ImageName.Length;
                if (bytes > sizeof(entries[count].Name) - sizeof(wchar_t))
                    bytes = sizeof(entries[count].Name) - sizeof(wchar_t);
                RtlCopyMemory(entries[count].Name, info->ImageName.Buffer, bytes);
            }
            count++;
        }
        if (info->NextEntryOffset == 0) break;
        info = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
    }

    outHdr->Count = count;
    outHdr->_pad  = 0;
    *information  = sizeof(PROCESS_LIST_OUT) + count * sizeof(PROCESS_ENTRY);
    ExFreePool(buf);
    return STATUS_SUCCESS;
}

// ───────── Helper: walk target's PEB->Ldr to enumerate modules ─────────
// Runs while attached to the target via KeStackAttachProcess so PEB
// pointers are valid in our virtual address space. SEH-guarded because
// the loader list can be torn down or in flux.

typedef void (*MODULE_VISITOR)(PVOID ctx, PLDR_DATA_TABLE_ENTRY_X64 entry);

static NTSTATUS EnumerateModules(PEPROCESS target, MODULE_VISITOR visit, PVOID ctx) {
    KAPC_STATE apc;
    KeStackAttachProcess(target, &apc);

    NTSTATUS status = STATUS_SUCCESS;
    __try {
        PPEB_X64 peb = (PPEB_X64)PsGetProcessPeb(target);
        if (!peb || !peb->Ldr) {
            status = STATUS_NOT_FOUND;
        } else {
            PLIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
            PLIST_ENTRY cur  = head->Flink;
            int safety = 0;
            while (cur && cur != head && safety++ < 2048) {
                PLDR_DATA_TABLE_ENTRY_X64 entry =
                    CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY_X64, InLoadOrderLinks);
                visit(ctx, entry);
                cur = cur->Flink;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_UNHANDLED_EXCEPTION;
    }

    KeUnstackDetachProcess(&apc);
    return status;
}

typedef struct {
    PMODULE_ENTRY entries;
    ULONG         capacity;
    ULONG         count;
} ModListCtx;

static void CollectModule(PVOID c, PLDR_DATA_TABLE_ENTRY_X64 entry) {
    ModListCtx* ctx = (ModListCtx*)c;
    if (ctx->count >= ctx->capacity) return;
    PMODULE_ENTRY out = &ctx->entries[ctx->count];
    out->BaseAddress = (ULONG_PTR)entry->DllBase;
    out->Size        = entry->SizeOfImage;
    RtlZeroMemory(out->Name, sizeof(out->Name));
    if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
        USHORT bytes = entry->BaseDllName.Length;
        if (bytes > sizeof(out->Name) - sizeof(wchar_t))
            bytes = sizeof(out->Name) - sizeof(wchar_t);
        RtlCopyMemory(out->Name, entry->BaseDllName.Buffer, bytes);
    }
    ctx->count++;
}

// ───────── Handler: REQ_MODULE_LIST ─────────

static NTSTATUS HandleModuleList(PVOID sysbuf, ULONG inLen, ULONG outLen, PULONG_PTR information) {
    if (inLen < sizeof(REQ_MODULE_LIST_IN)) return STATUS_BUFFER_TOO_SMALL;
    if (outLen < sizeof(MODULE_LIST_OUT))    return STATUS_BUFFER_TOO_SMALL;
    REQ_MODULE_LIST_IN req = *(PREQ_MODULE_LIST_IN)sysbuf;

    PEPROCESS target = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.ProcessId, &target);
    if (!NT_SUCCESS(status)) return status;

    PMODULE_LIST_OUT hdr = (PMODULE_LIST_OUT)sysbuf;
    ModListCtx ctx;
    ctx.entries  = (PMODULE_ENTRY)((PUCHAR)sysbuf + sizeof(MODULE_LIST_OUT));
    ctx.capacity = (outLen - sizeof(MODULE_LIST_OUT)) / sizeof(MODULE_ENTRY);
    ctx.count    = 0;

    status = EnumerateModules(target, CollectModule, &ctx);
    ObDereferenceObject(target);

    if (NT_SUCCESS(status)) {
        hdr->Count = ctx.count;
        hdr->_pad  = 0;
        *information = sizeof(MODULE_LIST_OUT) + ctx.count * sizeof(MODULE_ENTRY);
    }
    return status;
}

// ───────── Handler: REQ_MODULE_BY_NAME ─────────

typedef struct {
    const wchar_t*     wanted;
    SIZE_T             wantedLen;
    MODULE_BY_NAME_OUT result;
    BOOLEAN            found;
} ModFindCtx;

static int WStrICmpN(const wchar_t* a, const wchar_t* b, SIZE_T n) {
    for (SIZE_T i = 0; i < n; i++) {
        wchar_t ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == 0) return 0;
    }
    return 0;
}

static void MatchModule(PVOID c, PLDR_DATA_TABLE_ENTRY_X64 entry) {
    ModFindCtx* ctx = (ModFindCtx*)c;
    if (ctx->found) return;
    if (!entry->BaseDllName.Buffer) return;
    SIZE_T entryChars = entry->BaseDllName.Length / sizeof(wchar_t);
    if (entryChars != ctx->wantedLen) return;
    if (WStrICmpN(entry->BaseDllName.Buffer, ctx->wanted, ctx->wantedLen) != 0) return;
    ctx->result.BaseAddress = (ULONG_PTR)entry->DllBase;
    ctx->result.Size        = entry->SizeOfImage;
    ctx->found = TRUE;
}

static NTSTATUS HandleModuleByName(PVOID sysbuf, ULONG inLen, ULONG outLen, PULONG_PTR information) {
    if (inLen < sizeof(REQ_MODULE_BY_NAME_IN)) return STATUS_BUFFER_TOO_SMALL;
    if (outLen < sizeof(MODULE_BY_NAME_OUT))   return STATUS_BUFFER_TOO_SMALL;
    REQ_MODULE_BY_NAME_IN req = *(PREQ_MODULE_BY_NAME_IN)sysbuf;

    // NUL-terminate defensively
    req.Name[(sizeof(req.Name)/sizeof(wchar_t)) - 1] = 0;
    SIZE_T wantedLen = 0;
    while (req.Name[wantedLen] && wantedLen < (sizeof(req.Name)/sizeof(wchar_t)) - 1) wantedLen++;
    if (wantedLen == 0) return STATUS_INVALID_PARAMETER;

    PEPROCESS target = NULL;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)req.ProcessId, &target);
    if (!NT_SUCCESS(status)) return status;

    ModFindCtx ctx = { 0 };
    ctx.wanted = req.Name;
    ctx.wantedLen = wantedLen;

    status = EnumerateModules(target, MatchModule, &ctx);
    ObDereferenceObject(target);
    if (!NT_SUCCESS(status)) return status;
    if (!ctx.found) return STATUS_NOT_FOUND;

    *(PMODULE_BY_NAME_OUT)sysbuf = ctx.result;
    *information = sizeof(MODULE_BY_NAME_OUT);
    return STATUS_SUCCESS;
}

// ───────── IOCTL dispatch ─────────

NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS  status      = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    const ULONG code   = stack->Parameters.DeviceIoControl.IoControlCode;
    const ULONG inLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    const ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID sysbuf       = Irp->AssociatedIrp.SystemBuffer;

    if (code == IOCTL_DISPATCH && sysbuf && inLen >= sizeof(REQUEST_HEADER)) {
        REQUEST_TYPE type = (REQUEST_TYPE)((PREQUEST_HEADER)sysbuf)->Type;
        switch (type) {
            case REQ_READ_MEMORY:    status = HandleReadMemory(sysbuf, inLen, outLen, &information); break;
            case REQ_PROCESS_LIST:   status = HandleProcessList(sysbuf, inLen, outLen, &information); break;
            case REQ_MODULE_LIST:    status = HandleModuleList(sysbuf, inLen, outLen, &information); break;
            case REQ_MODULE_BY_NAME: status = HandleModuleByName(sysbuf, inLen, outLen, &information); break;
            default: status = STATUS_INVALID_PARAMETER; break;
        }
    }

    Irp->IoStatus.Status      = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ───────── Driver lifecycle ─────────

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
    if (!NT_SUCCESS(status)) { IoDeleteDevice(g_DeviceObject); return status; }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
    DriverObject->DriverUnload                          = DriverUnload;

    return STATUS_SUCCESS;
}
