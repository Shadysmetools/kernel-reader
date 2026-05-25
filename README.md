# kernel-reader

A minimal, educational, **read-only** Windows kernel driver + user-mode client that reads virtual memory from a target process by PID. Inspired by [Valthrun](https://github.com/Valthrun/Valthrun)'s clean IOCTL architecture.

> ⚠️ For learning only. Run inside a VM with test-signing enabled. A bad pointer in kernel mode = BSOD.

## Architecture

```
+----------------------+        IOCTL         +----------------------+
|  client.exe (user)   | -------------------> |  driver.sys (kernel) |
|  CreateFile + IOCTL  | <------------------- |  MmCopyVirtualMemory |
+----------------------+    bytes copied      +----------------------+
```

- **`shared/ioctl_shared.h`** — IOCTL code (`CTL_CODE`) + `READ_MEMORY_REQUEST` struct used by both sides.
- **`driver/driver.c`** — WDM driver: device + symlink, IRP dispatch, `MmCopyVirtualMemory` for safe cross-process reads.
- **`client/client.cpp`** — opens `\\.\KernelReader`, sends the IOCTL, hex-dumps the result.

## Build

### Driver (Visual Studio + WDK)
1. Install Visual Studio 2022 with the **Desktop C++** workload and the **WDK** (Windows Driver Kit) + matching SDK.
2. Open `kernel-reader.sln` → set config to `Release | x64` → Build.
3. Output: `driver/x64/Release/driver.sys`.

### Client
From a **x64 Native Tools Command Prompt for VS**:
```cmd
build-client.bat
```
Or manually:
```cmd
cl /EHsc client\client.cpp /link /OUT:client.exe
```

### CI
Every push builds `client.exe` on a hosted Windows runner; artifact downloadable from the [Actions tab](../../actions).

## Load & Run (test VM)
```cmd
bcdedit /set testsigning on
shutdown /r /t 0

sc create KernelReader type= kernel binPath= C:\path\to\driver.sys
sc start KernelReader

client.exe <pid> <hex-address> <size>
```

Unload:
```cmd
sc stop KernelReader && sc delete KernelReader
```

## Safety notes
- `METHOD_BUFFERED` — I/O manager copies user buffers; we never deref user pointers directly.
- `PsLookupProcessByProcessId` is always paired with `ObDereferenceObject`.
- `MmCopyVirtualMemory` returns `STATUS_PARTIAL_COPY` on bad source addresses instead of bugchecking.
- Input/output lengths are validated before use.

## Relation to Valthrun
| Concept | This repo | Valthrun |
|---|---|---|
| Shared IOCTL types | `shared/ioctl_shared.h` | `valthrun-driver-shared` crate |
| Driver entry | `DriverEntry` in `driver.c` | `driver_entry` in `valthrun-driver/src/lib.rs` |
| Cross-process read | `MmCopyVirtualMemory` (C) | `MmCopyVirtualMemory` via Rust FFI |
| User bridge | `CreateFile` + `DeviceIoControl` | `valthrun-driver-interface` (windows-sys) |

## License
MIT
