# kernel-reader

A minimal, educational, **read-only** Windows kernel driver + user-mode client that reads virtual memory from a target process by PID. Inspired by [Valthrun](https://github.com/Valthrun/Valthrun)'s clean IOCTL architecture.

> ⚠️ For learning only. Run inside a VM with test-signing enabled. A bad pointer in kernel mode = BSOD.

## Architecture

A single `IOCTL_DISPATCH` carries a `RequestType` discriminator in the first 4 bytes of the input buffer. The kernel switches on it to pick a handler — same pattern Valthrun uses.

```
client → IOCTL_DISPATCH(input={type, ...args})
              ↓
       ┌──────┴───────┐
       │  dispatch    │
       └──────┬───────┘
              │
   ┌──────────┼──────────┬─────────────┐
   ▼          ▼          ▼             ▼
 read     process     module       module
 memory   list        list         by name
   │        │           │             │
   ▼        ▼           ▼             ▼
 MmCopy   ZwQuery   KeStackAttach + walk PEB->Ldr (SEH-guarded)
```

## Commands

```
# Inspection
client list                                  list all processes
client modules <pid>                         list modules in process
client base    <pid> <module-name>           module base + size
client regions <pid>                         list committed memory regions
client read    <pid> <hex-addr> <size>       hex-dump memory
client scan    <pid> <module-name> "<sig>"   pattern scan within module

# Trainer framework
client write   <pid> <hex-addr> "DE AD BE EF"   raw byte write
client wu32    <pid> <hex-addr> <value>         write 32-bit unsigned
client wf32    <pid> <hex-addr> <float>         write 32-bit float
client find    <pid> <type> <value>             scan all writable memory for a value
client freeze  <pid> <hex-addr> <type> <val>    re-write value in a loop (Ctrl-C to stop)
client ptr     <pid> <hex-base> <off1> [...]    resolve pointer chain [[base+o1]+o2]+...
```

Pattern format: hex bytes separated by spaces, `?`/`??` for wildcards.
Example: `"48 8B 05 ? ? ? ?"`.

Value types: `u32 i32 u64 i64 f32 f64`.

## Intended use

Single-player game trainer / reverse engineering on processes you own or where modding is explicitly permitted (Skyrim and other Bethesda titles, mod-friendly indie games, CTF binaries, your own programs). **Not for multiplayer cheating** — that's both a ToS violation and not what this tool exists for.

### Typical trainer workflow

```cmd
# 1. find your game
client list | findstr /i myGame

# 2. note its modules
client modules 1234

# 3. start scanning for a known value (e.g. health = 100)
client find 1234 u32 100

# 4. take damage in-game, scan again with the new value
client find 1234 u32 87

# 5. addresses that appear in both lists are candidates. Freeze one:
client freeze 1234 7FF712340000 u32 100
```

For values that move between game launches, use `ptr` to resolve a stable
pointer chain from a module base to the dynamic address.

- **`shared/ioctl_shared.h`** — IOCTL code (`CTL_CODE`) + `READ_MEMORY_REQUEST` struct used by both sides.
- **`driver/driver.c`** — WDM driver: device + symlink, IRP dispatch, `MmCopyVirtualMemory` for safe cross-process reads.
- **`client/client.cpp`** — opens `\\.\KernelReader`, sends the IOCTL, hex-dumps the result.

A parallel **Rust port** lives under [`rust/`](./rust) — same architecture (shared / driver / controller), structured like Valthrun's actual workspace.

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
