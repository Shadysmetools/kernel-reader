# kernel-reader-rs

Rust port of the C kernel-reader, structured like Valthrun's workspace.

```
rust/
├── shared/        # IOCTL codes + repr(C) ReadMemoryRequest (no_std)
├── driver/        # cdylib → driver.sys (requires WDK)
└── controller/    # user-mode binary (windows-sys)
```

## Build status

| Crate | Builds without WDK? | CI |
|---|---|---|
| `shared` | yes (`cargo test`) | ✅ |
| `controller` | yes (`cargo build --release`) | ✅ |
| `driver` | **only with WDK installed**, `--features wdk` | manual |

The driver crate is a structural scaffold. The IOCTL handler, IRP parsing,
and `MmCopyVirtualMemory` wrapper are complete; the `DriverEntry` + dispatch
glue lives behind the `wdk` feature and requires the WDK toolchain to link.

## Build

```powershell
cd rust

# shared + controller (works on any Rust install)
cargo test  -p shared
cargo build -p controller --release

# driver (requires WDK + msvc toolchain)
cargo build -p driver --release --features wdk
```

## Mapping to Valthrun

| Valthrun crate | Here |
|---|---|
| `kernel-interface` | `shared` |
| `kernel` | `driver` |
| `controller` | `controller` |

See the repo-root README for safety architecture (RAII `ProcessRef`,
METHOD_BUFFERED, `read_unaligned`, `panic = "abort"`).
