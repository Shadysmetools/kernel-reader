//! Read-only Windows kernel driver, Rust port of the C version.
//!
//! Status: scaffold. The code below is structurally correct and mirrors
//! the C driver line-for-line, but kernel-mode Rust requires a working
//! WDK toolchain to build (`cargo build --features wdk` on a machine
//! with the WDK installed). On a vanilla host this crate is `cargo check`
//! -clean only; producing a `.sys` is out of scope for hosted CI.
//!
//! All foreign-process memory access goes through `MmCopyVirtualMemory`,
//! which validates source VAs against the target process's page tables
//! and returns `STATUS_PARTIAL_COPY` on bad addresses rather than
//! bugchecking.

#![no_std]
#![allow(non_snake_case, non_camel_case_types, dead_code)]

use core::{mem::size_of, ptr::null_mut};

use shared::{ReadMemoryRequest, IOCTL_READ_PROCESS_MEMORY};

// ─── Kernel types we reference ──────────────────────────────────────────────
// We declare a tiny subset by hand so this crate doesn't drag in the full
// `wdk-sys` surface. Wider bindings can be swapped in later.

pub type NTSTATUS = i32;
pub type PVOID    = *mut core::ffi::c_void;
pub type PEPROCESS = PVOID;
pub type PDEVICE_OBJECT = PVOID;
pub type PDRIVER_OBJECT = PVOID;
pub type PIRP = PVOID;
pub type KPROCESSOR_MODE = i8;

pub const STATUS_SUCCESS:                 NTSTATUS = 0x0000_0000;
pub const STATUS_BUFFER_TOO_SMALL:        NTSTATUS = 0xC000_0023u32 as i32;
pub const STATUS_INVALID_PARAMETER:       NTSTATUS = 0xC000_000Du32 as i32;
pub const STATUS_INVALID_DEVICE_REQUEST:  NTSTATUS = 0xC000_0010u32 as i32;

const KERNEL_MODE: KPROCESSOR_MODE = 0;
const IRP_MJ_CREATE:         usize = 0x00;
const IRP_MJ_CLOSE:          usize = 0x02;
const IRP_MJ_DEVICE_CONTROL: usize = 0x0E;

extern "system" {
    fn IoCreateDevice(
        driver: PDRIVER_OBJECT, device_extension_size: u32,
        device_name: PVOID, device_type: u32, characteristics: u32,
        exclusive: u8, device_object: *mut PDEVICE_OBJECT,
    ) -> NTSTATUS;
    fn IoDeleteDevice(device: PDEVICE_OBJECT);
    fn IoCreateSymbolicLink(sym: PVOID, dev: PVOID) -> NTSTATUS;
    fn IoDeleteSymbolicLink(sym: PVOID) -> NTSTATUS;
    fn IoCompleteRequest(irp: PIRP, priority_boost: i8);

    fn PsLookupProcessByProcessId(pid: PVOID, p: *mut PEPROCESS) -> NTSTATUS;
    fn PsGetCurrentProcess() -> PEPROCESS;
    fn ObfDereferenceObject(o: PVOID);

    fn MmCopyVirtualMemory(
        source_process: PEPROCESS, source_address: PVOID,
        target_process: PEPROCESS, target_address: PVOID,
        buffer_size: usize, previous_mode: KPROCESSOR_MODE,
        return_size: *mut usize,
    ) -> NTSTATUS;
}

// ─── Panic handler ──────────────────────────────────────────────────────────
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop { core::hint::spin_loop(); }
}

// ─── Process reference RAII guard ───────────────────────────────────────────
struct ProcessRef(PEPROCESS);
impl Drop for ProcessRef {
    fn drop(&mut self) {
        unsafe { ObfDereferenceObject(self.0); }
    }
}

fn lookup_process(pid: u64) -> Result<ProcessRef, NTSTATUS> {
    let mut p: PEPROCESS = null_mut();
    let status = unsafe { PsLookupProcessByProcessId(pid as PVOID, &mut p) };
    if status < 0 { Err(status) } else { Ok(ProcessRef(p)) }
}

fn read_process_memory(pid: u64, src_va: u64, dst: &mut [u8]) -> Result<usize, NTSTATUS> {
    let target = lookup_process(pid)?;
    let mut copied: usize = 0;
    let status = unsafe {
        MmCopyVirtualMemory(
            target.0,
            src_va as PVOID,
            PsGetCurrentProcess(),
            dst.as_mut_ptr() as PVOID,
            dst.len(),
            KERNEL_MODE,
            &mut copied,
        )
    };
    if status < 0 { Err(status) } else { Ok(copied) }
}

// ─── IOCTL handler ──────────────────────────────────────────────────────────
//
// `sysbuf` is the I/O manager's kernel-side copy of the user buffer
// (METHOD_BUFFERED). We never touch a user pointer directly.
unsafe fn handle_read(sysbuf: *mut u8, in_len: usize, out_len: usize) -> (NTSTATUS, usize) {
    if sysbuf.is_null() || in_len < size_of::<ReadMemoryRequest>() {
        return (STATUS_BUFFER_TOO_SMALL, 0);
    }
    let req: ReadMemoryRequest = core::ptr::read_unaligned(sysbuf as *const _);
    if req.size == 0 || req.size as usize > out_len {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let dst = core::slice::from_raw_parts_mut(sysbuf, req.size as usize);
    match read_process_memory(req.process_id, req.target_address, dst) {
        Ok(n)  => (STATUS_SUCCESS, n),
        Err(s) => (s, 0),
    }
}

// NOTE: `DriverEntry`, dispatch routines, and device/symlink creation depend
// on `IO_STACK_LOCATION` / `DEVICE_OBJECT` / `IRP` struct shapes that are
// non-trivial to declare by hand. Production code should pull these from
// `wdk-sys` once the WDK is installed. The handler above is fully
// self-contained and is the security-critical core; wiring it to the
// dispatch table is a mechanical step covered by `wdk-sys` examples.

#[cfg(feature = "wdk")]
mod entry {
    //! Real DriverEntry / dispatch — gated behind the `wdk` feature so
    //! `cargo check` works without the WDK installed.
    //!
    //! Implement using `wdk-sys` bindings; left as a TODO so the public
    //! crate compiles cleanly on any host. See README.
}
