#![cfg_attr(not(feature = "std"), no_std)]

//! Wire format shared between the kernel driver and user-mode controller.
//! Byte-for-byte compatible with the C `shared/ioctl_shared.h`.

pub const METHOD_BUFFERED:    u32 = 0;
pub const FILE_ANY_ACCESS:    u32 = 0;
pub const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;

pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const FN_DISPATCH: u32 = 0x800;
pub const IOCTL_DISPATCH: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, FN_DISPATCH, METHOD_BUFFERED, FILE_ANY_ACCESS);

pub const DEVICE_NAME_NT:  &str = r"\Device\KernelReader";
pub const DEVICE_NAME_DOS: &str = r"\DosDevices\KernelReader";
pub const DEVICE_PATH:     &str = r"\\.\KernelReader";

pub const KR_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub const NAME_LEN: usize = 260;

// ── Request type discriminator (first 4 bytes of every input buffer) ────────
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RequestType {
    ReadMemory     = 1,
    ProcessList    = 2,
    ModuleList     = 3,
    ModuleByName   = 4,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct RequestHeader {
    pub type_: u32,
}

// ── REQ_READ_MEMORY ─────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ReqReadMemoryIn {
    pub header:         RequestHeader,
    pub _pad:           u32,
    pub process_id:     u64,
    pub target_address: u64,
    pub size:           u64,
}

// ── REQ_PROCESS_LIST ────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ReqProcessListIn {
    pub header: RequestHeader,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ProcessEntry {
    pub process_id: u64,
    pub name:       [u16; NAME_LEN],
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ProcessListOut {
    pub count: u32,
    pub _pad:  u32,
    // followed by `count` ProcessEntry records
}

// ── REQ_MODULE_LIST ─────────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ReqModuleListIn {
    pub header:     RequestHeader,
    pub _pad:       u32,
    pub process_id: u64,
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ModuleEntry {
    pub base_address: u64,
    pub size:         u64,
    pub name:         [u16; NAME_LEN],
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ModuleListOut {
    pub count: u32,
    pub _pad:  u32,
}

// ── REQ_MODULE_BY_NAME ──────────────────────────────────────────────────────
#[repr(C, packed)]
#[derive(Copy, Clone)]
pub struct ReqModuleByNameIn {
    pub header:     RequestHeader,
    pub _pad:       u32,
    pub process_id: u64,
    pub name:       [u16; NAME_LEN],
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ModuleByNameOut {
    pub base_address: u64,
    pub size:         u64,
}

// ── Layout assertions: must match C struct sizes byte-for-byte ──────────────
const _: () = assert!(core::mem::size_of::<RequestHeader>()    == 4);
const _: () = assert!(core::mem::size_of::<ReqReadMemoryIn>()  == 4 + 4 + 8 + 8 + 8);
const _: () = assert!(core::mem::size_of::<ProcessEntry>()     == 8 + NAME_LEN * 2);
const _: () = assert!(core::mem::size_of::<ProcessListOut>()   == 8);
const _: () = assert!(core::mem::size_of::<ModuleEntry>()      == 8 + 8 + NAME_LEN * 2);
const _: () = assert!(core::mem::size_of::<ModuleListOut>()    == 8);
const _: () = assert!(core::mem::size_of::<ReqModuleByNameIn>() == 4 + 4 + 8 + NAME_LEN * 2);
const _: () = assert!(core::mem::size_of::<ModuleByNameOut>()  == 16);

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ioctl_code_matches() {
        // Same as C: (0x22 << 16) | 0 | (0x800 << 2) | 0 = 0x0022_2000
        assert_eq!(IOCTL_DISPATCH, 0x0022_2000);
    }
}
