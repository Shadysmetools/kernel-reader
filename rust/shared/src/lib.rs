#![cfg_attr(not(feature = "std"), no_std)]

//! Wire format shared between the kernel driver and the user controller.
//! Compiles `no_std` for the kernel side; `std` feature unlocks `Display`
//! etc. for the user side.

pub const METHOD_BUFFERED:    u32 = 0;
pub const FILE_ANY_ACCESS:    u32 = 0;
pub const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;

/// Rust reimplementation of the C `CTL_CODE` macro. `const fn` so the
/// IOCTL value is a compile-time constant on both sides.
pub const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

pub const FN_READ_MEMORY: u32 = 0x800;

pub const IOCTL_READ_PROCESS_MEMORY: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, FN_READ_MEMORY, METHOD_BUFFERED, FILE_ANY_ACCESS);

pub const DEVICE_NAME_NT:  &str = r"\Device\KernelReaderRs";
pub const DEVICE_NAME_DOS: &str = r"\DosDevices\KernelReaderRs";
pub const DEVICE_PATH:     &str = r"\\.\KernelReaderRs";

#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct ReadMemoryRequest {
    pub process_id:     u64,
    pub target_address: u64,
    pub size:           u64,
}

const _: () = assert!(core::mem::size_of::<ReadMemoryRequest>() == 24);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioctl_value_matches_c_ctl_code() {
        // METHOD_BUFFERED=0, FILE_ANY_ACCESS=0, function=0x800, devtype=0x22
        // (0x22 << 16) | (0 << 14) | (0x800 << 2) | 0 = 0x00222000
        assert_eq!(IOCTL_READ_PROCESS_MEMORY, 0x0022_2000);
    }

    #[test]
    fn request_layout_is_24_bytes() {
        assert_eq!(core::mem::size_of::<ReadMemoryRequest>(), 24);
    }
}
