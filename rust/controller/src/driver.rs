//! RAII wrapper around the kernel driver handle.

#![cfg(windows)]

use std::{ffi::OsStr, iter, os::windows::ffi::OsStrExt, ptr::null_mut};

use shared::{ReadMemoryRequest, DEVICE_PATH, IOCTL_READ_PROCESS_MEMORY};
use thiserror::Error;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{CreateFileW, OPEN_EXISTING},
    System::IO::DeviceIoControl,
};

const GENERIC_READ:  u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;

#[derive(Debug, Error)]
pub enum DriverError {
    #[error("CreateFile failed (Win32 {0}); is the driver loaded and running as admin?")]
    Open(u32),
    #[error("DeviceIoControl failed (Win32 {0})")]
    Ioctl(u32),
    #[error("output buffer must be non-empty")]
    EmptyBuffer,
}

pub struct Driver {
    handle: HANDLE,
}

impl Driver {
    pub fn open() -> Result<Self, DriverError> {
        let wide: Vec<u16> = OsStr::new(DEVICE_PATH)
            .encode_wide()
            .chain(iter::once(0))
            .collect();

        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null_mut(),
                OPEN_EXISTING,
                0,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(DriverError::Open(unsafe { GetLastError() }));
        }
        Ok(Self { handle })
    }

    pub fn read(&self, pid: u64, va: u64, out: &mut [u8]) -> Result<usize, DriverError> {
        if out.is_empty() {
            return Err(DriverError::EmptyBuffer);
        }
        let req = ReadMemoryRequest {
            process_id:     pid,
            target_address: va,
            size:           out.len() as u64,
        };
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_READ_PROCESS_MEMORY,
                &req as *const _ as *const _,
                std::mem::size_of_val(&req) as u32,
                out.as_mut_ptr() as *mut _,
                out.len() as u32,
                &mut returned,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(DriverError::Ioctl(unsafe { GetLastError() }));
        }
        Ok(returned as usize)
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.handle); }
        }
    }
}
