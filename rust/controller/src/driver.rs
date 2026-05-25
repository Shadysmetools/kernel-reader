//! RAII wrapper around the kernel driver handle, with typed request helpers.

#![cfg(windows)]

use std::{ffi::OsStr, iter, mem::size_of, os::windows::ffi::OsStrExt, ptr::null_mut};

use shared::*;
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
    #[error("module '{0}' not found in target process")]
    ModuleNotFound(String),
    #[error("output truncated (got {got} bytes, expected at least {wanted})")]
    Truncated { got: usize, wanted: usize },
}

pub struct Driver {
    handle: HANDLE,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid:  u64,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub base: u64,
    pub size: u64,
    pub name: String,
}

fn utf16_to_string(s: &[u16]) -> String {
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end])
}

fn string_to_utf16_buf(s: &str, buf: &mut [u16]) {
    for (i, c) in OsStr::new(s).encode_wide().chain(iter::once(0)).enumerate() {
        if i >= buf.len() { break; }
        buf[i] = c;
    }
}

impl Driver {
    pub fn open() -> Result<Self, DriverError> {
        let wide: Vec<u16> = OsStr::new(DEVICE_PATH)
            .encode_wide().chain(iter::once(0)).collect();
        let handle = unsafe {
            CreateFileW(wide.as_ptr(), GENERIC_READ | GENERIC_WRITE,
                        0, null_mut(), OPEN_EXISTING, 0, null_mut())
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(DriverError::Open(unsafe { GetLastError() }));
        }
        Ok(Self { handle })
    }

    fn ioctl(&self, input: &[u8], output: &mut [u8]) -> Result<usize, DriverError> {
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.handle, IOCTL_DISPATCH,
                input.as_ptr()  as *const _, input.len()  as u32,
                output.as_mut_ptr() as *mut _, output.len() as u32,
                &mut returned, null_mut(),
            )
        };
        if ok == 0 { Err(DriverError::Ioctl(unsafe { GetLastError() })) }
        else { Ok(returned as usize) }
    }

    pub fn list_processes(&self) -> Result<Vec<ProcessInfo>, DriverError> {
        let req = ReqProcessListIn { header: RequestHeader { type_: RequestType::ProcessList as u32 } };
        let in_bytes = unsafe { any_as_bytes(&req) };
        let mut out = vec![0u8; KR_MAX_OUTPUT_BYTES];
        let got = self.ioctl(in_bytes, &mut out)?;
        if got < size_of::<ProcessListOut>() {
            return Err(DriverError::Truncated { got, wanted: size_of::<ProcessListOut>() });
        }
        let hdr: ProcessListOut = unsafe {
            core::ptr::read_unaligned(out.as_ptr() as *const ProcessListOut)
        };
        let count = hdr.count as usize;
        let mut result = Vec::with_capacity(count);
        let stride = size_of::<ProcessEntry>();
        for i in 0..count {
            let off = size_of::<ProcessListOut>() + i * stride;
            if off + stride > got { break; }
            let entry = unsafe { core::ptr::read_unaligned(out.as_ptr().add(off) as *const ProcessEntry) };
            let pid = entry.process_id;
            result.push(ProcessInfo { pid, name: utf16_to_string(&entry.name) });
        }
        Ok(result)
    }

    pub fn list_modules(&self, pid: u64) -> Result<Vec<ModuleInfo>, DriverError> {
        let req = ReqModuleListIn {
            header:     RequestHeader { type_: RequestType::ModuleList as u32 },
            _pad:       0,
            process_id: pid,
        };
        let in_bytes = unsafe { any_as_bytes(&req) };
        let mut out = vec![0u8; KR_MAX_OUTPUT_BYTES];
        let got = self.ioctl(in_bytes, &mut out)?;
        if got < size_of::<ModuleListOut>() {
            return Err(DriverError::Truncated { got, wanted: size_of::<ModuleListOut>() });
        }
        let hdr: ModuleListOut = unsafe {
            core::ptr::read_unaligned(out.as_ptr() as *const ModuleListOut)
        };
        let count = hdr.count as usize;
        let stride = size_of::<ModuleEntry>();
        let mut result = Vec::with_capacity(count);
        for i in 0..count {
            let off = size_of::<ModuleListOut>() + i * stride;
            if off + stride > got { break; }
            let entry = unsafe { core::ptr::read_unaligned(out.as_ptr().add(off) as *const ModuleEntry) };
            let base = entry.base_address;
            let size = entry.size;
            result.push(ModuleInfo { base, size, name: utf16_to_string(&entry.name) });
        }
        Ok(result)
    }

    pub fn module_base(&self, pid: u64, name: &str) -> Result<ModuleByNameOut, DriverError> {
        let mut req = ReqModuleByNameIn {
            header:     RequestHeader { type_: RequestType::ModuleByName as u32 },
            _pad:       0,
            process_id: pid,
            name:       [0; NAME_LEN],
        };
        string_to_utf16_buf(name, &mut req.name);
        let in_bytes = unsafe { any_as_bytes(&req) };
        let mut out = [0u8; size_of::<ModuleByNameOut>()];
        let got = self.ioctl(in_bytes, &mut out)
            .map_err(|e| match e {
                DriverError::Ioctl(_) => DriverError::ModuleNotFound(name.to_string()),
                other => other,
            })?;
        if got < size_of::<ModuleByNameOut>() {
            return Err(DriverError::Truncated { got, wanted: size_of::<ModuleByNameOut>() });
        }
        Ok(unsafe { core::ptr::read_unaligned(out.as_ptr() as *const ModuleByNameOut) })
    }

    pub fn read(&self, pid: u64, va: u64, out: &mut [u8]) -> Result<usize, DriverError> {
        if out.is_empty() { return Ok(0); }
        let req = ReqReadMemoryIn {
            header:         RequestHeader { type_: RequestType::ReadMemory as u32 },
            _pad:           0,
            process_id:     pid,
            target_address: va,
            size:           out.len() as u64,
        };
        // Driver uses sysbuf for both in and out. Build a combined buffer
        // sized to hold whichever is larger, then copy results back.
        let in_size = size_of::<ReqReadMemoryIn>();
        let buf_size = in_size.max(out.len());
        let mut io = vec![0u8; buf_size];
        unsafe {
            core::ptr::copy_nonoverlapping(
                &req as *const _ as *const u8, io.as_mut_ptr(), in_size);
        }
        let mut returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.handle, IOCTL_DISPATCH,
                io.as_ptr()  as *const _, in_size as u32,
                io.as_mut_ptr() as *mut _, out.len() as u32,
                &mut returned, null_mut(),
            )
        };
        if ok == 0 { return Err(DriverError::Ioctl(unsafe { GetLastError() })); }
        let n = (returned as usize).min(out.len());
        out[..n].copy_from_slice(&io[..n]);
        Ok(n)
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.handle); }
        }
    }
}

unsafe fn any_as_bytes<T>(v: &T) -> &[u8] {
    core::slice::from_raw_parts(v as *const T as *const u8, size_of::<T>())
}
