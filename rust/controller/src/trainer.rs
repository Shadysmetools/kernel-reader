//! Trainer-framework helpers: value scanner, freeze loop, pointer chains.

#![cfg(windows)]

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crate::driver::Driver;
use shared::RegionEntry;

#[derive(Copy, Clone)]
pub enum ValType { U32, I32, U64, I64, F32, F64 }

impl ValType {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "u32" => Self::U32, "i32" => Self::I32,
            "u64" => Self::U64, "i64" => Self::I64,
            "f32" => Self::F32, "f64" => Self::F64,
            _ => return Err(anyhow!("unknown type '{s}' (use u32|i32|u64|i64|f32|f64)")),
        })
    }
    pub fn size(self) -> usize {
        match self { Self::U32|Self::I32|Self::F32 => 4, Self::U64|Self::I64|Self::F64 => 8 }
    }
    pub fn encode(self, s: &str) -> Result<Vec<u8>> {
        Ok(match self {
            Self::U32 => s.parse::<u32>()?.to_le_bytes().to_vec(),
            Self::I32 => s.parse::<i32>()?.to_le_bytes().to_vec(),
            Self::U64 => s.parse::<u64>()?.to_le_bytes().to_vec(),
            Self::I64 => s.parse::<i64>()?.to_le_bytes().to_vec(),
            Self::F32 => s.parse::<f32>()?.to_le_bytes().to_vec(),
            Self::F64 => s.parse::<f64>()?.to_le_bytes().to_vec(),
        })
    }
}

fn is_writable(r: &RegionEntry) -> bool {
    // PAGE_READWRITE 0x04, PAGE_WRITECOPY 0x08, PAGE_EXECUTE_READWRITE 0x40, PAGE_EXECUTE_WRITECOPY 0x80
    r.protect & 0xCC != 0
}

pub fn find(drv: &Driver, pid: u64, ty: ValType, value: &str, max: usize) -> Result<Vec<u64>> {
    let needle = ty.encode(value)?;
    let regions = drv.list_regions(pid)?;
    let mut hits = Vec::new();
    let chunk: usize = 256 * 1024;
    let mut buf = vec![0u8; chunk];

    for r in regions.iter().filter(|r| is_writable(r)) {
        let mut off: u64 = 0;
        while off < r.size {
            let want = ((r.size - off) as usize).min(chunk);
            buf.resize(want, 0);
            if drv.read(pid, r.base_address + off, &mut buf).is_err() {
                off += chunk as u64; continue;
            }
            for i in 0..buf.len().saturating_sub(needle.len() - 1) {
                if &buf[i..i + needle.len()] == needle.as_slice() {
                    hits.push(r.base_address + off + i as u64);
                    if hits.len() >= max { return Ok(hits); }
                }
            }
            off += buf.len() as u64;
        }
    }
    Ok(hits)
}

pub fn freeze(drv: &Driver, pid: u64, addr: u64, ty: ValType, value: &str) -> Result<()> {
    let payload = ty.encode(value)?;
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst))
            .map_err(|e| anyhow!("ctrl-c handler: {e}"))?;
    }
    println!("freezing pid {pid} @ 0x{addr:x} = {value} ({}). Ctrl-C to stop.",
        match ty { ValType::U32=>"u32",ValType::I32=>"i32",ValType::U64=>"u64",ValType::I64=>"i64",ValType::F32=>"f32",ValType::F64=>"f64" });
    let mut ticks: u64 = 0;
    while !stop.load(Ordering::SeqCst) {
        let _ = drv.write(pid, addr, &payload);
        ticks += 1;
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    println!("\nstopped after {ticks} writes");
    Ok(())
}

pub fn ptr_chain(drv: &Driver, pid: u64, base: u64, offsets: &[u64]) -> Result<u64> {
    let mut cur = base;
    for (i, &o) in offsets.iter().enumerate() {
        let addr = cur.wrapping_add(o);
        if i + 1 == offsets.len() {
            println!("[step {i}] final addr = 0x{addr:016x}");
            return Ok(addr);
        }
        let mut buf = [0u8; 8];
        drv.read(pid, addr, &mut buf).map_err(|e| anyhow!("read at step {i}: {e}"))?;
        let next = u64::from_le_bytes(buf);
        println!("[step {i}] *(0x{addr:016x}) = 0x{next:016x}");
        cur = next;
    }
    Ok(cur)
}
