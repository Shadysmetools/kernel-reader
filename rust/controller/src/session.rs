//! Incremental-scan session file (Cheat-Engine-style first-scan/next-scan).
//!
//! Format: plain text, tab-separated:
//!   # kr-session v1 pid=<pid> type=<type>
//!   <hex-addr>\t<value-string>
//!   ...

#![cfg(windows)]

use anyhow::{anyhow, bail, Result};
use std::{fs, path::Path};
use crate::driver::Driver;
use crate::trainer::ValType;

pub struct Session {
    pub pid:     u64,
    pub ty:      ValType,
    pub entries: Vec<(u64, String)>, // (addr, last-seen value as string)
}

fn ty_str(t: ValType) -> &'static str {
    match t {
        ValType::U32 => "u32", ValType::I32 => "i32",
        ValType::U64 => "u64", ValType::I64 => "i64",
        ValType::F32 => "f32", ValType::F64 => "f64",
    }
}

impl Session {
    pub fn save(&self, path: &Path) -> Result<()> {
        let mut s = format!("# kr-session v1 pid={} type={}\n", self.pid, ty_str(self.ty));
        for (a, v) in &self.entries { s.push_str(&format!("{a:016x}\t{v}\n")); }
        fs::write(path, s)?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)?;
        let mut pid: Option<u64> = None;
        let mut ty:  Option<ValType> = None;
        let mut entries = Vec::new();
        for line in raw.lines() {
            if let Some(rest) = line.strip_prefix("# kr-session v1 ") {
                for kv in rest.split_whitespace() {
                    if let Some(v) = kv.strip_prefix("pid=") { pid = v.parse().ok(); }
                    else if let Some(v) = kv.strip_prefix("type=") { ty = ValType::parse(v).ok(); }
                }
                continue;
            }
            if line.starts_with('#') || line.is_empty() { continue; }
            let mut it = line.splitn(2, '\t');
            let a = it.next().ok_or_else(|| anyhow!("bad row"))?;
            let v = it.next().ok_or_else(|| anyhow!("bad row"))?;
            let addr = u64::from_str_radix(a.trim(), 16)?;
            entries.push((addr, v.trim().to_string()));
        }
        Ok(Self {
            pid: pid.ok_or_else(|| anyhow!("session missing pid"))?,
            ty:  ty.ok_or_else(|| anyhow!("session missing type"))?,
            entries,
        })
    }
}

// Re-read a single address into a small buffer of the right size.
fn read_typed(drv: &Driver, pid: u64, addr: u64, ty: ValType) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; ty.size()];
    drv.read(pid, addr, &mut buf)?;
    Ok(buf)
}

// Format raw bytes as a canonical value string for the type.
fn fmt(bytes: &[u8], ty: ValType) -> String {
    match ty {
        ValType::U32 => u32::from_le_bytes(bytes.try_into().unwrap()).to_string(),
        ValType::I32 => i32::from_le_bytes(bytes.try_into().unwrap()).to_string(),
        ValType::U64 => u64::from_le_bytes(bytes.try_into().unwrap()).to_string(),
        ValType::I64 => i64::from_le_bytes(bytes.try_into().unwrap()).to_string(),
        ValType::F32 => f32::from_le_bytes(bytes.try_into().unwrap()).to_string(),
        ValType::F64 => f64::from_le_bytes(bytes.try_into().unwrap()).to_string(),
    }
}

pub fn first(drv: &Driver, pid: u64, ty: ValType, value: &str, path: &Path, cap: usize) -> Result<usize> {
    let needle = ty.encode(value)?;
    let regions = drv.list_regions(pid)?;
    let chunk: usize = 256 * 1024;
    let mut buf = vec![0u8; chunk];
    let mut entries: Vec<(u64, String)> = Vec::new();

    for r in regions.iter().filter(|r| r.protect & 0xCC != 0) {
        let mut off: u64 = 0;
        while off < r.size {
            let want = ((r.size - off) as usize).min(chunk);
            buf.resize(want, 0);
            if drv.read(pid, r.base_address + off, &mut buf).is_err() {
                off += chunk as u64; continue;
            }
            for i in 0..buf.len().saturating_sub(needle.len() - 1) {
                if &buf[i..i + needle.len()] == needle.as_slice() {
                    entries.push((r.base_address + off + i as u64, value.to_string()));
                    if entries.len() >= cap { break; }
                }
            }
            if entries.len() >= cap { break; }
            off += buf.len() as u64;
        }
        if entries.len() >= cap { break; }
    }

    let count = entries.len();
    Session { pid, ty, entries }.save(path)?;
    Ok(count)
}

pub fn next(drv: &Driver, path: &Path, value: &str) -> Result<usize> {
    let mut s = Session::load(path)?;
    let needle = s.ty.encode(value)?;
    let mut kept = Vec::new();
    for (addr, _prev) in &s.entries {
        if let Ok(buf) = read_typed(drv, s.pid, *addr, s.ty) {
            if buf == needle { kept.push((*addr, value.to_string())); }
        }
    }
    s.entries = kept;
    let count = s.entries.len();
    s.save(path)?;
    Ok(count)
}

#[derive(Copy, Clone)]
pub enum CmpOp { Changed, Unchanged, Inc, Dec }
impl CmpOp {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "changed" => Self::Changed, "unchanged" => Self::Unchanged,
            "inc" => Self::Inc, "dec" => Self::Dec,
            _ => bail!("op must be changed|unchanged|inc|dec"),
        })
    }
}

pub fn cmp(drv: &Driver, path: &Path, op: CmpOp) -> Result<usize> {
    let mut s = Session::load(path)?;
    let mut kept = Vec::new();
    for (addr, prev) in &s.entries {
        let Ok(buf) = read_typed(drv, s.pid, *addr, s.ty) else { continue; };
        let now = fmt(&buf, s.ty);

        // numeric compare against the stored prev
        let ord = match s.ty {
            ValType::F32 | ValType::F64 => {
                let a: f64 = now.parse().unwrap_or(0.0);
                let b: f64 = prev.parse().unwrap_or(0.0);
                a.partial_cmp(&b)
            }
            _ => {
                let a: i128 = now.parse().unwrap_or(0);
                let b: i128 = prev.parse().unwrap_or(0);
                Some(a.cmp(&b))
            }
        };
        let keep = match (op, ord) {
            (CmpOp::Changed,   Some(o)) => o != std::cmp::Ordering::Equal,
            (CmpOp::Unchanged, Some(o)) => o == std::cmp::Ordering::Equal,
            (CmpOp::Inc,       Some(o)) => o == std::cmp::Ordering::Greater,
            (CmpOp::Dec,       Some(o)) => o == std::cmp::Ordering::Less,
            _ => false,
        };
        if keep { kept.push((*addr, now)); }
    }
    s.entries = kept;
    let count = s.entries.len();
    s.save(path)?;
    Ok(count)
}
