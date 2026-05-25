//! User-space pattern scanner. Reads target module memory in chunks via
//! the driver, scans with overlap for matches spanning chunk boundaries.

#![cfg(windows)]

use anyhow::{anyhow, Result};
use crate::driver::Driver;

pub struct Pattern {
    pub bytes: Vec<u8>,
    pub mask:  Vec<bool>, // true = match this byte, false = wildcard
}

pub fn parse(s: &str) -> Result<Pattern> {
    let mut bytes = Vec::new();
    let mut mask  = Vec::new();
    for tok in s.split_whitespace() {
        if tok == "?" || tok == "??" {
            bytes.push(0); mask.push(false);
        } else if tok.len() == 2 {
            let b = u8::from_str_radix(tok, 16)
                .map_err(|_| anyhow!("invalid hex byte '{tok}'"))?;
            bytes.push(b); mask.push(true);
        } else {
            return Err(anyhow!("token '{tok}' is not '??' or a 2-char hex byte"));
        }
    }
    if bytes.is_empty() { return Err(anyhow!("empty pattern")); }
    Ok(Pattern { bytes, mask })
}

pub fn scan(drv: &Driver, pid: u64, base: u64, size: u64, sig: &Pattern) -> Result<Vec<u64>> {
    let chunk_size: usize = 64 * 1024;
    let overlap = sig.bytes.len() - 1;
    let mut window: Vec<u8> = Vec::new();
    let mut window_start_va: u64 = base;
    let mut hits: Vec<u64> = Vec::new();
    let mut off: u64 = 0;

    while off < size {
        let want = ((size - off) as usize).min(chunk_size);
        let mut chunk = vec![0u8; want];
        // Unreadable pages: skip silently and continue past this chunk.
        if drv.read(pid, base + off, &mut chunk).is_err() {
            window.clear();
            off += chunk_size as u64;
            window_start_va = base + off;
            continue;
        }
        let chunk_va = base + off;
        if window.is_empty() {
            window_start_va = chunk_va;
        }
        window.extend_from_slice(&chunk);

        for i in 0..window.len().saturating_sub(sig.bytes.len() - 1) {
            let mut matches = true;
            for j in 0..sig.bytes.len() {
                if sig.mask[j] && window[i + j] != sig.bytes[j] { matches = false; break; }
            }
            if matches { hits.push(window_start_va + i as u64); }
        }

        // Keep tail for cross-chunk matches
        if window.len() > overlap {
            let drop = window.len() - overlap;
            window.drain(..drop);
            window_start_va += drop as u64;
        }
        off += chunk.len() as u64;
    }
    Ok(hits)
}
