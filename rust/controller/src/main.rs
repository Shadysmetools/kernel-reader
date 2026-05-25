#[cfg(windows)]
mod driver;

#[cfg(not(windows))]
fn main() {
    eprintln!("controller is Windows-only.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use driver::Driver;

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: controller <pid> <hex-va> <size-bytes>");
        eprintln!("example: controller 1234 0x7ff712340000 64");
        std::process::exit(2);
    }

    let pid: u64  = args[1].parse()?;
    let va:  u64  = u64::from_str_radix(args[2].trim_start_matches("0x"), 16)?;
    let size: usize = args[3].parse()?;

    let drv = Driver::open()?;
    let mut buf = vec![0u8; size];
    let n = drv.read(pid, va, &mut buf)?;

    println!("read {n} bytes from pid {pid} @ 0x{va:x}:");
    for (i, chunk) in buf[..n].chunks(16).enumerate() {
        print!("  {:08x}: ", i * 16);
        for b in chunk { print!("{b:02x} "); }
        println!();
    }
    Ok(())
}
