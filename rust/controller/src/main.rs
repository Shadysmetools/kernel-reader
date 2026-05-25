#[cfg(windows)]
mod driver;
#[cfg(windows)]
mod pattern;

#[cfg(not(windows))]
fn main() {
    eprintln!("controller is Windows-only.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use driver::Driver;

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { usage(); std::process::exit(2); }

    let drv = Driver::open()?;
    match args[1].as_str() {
        "list" if args.len() == 2 => {
            for p in drv.list_processes()? {
                println!("{:>6}  {}", p.pid, p.name);
            }
        }
        "modules" if args.len() == 3 => {
            let pid: u64 = args[2].parse()?;
            for m in drv.list_modules(pid)? {
                println!("{:016x}  {:>8}  {}", m.base, m.size, m.name);
            }
        }
        "base" if args.len() == 4 => {
            let pid: u64 = args[2].parse()?;
            let r = drv.module_base(pid, &args[3])?;
            println!("base=0x{:016x} size={}", { r.base_address }, { r.size });
        }
        "read" if args.len() == 5 => {
            let pid: u64 = args[2].parse()?;
            let va: u64  = u64::from_str_radix(args[3].trim_start_matches("0x"), 16)?;
            let size: usize = args[4].parse()?;
            let mut buf = vec![0u8; size];
            let n = drv.read(pid, va, &mut buf)?;
            println!("read {n} bytes from pid {pid} @ 0x{va:x}:");
            for (i, chunk) in buf[..n].chunks(16).enumerate() {
                print!("  {:08x}: ", i * 16);
                for b in chunk { print!("{b:02x} "); }
                println!();
            }
        }
        "scan" if args.len() == 5 => {
            let pid: u64 = args[2].parse()?;
            let module = &args[3];
            let sig = pattern::parse(&args[4])?;
            let base = drv.module_base(pid, module)?;
            let hits = pattern::scan(&drv, pid, base.base_address, base.size, &sig)?;
            println!("{} hits for '{}' in {} (pid {}):", hits.len(), args[4], module, pid);
            for h in hits { println!("  0x{h:016x}"); }
        }
        _ => { usage(); std::process::exit(2); }
    }
    Ok(())
}

#[cfg(windows)]
fn usage() {
    eprintln!("usage:");
    eprintln!("  controller list");
    eprintln!("  controller modules <pid>");
    eprintln!("  controller base    <pid> <module-name>");
    eprintln!("  controller read    <pid> <hex-addr> <size>");
    eprintln!("  controller scan    <pid> <module-name> \"<hex sig with ?>\"");
}
