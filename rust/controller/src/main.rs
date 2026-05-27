#[cfg(windows)]
mod driver;
#[cfg(windows)]
mod pattern;
#[cfg(windows)]
mod trainer;
#[cfg(windows)]
mod session;

#[cfg(not(windows))]
fn main() {
    eprintln!("controller is Windows-only.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use driver::Driver;
    use trainer::ValType;

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
            for m in drv.list_modules(args[2].parse()?)? {
                println!("{:016x}  {:>8}  {}", m.base, m.size, m.name);
            }
        }
        "base" if args.len() == 4 => {
            let r = drv.module_base(args[2].parse()?, &args[3])?;
            println!("base=0x{:016x} size={}", { r.base_address }, { r.size });
        }
        "regions" if args.len() == 3 => {
            for r in drv.list_regions(args[2].parse()?)? {
                println!("{:016x}  {:>12}  prot=0x{:08x}  type=0x{:08x}",
                    { r.base_address }, { r.size }, { r.protect }, { r.type_ });
            }
        }
        "read" if args.len() == 5 => {
            let pid: u64 = args[2].parse()?;
            let va = u64::from_str_radix(args[3].trim_start_matches("0x"), 16)?;
            let size: usize = args[4].parse()?;
            let mut buf = vec![0u8; size];
            let n = drv.read(pid, va, &mut buf)?;
            println!("read {n} bytes from pid {pid} @ 0x{va:x}:");
            for (i, c) in buf[..n].chunks(16).enumerate() {
                print!("  {:08x}: ", i * 16);
                for b in c { print!("{b:02x} "); }
                println!();
            }
        }
        "scan" if args.len() == 5 => {
            let pid: u64 = args[2].parse()?;
            let sig = pattern::parse(&args[4])?;
            let base = drv.module_base(pid, &args[3])?;
            for h in pattern::scan(&drv, pid, base.base_address, base.size, &sig)? {
                println!("0x{h:016x}");
            }
        }
        "write" if args.len() == 5 => {
            let pid: u64 = args[2].parse()?;
            let va = u64::from_str_radix(args[3].trim_start_matches("0x"), 16)?;
            let bytes: Vec<u8> = args[4].split_whitespace()
                .map(|t| u8::from_str_radix(t, 16))
                .collect::<Result<_, _>>()?;
            let n = drv.write(pid, va, &bytes)?;
            println!("wrote {n} bytes");
        }
        "wu32" if args.len() == 5 => {
            let pid: u64 = args[2].parse()?;
            let va = u64::from_str_radix(args[3].trim_start_matches("0x"), 16)?;
            drv.write(pid, va, &ValType::U32.encode(&args[4])?)?;
            println!("wrote u32 = {}", args[4]);
        }
        "wf32" if args.len() == 5 => {
            let pid: u64 = args[2].parse()?;
            let va = u64::from_str_radix(args[3].trim_start_matches("0x"), 16)?;
            drv.write(pid, va, &ValType::F32.encode(&args[4])?)?;
            println!("wrote f32 = {}", args[4]);
        }
        "find" if args.len() == 5 => {
            let pid: u64 = args[2].parse()?;
            let ty = ValType::parse(&args[3])?;
            for h in trainer::find(&drv, pid, ty, &args[4], 1000)? {
                println!("0x{h:016x}");
            }
        }
        "freeze" if args.len() == 6 => {
            let pid: u64 = args[2].parse()?;
            let va = u64::from_str_radix(args[3].trim_start_matches("0x"), 16)?;
            let ty = ValType::parse(&args[4])?;
            trainer::freeze(&drv, pid, va, ty, &args[5])?;
        }
        "find-first" if args.len() == 6 => {
            let pid: u64 = args[2].parse()?;
            let ty = ValType::parse(&args[3])?;
            let n = session::first(&drv, pid, ty, &args[4],
                                   std::path::Path::new(&args[5]), 100_000)?;
            println!("first scan: {n} matches → {}", args[5]);
        }
        "find-next" if args.len() == 5 => {
            // args: <pid> <session-file> <value> — pid kept for symmetry with C client
            let n = session::next(&drv, std::path::Path::new(&args[3]), &args[4])?;
            println!("narrowed: {n} remaining");
        }
        "find-cmp" if args.len() == 5 => {
            let op = session::CmpOp::parse(&args[4])?;
            let n = session::cmp(&drv, std::path::Path::new(&args[3]), op)?;
            println!("after '{}': {n} remaining", args[4]);
        }
        "find-show" if args.len() == 3 => {
            let s = session::Session::load(std::path::Path::new(&args[2]))?;
            println!("# pid={} entries={}", s.pid, s.entries.len());
            for (a, v) in &s.entries { println!("  {a:016x} = {v}"); }
        }
        "ptr" if args.len() >= 5 => {
            let pid: u64 = args[2].parse()?;
            let base = u64::from_str_radix(args[3].trim_start_matches("0x"), 16)?;
            let offs: Vec<u64> = args[4..].iter()
                .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16))
                .collect::<Result<_, _>>()?;
            trainer::ptr_chain(&drv, pid, base, &offs)?;
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
    eprintln!("  controller regions <pid>");
    eprintln!("  controller read    <pid> <hex-addr> <size>");
    eprintln!("  controller scan    <pid> <module-name> \"<hex sig with ?>\"");
    eprintln!("  controller write   <pid> <hex-addr> \"DE AD BE EF\"");
    eprintln!("  controller wu32    <pid> <hex-addr> <value>");
    eprintln!("  controller wf32    <pid> <hex-addr> <value>");
    eprintln!("  controller find    <pid> <u32|i32|u64|f32|f64> <value>");
    eprintln!("  controller freeze  <pid> <hex-addr> <type> <value>");
    eprintln!("  controller ptr     <pid> <hex-base> <hex-off1> [hex-off2 ...]");
    eprintln!("  controller find-first <pid> <type> <value> <session-file>");
    eprintln!("  controller find-next  <pid> <session-file> <value>");
    eprintln!("  controller find-cmp   <pid> <session-file> <changed|unchanged|inc|dec>");
    eprintln!("  controller find-show  <session-file>");
}
