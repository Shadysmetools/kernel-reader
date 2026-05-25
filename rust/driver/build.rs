fn main() {
    // When the `wdk` feature is on, hand control to wdk-build so it sets
    // up the kernel linker flags, ntoskrnl.lib, /SUBSYSTEM:NATIVE, etc.
    #[cfg(feature = "wdk")]
    {
        if let Err(e) = wdk_build::Config::from_env_auto().and_then(|c| {
            c.configure_binary_build();
            Ok(())
        }) {
            eprintln!("wdk-build failed: {e}. Install the WDK and set its env vars.");
            std::process::exit(1);
        }
    }

    // Without the `wdk` feature this build script is a no-op so the crate
    // can be `cargo check`'d in CI on machines without WDK installed.
}
