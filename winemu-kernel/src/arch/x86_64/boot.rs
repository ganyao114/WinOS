#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Placeholder entry while x86_64 backend is under construction.
    loop {
        core::hint::spin_loop();
    }
}
