extern "C" {
    fn sqlite3_open(filename: *const u8, db: *mut *mut u8) -> i32;
}

pub fn open_db() -> i32 {
    unsafe { sqlite3_open(std::ptr::null(), std::ptr::null_mut()) }
}
