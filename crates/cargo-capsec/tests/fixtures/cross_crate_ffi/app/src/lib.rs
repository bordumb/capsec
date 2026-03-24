use ffi_dep;

pub fn init() -> i32 {
    ffi_dep::open_db()
}
