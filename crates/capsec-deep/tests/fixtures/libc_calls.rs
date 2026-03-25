unsafe extern "C" {
    fn open(path: *const u8, flags: i32) -> i32;
    fn socket(domain: i32, ty: i32, proto: i32) -> i32;
    fn getenv(name: *const u8) -> *const u8;
    fn fork() -> i32;
}

fn read_config() -> i32 {
    unsafe { open(b"/etc/config\0".as_ptr(), 0) }
}

fn open_socket() -> i32 {
    unsafe { socket(2, 1, 0) }
}

fn check_env() -> *const u8 {
    unsafe { getenv(b"HOME\0".as_ptr()) }
}

fn spawn_child() -> i32 {
    unsafe { fork() }
}

fn main() {
    let _ = read_config();
    let _ = open_socket();
    let _ = check_env();
    let _ = spawn_child();
}
