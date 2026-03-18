/// capsec::fs::open() returns ReadFile, which does not implement Write.
use std::io::Write;

fn main() {
    let root = capsec::root();
    let cap = root.fs_read();
    let mut file = capsec::fs::open("/tmp/test.txt", &cap).unwrap();
    file.write_all(b"nope").unwrap();
}
