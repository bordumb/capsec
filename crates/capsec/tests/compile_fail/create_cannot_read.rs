/// capsec::fs::create() returns WriteFile, which does not implement Read.
use std::io::Read;

fn main() {
    let root = capsec::root();
    let cap = root.fs_write();
    let mut file = capsec::fs::create("/tmp/test.txt", &cap).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
}
