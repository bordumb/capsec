use std::fs;

pub fn read_file() -> Vec<u8> {
    fs::read("data.bin").unwrap()
}
