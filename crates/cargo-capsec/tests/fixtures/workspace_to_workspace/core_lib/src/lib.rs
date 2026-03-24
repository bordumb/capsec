use std::fs;

pub fn read_config() -> Vec<u8> {
    fs::read("config.toml").unwrap()
}
