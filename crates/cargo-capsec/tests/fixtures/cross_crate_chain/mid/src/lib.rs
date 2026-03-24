use leaf;

pub fn fetch() -> Vec<u8> {
    let _stream = leaf::connect().unwrap();
    vec![1, 2, 3]
}
