/// capsec_tokio::fs::open() returns AsyncReadFile, which does not implement AsyncWrite.
use capsec_tokio::file::AsyncReadFile;

fn assert_type(_: &AsyncReadFile) {}

fn main() {
    // AsyncReadFile does not implement AsyncWrite — this must not compile
    fn check<T: tokio::io::AsyncWrite>() {}
    check::<AsyncReadFile>();
}
