/// capsec_tokio::fs::create() returns AsyncWriteFile, which does not implement AsyncRead.
use capsec_tokio::file::AsyncWriteFile;

fn assert_type(_: &AsyncWriteFile) {}

fn main() {
    // AsyncWriteFile does not implement AsyncRead — this must not compile
    fn check<T: tokio::io::AsyncRead>() {}
    check::<AsyncWriteFile>();
}
