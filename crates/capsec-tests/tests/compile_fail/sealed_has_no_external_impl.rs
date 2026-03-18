/// The Has<P> trait is sealed — external crates cannot implement it.
/// This prevents forging capability proofs outside capsec-core.
use capsec::prelude::*;

struct FakeCap;

impl Has<FsRead> for FakeCap {
    fn cap_ref(&self) -> Cap<FsRead> {
        loop {}
    }
}

fn main() {}
