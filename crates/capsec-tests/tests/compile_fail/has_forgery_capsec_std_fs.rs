/// End-to-end capsec-std forgery is now blocked by Has<P> being sealed.
/// Previously, a forged Has<FsRead> impl could read files via capsec_std::fs::read.
use capsec::prelude::*;

struct Forgery;

impl Has<FsRead> for Forgery {
    fn cap_ref(&self) -> Cap<FsRead> {
        panic!("never called — capsec-std used to ignore the cap parameter")
    }
}

fn main() {
    let forge = Forgery;
    let _ = capsec::fs::read("/dev/null", &forge);
}
