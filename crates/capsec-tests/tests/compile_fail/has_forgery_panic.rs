/// Forgery via panic!() divergence is now blocked by Has<P> being sealed.
/// Previously this compiled because panic!() diverges, satisfying any return type.
use capsec::prelude::*;

struct Forgery;

impl Has<FsRead> for Forgery {
    fn cap_ref(&self) -> Cap<FsRead> {
        panic!("This should not compile")
    }
}

fn main() {
    let forge = Forgery;
    fn needs_fs_read(_cap: &impl Has<FsRead>) {}
    needs_fs_read(&forge);
}
