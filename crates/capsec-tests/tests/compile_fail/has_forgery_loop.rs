/// Forgery via loop {} divergence is now blocked by Has<P> being sealed.
use capsec::prelude::*;

struct LoopForgery;

impl Has<FsRead> for LoopForgery {
    fn cap_ref(&self) -> Cap<FsRead> {
        loop {}
    }
}

fn main() {
    let forge = LoopForgery;
    fn needs_fs_read(_cap: &impl Has<FsRead>) {}
    needs_fs_read(&forge);
}
