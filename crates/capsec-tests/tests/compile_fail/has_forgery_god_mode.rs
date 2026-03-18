/// God-mode forgery (claiming ALL permissions) is now blocked by Has<P> being sealed.
use capsec::prelude::*;

struct GodForgery;

impl Has<FsRead> for GodForgery {
    fn cap_ref(&self) -> Cap<FsRead> { panic!() }
}

fn main() {}
