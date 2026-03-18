/// Forgery via process::exit() divergence is now blocked by Has<P> being sealed.
use capsec::prelude::*;

struct ExitForgery;

impl Has<FsRead> for ExitForgery {
    fn cap_ref(&self) -> Cap<FsRead> {
        std::process::exit(0)
    }
}

fn main() {
    let forge = ExitForgery;
    fn needs_fs_read(_cap: &impl Has<FsRead>) {}
    needs_fs_read(&forge);
}
