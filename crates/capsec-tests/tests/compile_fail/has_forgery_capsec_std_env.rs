/// End-to-end capsec-std env forgery is now blocked by Has<P> being sealed.
use capsec::prelude::*;

struct EnvForgery;

impl Has<EnvRead> for EnvForgery {
    fn cap_ref(&self) -> Cap<EnvRead> { panic!() }
}

fn main() {
    let forge = EnvForgery;
    let _ = capsec::env::var("PATH", &forge);
}
