/// #[capsec::requires(fs::read, on = ctx)] fails when ctx type lacks Has<FsRead>.
use capsec::prelude::*;

struct NoHas;

#[capsec::requires(fs::read, on = ctx)]
fn process(ctx: &NoHas) {}

fn main() {}
