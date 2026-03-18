/// #[capsec::requires] with concrete types requires `on = param`.
use capsec::prelude::*;

struct AppCtx;

#[capsec::requires(fs::read)]
fn process(ctx: &AppCtx) {}

fn main() {}
