/// #[capsec::context] rejects non-permission field types.
use capsec::prelude::*;

#[capsec::context]
struct Bad {
    x: String,
}

fn main() {}
