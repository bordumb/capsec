/// #[capsec::context] rejects duplicate permission types.
use capsec::prelude::*;

#[capsec::context]
struct Bad {
    a: FsRead,
    b: FsRead,
}

fn main() {}
