/// #[capsec::context] rejects tuple structs.
use capsec::prelude::*;

#[capsec::context]
struct Bad(FsRead);

fn main() {}
