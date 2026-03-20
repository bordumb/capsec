/// The Permission trait requires a seal token — external crates cannot
/// implement it without the `#[capsec::permission]` derive macro.
use capsec::prelude::*;

struct MyPerm;
impl Permission for MyPerm {}

fn main() {}
