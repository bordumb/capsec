/// Attempt to implement Permission directly without the derive macro.
///
/// The `Permission` trait requires a `__CapsecSeal` associated type that
/// satisfies `__private::SealToken`. Without the `#[capsec::permission]`
/// macro, you must provide this type — but leaving it out means the impl
/// is incomplete and the compiler rejects it.

use capsec::prelude::*;

struct EvilPerm;
impl Permission for EvilPerm {}

fn main() {}
