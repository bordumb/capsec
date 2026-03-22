import Lake
open Lake DSL

package capsec where
  leanOptions := #[⟨`autoImplicit, false⟩]

lean_lib Capsec where
  srcDir := "."
