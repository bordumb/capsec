import Capsec.Perm

/-!
# Has judgment

Models the `Has<P>` trait from `capsec-core/src/has.rs`.

`Has ps p` means "a capability token holding permissions `ps` satisfies the
requirement for permission `p`."

Four constructors mirror the four impl families in capsec-core:
1. `direct` — `impl<P> Has<P> for Cap<P>`
2. `subsumes` — `impl<Sub> Has<Sub> for Cap<Super> where Super: Subsumes<Sub>`
3. `ambient` — `impl_ambient!` enumerated impls for `Cap<Ambient>`
4. `tuple` — `impl_tuple_has_first!` / `impl_tuple_has_second!` impls
-/

inductive Has : List Perm → Perm → Prop where
  | direct (p : Perm) : Has [p] p
  | subsumes {a b : Perm} : Subsumes a b → Has [a] b
  | ambient (p : Perm) : Has [Perm.ambient] p
  | tuple {ps : List Perm} {p : Perm} : p ∈ ps → Has ps p
