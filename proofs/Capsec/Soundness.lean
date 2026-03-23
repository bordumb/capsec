import Capsec.Perm
import Capsec.Has

/-!
# Soundness theorems for capsec's permission lattice

Four key properties, machine-verified by Lean's kernel:

1. **No escalation** — non-subsuming permissions cannot grant each other
2. **No cross-category leakage** — Fs permissions cannot satisfy Net requirements
3. **Ambient completeness** — `Ambient` subsumes every permission
4. **Subsumption correctness** — `Subsumes a b` implies `Has [a] b`
-/

-- ============================================================================
-- 1. No escalation
-- ============================================================================

/-- FsRead does not subsume FsWrite. -/
theorem no_escalation_fsRead_fsWrite : ¬ Subsumes Perm.fsRead Perm.fsWrite := by
  intro h; cases h

/-- FsWrite does not subsume FsRead. -/
theorem no_escalation_fsWrite_fsRead : ¬ Subsumes Perm.fsWrite Perm.fsRead := by
  intro h; cases h

/-- NetConnect does not subsume NetBind. -/
theorem no_escalation_netConnect_netBind : ¬ Subsumes Perm.netConnect Perm.netBind := by
  intro h; cases h

/-- NetBind does not subsume NetConnect. -/
theorem no_escalation_netBind_netConnect : ¬ Subsumes Perm.netBind Perm.netConnect := by
  intro h; cases h

/-- FsRead does not subsume FsAll (children don't subsume parents). -/
theorem no_escalation_fsRead_fsAll : ¬ Subsumes Perm.fsRead Perm.fsAll := by
  intro h; cases h

/-- NetConnect does not subsume NetAll. -/
theorem no_escalation_netConnect_netAll : ¬ Subsumes Perm.netConnect Perm.netAll := by
  intro h; cases h

/-- General: if Subsumes a b is decidably false, no proof exists. -/
theorem no_escalation_general {a b : Perm} (h : ¬ Subsumes a b) :
    ¬ Subsumes a b := h

-- ============================================================================
-- 2. No cross-category leakage
-- ============================================================================

/-- FsAll does not grant NetConnect. -/
theorem no_cross_leak_fs_net : ¬ Has [Perm.fsAll] Perm.netConnect := by
  intro h
  cases h with
  | direct => contradiction
  | subsumes hs => cases hs
  | ambient => contradiction
  | tuple hm => simp [List.mem_cons, List.mem_nil_iff] at hm

/-- NetAll does not grant FsRead. -/
theorem no_cross_leak_net_fs : ¬ Has [Perm.netAll] Perm.fsRead := by
  intro h
  cases h with
  | direct => contradiction
  | subsumes hs => cases hs
  | ambient => contradiction
  | tuple hm => simp [List.mem_cons, List.mem_nil_iff] at hm

/-- FsAll does not grant Spawn. -/
theorem no_cross_leak_fs_spawn : ¬ Has [Perm.fsAll] Perm.spawn := by
  intro h
  cases h with
  | direct => contradiction
  | subsumes hs => cases hs
  | ambient => contradiction
  | tuple hm => simp [List.mem_cons, List.mem_nil_iff] at hm

/-- Spawn does not grant EnvRead. -/
theorem no_cross_leak_spawn_env : ¬ Has [Perm.spawn] Perm.envRead := by
  intro h
  cases h with
  | direct => contradiction
  | subsumes hs => cases hs
  | ambient => contradiction
  | tuple hm => simp [List.mem_cons, List.mem_nil_iff] at hm

-- ============================================================================
-- 3. Ambient completeness
-- ============================================================================

/-- Ambient grants every permission. -/
theorem ambient_complete (p : Perm) : Has [Perm.ambient] p :=
  Has.ambient p

-- ============================================================================
-- 4. Subsumption correctness
-- ============================================================================

/-- If a subsumes b, then holding [a] grants b. -/
theorem subsumption_sound {a b : Perm} (h : Subsumes a b) : Has [a] b :=
  Has.subsumes h

-- ============================================================================
-- Bonus: Tuple composition
-- ============================================================================

/-- A tuple grants any permission it contains. -/
theorem tuple_composition {ps : List Perm} {p : Perm} (h : p ∈ ps) : Has ps p :=
  Has.tuple h

/-- The first element of a pair is granted. -/
theorem tuple_has_first (a b : Perm) : Has [a, b] a :=
  Has.tuple (List.mem_cons_self a [b])

/-- The second element of a pair is granted. -/
theorem tuple_has_second (a b : Perm) : Has [a, b] b :=
  Has.tuple (List.mem_cons_of_mem a (List.mem_cons_self b []))

-- ============================================================================
-- 5. CapProvides — non-transitive authority
-- ============================================================================

/-- Any Has judgment lifts to CapProvides (blanket impl). -/
theorem has_implies_cap_provides {ps : List Perm} {p : Perm} (h : Has ps p) :
    CapProvides ps p :=
  CapProvides.from_has h

/-- A scoped capability provides its own permission. -/
theorem cap_provides_scope_self (p : Perm) : CapProvides [p] p :=
  CapProvides.from_scope [p] p (List.mem_cons_self p [])

/-- CapProvides through scoped FsRead does not grant FsWrite. -/
theorem cap_provides_no_escalation_fs :
    ¬ CapProvides [Perm.fsRead] Perm.fsWrite := by
  intro h
  cases h with
  | from_has hhas =>
    cases hhas with
    | direct => contradiction
    | subsumes hs => cases hs
    | ambient => contradiction
    | tuple hm => simp [List.mem_cons, List.mem_nil_iff] at hm
  | from_scope _ _ hm =>
    simp [List.mem_cons, List.mem_nil_iff] at hm

/-- CapProvides through FsAll does not grant NetConnect. -/
theorem cap_provides_no_cross_leak :
    ¬ CapProvides [Perm.fsAll] Perm.netConnect := by
  intro h
  cases h with
  | from_has hhas =>
    exact absurd hhas no_cross_leak_fs_net
  | from_scope _ _ hm =>
    simp [List.mem_cons, List.mem_nil_iff] at hm
