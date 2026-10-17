//! Opacity FFI from the per-site state machines.
//!
//! These three symbols come from the tiny staticlib built by `build.rs`.
//! `X` and `Y` are atomic zero values seeded on first call; the opaque FFI
//! boundary stops LLVM from folding the predicates that compare against them.

unsafe extern "C" {
    /// Seed the opacity atomics. Called once at the top of each state machine
    /// before the first use of [`__xorany_x`] / [`__xorany_y`].
    pub fn __xorany_seed();

    /// Returns 0 at runtime, opaque to LLVM. Used as the `stack_x` predicate
    /// seed in the generated state machines.
    pub fn __xorany_x() -> usize;

    /// Returns 0 at runtime, opaque to LLVM. Used as the `stack_y` predicate
    /// seed in the generated state machines.
    pub fn __xorany_y() -> usize;
}
