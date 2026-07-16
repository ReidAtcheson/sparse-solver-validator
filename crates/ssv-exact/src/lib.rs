//! Exact Q63.64 / Field192 sparse-solve certificate backend.
//!
//! The backend composes the proof-system-independent fixed relation, a shared
//! generator-owned public-MLE capability, three exact sumchecks, and the fixed
//! WHIR PCS. Protocol composition lives here; digit arithmetic is reusable and
//! commitment internals remain isolated in `ssv-whir-pcs`.
//!
//! The mathematical schedule and digit layout are derived from
//! `sparse-solution-stark`'s `whir_v4` implementation at research revision
//! `be8b67b74da54d162df2e6e0a9d813779959bb60`. This crate deliberately uses
//! the new repository's typed statement and component boundaries rather than
//! copying that research application's architecture.

#![forbid(unsafe_code)]

mod digits;
mod protocol;

pub use digits::{
    COMMITTED_DIGIT_COLUMNS, DigitError, RESIDUAL_NIBBLE_COLUMNS, RESIDUAL_TABLE_COLUMNS,
    ResidualDigitTables, SELECTOR_SLOTS, SELECTOR_VARIABLES, WITNESS_NIBBLE_COLUMNS,
    WITNESS_TABLE_COLUMNS, WitnessDigitTables, evaluate_mle, field_from_biguint_checked,
    field_from_i128, field_modulus, pack_digit_tables, packed_point, reconstruct_residual,
    reconstruct_witness,
};
pub use protocol::{
    AlgebraicProverWork, AlgebraicVerifierWork, ExactBackend, ExactError, ExactProverReport,
    ExactVerifierReport, SquaredResidualReport,
};
