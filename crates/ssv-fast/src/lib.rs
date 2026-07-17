//! Experimental binary64 sparse-solve validation and reusable metric-proof
//! components.
//!
//! [`FastBackend`] composes the complete three-sumcheck, unit-circle protocol.
//! Its verifier knows no matrix-family variants: public endpoints come through
//! the registered succinct-evaluator capability. The numerical contract,
//! sumcheck, transcript, code, Merkle, and score modules remain independent
//! components so future validators can reuse them without cloning the sparse-
//! solve protocol.
//!
//! The algorithms and frozen domains were audited in the research repository
//! `sparse-solution-stark` at revision
//! `be8b67b74da54d162df2e6e0a9d813779959bb60`. They are factored here so future
//! validators reuse one implementation instead of reimplementing numerical
//! contracts, sumcheck, code folding, Merkle authentication, and scoring. This
//! backend remains a provisional metric certificate, not a replacement for the
//! exact field proof or a claim of a completed global numerical soundness
//! theorem.

#![forbid(unsafe_code)]

pub mod backend;
pub mod float_contract;
pub mod merkle;
pub mod score;
pub mod sumcheck;
pub mod transcript;
pub mod unit_circle;

pub use backend::{
    FastBackend, FastCommitmentReport, FastError, FastPrecommitment, FastPreflight,
    FastProverContext, FastProverReport, FastSourceDigests, FastVerifierReport, FastVerifierWork,
};

pub use float_contract::{
    FloatContractError, canonical_bits, canonicalize_source, decode_canonical_bits,
    i128_vector_digest, vector_digest,
};
pub use merkle::{
    ComplexMultiProof, MerkleError, MerkleRoot, complex_multiproof_frontier_len,
    streaming_complex_root, streaming_complex_root_and_multiproof,
    streaming_complex_root_and_multiproof_iter, streaming_complex_root_iter,
    verify_complex_multiproof,
};
pub use score::{
    DefectAccumulator, DefectSummary, FastValidationScore, POLICY_3, Policy3,
    PolicyTranscriptParameters, RelativeErrorObservation, conditional_miss_probabilities,
};
pub use sumcheck::{
    DefectObservation, ProductEndpoint, ProductEndpointClaim, ProductSumcheckProof,
    ProductSumcheckVerification, QuadraticBernstein, SumcheckError, evaluate_mle, product_sum,
    prove_product, prove_product_owned, verify_product, verify_product_endpoint,
};
pub use transcript::{Transcript, TranscriptError};
pub use unit_circle::{
    ComplexValue, UnitCircleCodeword, UnitCircleError, bit_reversed_source_coefficients,
    fold_pair_at_index,
};
