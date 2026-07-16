//! Deterministic, random-access sparse linear-system generation.
//!
//! The JSON documents in this crate are presentation formats. Problem identity
//! comes from the validated, typed canonical encoding exposed through
//! [`ProblemTemplate::digest`] and [`FinalizedProblem::digest`]. A finalized
//! problem compiles to flat periodic tables; neither the matrix nor the right
//! hand side is materialized at problem dimension.

#![forbid(unsafe_code)]

mod digest;
mod evaluator;
mod generator;
mod randomness;
mod spec;

pub use digest::{ProblemDigest, ProblemTemplateDigest};
pub use evaluator::{
    BooleanCoordinateOrder, ExactArithmeticBounds, ExactNoWrapDiagnostics, F64MleEvaluation,
    F64RoundoffDiagnostics, MleDomain, MleEvaluation, MleEvaluationError, MleInterpreter,
    PublicEvaluationMetadata, PublicEvaluationPlan, PublicEvaluationWork, SuccinctPublicEvaluator,
};
pub use generator::{
    GeneratedProblem, GeneratorCertificate, MatrixEntry, MatrixRow, MatrixRows, SparseMatrix,
};
pub use randomness::{
    CanonicalContextBytes, ChallengeContext, FinalizedRandomness, InstanceSeed, SeedDerivation,
    TemplateRandomness, derive_instance_seed, derive_subseed,
};
pub use spec::{
    BoundaryRule, DiagonalConstruction, Dyadic, FinalizedProblem, MAX_CHALLENGE_CONTEXT_BYTES,
    MAX_DIMENSION, MAX_FRACTIONAL_BITS, MAX_PERIOD_BITS, MatrixSpec, OffDiagonalValues,
    ProblemError, ProblemSchema, ProblemTemplate, RequestedOutput, RhsSpec, TemplateSchema,
};
