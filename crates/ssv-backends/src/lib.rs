//! Exhaustive registry for validation-backend lifecycle dispatch.
//!
//! Protocol implementations stay in their own crates. This thin composition
//! layer is the one place where an application chooses among registered
//! backend IDs and translates a verified report into certificate semantics.
//! Adding a backend therefore forces one exhaustive compiler-visible update,
//! without coupling exact and floating-point arithmetic behind a misleading
//! common numerical abstraction.

#![forbid(unsafe_code)]

use ssv_direct::{DirectBackend, DirectError, DirectProverReport, DirectVerifierReport};
use ssv_exact::{ExactBackend, ExactError, ExactProverReport, ExactVerifierReport};
use ssv_fast::{FastBackend, FastError, FastProverContext, FastProverReport, FastVerifierReport};
use ssv_service_protocol::{
    CertifiedScore, DefectMetrics, FastConsistencyMetrics, ProofProtocol, Unsigned192,
};
use ssv_solution::Solution;
use ssv_validation::{
    ArtifactPrelude, PublicStatement, ReferenceValidationBackend, ValidationBackend,
};
use thiserror::Error;

#[derive(Clone, Debug)]
pub enum BackendProverReport {
    Direct(DirectProverReport),
    Exact(ExactProverReport),
    Fast(FastProverReport),
}

/// Report produced only after a backend's structural and cryptographic
/// relations verify successfully.
///
/// The fast backend additionally records approximate algebraic discrepancies.
/// Those values are diagnostics and do not turn this type into a residual-
/// quality verdict.
#[derive(Clone, Debug)]
pub enum BackendVerifierReport {
    Direct(DirectVerifierReport),
    Exact(ExactVerifierReport),
    Fast(Box<FastVerifierReport>),
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("direct backend failed: {0}")]
    Direct(#[from] DirectError),
    #[error("exact backend failed: {0}")]
    Exact(#[from] ExactError),
    #[error("fast backend failed: {0}")]
    Fast(#[from] FastError),
    #[error("exact residual numerator does not fit the certificate's unsigned-192 field")]
    ExactScoreOverflow,
}

/// Proves any registered backend as one application operation.
///
/// The fast path still fixes its packed-oracle commitment before deriving any
/// Fiat--Shamir challenge. This wrapper simply keeps that local staging detail
/// out of applications that do not need checkpointing or phase accounting.
pub fn prove_single_stage(
    statement: &PublicStatement,
    solution: &Solution,
) -> Result<(Vec<u8>, BackendProverReport), BackendError> {
    match statement.manifest().protocol {
        ProofProtocol::DirectReferenceV1 => {
            let (payload, report) =
                <DirectBackend as ReferenceValidationBackend>::prove(statement, solution, &())?;
            Ok((payload, BackendProverReport::Direct(report)))
        }
        ProofProtocol::WhirField192L2V4 => {
            let (payload, report) =
                <ExactBackend as ValidationBackend>::prove(statement, solution, &())?;
            Ok((payload, BackendProverReport::Exact(report)))
        }
        ProofProtocol::FastBinary64UnitCircleV4 => {
            let (commitment, _) = FastBackend::commit(statement, solution)?;
            let context = FastProverContext::new(commitment);
            let (payload, report) =
                <FastBackend as ValidationBackend>::prove(statement, solution, &context)?;
            Ok((payload, BackendProverReport::Fast(report)))
        }
    }
}

/// Exhaustively dispatches a strictly framed common artifact.
pub fn verify(prelude: &ArtifactPrelude<'_>) -> Result<BackendVerifierReport, BackendError> {
    match prelude.statement().manifest().protocol {
        ProofProtocol::DirectReferenceV1 => Ok(BackendVerifierReport::Direct(
            prelude.verify_reference_with::<DirectBackend>()?,
        )),
        ProofProtocol::WhirField192L2V4 => Ok(BackendVerifierReport::Exact(
            prelude.verify_with::<ExactBackend>()?,
        )),
        ProofProtocol::FastBinary64UnitCircleV4 => Ok(BackendVerifierReport::Fast(Box::new(
            prelude.verify_with::<FastBackend>()?,
        ))),
    }
}

impl BackendVerifierReport {
    #[must_use]
    pub const fn protocol(&self) -> ProofProtocol {
        match self {
            Self::Direct(_) => ProofProtocol::DirectReferenceV1,
            Self::Exact(_) => ProofProtocol::WhirField192L2V4,
            Self::Fast(_) => ProofProtocol::FastBinary64UnitCircleV4,
        }
    }

    /// Converts a verified backend report into its protocol-specific signed
    /// certificate semantics.
    ///
    /// Fast binary64 relation errors are diagnostic provenance, not an
    /// additional acceptance gate. Structural and cryptographic failures have
    /// already returned an error from [`verify`].
    pub fn certified_score(&self) -> Result<CertifiedScore, BackendError> {
        match self {
            BackendVerifierReport::Direct(report) => Ok(CertifiedScore::DirectBinary64ResidualV1 {
                residual: report.residual,
            }),
            BackendVerifierReport::Exact(report) => {
                let encoded = report.residual.numerator.to_bytes_be();
                if encoded.len() > 24 {
                    return Err(BackendError::ExactScoreOverflow);
                }
                let mut bytes = [0_u8; 24];
                bytes[24 - encoded.len()..].copy_from_slice(&encoded);
                Ok(CertifiedScore::ExactDyadicSquaredL2V1 {
                    numerator: Unsigned192::from_be_bytes(bytes),
                    denominator_power: report.residual.denominator_power,
                })
            }
            BackendVerifierReport::Fast(report) => {
                let score = &report.score;
                Ok(CertifiedScore::FastBinary64DiagnosticsV1 {
                    squared_l2_claim: score.squared_l2_claim,
                    consistency: Box::new(FastConsistencyMetrics {
                        norm_sumcheck: defect_metrics(score.norm_sumcheck),
                        matvec_sumcheck: defect_metrics(score.matvec_sumcheck),
                        linear_opening: defect_metrics(score.linear_opening_sumcheck),
                        unit_circle_folds: defect_metrics(score.unit_circle_folds),
                        recursive_query_trajectories: score.proximity_queries_per_round,
                    }),
                })
            }
        }
    }
}

fn defect_metrics(summary: ssv_fast::DefectSummary) -> DefectMetrics {
    DefectMetrics {
        checks: summary.checks,
        zero_scale: summary.zero_scale,
        maximum_absolute_defect: summary.max_absolute,
        maximum_relative_error: summary.max_relative,
        rms_relative_error: summary.rms_relative,
        minimum_normalization_scale: summary.min_normalization_scale,
        maximum_normalization_scale: summary.max_normalization_scale,
    }
}
