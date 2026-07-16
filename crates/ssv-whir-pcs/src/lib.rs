//! Fixed-profile Field192 multilinear polynomial commitments.
//!
//! This crate is the reusable commitment boundary for exact validators. It
//! owns the Field192/WHIR integration, transcript composition, strict inner
//! certificate framing, and commitment-specific metrics. It deliberately has
//! no knowledge of matrices, right-hand sides, sparse relations, or proof
//! backends.
//!
//! The only configurable values are the committed table shape: vector length
//! and exact batch size. All security choices are pinned by [`FIXED_PROFILE`]:
//! unique decoding, inverse rate two, initial and recursive folding factors of
//! four, BLAKE3 Merkle hashing, no proof of work, and at least 128 bits of
//! security as computed by WHIR. Neither a proof nor an application caller can
//! substitute weaker parameters.
//!
//! The transcript order enforced here is:
//!
//! 1. bind the fixed protocol configuration and public statement digest;
//! 2. commit to exactly `batch_size` same-length vectors;
//! 3. run an optional caller-supplied transcript hook;
//! 4. bind a canonical digest of every opening point and claimed value;
//! 5. prove all openings with WHIR; and
//! 6. verify WHIR's deferred final claim and require strict end-of-file.
//!
//! # Provenance and security status
//!
//! The protocol logic and parameter choices are refactored from the rigorously
//! tested `sparse-mle-pcs` crate in the sparse-solution-stark research
//! implementation (revision current on 2026-07-15). WHIR itself is pinned to
//! upstream git revision `10aa7d0bae3663fd149b6b88b6eff2209b867970`.
//! The upstream project describes itself as an unaudited academic prototype;
//! preserving its configuration is not a production-security endorsement.

#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::convert::Infallible;
use std::fmt::Display;
use std::mem::size_of;
use std::panic::{AssertUnwindSafe, catch_unwind};

use ark_ff::PrimeField;
use bincode::Options;
use serde::Serialize;
use thiserror::Error;
use whir::algebra::embedding::Identity;
pub use whir::algebra::fields::Field192;
use whir::algebra::linear_form::{Evaluate, LinearForm, MultilinearExtension};
use whir::bits::Bits;
use whir::buffer::{ActiveBuffer, BufferOps};
use whir::hash::{BLAKE3, HASH_COUNTER};
use whir::parameters::ProtocolParameters;
use whir::protocols::whir::Config as WhirConfig;
use whir::transcript::{DomainSeparator, Proof, ProverState, VerifierState};

/// Native field used by committed values and Fiat--Shamir challenges.
///
/// Its modulus is
/// `3801539170989320091464968600173246866371124347557388484609`,
/// which is approximately 192 bits and has 2-adicity 48.
pub type PcsField = Field192;

/// Prover transcript exposed to an application composition hook.
pub type ProverTranscript = ProverState;

/// Verifier transcript exposed to an application composition hook.
pub type VerifierTranscript<'proof> = VerifierState<'proof>;

/// Transcript traits needed by protocols composed with this PCS.
///
/// Re-exporting these traits avoids making downstream code depend on WHIR's
/// module layout. The concrete transcript remains pinned by this crate.
pub mod transcript {
    pub use whir::transcript::{
        Codec, Decoding, Encoding, NargDeserialize, NargSerialize, ProverState, VerificationError,
        VerificationResult, VerifierMessage, VerifierState,
    };
}

const SECURITY_BITS: usize = 128;
const STARTING_LOG_INV_RATE: usize = 1;
const INITIAL_FOLDING_FACTOR: usize = 4;
const FOLDING_FACTOR: usize = 4;
// Soundness comes from query checks, not a hidden prover cost of up to 2^k
// trials. This also keeps performance measurements comparable.
const MAX_POW_BITS: usize = 0;
const FIELD_BYTES: usize = size_of::<PcsField>();
const HASH_BYTES: usize = 32;
const CERTIFICATE_MAGIC: [u8; 8] = *b"SSMPCS01";
const CERTIFICATE_VERSION: u16 = 1;
const CERTIFICATE_HEADER_BYTES: usize = 8 + 2 + 8 + 8;

// These tags intentionally retain the audited research implementation's byte
// strings. Changing a crate name must not silently fork Fiat--Shamir semantics.
const SESSION_TAG: &[u8] = b"sparse-solution/mle-pcs/v1";
const OPENING_DIGEST_TAG: &[u8] = b"sparse-solution/mle-pcs/openings/v1\0";

/// Default defensive limit used by [`Certificate::decode_default`].
pub const DEFAULT_MAX_CERTIFICATE_BYTES: usize = 256 * 1024 * 1024;

/// Immutable description of the only supported commitment profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedProfile {
    security_bits: usize,
    starting_inverse_rate: usize,
    initial_folding_factor: usize,
    folding_factor: usize,
    maximum_pow_bits: usize,
}

impl FixedProfile {
    /// Minimum security required from WHIR's computed bound.
    #[must_use]
    pub const fn security_bits(self) -> usize {
        self.security_bits
    }

    /// Initial Reed--Solomon inverse rate (two).
    #[must_use]
    pub const fn starting_inverse_rate(self) -> usize {
        self.starting_inverse_rate
    }

    /// Number of variables folded by the first WHIR round.
    #[must_use]
    pub const fn initial_folding_factor(self) -> usize {
        self.initial_folding_factor
    }

    /// Number of variables folded by subsequent WHIR rounds.
    #[must_use]
    pub const fn folding_factor(self) -> usize {
        self.folding_factor
    }

    /// Maximum permitted proof-of-work bits (zero).
    #[must_use]
    pub const fn maximum_pow_bits(self) -> usize {
        self.maximum_pow_bits
    }

    /// Name of the fixed transparent commitment hash.
    #[must_use]
    pub const fn hash_name(self) -> &'static str {
        "blake3"
    }

    /// Whether unique decoding is mandatory.
    #[must_use]
    pub const fn unique_decoding(self) -> bool {
        true
    }
}

/// The fixed, non-negotiable WHIR profile.
pub const FIXED_PROFILE: FixedProfile = FixedProfile {
    security_bits: SECURITY_BITS,
    starting_inverse_rate: 1 << STARTING_LOG_INV_RATE,
    initial_folding_factor: INITIAL_FOLDING_FACTOR,
    folding_factor: FOLDING_FACTOR,
    maximum_pow_bits: MAX_POW_BITS,
};

/// Validated WHIR protocol object reusable across proofs of one table shape.
///
/// Construction accepts only shape information. There is intentionally no
/// public configuration object and no security-parameter setter.
#[derive(Clone, Debug)]
pub struct PcsProtocol {
    vector_len: usize,
    batch_size: usize,
    whir: WhirConfig<Identity<PcsField>>,
}

impl PcsProtocol {
    /// Constructs the fixed-profile PCS for `batch_size` vectors of exactly
    /// `vector_len` elements each.
    ///
    /// `vector_len` must be a power of two with at least four variables. The
    /// batch size is exact; proof and verification reject any other count.
    pub fn new(vector_len: usize, batch_size: usize) -> Result<Self, PcsError> {
        validate_shape(vector_len, batch_size)?;
        let parameters = ProtocolParameters {
            unique_decoding: true,
            starting_log_inv_rate: STARTING_LOG_INV_RATE,
            initial_folding_factor: INITIAL_FOLDING_FACTOR,
            folding_factor: FOLDING_FACTOR,
            security_level: SECURITY_BITS,
            pow_bits: MAX_POW_BITS,
            batch_size,
            hash_id: BLAKE3,
        };
        let whir = WhirConfig::<Identity<PcsField>>::new(vector_len, &parameters);
        if !whir.check_max_pow_bits(Bits::new(MAX_POW_BITS as f64)) {
            return Err(PcsError::ExcessiveProofOfWork {
                maximum_bits: MAX_POW_BITS,
            });
        }
        let protocol = Self {
            vector_len,
            batch_size,
            whir,
        };
        // Fail construction if even one opening cannot meet the promised
        // profile. Exact opening counts are checked again per proof.
        let _ = protocol.security_bits_floor(1)?;
        Ok(protocol)
    }

    /// Number of elements in every committed vector.
    #[must_use]
    pub const fn vector_len(&self) -> usize {
        self.vector_len
    }

    /// Exact number of committed vectors.
    #[must_use]
    pub const fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Number of Boolean variables in one vector's multilinear extension.
    #[must_use]
    pub const fn variables(&self) -> usize {
        self.vector_len.trailing_zeros() as usize
    }

    /// Convenience proving API when no transcript protocol is composed between
    /// commitment and opening.
    pub fn prove(
        &self,
        statement_digest: &[u8; 32],
        vectors: Vec<Vec<PcsField>>,
        points: Vec<Vec<PcsField>>,
    ) -> Result<ProverOutput, PcsError> {
        self.prove_with_transcript(statement_digest, vectors, move |_, _| {
            Ok::<_, Infallible>(points)
        })
    }

    /// Commits first, then lets an outer protocol append transcript messages
    /// before WHIR opens the returned points.
    ///
    /// The hook receives read-only slices of the committed vectors. Its return
    /// value is the exact list of MLE points to authenticate. Points and
    /// computed evaluations are subsequently bound by a canonical digest.
    pub fn prove_with_transcript<F, E>(
        &self,
        statement_digest: &[u8; 32],
        vectors: Vec<Vec<PcsField>>,
        hook: F,
    ) -> Result<ProverOutput, PcsError>
    where
        F: FnOnce(&mut ProverTranscript, &[&[PcsField]]) -> Result<Vec<Vec<PcsField>>, E>,
        E: Display,
    {
        self.prove_claims_with_transcript(statement_digest, vectors, move |transcript, vectors| {
            let points = hook(transcript, vectors).map_err(|error| error.to_string())?;
            self.evaluate_claims(vectors, points)
                .map_err(|error| error.to_string())
        })
    }

    /// Composed proving API for callers that computed endpoint claims while
    /// running an outer sumcheck.
    ///
    /// Caller-supplied evaluations are not trusted: WHIR authenticates every
    /// value against the earlier commitment. This API avoids evaluating a
    /// packed table again for every selector point.
    pub fn prove_claims_with_transcript<F, E>(
        &self,
        statement_digest: &[u8; 32],
        vectors: Vec<Vec<PcsField>>,
        hook: F,
    ) -> Result<ProverOutput, PcsError>
    where
        F: FnOnce(&mut ProverTranscript, &[&[PcsField]]) -> Result<OpeningClaims, E>,
        E: Display,
    {
        self.validate_vectors(&vectors)?;

        let buffers = vectors
            .into_iter()
            .map(ActiveBuffer::from_vec)
            .collect::<Vec<_>>();
        let buffer_refs = buffers.iter().collect::<Vec<_>>();
        let vector_slices = buffers.iter().map(BufferOps::to_slice).collect::<Vec<_>>();

        let domain_separator = self.domain_separator(statement_digest);
        let mut prover_state = ProverState::new_std(&domain_separator);
        let hash_count_before = HASH_COUNTER.get();

        // In unique-decoding mode the public commitment is the first prover
        // message after domain separation and there are no commitment OODs.
        let witness = self.whir.commit(&mut prover_state, &buffer_refs);

        let claims = hook(&mut prover_state, &vector_slices)
            .map_err(|error| PcsError::TranscriptHook(error.to_string()))?;
        self.validate_claims(&claims)?;
        let opening_digest = opening_statement_digest(self.vector_len, self.batch_size, &claims)?;
        prover_state.prover_message(&opening_digest);

        let forms = claims
            .points
            .iter()
            .cloned()
            .map(MultilinearExtension::new)
            .map(|form| Box::new(form) as Box<dyn LinearForm<PcsField>>)
            .collect::<Vec<_>>();

        let initial_memory = InitialCommitmentMemory::from_witness(&buffers, &witness)?;
        let largest_round_commitment_bytes = self.largest_round_commitment_bytes()?;

        // WHIR returns a deferred claim. The prover need not inspect it; the
        // verifier authenticates and checks it below.
        let _deferred_final_claim = self.whir.prove(
            &mut prover_state,
            &buffer_refs,
            vec![&witness],
            forms,
            Cow::Borrowed(&claims.evaluations),
        );
        let proof = prover_state.proof();
        let diagnostic_hash_invocations = HASH_COUNTER.get().saturating_sub(hash_count_before);
        let certificate = Certificate::from_whir_proof(proof);

        let two_full_folding_buffers = checked_mul3(2, self.vector_len, FIELD_BYTES)?;
        let certificate_bytes = certificate.encoded_len()?;
        let accounted_high_watermark_bytes = checked_add_many(&[
            initial_memory.total_bytes,
            two_full_folding_buffers,
            largest_round_commitment_bytes,
            certificate_bytes,
        ])?;

        let metrics = ProverMetrics {
            source_vector_bytes: initial_memory.source_vector_bytes,
            initial_codeword_bytes: initial_memory.codeword_bytes,
            initial_merkle_tree_bytes: initial_memory.merkle_tree_bytes,
            initial_ood_bytes: initial_memory.ood_bytes,
            largest_round_commitment_bytes,
            two_full_folding_buffers,
            certificate_bytes,
            accounted_high_watermark_bytes,
            diagnostic_hash_invocations,
            security_bits_floor: self.security_bits_floor(claims.points.len())?,
        };

        Ok(ProverOutput {
            certificate,
            claims,
            metrics,
        })
    }

    /// Convenience verifier API when no transcript protocol is composed
    /// between commitment and opening.
    pub fn verify(
        &self,
        statement_digest: &[u8; 32],
        claims: &OpeningClaims,
        certificate: &Certificate,
    ) -> Result<VerifierMetrics, PcsError> {
        let claims = claims.clone();
        self.verify_with_transcript(statement_digest, certificate, move |_| {
            Ok::<_, Infallible>(claims)
        })
    }

    /// Receives the commitment, replays an outer transcript hook, and verifies
    /// WHIR against the hook's exact endpoint claims.
    ///
    /// Verification checks WHIR's deferred final claim and rejects any unread
    /// inner transcript or hint bytes. Panics reached while parsing untrusted
    /// upstream WHIR bytes are contained and reported as verification failure;
    /// panics in the application hook are deliberately not swallowed.
    pub fn verify_with_transcript<F, E>(
        &self,
        statement_digest: &[u8; 32],
        certificate: &Certificate,
        hook: F,
    ) -> Result<VerifierMetrics, PcsError>
    where
        F: FnOnce(&mut VerifierTranscript<'_>) -> Result<OpeningClaims, E>,
        E: Display,
    {
        let proof = certificate.to_whir_proof()?;
        let domain_separator = self.domain_separator(statement_digest);
        let mut verifier_state = VerifierState::new_std(&domain_separator, &proof);
        let hash_count_before = HASH_COUNTER.get();

        let commitment =
            contain_untrusted_whir(|| self.whir.receive_commitment(&mut verifier_state))?
                .map_err(|_| PcsError::Verification)?;

        let claims = hook(&mut verifier_state)
            .map_err(|error| PcsError::TranscriptHook(error.to_string()))?;
        self.validate_claims(&claims)?;

        let expected_digest = opening_statement_digest(self.vector_len, self.batch_size, &claims)?;
        let received_digest: [u8; 32] = contain_untrusted_whir(|| verifier_state.prover_message())?
            .map_err(|_| PcsError::Verification)?;
        if received_digest != expected_digest {
            return Err(PcsError::OpeningStatementDigestMismatch);
        }

        let forms = claims
            .points
            .iter()
            .cloned()
            .map(MultilinearExtension::new)
            .collect::<Vec<_>>();
        let form_refs = forms
            .iter()
            .map(|form| form as &dyn LinearForm<PcsField>)
            .collect::<Vec<_>>();

        let final_claim = contain_untrusted_whir(|| {
            self.whir
                .verify(&mut verifier_state, &[&commitment], &claims.evaluations)
        })?
        .map_err(|_| PcsError::Verification)?;
        contain_untrusted_whir(|| final_claim.verify(form_refs))?
            .map_err(|_| PcsError::Verification)?;
        contain_untrusted_whir(|| verifier_state.check_eof())?
            .map_err(|_| PcsError::Verification)?;

        Ok(VerifierMetrics {
            certificate_bytes: certificate.encoded_len()?,
            opening_points: claims.points.len(),
            claimed_evaluations: claims.evaluations.len(),
            diagnostic_hash_invocations: HASH_COUNTER.get().saturating_sub(hash_count_before),
            security_bits_floor: self.security_bits_floor(claims.points.len())?,
        })
    }

    fn domain_separator<'digest>(
        &self,
        statement_digest: &'digest [u8; 32],
    ) -> DomainSeparator<'digest, [u8; 32]> {
        DomainSeparator::protocol(&self.whir)
            .session(&SESSION_TAG)
            .instance(statement_digest)
    }

    fn validate_vectors(&self, vectors: &[Vec<PcsField>]) -> Result<(), PcsError> {
        if vectors.len() != self.batch_size {
            return Err(PcsError::WrongBatchSize {
                expected: self.batch_size,
                actual: vectors.len(),
            });
        }
        for (index, vector) in vectors.iter().enumerate() {
            if vector.len() != self.vector_len {
                return Err(PcsError::WrongVectorLength {
                    index,
                    expected: self.vector_len,
                    actual: vector.len(),
                });
            }
        }
        Ok(())
    }

    fn validate_points(&self, points: &[Vec<PcsField>]) -> Result<(), PcsError> {
        if points.is_empty() {
            return Err(PcsError::NoOpeningPoints);
        }
        let expected = self.variables();
        for (index, point) in points.iter().enumerate() {
            if point.len() != expected {
                return Err(PcsError::WrongPointDimension {
                    index,
                    expected,
                    actual: point.len(),
                });
            }
        }
        let _ = self.security_bits_floor(points.len())?;
        Ok(())
    }

    fn validate_claims(&self, claims: &OpeningClaims) -> Result<(), PcsError> {
        self.validate_points(&claims.points)?;
        let expected = claims
            .points
            .len()
            .checked_mul(self.batch_size)
            .ok_or(PcsError::SizeOverflow)?;
        if claims.evaluations.len() != expected {
            return Err(PcsError::WrongEvaluationCount {
                expected,
                actual: claims.evaluations.len(),
            });
        }
        Ok(())
    }

    fn evaluate_claims(
        &self,
        vectors: &[&[PcsField]],
        points: Vec<Vec<PcsField>>,
    ) -> Result<OpeningClaims, PcsError> {
        self.validate_points(&points)?;
        let evaluation_count = points
            .len()
            .checked_mul(vectors.len())
            .ok_or(PcsError::SizeOverflow)?;
        let mut evaluations = Vec::new();
        evaluations
            .try_reserve_exact(evaluation_count)
            .map_err(|_| PcsError::AllocationFailed)?;
        let embedding = Identity::<PcsField>::new();
        for point in &points {
            let form = MultilinearExtension::new(point.clone());
            for vector in vectors {
                evaluations.push(form.evaluate(&embedding, vector));
            }
        }
        Ok(OpeningClaims {
            points,
            evaluations,
        })
    }

    fn security_bits_floor(&self, opening_points: usize) -> Result<u32, PcsError> {
        let bits = self.whir.security_level(self.batch_size, opening_points);
        if !bits.is_finite() || bits < SECURITY_BITS as f64 {
            return Err(PcsError::InsufficientComputedSecurity {
                required_bits: SECURITY_BITS,
                computed_bits: bits,
            });
        }
        if bits.floor() > f64::from(u32::MAX) {
            return Err(PcsError::InvalidComputedSecurity {
                computed_bits: bits,
            });
        }
        Ok(bits.floor() as u32)
    }

    fn largest_round_commitment_bytes(&self) -> Result<usize, PcsError> {
        // This intentionally reads data-layout metadata from the pinned WHIR
        // revision. Keeping the accounting here prevents backend crates from
        // learning or duplicating WHIR internals.
        self.whir
            .round_configs
            .iter()
            .map(|round| {
                let committer = &round.irs_committer;
                let matrix = checked_mul(committer.size(), FIELD_BYTES)?;
                let tree =
                    checked_mul(committer.matrix_commit.merkle_tree.num_nodes(), HASH_BYTES)?;
                let ood_elements = checked_add(
                    committer.out_domain_samples,
                    checked_mul(committer.out_domain_samples, committer.num_vectors)?,
                )?;
                checked_add_many(&[matrix, tree, checked_mul(ood_elements, FIELD_BYTES)?])
            })
            .try_fold(0, |largest, bytes| bytes.map(|bytes| largest.max(bytes)))
    }
}

fn validate_shape(vector_len: usize, batch_size: usize) -> Result<(), PcsError> {
    if !vector_len.is_power_of_two() {
        return Err(PcsError::VectorLengthNotPowerOfTwo(vector_len));
    }
    if batch_size == 0 {
        return Err(PcsError::EmptyBatch);
    }
    let variables = vector_len.trailing_zeros() as usize;
    if variables < INITIAL_FOLDING_FACTOR {
        return Err(PcsError::InitialFoldTooLarge {
            variables,
            folding_factor: INITIAL_FOLDING_FACTOR,
        });
    }
    Ok(())
}

/// Public opening statement.
///
/// Evaluations are row-major:
/// `evaluations[point_index * batch_size + vector_index]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpeningClaims {
    pub points: Vec<Vec<PcsField>>,
    pub evaluations: Vec<PcsField>,
}

impl OpeningClaims {
    /// Returns one claimed evaluation using the documented row-major layout.
    #[must_use]
    pub fn evaluation(&self, point: usize, vector: usize, batch_size: usize) -> Option<PcsField> {
        point
            .checked_mul(batch_size)
            .and_then(|offset| offset.checked_add(vector))
            .and_then(|index| self.evaluations.get(index))
            .copied()
    }
}

/// Strict wire wrapper for WHIR's two internal proof byte streams.
///
/// Encoding is fixed-width little-endian:
/// `magic || version || narg_len || hints_len || narg || hints`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Certificate {
    narg_string: Vec<u8>,
    hints: Vec<u8>,
}

impl Certificate {
    fn from_whir_proof(proof: Proof) -> Self {
        Self {
            narg_string: proof.narg_string,
            hints: proof.hints,
        }
    }

    /// Bytes in WHIR's argument transcript stream.
    #[must_use]
    pub fn narg_string_len(&self) -> usize {
        self.narg_string.len()
    }

    /// Bytes in WHIR's auxiliary hint stream.
    #[must_use]
    pub fn hints_len(&self) -> usize {
        self.hints.len()
    }

    /// Encoded certificate size, including the strict wrapper header.
    pub fn encoded_len(&self) -> Result<usize, PcsError> {
        checked_add_many(&[
            CERTIFICATE_HEADER_BYTES,
            self.narg_string.len(),
            self.hints.len(),
        ])
    }

    /// Encodes one canonical certificate.
    pub fn encode(&self) -> Result<Vec<u8>, PcsError> {
        let encoded_len = self.encoded_len()?;
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(encoded_len)
            .map_err(|_| PcsError::AllocationFailed)?;
        encoded.extend_from_slice(&CERTIFICATE_MAGIC);
        encoded.extend_from_slice(&CERTIFICATE_VERSION.to_le_bytes());
        encoded.extend_from_slice(&usize_to_u64(self.narg_string.len())?.to_le_bytes());
        encoded.extend_from_slice(&usize_to_u64(self.hints.len())?.to_le_bytes());
        encoded.extend_from_slice(&self.narg_string);
        encoded.extend_from_slice(&self.hints);
        Ok(encoded)
    }

    /// Decodes with [`DEFAULT_MAX_CERTIFICATE_BYTES`] as the allocation limit.
    pub fn decode_default(encoded: &[u8]) -> Result<Self, PcsError> {
        Self::decode(encoded, DEFAULT_MAX_CERTIFICATE_BYTES)
    }

    /// Strictly decodes exactly one certificate.
    ///
    /// This rejects truncation, trailing bytes, unknown versions,
    /// non-representable lengths, and oversized payloads before copying either
    /// WHIR stream.
    pub fn decode(encoded: &[u8], maximum_bytes: usize) -> Result<Self, PcsError> {
        if encoded.len() < CERTIFICATE_HEADER_BYTES {
            return Err(PcsError::TruncatedCertificate);
        }
        if encoded.get(..CERTIFICATE_MAGIC.len()) != Some(CERTIFICATE_MAGIC.as_slice()) {
            return Err(PcsError::BadCertificateMagic);
        }
        let version = read_u16(encoded, 8)?;
        if version != CERTIFICATE_VERSION {
            return Err(PcsError::UnsupportedCertificateVersion(version));
        }
        let narg_len = u64_to_usize(read_u64(encoded, 10)?)?;
        let hints_len = u64_to_usize(read_u64(encoded, 18)?)?;
        let payload_len = checked_add(narg_len, hints_len)?;
        let total_len = checked_add(CERTIFICATE_HEADER_BYTES, payload_len)?;
        if total_len > maximum_bytes {
            return Err(PcsError::CertificateTooLarge {
                maximum: maximum_bytes,
                actual: total_len,
            });
        }
        if encoded.len() < total_len {
            return Err(PcsError::TruncatedCertificate);
        }
        if encoded.len() > total_len {
            return Err(PcsError::TrailingCertificateBytes {
                trailing: encoded.len() - total_len,
            });
        }
        let split = checked_add(CERTIFICATE_HEADER_BYTES, narg_len)?;
        let narg_string = encoded
            .get(CERTIFICATE_HEADER_BYTES..split)
            .ok_or(PcsError::TruncatedCertificate)?
            .to_vec();
        let hints = encoded
            .get(split..total_len)
            .ok_or(PcsError::TruncatedCertificate)?
            .to_vec();
        Ok(Self { narg_string, hints })
    }

    fn to_whir_proof(&self) -> Result<Proof, PcsError> {
        // The pinned WHIR revision does not expose `Proof::from_parts`. Its
        // Serde representation is used as a narrow construction bridge. These
        // bincode bytes are temporary and are not the public wire format.
        #[derive(Serialize)]
        struct ProofRef<'streams> {
            narg_string: &'streams [u8],
            hints: &'streams [u8],
        }

        let options = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .reject_trailing_bytes();
        let temporary = options
            .serialize(&ProofRef {
                narg_string: &self.narg_string,
                hints: &self.hints,
            })
            .map_err(|error| PcsError::InternalProofDecode(error.to_string()))?;
        options
            .deserialize::<Proof>(&temporary)
            .map_err(|error| PcsError::InternalProofDecode(error.to_string()))
    }
}

/// Result of committing and proving all requested openings.
#[derive(Clone, Debug)]
pub struct ProverOutput {
    pub certificate: Certificate,
    pub claims: OpeningClaims,
    pub metrics: ProverMetrics,
}

/// Logical buffer accounting from the prover implementation.
///
/// `accounted_high_watermark_bytes` is not RSS and is not a hard memory bound.
/// It adds retained source vectors, the initial Reed--Solomon codeword and
/// Merkle tree, OOD data, two full-size WHIR folding buffers, the largest later
/// commitment, and the completed proof. It excludes allocator metadata,
/// thread stacks, FFT scratch/root caches, transient serialization, and outer
/// application storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProverMetrics {
    pub source_vector_bytes: usize,
    pub initial_codeword_bytes: usize,
    pub initial_merkle_tree_bytes: usize,
    pub initial_ood_bytes: usize,
    pub largest_round_commitment_bytes: usize,
    pub two_full_folding_buffers: usize,
    pub certificate_bytes: usize,
    pub accounted_high_watermark_bytes: usize,
    /// Exact only when no other WHIR operation runs concurrently in-process.
    pub diagnostic_hash_invocations: usize,
    pub security_bits_floor: u32,
}

/// Commitment-specific verifier measurements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifierMetrics {
    pub certificate_bytes: usize,
    pub opening_points: usize,
    pub claimed_evaluations: usize,
    /// Exact only when no other WHIR operation runs concurrently in-process.
    pub diagnostic_hash_invocations: usize,
    pub security_bits_floor: u32,
}

struct InitialCommitmentMemory {
    source_vector_bytes: usize,
    codeword_bytes: usize,
    merkle_tree_bytes: usize,
    ood_bytes: usize,
    total_bytes: usize,
}

impl InitialCommitmentMemory {
    fn from_witness(
        buffers: &[ActiveBuffer<PcsField>],
        witness: &whir::protocols::whir::Witness<PcsField, Identity<PcsField>>,
    ) -> Result<Self, PcsError> {
        let source_elements = buffers
            .iter()
            .try_fold(0usize, |sum, buffer| checked_add(sum, buffer.len()))?;
        let source_vector_bytes = checked_mul(source_elements, FIELD_BYTES)?;
        let codeword_bytes = checked_mul(witness.matrix.len(), FIELD_BYTES)?;
        let merkle_tree_bytes = checked_mul(witness.matrix_witness.num_nodes(), HASH_BYTES)?;
        let ood_elements = checked_add(
            witness.out_of_domain.points.len(),
            witness.out_of_domain.matrix.len(),
        )?;
        let ood_bytes = checked_mul(ood_elements, FIELD_BYTES)?;
        let total_bytes = checked_add_many(&[
            source_vector_bytes,
            codeword_bytes,
            merkle_tree_bytes,
            ood_bytes,
        ])?;
        Ok(Self {
            source_vector_bytes,
            codeword_bytes,
            merkle_tree_bytes,
            ood_bytes,
            total_bytes,
        })
    }
}

/// Errors returned by the fixed-profile commitment layer.
#[derive(Debug, Error)]
pub enum PcsError {
    #[error("PCS vector length {0} is not a power of two")]
    VectorLengthNotPowerOfTwo(usize),
    #[error("PCS batch size must be nonzero")]
    EmptyBatch,
    #[error("initial folding factor {folding_factor} exceeds the vector's {variables} variables")]
    InitialFoldTooLarge {
        variables: usize,
        folding_factor: usize,
    },
    #[error("configured WHIR parameters require more than {maximum_bits} proof-of-work bits")]
    ExcessiveProofOfWork { maximum_bits: usize },
    #[error("expected exactly {expected} committed vectors, got {actual}")]
    WrongBatchSize { expected: usize, actual: usize },
    #[error("vector {index} has length {actual}; expected {expected}")]
    WrongVectorLength {
        index: usize,
        expected: usize,
        actual: usize,
    },
    #[error("at least one MLE opening point is required")]
    NoOpeningPoints,
    #[error("opening point {index} has dimension {actual}; expected {expected}")]
    WrongPointDimension {
        index: usize,
        expected: usize,
        actual: usize,
    },
    #[error("opening statement contains {actual} evaluations; expected {expected}")]
    WrongEvaluationCount { expected: usize, actual: usize },
    #[error(
        "computed WHIR security {computed_bits:.2} bits is below the required {required_bits} bits"
    )]
    InsufficientComputedSecurity {
        required_bits: usize,
        computed_bits: f64,
    },
    #[error("WHIR returned an invalid computed security value {computed_bits}")]
    InvalidComputedSecurity { computed_bits: f64 },
    #[error("application transcript hook failed: {0}")]
    TranscriptHook(String),
    #[error("opening points or values do not match the transcript-bound opening statement")]
    OpeningStatementDigestMismatch,
    #[error("WHIR verification failed")]
    Verification,
    #[error("certificate is truncated")]
    TruncatedCertificate,
    #[error("certificate magic is invalid")]
    BadCertificateMagic,
    #[error("unsupported certificate version {0}")]
    UnsupportedCertificateVersion(u16),
    #[error("certificate has {trailing} trailing bytes")]
    TrailingCertificateBytes { trailing: usize },
    #[error("certificate is {actual} bytes; configured maximum is {maximum}")]
    CertificateTooLarge { maximum: usize, actual: usize },
    #[error("WHIR proof reconstruction failed: {0}")]
    InternalProofDecode(String),
    #[error("memory allocation failed")]
    AllocationFailed,
    #[error("size arithmetic overflow")]
    SizeOverflow,
}

/// Maps a signed integer into Field192 without truncation.
///
/// This is an encoding helper only. A PCS opening does not establish an i128
/// range; an exact backend must prove that separately.
#[must_use]
pub fn encode_i128(value: i128) -> PcsField {
    if value >= 0 {
        PcsField::from(value as u128)
    } else {
        -PcsField::from(value.unsigned_abs())
    }
}

fn opening_statement_digest(
    vector_len: usize,
    batch_size: usize,
    claims: &OpeningClaims,
) -> Result<[u8; 32], PcsError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(OPENING_DIGEST_TAG);
    hash_usize(&mut hasher, vector_len)?;
    hash_usize(&mut hasher, batch_size)?;
    hash_usize(&mut hasher, claims.points.len())?;
    for point in &claims.points {
        hash_usize(&mut hasher, point.len())?;
        for &coordinate in point {
            hash_field(&mut hasher, coordinate);
        }
    }
    hash_usize(&mut hasher, claims.evaluations.len())?;
    for &evaluation in &claims.evaluations {
        hash_field(&mut hasher, evaluation);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hash_usize(hasher: &mut blake3::Hasher, value: usize) -> Result<(), PcsError> {
    hasher.update(&usize_to_u64(value)?.to_le_bytes());
    Ok(())
}

fn hash_field(hasher: &mut blake3::Hasher, value: PcsField) {
    let bigint = value.into_bigint();
    for &limb in bigint.as_ref() {
        hasher.update(&limb.to_le_bytes());
    }
}

fn contain_untrusted_whir<T>(operation: impl FnOnce() -> T) -> Result<T, PcsError> {
    catch_unwind(AssertUnwindSafe(operation)).map_err(|_| PcsError::Verification)
}

fn read_u16(encoded: &[u8], offset: usize) -> Result<u16, PcsError> {
    let end = checked_add(offset, size_of::<u16>())?;
    let bytes: [u8; 2] = encoded
        .get(offset..end)
        .ok_or(PcsError::TruncatedCertificate)?
        .try_into()
        .map_err(|_| PcsError::TruncatedCertificate)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u64(encoded: &[u8], offset: usize) -> Result<u64, PcsError> {
    let end = checked_add(offset, size_of::<u64>())?;
    let bytes: [u8; 8] = encoded
        .get(offset..end)
        .ok_or(PcsError::TruncatedCertificate)?
        .try_into()
        .map_err(|_| PcsError::TruncatedCertificate)?;
    Ok(u64::from_le_bytes(bytes))
}

fn checked_mul(a: usize, b: usize) -> Result<usize, PcsError> {
    a.checked_mul(b).ok_or(PcsError::SizeOverflow)
}

fn checked_mul3(a: usize, b: usize, c: usize) -> Result<usize, PcsError> {
    checked_mul(checked_mul(a, b)?, c)
}

fn checked_add(a: usize, b: usize) -> Result<usize, PcsError> {
    a.checked_add(b).ok_or(PcsError::SizeOverflow)
}

fn checked_add_many(values: &[usize]) -> Result<usize, PcsError> {
    values
        .iter()
        .try_fold(0usize, |sum, &value| checked_add(sum, value))
}

fn usize_to_u64(value: usize) -> Result<u64, PcsError> {
    u64::try_from(value).map_err(|_| PcsError::SizeOverflow)
}

fn u64_to_usize(value: u64) -> Result<usize, PcsError> {
    usize::try_from(value).map_err(|_| PcsError::SizeOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript::VerifierMessage;

    fn vectors(batch: usize, len: usize) -> Vec<Vec<PcsField>> {
        (0..batch)
            .map(|vector| {
                (0..len)
                    .map(|index| PcsField::from((1 + vector * 101 + index * 7) as u64))
                    .collect()
            })
            .collect()
    }

    fn arbitrary_points(count: usize, variables: usize) -> Vec<Vec<PcsField>> {
        (0..count)
            .map(|point| {
                (0..variables)
                    .map(|coordinate| {
                        // Independent caller-selected coordinates, deliberately
                        // neither a power sequence nor a Boolean point.
                        PcsField::from((13 + point * 37 + coordinate * 11) as u64)
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn fixed_profile_is_the_research_v4_profile() {
        assert_eq!(FIXED_PROFILE.security_bits(), 128);
        assert_eq!(FIXED_PROFILE.starting_inverse_rate(), 2);
        assert_eq!(FIXED_PROFILE.initial_folding_factor(), 4);
        assert_eq!(FIXED_PROFILE.folding_factor(), 4);
        assert_eq!(FIXED_PROFILE.maximum_pow_bits(), 0);
        assert_eq!(FIXED_PROFILE.hash_name(), "blake3");
        assert!(FIXED_PROFILE.unique_decoding());
    }

    #[test]
    fn invalid_shapes_are_rejected_before_upstream_construction() {
        assert!(matches!(
            PcsProtocol::new(31, 1),
            Err(PcsError::VectorLengthNotPowerOfTwo(31))
        ));
        assert!(matches!(PcsProtocol::new(32, 0), Err(PcsError::EmptyBatch)));
        assert!(matches!(
            PcsProtocol::new(8, 1),
            Err(PcsError::InitialFoldTooLarge { .. })
        ));
    }

    #[test]
    fn multiple_vectors_arbitrary_points_round_trip_with_composed_transcript() {
        const LEN: usize = 32;
        const BATCH: usize = 3;
        let protocol = PcsProtocol::new(LEN, BATCH).unwrap();
        let statement_digest = [0x42; 32];
        let points = arbitrary_points(2, protocol.variables());
        let prover_points = points.clone();

        let output = protocol
            .prove_with_transcript(
                &statement_digest,
                vectors(BATCH, LEN),
                move |transcript, _| {
                    // Stand-in for an outer sparse sumcheck. Both this message
                    // and its challenge precede WHIR's opening statement.
                    transcript.prover_message(&PcsField::from(99_u64));
                    let _: PcsField = transcript.verifier_message();
                    Ok::<_, String>(prover_points)
                },
            )
            .unwrap();

        assert_eq!(output.claims.points, points);
        assert_eq!(output.claims.evaluations.len(), 2 * BATCH);
        assert!(output.metrics.security_bits_floor >= SECURITY_BITS as u32);
        assert!(output.metrics.initial_codeword_bytes > 0);
        assert!(output.metrics.accounted_high_watermark_bytes > output.metrics.certificate_bytes);

        let encoded = output.certificate.encode().unwrap();
        let decoded = Certificate::decode_default(&encoded).unwrap();
        assert_eq!(decoded, output.certificate);

        let verifier_claims = output.claims.clone();
        let metrics = protocol
            .verify_with_transcript(&statement_digest, &decoded, move |transcript| {
                let marker: PcsField = transcript
                    .prover_message()
                    .map_err(|_| "could not read outer transcript marker".to_owned())?;
                if marker != PcsField::from(99_u64) {
                    return Err("wrong outer transcript marker".to_owned());
                }
                let _: PcsField = transcript.verifier_message();
                Ok(verifier_claims)
            })
            .unwrap();
        assert_eq!(metrics.opening_points, 2);
        assert_eq!(metrics.claimed_evaluations, 2 * BATCH);
        assert!(metrics.security_bits_floor >= SECURITY_BITS as u32);
    }

    #[test]
    fn strict_decoder_rejects_bad_magic_version_trailing_and_truncation() {
        let certificate = Certificate {
            narg_string: vec![1, 2, 3],
            hints: vec![4, 5],
        };
        let encoded = certificate.encode().unwrap();

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert!(matches!(
            Certificate::decode_default(&bad_magic),
            Err(PcsError::BadCertificateMagic)
        ));

        let mut bad_version = encoded.clone();
        bad_version[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert!(matches!(
            Certificate::decode_default(&bad_version),
            Err(PcsError::UnsupportedCertificateVersion(2))
        ));

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            Certificate::decode_default(&trailing),
            Err(PcsError::TrailingCertificateBytes { trailing: 1 })
        ));

        let truncated = &encoded[..encoded.len() - 1];
        assert!(matches!(
            Certificate::decode_default(truncated),
            Err(PcsError::TruncatedCertificate)
        ));
    }

    #[test]
    fn decoder_enforces_limit_before_copying_streams() {
        let certificate = Certificate {
            narg_string: vec![1, 2, 3],
            hints: vec![4, 5],
        };
        let encoded = certificate.encode().unwrap();
        assert!(matches!(
            Certificate::decode(&encoded, encoded.len() - 1),
            Err(PcsError::CertificateTooLarge { .. })
        ));
    }

    #[test]
    fn configured_batch_size_is_exact() {
        let protocol = PcsProtocol::new(32, 27).unwrap();
        let error = protocol
            .prove(&[0; 32], vectors(2, 32), arbitrary_points(1, 5))
            .unwrap_err();
        assert!(matches!(
            error,
            PcsError::WrongBatchSize {
                expected: 27,
                actual: 2
            }
        ));
    }

    #[test]
    fn intended_twenty_seven_vector_batch_round_trips() {
        let protocol = PcsProtocol::new(32, 27).unwrap();
        let output = protocol
            .prove(&[0x27; 32], vectors(27, 32), arbitrary_points(1, 5))
            .unwrap();

        let metrics = protocol
            .verify(&[0x27; 32], &output.claims, &output.certificate)
            .unwrap();
        assert_eq!(metrics.claimed_evaluations, 27);
        assert!(metrics.security_bits_floor >= SECURITY_BITS as u32);
    }

    #[test]
    fn opening_claim_mutation_is_rejected_before_whir() {
        let protocol = PcsProtocol::new(32, 2).unwrap();
        let output = protocol
            .prove(&[7; 32], vectors(2, 32), arbitrary_points(1, 5))
            .unwrap();
        let mut bad_claims = output.claims;
        bad_claims.evaluations[0] += PcsField::from(1_u64);
        assert!(matches!(
            protocol.verify(&[7; 32], &bad_claims, &output.certificate),
            Err(PcsError::OpeningStatementDigestMismatch)
        ));
    }

    #[test]
    fn certificate_is_bound_to_public_statement() {
        let protocol = PcsProtocol::new(32, 1).unwrap();
        let output = protocol
            .prove(&[0x11; 32], vectors(1, 32), arbitrary_points(1, 5))
            .unwrap();

        assert!(
            protocol
                .verify(&[0x22; 32], &output.claims, &output.certificate)
                .is_err()
        );
    }

    #[test]
    fn mutated_whir_payload_is_rejected() {
        let protocol = PcsProtocol::new(32, 1).unwrap();
        let output = protocol
            .prove(&[0x33; 32], vectors(1, 32), arbitrary_points(1, 5))
            .unwrap();
        let mut certificate = output.certificate;
        let index = certificate.narg_string.len() / 2;
        certificate.narg_string[index] ^= 1;

        assert!(
            protocol
                .verify(&[0x33; 32], &output.claims, &certificate)
                .is_err()
        );
    }

    #[test]
    fn malformed_whir_transcript_returns_error_without_unwinding() {
        let protocol = PcsProtocol::new(32, 1).unwrap();
        let output = protocol
            .prove(&[0x55; 32], vectors(1, 32), arbitrary_points(1, 5))
            .unwrap();
        let len = output.certificate.narg_string.len();
        assert!(len > 1);

        for index in [0, 1, len / 4, len / 2, 3 * len / 4, len - 1] {
            let mut malformed = output.certificate.clone();
            malformed.narg_string[index] ^= 1;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                protocol.verify(&[0x55; 32], &output.claims, &malformed)
            }));
            assert!(
                result.is_ok(),
                "malformed transcript unwound at byte {index}"
            );
            assert!(
                result.unwrap().is_err(),
                "mutation at byte {index} was accepted"
            );
        }
    }

    #[test]
    fn trailing_inner_whir_material_is_rejected() {
        let protocol = PcsProtocol::new(32, 1).unwrap();
        let output = protocol
            .prove(&[0x66; 32], vectors(1, 32), arbitrary_points(1, 5))
            .unwrap();
        let mut certificate = output.certificate;
        certificate.narg_string.push(0);
        assert!(
            protocol
                .verify(&[0x66; 32], &output.claims, &certificate)
                .is_err()
        );
    }

    #[test]
    fn signed_i128_encoding_preserves_additive_inverse() {
        let positive = encode_i128(i128::MAX);
        let negative = encode_i128(-i128::MAX);
        assert_eq!(positive + negative, PcsField::from(0_u64));
        assert_eq!(encode_i128(i128::MIN), -PcsField::from(1_u128 << 127));
    }
}
