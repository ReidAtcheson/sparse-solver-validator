//! Length-delimited BLAKE3 Fiat--Shamir transcript for metric protocols.
//!
//! Every record carries a semantic tag and an unambiguous length. Challenge
//! draws ratchet state, so changing type, order, bound, or tag changes every
//! later challenge. Domains and byte order are frozen from
//! `fast-validation/src/transcript.rs` at research revision
//! `be8b67b74da54d162df2e6e0a9d813779959bb60`.

use thiserror::Error;

const TRANSCRIPT_DOMAIN: &[u8] = b"sparse-solution/fast-validation/transcript/v1";
const ABSORB_BYTES_DOMAIN: &[u8] = b"sparse-solution/fast-validation/transcript/absorb-bytes/v1";
const ABSORB_U64_DOMAIN: &[u8] = b"sparse-solution/fast-validation/transcript/absorb-u64/v1";
const ABSORB_ROOT_DOMAIN: &[u8] = b"sparse-solution/fast-validation/transcript/absorb-root/v1";
const CHALLENGE_DERIVE_DOMAIN: &[u8] =
    b"sparse-solution/fast-validation/transcript/challenge-derive/v1";
const CHALLENGE_RATCHET_DOMAIN: &[u8] =
    b"sparse-solution/fast-validation/transcript/challenge-ratchet/v1";
const USIZE_CHALLENGE_KIND: &[u8] = b"query-index/v1";
const DYADIC_CHALLENGE_KIND: &[u8] = b"dyadic-f64/v1";
const DYADIC_RANDOM_BITS: u32 = 52;

/// Deterministic transcript state shared by a prover and validator.
#[derive(Clone, Debug)]
pub struct Transcript {
    state: blake3::Hasher,
    challenge_counter: u64,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum TranscriptError {
    #[error("a query domain cannot be empty")]
    EmptyQueryDomain,
    #[error("query domain size {0} does not fit in u64")]
    QueryDomainTooLarge(usize),
    #[error("transcript challenge counter overflow")]
    ChallengeCounterOverflow,
    #[error("query rejection counter overflow")]
    RejectionCounterOverflow,
}

impl Transcript {
    /// Starts a transcript under a caller-selected protocol or phase label.
    #[must_use]
    pub fn new(protocol_label: &[u8]) -> Self {
        let mut state = blake3::Hasher::new();
        update_field(&mut state, TRANSCRIPT_DOMAIN);
        update_field(&mut state, protocol_label);
        Self {
            state,
            challenge_counter: 0,
        }
    }

    /// Absorbs an arbitrary byte string under a semantic tag.
    pub fn absorb(&mut self, tag: &[u8], bytes: &[u8]) {
        self.absorb_bytes(tag, bytes);
    }

    /// Absorbs an arbitrary byte string under a semantic tag.
    pub fn absorb_bytes(&mut self, tag: &[u8], bytes: &[u8]) {
        update_field(&mut self.state, ABSORB_BYTES_DOMAIN);
        update_field(&mut self.state, tag);
        update_field(&mut self.state, bytes);
    }

    /// Absorbs one little-endian integer under a semantic tag.
    pub fn absorb_u64(&mut self, tag: &[u8], value: u64) {
        update_field(&mut self.state, ABSORB_U64_DOMAIN);
        update_field(&mut self.state, tag);
        self.state.update(&value.to_le_bytes());
    }

    /// Absorbs one 32-byte commitment root under a distinct record type.
    pub fn absorb_root(&mut self, tag: &[u8], root: &[u8; 32]) {
        update_field(&mut self.state, ABSORB_ROOT_DOMAIN);
        update_field(&mut self.state, tag);
        self.state.update(root);
    }

    /// Returns a stable digest for audit logs and binding child phases.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        *self.state.clone().finalize().as_bytes()
    }

    /// Draws an unbiased index in `0..upper_bound` using rejection sampling.
    pub fn challenge_usize(
        &mut self,
        tag: &[u8],
        upper_bound: usize,
    ) -> Result<usize, TranscriptError> {
        if upper_bound == 0 {
            return Err(TranscriptError::EmptyQueryDomain);
        }
        let bound = u64::try_from(upper_bound)
            .map_err(|_| TranscriptError::QueryDomainTooLarge(upper_bound))?;
        let counter = self.reserve_challenge_counter()?;

        // `threshold == 2^64 mod bound`. Discarding lower samples leaves an
        // integer number of equally sized residue classes.
        let threshold = bound.wrapping_neg() % bound;
        let mut rejection_counter = 0_u64;
        loop {
            let sample =
                self.derive_u64(USIZE_CHALLENGE_KIND, tag, counter, rejection_counter, bound);
            if sample >= threshold {
                let result = sample % bound;
                let mut result_record = [0_u8; 16];
                result_record[..8].copy_from_slice(&sample.to_le_bytes());
                result_record[8..].copy_from_slice(&result.to_le_bytes());
                self.ratchet_challenge(
                    USIZE_CHALLENGE_KIND,
                    tag,
                    counter,
                    rejection_counter,
                    bound,
                    &result_record,
                );
                return usize::try_from(result)
                    .map_err(|_| TranscriptError::QueryDomainTooLarge(upper_bound));
            }
            rejection_counter = rejection_counter
                .checked_add(1)
                .ok_or(TranscriptError::RejectionCounterOverflow)?;
        }
    }

    /// Draws an exactly representable binary64 dyadic in `[1/4, 3/4)`.
    ///
    /// The challenge is `1/4 + k * 2^-53` for a uniformly hashed 52-bit `k`.
    pub fn challenge_dyadic_f64(&mut self, tag: &[u8]) -> Result<f64, TranscriptError> {
        let counter = self.reserve_challenge_counter()?;
        let sample = self.derive_u64(
            DYADIC_CHALLENGE_KIND,
            tag,
            counter,
            0,
            u64::from(DYADIC_RANDOM_BITS),
        );
        let numerator = sample & ((1_u64 << DYADIC_RANDOM_BITS) - 1);
        self.ratchet_challenge(
            DYADIC_CHALLENGE_KIND,
            tag,
            counter,
            0,
            u64::from(DYADIC_RANDOM_BITS),
            &numerator.to_le_bytes(),
        );

        let challenge = 0.25 + (numerator as f64) / ((1_u64 << 53) as f64);
        debug_assert!((0.25..0.75).contains(&challenge));
        Ok(challenge)
    }

    fn reserve_challenge_counter(&mut self) -> Result<u64, TranscriptError> {
        let counter = self.challenge_counter;
        self.challenge_counter = self
            .challenge_counter
            .checked_add(1)
            .ok_or(TranscriptError::ChallengeCounterOverflow)?;
        Ok(counter)
    }

    fn derive_u64(
        &self,
        kind: &[u8],
        tag: &[u8],
        counter: u64,
        rejection_counter: u64,
        parameter: u64,
    ) -> u64 {
        let mut state = self.state.clone();
        update_field(&mut state, CHALLENGE_DERIVE_DOMAIN);
        update_field(&mut state, kind);
        update_field(&mut state, tag);
        state.update(&counter.to_le_bytes());
        state.update(&rejection_counter.to_le_bytes());
        state.update(&parameter.to_le_bytes());
        let hash = state.finalize();
        let mut prefix = [0_u8; 8];
        prefix.copy_from_slice(&hash.as_bytes()[..8]);
        u64::from_le_bytes(prefix)
    }

    fn ratchet_challenge(
        &mut self,
        kind: &[u8],
        tag: &[u8],
        counter: u64,
        rejection_counter: u64,
        parameter: u64,
        result: &[u8],
    ) {
        update_field(&mut self.state, CHALLENGE_RATCHET_DOMAIN);
        update_field(&mut self.state, kind);
        update_field(&mut self.state, tag);
        self.state.update(&counter.to_le_bytes());
        self.state.update(&rejection_counter.to_le_bytes());
        self.state.update(&parameter.to_le_bytes());
        update_field(&mut self.state, result);
    }
}

fn update_field(state: &mut blake3::Hasher, value: &[u8]) {
    state.update(&(value.len() as u64).to_le_bytes());
    state.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Transcript {
        let mut transcript = Transcript::new(b"fast-validation-test/v1");
        transcript.absorb_bytes(b"statement", b"canonical problem bytes");
        transcript.absorb_u64(b"rows", 4096);
        transcript.absorb_root(b"solution-root", &[0x5a; 32]);
        transcript
    }

    #[test]
    fn deterministic_clones_draw_identical_challenges() {
        let mut left = fixture();
        let mut right = left.clone();
        for _ in 0..32 {
            assert_eq!(
                left.challenge_usize(b"proximity-query", 10_003).unwrap(),
                right.challenge_usize(b"proximity-query", 10_003).unwrap()
            );
            assert_eq!(
                left.challenge_dyadic_f64(b"sumcheck-round")
                    .unwrap()
                    .to_bits(),
                right
                    .challenge_dyadic_f64(b"sumcheck-round")
                    .unwrap()
                    .to_bits()
            );
        }
        assert_eq!(left.digest(), right.digest());
    }

    #[test]
    fn absorb_type_length_order_and_challenge_order_are_bound() {
        let baseline = fixture().digest();

        let mut changed_order = Transcript::new(b"fast-validation-test/v1");
        changed_order.absorb_u64(b"rows", 4096);
        changed_order.absorb_bytes(b"statement", b"canonical problem bytes");
        changed_order.absorb_root(b"solution-root", &[0x5a; 32]);
        assert_ne!(baseline, changed_order.digest());

        let mut changed_split = Transcript::new(b"fast-validation-test/v1");
        changed_split.absorb_bytes(b"statement", b"canonical problem ");
        changed_split.absorb_bytes(b"statement", b"bytes");
        changed_split.absorb_u64(b"rows", 4096);
        changed_split.absorb_root(b"solution-root", &[0x5a; 32]);
        assert_ne!(baseline, changed_split.digest());

        let mut bytes_instead_of_integer = Transcript::new(b"fast-validation-test/v1");
        bytes_instead_of_integer.absorb_bytes(b"statement", b"canonical problem bytes");
        bytes_instead_of_integer.absorb_bytes(b"rows", &4096_u64.to_le_bytes());
        bytes_instead_of_integer.absorb_root(b"solution-root", &[0x5a; 32]);
        assert_ne!(baseline, bytes_instead_of_integer.digest());

        let mut first = fixture();
        let mut second = fixture();
        let first_index = first.challenge_usize(b"query", 97).unwrap();
        let first_float = first.challenge_dyadic_f64(b"round").unwrap();
        let second_float = second.challenge_dyadic_f64(b"round").unwrap();
        let second_index = second.challenge_usize(b"query", 97).unwrap();
        assert_ne!(first.digest(), second.digest());
        assert_ne!(
            (first_index, first_float.to_bits()),
            (second_index, second_float.to_bits())
        );
    }

    #[test]
    fn query_bounds_tags_and_draw_counters_are_bound() {
        let mut a = fixture();
        let mut b = fixture();
        let mut c = fixture();
        let a0 = a.challenge_usize(b"query-a", 101).unwrap();
        let a1 = a.challenge_usize(b"query-a", 101).unwrap();
        let b0 = b.challenge_usize(b"query-b", 101).unwrap();
        let c0 = c.challenge_usize(b"query-a", 103).unwrap();
        assert!(a0 < 101 && a1 < 101 && b0 < 101 && c0 < 103);
        assert_ne!(a.digest(), b.digest());
        assert_ne!(a.digest(), c.digest());
    }

    #[test]
    fn dyadic_challenges_are_exact_and_conditioned() {
        let mut transcript = fixture();
        for _ in 0..10_000 {
            let challenge = transcript.challenge_dyadic_f64(b"round").unwrap();
            assert!((0.25..0.75).contains(&challenge));
            assert_eq!(
                challenge * ((1_u64 << 53) as f64),
                (challenge * ((1_u64 << 53) as f64)).round()
            );
        }
    }

    #[test]
    fn empty_query_domain_is_rejected_without_advancing_state() {
        let mut transcript = fixture();
        let before = transcript.digest();
        assert_eq!(
            transcript.challenge_usize(b"query", 0),
            Err(TranscriptError::EmptyQueryDomain)
        );
        assert_eq!(before, transcript.digest());
    }

    #[test]
    fn golden_transcript_is_stable() {
        let mut transcript = fixture();
        let index = transcript
            .challenge_usize(b"proximity-query", 65_537)
            .unwrap();
        let challenge = transcript.challenge_dyadic_f64(b"sumcheck-round").unwrap();

        assert_eq!(index, 196);
        assert_eq!(challenge.to_bits(), 4_604_906_413_741_683_725);
        assert_eq!(
            transcript.digest(),
            [
                252, 152, 6, 161, 229, 55, 28, 149, 36, 165, 86, 229, 24, 114, 227, 30, 92, 183,
                41, 202, 136, 44, 110, 72, 83, 60, 90, 227, 239, 113, 161, 192,
            ]
        );
    }
}
