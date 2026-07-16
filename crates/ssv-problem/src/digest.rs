use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use ssv_canonical::{CanonicalEncode, Digest, Encoder, domain_separated_digest};

use crate::{FinalizedProblem, ProblemError, ProblemTemplate};

const TEMPLATE_DIGEST_DOMAIN: &[u8] = b"sparse-solve/problem-template/v1";
const PROBLEM_DIGEST_DOMAIN: &[u8] = b"sparse-solve/problem/v1";

/// Digest of a validated problem template before challenge-derived randomness.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProblemTemplateDigest(Digest);

impl ProblemTemplateDigest {
    pub(crate) fn for_template(template: &ProblemTemplate) -> Result<Self, ProblemError> {
        template.validate()?;
        let mut encoder = Encoder::new();
        template.encode(&mut encoder);
        Ok(Self(domain_separated_digest(
            TEMPLATE_DIGEST_DOMAIN,
            &encoder.into_bytes(),
        )))
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Digest::from_bytes(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0.into_bytes()
    }

    pub(crate) const fn inner(&self) -> &Digest {
        &self.0
    }
}

impl Display for ProblemTemplateDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ProblemTemplateDigest {
    type Err = <Digest as FromStr>::Err;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Self)
    }
}

/// Digest of the complete finalized public matrix and right-hand-side recipe.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ProblemDigest(Digest);

impl ProblemDigest {
    pub(crate) fn for_problem(problem: &FinalizedProblem) -> Result<Self, ProblemError> {
        problem.validate()?;
        let mut encoder = Encoder::new();
        problem.encode(&mut encoder);
        Ok(Self(domain_separated_digest(
            PROBLEM_DIGEST_DOMAIN,
            &encoder.into_bytes(),
        )))
    }

    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Digest::from_bytes(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0.into_bytes()
    }
}

impl Display for ProblemDigest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ProblemDigest {
    type Err = <Digest as FromStr>::Err;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Self)
    }
}
