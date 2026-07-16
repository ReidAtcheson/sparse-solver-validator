//! Strict, proof-system-independent solution-vector input.
//!
//! JSON is an interchange format for solver output. Proof artifacts use the
//! validated binary64 bits so parsing behavior is never part of verification.

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{self, Read, Write};

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use thiserror::Error;

const SCHEMA: &str = "sparse-solve/solution/binary64-v1";
const MAX_DECIMAL_BYTES: usize = 128;
const JSON_FIXED_ALLOWANCE: usize = 1024;
const JSON_BYTES_PER_VALUE: usize = MAX_DECIMAL_BYTES + 8;
const RESERVE_CHUNK: usize = 4096;

/// A validated, contiguous binary64 solution vector.
#[derive(Clone, PartialEq)]
pub struct Solution {
    values: Box<[f64]>,
}

impl fmt::Debug for Solution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Solution")
            .field("length", &self.values.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum SolutionError {
    #[error("could not write solution JSON: {0}")]
    Write(#[from] io::Error),
    #[error("solution JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported solution schema")]
    UnsupportedSchema,
    #[error("solution has {actual} values but the problem requires {expected}")]
    WrongLength { expected: usize, actual: usize },
    #[error("solution value {index} is not a valid bounded binary64 decimal string")]
    InvalidDecimal { index: usize },
    #[error("solution value {index} is NaN or infinite")]
    NonFinite { index: usize },
    #[error("solution value {index} is negative zero")]
    NegativeZero { index: usize },
    #[error("solution value {index} is subnormal")]
    Subnormal { index: usize },
}

struct ParsedDocument {
    values: Vec<f64>,
}

impl Solution {
    /// Validates values under the repository's strict binary64 source policy.
    pub fn new(values: Vec<f64>, expected_len: usize) -> Result<Self, SolutionError> {
        if values.len() != expected_len {
            return Err(SolutionError::WrongLength {
                expected: expected_len,
                actual: values.len(),
            });
        }
        for (index, value) in values.iter().copied().enumerate() {
            validate_value(index, value)?;
        }
        Ok(Self {
            values: values.into_boxed_slice(),
        })
    }

    pub fn from_json(bytes: &[u8], expected_len: usize) -> Result<Self, SolutionError> {
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let document = SolutionDocumentSeed { expected_len }.deserialize(&mut deserializer)?;
        deserializer.end()?;
        Ok(Self {
            values: document.values.into_boxed_slice(),
        })
    }

    /// Parses directly from a reader without retaining the complete JSON file.
    pub fn from_json_reader(reader: impl Read, expected_len: usize) -> Result<Self, SolutionError> {
        let mut deserializer = serde_json::Deserializer::from_reader(reader);
        let document = SolutionDocumentSeed { expected_len }.deserialize(&mut deserializer)?;
        deserializer.end()?;
        Ok(Self {
            values: document.values.into_boxed_slice(),
        })
    }

    pub fn from_bits(bits: Vec<u64>, expected_len: usize) -> Result<Self, SolutionError> {
        let values = bits.into_iter().map(f64::from_bits).collect();
        Self::new(values, expected_len)
    }

    /// Conservative input-file cap for a solution of the expected length.
    #[must_use]
    pub const fn maximum_json_bytes(expected_len: usize) -> usize {
        JSON_FIXED_ALLOWANCE.saturating_add(expected_len.saturating_mul(JSON_BYTES_PER_VALUE))
    }

    /// Streams canonical human-readable JSON without allocating one string per value.
    pub fn write_json(&self, mut output: impl Write) -> io::Result<()> {
        write_json_values(&mut output, self.values.iter().copied())
    }

    /// Streams a repeated solution value without materializing the vector.
    pub fn write_repeated_json(
        mut output: impl Write,
        value: f64,
        count: usize,
    ) -> Result<(), SolutionError> {
        validate_value(0, value)?;
        write_json_values(&mut output, std::iter::repeat_n(value, count))?;
        Ok(())
    }

    pub fn to_pretty_json(&self) -> io::Result<Vec<u8>> {
        let mut output = Vec::new();
        self.write_json(&mut output)?;
        Ok(output)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[f64] {
        &self.values
    }

    #[must_use]
    pub fn into_boxed_slice(self) -> Box<[f64]> {
        self.values
    }
}

fn write_json_values(
    output: &mut impl Write,
    values: impl IntoIterator<Item = f64>,
) -> io::Result<()> {
    output.write_all(b"{\n  \"schema\": \"")?;
    output.write_all(SCHEMA.as_bytes())?;
    output.write_all(b"\",\n  \"values\": [")?;
    let mut count = 0_usize;
    for (index, value) in values.into_iter().enumerate() {
        if index == 0 {
            output.write_all(b"\n")?;
        } else {
            output.write_all(b",\n")?;
        }
        write!(output, "    \"{value}\"")?;
        count += 1;
    }
    if count == 0 {
        output.write_all(b"]\n}\n")?;
    } else {
        output.write_all(b"\n  ]\n}\n")?;
    }
    Ok(())
}

struct SolutionDocumentSeed {
    expected_len: usize,
}

impl<'de> DeserializeSeed<'de> for SolutionDocumentSeed {
    type Value = ParsedDocument;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(SolutionDocumentVisitor {
            expected_len: self.expected_len,
        })
    }
}

struct SolutionDocumentVisitor {
    expected_len: usize,
}

impl<'de> Visitor<'de> for SolutionDocumentVisitor {
    type Value = ParsedDocument;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a solution object containing schema and values")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut schema_seen = false;
        let mut values = None;
        while let Some(field) = map.next_key::<SolutionField>()? {
            match field {
                SolutionField::Schema => {
                    if schema_seen {
                        return Err(de::Error::duplicate_field("schema"));
                    }
                    map.next_value_seed(SolutionSchemaSeed)?;
                    schema_seen = true;
                }
                SolutionField::Values => {
                    if values.is_some() {
                        return Err(de::Error::duplicate_field("values"));
                    }
                    values = Some(map.next_value_seed(SolutionValuesSeed {
                        expected_len: self.expected_len,
                    })?);
                }
            }
        }
        if !schema_seen {
            return Err(de::Error::missing_field("schema"));
        }
        Ok(ParsedDocument {
            values: values.ok_or_else(|| de::Error::missing_field("values"))?,
        })
    }
}

enum SolutionField {
    Schema,
    Values,
}

impl<'de> de::Deserialize<'de> for SolutionField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_identifier(SolutionFieldVisitor)
    }
}

struct SolutionFieldVisitor;

impl Visitor<'_> for SolutionFieldVisitor {
    type Value = SolutionField;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the schema or values field")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match value {
            "schema" => Ok(SolutionField::Schema),
            "values" => Ok(SolutionField::Values),
            _ => Err(E::custom("unknown solution field")),
        }
    }
}

struct SolutionSchemaSeed;

impl<'de> DeserializeSeed<'de> for SolutionSchemaSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(SolutionSchemaVisitor)
    }
}

struct SolutionSchemaVisitor;

impl Visitor<'_> for SolutionSchemaVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the supported solution schema")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value == SCHEMA {
            Ok(())
        } else {
            Err(E::custom(SolutionError::UnsupportedSchema))
        }
    }
}

struct SolutionValuesSeed {
    expected_len: usize,
}

impl<'de> DeserializeSeed<'de> for SolutionValuesSeed {
    type Value = Vec<f64>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(SolutionValuesVisitor {
            expected_len: self.expected_len,
        })
    }
}

struct SolutionValuesVisitor {
    expected_len: usize,
}

impl<'de> Visitor<'de> for SolutionValuesVisitor {
    type Value = Vec<f64>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "exactly {} bounded decimal strings",
            self.expected_len
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|size| size > self.expected_len)
        {
            return Err(de::Error::custom(
                "solution value count exceeds the problem dimension",
            ));
        }
        let mut values = Vec::new();
        while values.len() < self.expected_len {
            if values.len() == values.capacity() {
                let additional = (self.expected_len - values.len()).min(RESERVE_CHUNK);
                values
                    .try_reserve(additional)
                    .map_err(|_| de::Error::custom("could not allocate bounded solution vector"))?;
            }
            let index = values.len();
            let Some(value) = sequence.next_element_seed(DecimalValueSeed { index })? else {
                return Err(de::Error::custom(format_args!(
                    "solution has {index} values but requires {}",
                    self.expected_len
                )));
            };
            values.push(value);
        }
        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(format_args!(
                "solution has more than the required {} values",
                self.expected_len
            )));
        }
        Ok(values)
    }
}

struct DecimalValueSeed {
    index: usize,
}

impl<'de> DeserializeSeed<'de> for DecimalValueSeed {
    type Value = f64;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DecimalValueVisitor { index: self.index })
    }
}

struct DecimalValueVisitor {
    index: usize,
}

impl Visitor<'_> for DecimalValueVisitor {
    type Value = f64;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded binary64 decimal string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value.len() > MAX_DECIMAL_BYTES {
            return Err(E::custom(SolutionError::InvalidDecimal {
                index: self.index,
            }));
        }
        let parsed = value
            .parse::<f64>()
            .map_err(|_| E::custom(SolutionError::InvalidDecimal { index: self.index }))?;
        validate_value(self.index, parsed).map_err(E::custom)?;
        Ok(parsed)
    }
}

fn validate_value(index: usize, value: f64) -> Result<(), SolutionError> {
    if !value.is_finite() {
        return Err(SolutionError::NonFinite { index });
    }
    if value.to_bits() == (-0.0_f64).to_bits() {
        return Err(SolutionError::NegativeZero { index });
    }
    if value != 0.0 && value.is_subnormal() {
        return Err(SolutionError::Subnormal { index });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip() {
        let solution = Solution::new(vec![1.0, -2.5, 0.0], 3).unwrap();
        let encoded = solution.to_pretty_json().unwrap();
        assert_eq!(Solution::from_json(&encoded, 3).unwrap(), solution);
        assert_eq!(
            Solution::from_json_reader(encoded.as_slice(), 3).unwrap(),
            solution
        );
    }

    #[test]
    fn rejects_bad_length_and_noncanonical_values() {
        assert!(matches!(
            Solution::new(vec![1.0], 2),
            Err(SolutionError::WrongLength { .. })
        ));
        assert!(matches!(
            Solution::new(vec![-0.0], 1),
            Err(SolutionError::NegativeZero { index: 0 })
        ));
        assert!(matches!(
            Solution::new(vec![f64::MIN_POSITIVE / 2.0], 1),
            Err(SolutionError::Subnormal { index: 0 })
        ));
    }

    #[test]
    fn rejects_unknown_fields_and_numeric_json_values() {
        let unknown = br#"{"schema":"sparse-solve/solution/binary64-v1","values":["1"],"extra":0}"#;
        assert!(Solution::from_json(unknown, 1).is_err());
        let numeric = br#"{"schema":"sparse-solve/solution/binary64-v1","values":[1]}"#;
        assert!(Solution::from_json(numeric, 1).is_err());
    }

    #[test]
    fn parser_enforces_count_and_decimal_bounds_while_decoding() {
        let short = br#"{"schema":"sparse-solve/solution/binary64-v1","values":["1"]}"#;
        assert!(Solution::from_json(short, 2).is_err());
        let long = br#"{"schema":"sparse-solve/solution/binary64-v1","values":["1","2"]}"#;
        assert!(Solution::from_json(long, 1).is_err());
        let oversized_decimal = format!(
            "{{\"schema\":\"{SCHEMA}\",\"values\":[\"{}\"]}}",
            "1".repeat(MAX_DECIMAL_BYTES + 1)
        );
        assert!(Solution::from_json(oversized_decimal.as_bytes(), 1).is_err());
        assert!(Solution::maximum_json_bytes(2) < Solution::maximum_json_bytes(3));
    }

    #[test]
    fn repeated_writer_streams_without_a_solution_allocation() {
        let mut encoded = Vec::new();
        Solution::write_repeated_json(&mut encoded, 1.0, 3).unwrap();
        assert_eq!(
            Solution::from_json(&encoded, 3).unwrap().as_slice(),
            [1.0, 1.0, 1.0]
        );
    }
}
