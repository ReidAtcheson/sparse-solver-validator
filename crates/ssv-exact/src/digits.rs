use std::sync::OnceLock;

use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use num_bigint::BigUint;
use ssv_relation::RESIDUAL_MAGNITUDE_BITS;
use ssv_whir_pcs::PcsField;
use thiserror::Error;

pub const WITNESS_NIBBLE_COLUMNS: usize = 31;
pub const WITNESS_TABLE_COLUMNS: usize = WITNESS_NIBBLE_COLUMNS + 2;
pub const RESIDUAL_NIBBLE_COLUMNS: usize = 17;
pub const RESIDUAL_TABLE_COLUMNS: usize = RESIDUAL_NIBBLE_COLUMNS + 1;
pub const COMMITTED_DIGIT_COLUMNS: usize = WITNESS_TABLE_COLUMNS + RESIDUAL_TABLE_COLUMNS;
pub const SELECTOR_VARIABLES: usize = 6;
pub const SELECTOR_SLOTS: usize = 1 << SELECTOR_VARIABLES;

static WITNESS_RECONSTRUCTION_WEIGHTS: OnceLock<[PcsField; WITNESS_TABLE_COLUMNS]> =
    OnceLock::new();
static RESIDUAL_RECONSTRUCTION_WEIGHTS: OnceLock<[PcsField; RESIDUAL_TABLE_COLUMNS]> =
    OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessDigitTables {
    nibbles: [Vec<PcsField>; WITNESS_NIBBLE_COLUMNS],
    top_three: Vec<PcsField>,
    sign: Vec<PcsField>,
    logical_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResidualDigitTables {
    nibbles: [Vec<PcsField>; RESIDUAL_NIBBLE_COLUMNS],
    sign: Vec<PcsField>,
    logical_len: usize,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum DigitError {
    #[error("digit table length {0} is not a nonzero power of two")]
    TableLength(usize),
    #[error("requested padded length {padded} cannot contain logical length {logical}")]
    InvalidPadding { logical: usize, padded: usize },
    #[error("MLE point has {actual} coordinates; expected {expected}")]
    PointDimension { expected: usize, actual: usize },
    #[error("residual value at row {row} lies outside the signed 69-bit profile")]
    ResidualRange { row: usize },
    #[error("digit evaluation block has {actual} values; expected {expected}")]
    EvaluationCount { expected: usize, actual: usize },
    #[error("packed selector column is outside the committed digit layout")]
    SelectorColumn,
    #[error("integer does not fit canonically in Field192")]
    IntegerExceedsField,
    #[error("size arithmetic overflow")]
    SizeOverflow,
}

impl WitnessDigitTables {
    pub fn from_i128(values: &[i128], padded_len: usize) -> Result<Self, DigitError> {
        validate_padding(values.len(), padded_len)?;
        let mut nibbles = std::array::from_fn(|_| vec![PcsField::ZERO; padded_len]);
        let mut top_three = vec![PcsField::ZERO; padded_len];
        let mut sign = vec![PcsField::ZERO; padded_len];
        for (row, &value) in values.iter().enumerate() {
            let encoded = value as u128;
            for (column, table) in nibbles.iter_mut().enumerate() {
                table[row] = PcsField::from(((encoded >> (4 * column)) & 0x0f) as u64);
            }
            top_three[row] = PcsField::from(((encoded >> 124) & 0x07) as u64);
            sign[row] = PcsField::from(((encoded >> 127) & 1) as u64);
        }
        Ok(Self {
            nibbles,
            top_three,
            sign,
            logical_len: values.len(),
        })
    }

    #[must_use]
    pub const fn logical_len(&self) -> usize {
        self.logical_len
    }

    #[must_use]
    pub fn padded_len(&self) -> usize {
        self.sign.len()
    }

    #[must_use]
    pub fn ordered_tables(&self) -> Vec<&[PcsField]> {
        self.nibbles
            .iter()
            .map(Vec::as_slice)
            .chain([self.top_three.as_slice(), self.sign.as_slice()])
            .collect()
    }

    pub fn evaluate_digits(&self, point: &[PcsField]) -> Result<Vec<PcsField>, DigitError> {
        self.ordered_tables()
            .into_iter()
            .map(|table| evaluate_mle(table, point))
            .collect()
    }

    pub fn reconstructed_table(&self) -> Vec<PcsField> {
        (0..self.padded_len())
            .map(|row| {
                let mut values = [PcsField::ZERO; WITNESS_TABLE_COLUMNS];
                for (column, table) in self.nibbles.iter().enumerate() {
                    values[column] = table[row];
                }
                values[WITNESS_NIBBLE_COLUMNS] = self.top_three[row];
                values[WITNESS_TABLE_COLUMNS - 1] = self.sign[row];
                reconstruct_witness_unchecked(&values)
            })
            .collect()
    }
}

impl ResidualDigitTables {
    pub fn from_i128(values: &[i128], padded_len: usize) -> Result<Self, DigitError> {
        validate_padding(values.len(), padded_len)?;
        let mut nibbles = std::array::from_fn(|_| vec![PcsField::ZERO; padded_len]);
        let mut sign = vec![PcsField::ZERO; padded_len];
        let modulus = 1_i128 << (RESIDUAL_MAGNITUDE_BITS + 1);
        let minimum = -(1_i128 << RESIDUAL_MAGNITUDE_BITS);
        let maximum = (1_i128 << RESIDUAL_MAGNITUDE_BITS) - 1;
        for (row, &value) in values.iter().enumerate() {
            if !(minimum..=maximum).contains(&value) {
                return Err(DigitError::ResidualRange { row });
            }
            let encoded = if value < 0 { modulus + value } else { value } as u128;
            for (column, table) in nibbles.iter_mut().enumerate() {
                table[row] = PcsField::from(((encoded >> (4 * column)) & 0x0f) as u64);
            }
            sign[row] = PcsField::from(((encoded >> 68) & 1) as u64);
        }
        Ok(Self {
            nibbles,
            sign,
            logical_len: values.len(),
        })
    }

    #[must_use]
    pub const fn logical_len(&self) -> usize {
        self.logical_len
    }

    #[must_use]
    pub fn padded_len(&self) -> usize {
        self.sign.len()
    }

    #[must_use]
    pub fn ordered_tables(&self) -> Vec<&[PcsField]> {
        self.nibbles
            .iter()
            .map(Vec::as_slice)
            .chain([self.sign.as_slice()])
            .collect()
    }

    pub fn evaluate_digits(&self, point: &[PcsField]) -> Result<Vec<PcsField>, DigitError> {
        self.ordered_tables()
            .into_iter()
            .map(|table| evaluate_mle(table, point))
            .collect()
    }

    pub fn reconstructed_table(&self) -> Vec<PcsField> {
        (0..self.padded_len())
            .map(|row| {
                let mut values = [PcsField::ZERO; RESIDUAL_TABLE_COLUMNS];
                for (column, table) in self.nibbles.iter().enumerate() {
                    values[column] = table[row];
                }
                values[RESIDUAL_TABLE_COLUMNS - 1] = self.sign[row];
                reconstruct_residual_unchecked(&values)
            })
            .collect()
    }
}

pub fn reconstruct_witness(values: &[PcsField]) -> Result<PcsField, DigitError> {
    if values.len() != WITNESS_TABLE_COLUMNS {
        return Err(DigitError::EvaluationCount {
            expected: WITNESS_TABLE_COLUMNS,
            actual: values.len(),
        });
    }
    Ok(reconstruct_witness_unchecked(values))
}

pub(crate) fn reconstruct_witness_unchecked(values: &[PcsField]) -> PcsField {
    values
        .iter()
        .zip(witness_reconstruction_weights())
        .map(|(&value, &weight)| value * weight)
        .sum()
}

pub fn reconstruct_residual(values: &[PcsField]) -> Result<PcsField, DigitError> {
    if values.len() != RESIDUAL_TABLE_COLUMNS {
        return Err(DigitError::EvaluationCount {
            expected: RESIDUAL_TABLE_COLUMNS,
            actual: values.len(),
        });
    }
    Ok(reconstruct_residual_unchecked(values))
}

pub(crate) fn reconstruct_residual_unchecked(values: &[PcsField]) -> PcsField {
    values
        .iter()
        .zip(residual_reconstruction_weights())
        .map(|(&value, &weight)| value * weight)
        .sum()
}

pub fn pack_digit_tables(
    witness: &WitnessDigitTables,
    residual: &ResidualDigitTables,
) -> Result<Vec<PcsField>, DigitError> {
    if witness.padded_len() != residual.padded_len() {
        return Err(DigitError::InvalidPadding {
            logical: residual.padded_len(),
            padded: witness.padded_len(),
        });
    }
    let padded_len = witness.padded_len();
    let total = SELECTOR_SLOTS
        .checked_mul(padded_len)
        .ok_or(DigitError::SizeOverflow)?;
    let mut packed = vec![PcsField::ZERO; total];
    for (column, table) in witness
        .ordered_tables()
        .into_iter()
        .chain(residual.ordered_tables())
        .enumerate()
    {
        let start = column
            .checked_mul(padded_len)
            .ok_or(DigitError::SizeOverflow)?;
        packed[start..start + padded_len].copy_from_slice(table);
    }
    Ok(packed)
}

pub fn packed_point(column: usize, row_point: &[PcsField]) -> Result<Vec<PcsField>, DigitError> {
    if column >= COMMITTED_DIGIT_COLUMNS {
        return Err(DigitError::SelectorColumn);
    }
    let mut point = Vec::with_capacity(SELECTOR_VARIABLES + row_point.len());
    for shift in (0..SELECTOR_VARIABLES).rev() {
        point.push(PcsField::from(((column >> shift) & 1) as u64));
    }
    point.extend_from_slice(row_point);
    Ok(point)
}

pub fn evaluate_mle(evaluations: &[PcsField], point: &[PcsField]) -> Result<PcsField, DigitError> {
    if evaluations.is_empty() || !evaluations.len().is_power_of_two() {
        return Err(DigitError::TableLength(evaluations.len()));
    }
    let expected = evaluations.len().ilog2() as usize;
    if point.len() != expected {
        return Err(DigitError::PointDimension {
            expected,
            actual: point.len(),
        });
    }
    let mut folded = evaluations.to_vec();
    for &challenge in point {
        let half = folded.len() / 2;
        for index in 0..half {
            let low = folded[index];
            folded[index] = low + challenge * (folded[index + half] - low);
        }
        folded.truncate(half);
    }
    Ok(folded[0])
}

pub fn field_modulus() -> BigUint {
    BigUint::from_bytes_le(&PcsField::MODULUS.to_bytes_le())
}

pub fn field_from_i128(value: i128) -> PcsField {
    let magnitude = PcsField::from_le_bytes_mod_order(&value.unsigned_abs().to_le_bytes());
    if value < 0 { -magnitude } else { magnitude }
}

pub fn field_from_biguint_checked(value: &BigUint) -> Result<PcsField, DigitError> {
    if value >= &field_modulus() {
        return Err(DigitError::IntegerExceedsField);
    }
    Ok(PcsField::from_le_bytes_mod_order(&value.to_bytes_le()))
}

fn validate_padding(logical: usize, padded: usize) -> Result<(), DigitError> {
    if logical == 0 || !padded.is_power_of_two() || padded < logical {
        return Err(DigitError::InvalidPadding { logical, padded });
    }
    Ok(())
}

fn pow2_field(exponent: usize) -> PcsField {
    let mut value = PcsField::ONE;
    for _ in 0..exponent {
        value += value;
    }
    value
}

fn witness_reconstruction_weights() -> &'static [PcsField; WITNESS_TABLE_COLUMNS] {
    WITNESS_RECONSTRUCTION_WEIGHTS.get_or_init(|| {
        let mut weights = [PcsField::ZERO; WITNESS_TABLE_COLUMNS];
        for (column, weight) in weights[..WITNESS_NIBBLE_COLUMNS].iter_mut().enumerate() {
            *weight = pow2_field(4 * column);
        }
        weights[WITNESS_NIBBLE_COLUMNS] = pow2_field(124);
        weights[WITNESS_TABLE_COLUMNS - 1] = -pow2_field(127);
        weights
    })
}

fn residual_reconstruction_weights() -> &'static [PcsField; RESIDUAL_TABLE_COLUMNS] {
    RESIDUAL_RECONSTRUCTION_WEIGHTS.get_or_init(|| {
        let mut weights = [PcsField::ZERO; RESIDUAL_TABLE_COLUMNS];
        for (column, weight) in weights[..RESIDUAL_NIBBLE_COLUMNS].iter_mut().enumerate() {
            *weight = pow2_field(4 * column);
        }
        weights[RESIDUAL_TABLE_COLUMNS - 1] = -pow2_field(68);
        weights
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_endpoint_values_reconstruct_and_padding_is_zero() {
        let values = [i128::MIN, i128::MAX, -1, 0, 1];
        let tables = WitnessDigitTables::from_i128(&values, 64).unwrap();
        let reconstructed = tables.reconstructed_table();
        for (actual, expected) in reconstructed.iter().zip(values) {
            assert_eq!(*actual, field_from_i128(expected));
        }
        assert!(
            reconstructed[values.len()..]
                .iter()
                .all(|&value| value == PcsField::ZERO)
        );
    }

    #[test]
    fn residual_signed_range_is_exact() {
        let minimum = -(1_i128 << RESIDUAL_MAGNITUDE_BITS);
        let maximum = (1_i128 << RESIDUAL_MAGNITUDE_BITS) - 1;
        let tables = ResidualDigitTables::from_i128(&[minimum, maximum], 64).unwrap();
        let reconstructed = tables.reconstructed_table();
        assert_eq!(reconstructed[0], field_from_i128(minimum));
        assert_eq!(reconstructed[1], field_from_i128(maximum));
        assert!(matches!(
            ResidualDigitTables::from_i128(&[maximum + 1], 64),
            Err(DigitError::ResidualRange { row: 0 })
        ));
    }

    #[test]
    fn reconstruction_commutes_with_msb_first_mle() {
        let values = [7, -4, 11, i128::MIN, 9];
        let tables = WitnessDigitTables::from_i128(&values, 8).unwrap();
        let point = [
            PcsField::from(2_u64),
            PcsField::from(3_u64),
            PcsField::from(5_u64),
        ];
        let digit_values = tables.evaluate_digits(&point).unwrap();
        assert_eq!(
            reconstruct_witness(&digit_values).unwrap(),
            evaluate_mle(&tables.reconstructed_table(), &point).unwrap()
        );
    }

    #[test]
    fn packed_layout_has_64_selector_slots_and_zero_unused_columns() {
        let witness = WitnessDigitTables::from_i128(&[1, -2], 64).unwrap();
        let residual = ResidualDigitTables::from_i128(&[3, -4], 64).unwrap();
        let packed = pack_digit_tables(&witness, &residual).unwrap();
        assert_eq!(packed.len(), 64 * 64);
        assert!(
            packed[COMMITTED_DIGIT_COLUMNS * 64..]
                .iter()
                .all(|&value| value == PcsField::ZERO)
        );
    }
}
