use std::str;

use thiserror::Error;

use crate::Digest;

/// A value with one deterministic canonical byte encoding.
pub trait CanonicalEncode {
    /// Appends the canonical representation of this value to `encoder`.
    fn encode(&self, encoder: &mut Encoder);
}

/// Encodes a value into a newly allocated canonical byte vector.
#[must_use]
pub fn encode_to_vec<T>(value: &T) -> Vec<u8>
where
    T: CanonicalEncode + ?Sized,
{
    let mut encoder = Encoder::new();
    value.encode(&mut encoder);
    encoder.into_bytes()
}

/// An append-only builder for canonical wire bytes.
///
/// Fixed-width integers use big-endian byte order. [`Encoder::write_bytes`]
/// and [`Encoder::write_str`] write a big-endian `u64` byte length followed by
/// the bytes. [`Encoder::write_fixed_bytes`] performs no framing and should be
/// reserved for fields whose width is fixed by their protocol version.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    /// Creates an empty encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Creates an empty encoder with space for at least `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Returns the number of bytes written so far.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Reports whether no bytes have been written.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Borrows all bytes written so far.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the encoder and returns its contiguous byte buffer.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Appends another canonically encodable value.
    pub fn write<T>(&mut self, value: &T)
    where
        T: CanonicalEncode + ?Sized,
    {
        value.encode(self);
    }

    /// Writes a Boolean as exactly one byte: zero for false or one for true.
    pub fn write_bool(&mut self, value: bool) {
        self.bytes.push(u8::from(value));
    }

    /// Writes an unsigned byte.
    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Writes a big-endian `u16`.
    pub fn write_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a big-endian `u32`.
    pub fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a big-endian `u64`.
    pub fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes a big-endian two's-complement `i64`.
    pub fn write_i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Writes bytes without a length prefix.
    pub fn write_fixed_bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    /// Writes a `u64` byte length followed by the provided bytes.
    pub fn write_bytes(&mut self, value: &[u8]) {
        self.write_u64(wire_length(value.len()));
        self.write_fixed_bytes(value);
    }

    /// Writes a `u64` UTF-8 byte length followed by the string bytes.
    pub fn write_str(&mut self, value: &str) {
        self.write_bytes(value.as_bytes());
    }

    /// Writes a digest as exactly 32 bytes, without a length prefix.
    pub fn write_digest(&mut self, value: &Digest) {
        self.write_fixed_bytes(value.as_bytes());
    }
}

fn wire_length(length: usize) -> u64 {
    u64::try_from(length).expect("Rust targets have pointers no wider than the u64 wire length")
}

impl CanonicalEncode for bool {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_bool(*self);
    }
}

impl CanonicalEncode for u8 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_u8(*self);
    }
}

impl CanonicalEncode for u16 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_u16(*self);
    }
}

impl CanonicalEncode for u32 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_u32(*self);
    }
}

impl CanonicalEncode for u64 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_u64(*self);
    }
}

impl CanonicalEncode for i64 {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_i64(*self);
    }
}

impl CanonicalEncode for [u8] {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_bytes(self);
    }
}

impl<const LENGTH: usize> CanonicalEncode for [u8; LENGTH] {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_bytes(self);
    }
}

impl CanonicalEncode for Vec<u8> {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_bytes(self);
    }
}

impl CanonicalEncode for str {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_str(self);
    }
}

impl CanonicalEncode for String {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_str(self);
    }
}

impl CanonicalEncode for Digest {
    fn encode(&self, encoder: &mut Encoder) {
        encoder.write_digest(self);
    }
}

/// Resource limits applied while decoding untrusted bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    /// Maximum accepted size of the complete input slice.
    pub max_input_bytes: usize,
    /// Maximum accepted size of any one length-delimited byte or string field.
    pub max_field_bytes: usize,
}

impl DecodeLimits {
    /// Constructs explicit input and field limits.
    #[must_use]
    pub const fn new(max_input_bytes: usize, max_field_bytes: usize) -> Self {
        Self {
            max_input_bytes,
            max_field_bytes,
        }
    }
}

/// A canonical decoding failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DecodeError {
    /// The complete supplied input exceeded its configured bound.
    #[error("input contains {length} bytes, exceeding the limit of {maximum}")]
    InputTooLarge {
        /// Supplied input size.
        length: usize,
        /// Configured maximum input size.
        maximum: usize,
    },

    /// A fixed-width value or declared payload was truncated.
    #[error("truncated input at offset {offset}: need {needed} bytes but only {remaining} remain")]
    Truncated {
        /// Byte offset at which the read was attempted.
        offset: usize,
        /// Number of bytes required by the read.
        needed: usize,
        /// Number of bytes still available.
        remaining: usize,
    },

    /// A length prefix exceeded the bound for that field or sequence.
    #[error("declared length {length} at offset {offset} exceeds the limit of {maximum}")]
    LengthTooLarge {
        /// Offset of the length prefix.
        offset: usize,
        /// Length declared on the wire.
        length: u64,
        /// Configured maximum length.
        maximum: usize,
    },

    /// A Boolean byte was neither zero nor one.
    #[error("invalid Boolean byte {value} at offset {offset}; expected 0 or 1")]
    InvalidBool {
        /// Offset of the invalid byte.
        offset: usize,
        /// Rejected byte value.
        value: u8,
    },

    /// A length-delimited string was not valid UTF-8.
    #[error("invalid UTF-8 at offset {offset}; valid prefix has {valid_up_to} bytes")]
    InvalidUtf8 {
        /// Offset of the string payload.
        offset: usize,
        /// Valid UTF-8 prefix length reported by the standard decoder.
        valid_up_to: usize,
    },

    /// Bytes remained after the expected final field.
    #[error("{remaining} trailing bytes remain at offset {offset}")]
    TrailingBytes {
        /// Offset immediately after the expected value.
        offset: usize,
        /// Number of unexpected bytes.
        remaining: usize,
    },
}

/// A bounded, allocation-free reader over untrusted canonical bytes.
///
/// Failed fixed-width reads do not advance the cursor. All slicing is checked,
/// so malformed offsets and lengths are returned as [`DecodeError`] values
/// rather than causing panics.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
    limits: DecodeLimits,
}

impl<'a> Reader<'a> {
    /// Creates a reader after validating the complete input-size bound.
    pub fn new(input: &'a [u8], limits: DecodeLimits) -> Result<Self, DecodeError> {
        if input.len() > limits.max_input_bytes {
            return Err(DecodeError::InputTooLarge {
                length: input.len(),
                maximum: limits.max_input_bytes,
            });
        }
        Ok(Self {
            input,
            offset: 0,
            limits,
        })
    }

    /// Returns the current byte offset.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.offset
    }

    /// Returns the number of unread bytes.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.offset)
    }

    /// Reports whether the complete input has been consumed.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.remaining() == 0
    }

    /// Reads a strict one-byte Boolean.
    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        let offset = self.offset;
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(DecodeError::InvalidBool { offset, value }),
        }
    }

    /// Reads an unsigned byte.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.read_array::<1>()?[0])
    }

    /// Reads a big-endian `u16`.
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    /// Reads a big-endian `u32`.
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    /// Reads a big-endian `u64`.
    pub fn read_u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    /// Reads a big-endian two's-complement `i64`.
    pub fn read_i64(&mut self) -> Result<i64, DecodeError> {
        Ok(i64::from_be_bytes(self.read_array()?))
    }

    /// Reads exactly `LENGTH` bytes into an array.
    pub fn read_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], DecodeError> {
        let bytes = self.read_fixed_bytes(LENGTH)?;
        let array = <&[u8; LENGTH]>::try_from(bytes).map_err(|_| DecodeError::Truncated {
            offset: self.offset.saturating_sub(bytes.len()),
            needed: LENGTH,
            remaining: bytes.len(),
        })?;
        Ok(*array)
    }

    /// Borrows exactly `length` bytes without reading a length prefix.
    pub fn read_fixed_bytes(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        let remaining = self.remaining();
        if length > remaining {
            return Err(DecodeError::Truncated {
                offset: self.offset,
                needed: length,
                remaining,
            });
        }

        let Some(end) = self.offset.checked_add(length) else {
            return Err(DecodeError::Truncated {
                offset: self.offset,
                needed: length,
                remaining,
            });
        };
        let Some(bytes) = self.input.get(self.offset..end) else {
            return Err(DecodeError::Truncated {
                offset: self.offset,
                needed: length,
                remaining,
            });
        };
        self.offset = end;
        Ok(bytes)
    }

    /// Reads a `u64` length and validates it against `maximum`.
    ///
    /// This is useful for sequence element counts. Byte and string fields use
    /// the reader's configured `max_field_bytes` through [`Reader::read_bytes`].
    pub fn read_length(&mut self, maximum: usize) -> Result<usize, DecodeError> {
        let offset = self.offset;
        let length = self.read_u64()?;
        let wire_maximum = u64::try_from(maximum).unwrap_or(u64::MAX);
        if length > wire_maximum {
            return Err(DecodeError::LengthTooLarge {
                offset,
                length,
                maximum,
            });
        }
        usize::try_from(length).map_err(|_| DecodeError::LengthTooLarge {
            offset,
            length,
            maximum,
        })
    }

    /// Reads and borrows a length-delimited byte field.
    pub fn read_bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let length = self.read_length(self.limits.max_field_bytes)?;
        self.read_fixed_bytes(length)
    }

    /// Reads and borrows a length-delimited UTF-8 string.
    pub fn read_str(&mut self) -> Result<&'a str, DecodeError> {
        let bytes = self.read_bytes()?;
        let offset = self.offset.saturating_sub(bytes.len());
        str::from_utf8(bytes).map_err(|error| DecodeError::InvalidUtf8 {
            offset,
            valid_up_to: error.valid_up_to(),
        })
    }

    /// Reads a fixed-width digest.
    pub fn read_digest(&mut self) -> Result<Digest, DecodeError> {
        Ok(Digest::from_bytes(self.read_array()?))
    }

    /// Succeeds only when no trailing bytes remain.
    pub fn finish(self) -> Result<(), DecodeError> {
        let remaining = self.remaining();
        if remaining == 0 {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes {
                offset: self.offset,
                remaining,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    const LIMITS: DecodeLimits = DecodeLimits::new(1_024, 128);

    fn encoded_sample() -> Vec<u8> {
        let mut encoder = Encoder::with_capacity(128);
        encoder.write_bool(true);
        encoder.write_u8(0xa5);
        encoder.write_u16(0x1234);
        encoder.write_u32(0x5678_9abc);
        encoder.write_u64(0x0123_4567_89ab_cdef);
        encoder.write_i64(-0x0102_0304_0506_0708);
        encoder.write_bytes(&[1, 2, 3]);
        encoder.write_str("sparse");
        encoder.write_digest(&Digest::from_bytes([0x5a; Digest::LENGTH]));
        encoder.into_bytes()
    }

    fn decode_sample(bytes: &[u8]) -> Result<(), DecodeError> {
        let mut reader = Reader::new(bytes, LIMITS)?;
        let _ = reader.read_bool()?;
        let _ = reader.read_u8()?;
        let _ = reader.read_u16()?;
        let _ = reader.read_u32()?;
        let _ = reader.read_u64()?;
        let _ = reader.read_i64()?;
        let _ = reader.read_bytes()?;
        let _ = reader.read_str()?;
        let _ = reader.read_digest()?;
        reader.finish()
    }

    #[test]
    fn fixed_and_delimited_values_round_trip() {
        let bytes = encoded_sample();
        let mut reader = Reader::new(&bytes, LIMITS).expect("sample should fit limits");

        assert!(reader.read_bool().expect("Boolean should decode"));
        assert_eq!(reader.read_u8().expect("u8 should decode"), 0xa5);
        assert_eq!(reader.read_u16().expect("u16 should decode"), 0x1234);
        assert_eq!(reader.read_u32().expect("u32 should decode"), 0x5678_9abc);
        assert_eq!(
            reader.read_u64().expect("u64 should decode"),
            0x0123_4567_89ab_cdef
        );
        assert_eq!(
            reader.read_i64().expect("i64 should decode"),
            -0x0102_0304_0506_0708
        );
        assert_eq!(reader.read_bytes().expect("bytes should decode"), [1, 2, 3]);
        assert_eq!(reader.read_str().expect("string should decode"), "sparse");
        assert_eq!(
            reader.read_digest().expect("digest should decode"),
            Digest::from_bytes([0x5a; Digest::LENGTH])
        );
        assert!(reader.is_finished());
        reader
            .finish()
            .expect("sample should have no trailing bytes");
    }

    #[test]
    fn canonical_encode_implementations_match_helpers() {
        let digest = Digest::from_bytes([7; Digest::LENGTH]);
        assert_eq!(encode_to_vec(&true), [1]);
        assert_eq!(encode_to_vec(&0x1234_u16), [0x12, 0x34]);
        assert_eq!(
            encode_to_vec("abc"),
            [0, 0, 0, 0, 0, 0, 0, 3, b'a', b'b', b'c']
        );
        assert_eq!(encode_to_vec(&digest), [7; Digest::LENGTH]);
    }

    #[test]
    fn reader_rejects_truncation_at_every_boundary_without_panicking() {
        let bytes = encoded_sample();
        for end in 0..bytes.len() {
            let result = catch_unwind(AssertUnwindSafe(|| decode_sample(&bytes[..end])));
            assert!(result.is_ok(), "decoder panicked for truncation at {end}");
            assert!(
                result.expect("panic checked above").is_err(),
                "truncated input unexpectedly decoded at {end}"
            );
        }
        assert_eq!(decode_sample(&bytes), Ok(()));
    }

    #[test]
    fn reader_handles_single_byte_mutations_without_panicking() {
        let original = encoded_sample();
        for index in 0..original.len() {
            let mut mutated = original.clone();
            mutated[index] ^= 0xff;
            let result = catch_unwind(AssertUnwindSafe(|| decode_sample(&mutated)));
            assert!(result.is_ok(), "decoder panicked after mutation at {index}");
        }
    }

    #[test]
    fn reader_enforces_input_and_field_bounds() {
        let error = Reader::new(&[0; 5], DecodeLimits::new(4, 4))
            .expect_err("oversized input must be rejected");
        assert_eq!(
            error,
            DecodeError::InputTooLarge {
                length: 5,
                maximum: 4
            }
        );

        let mut encoder = Encoder::new();
        encoder.write_bytes(&[1, 2, 3, 4, 5]);
        let bytes = encoder.into_bytes();
        let mut reader =
            Reader::new(&bytes, DecodeLimits::new(bytes.len(), 4)).expect("input bound fits");
        assert_eq!(
            reader.read_bytes(),
            Err(DecodeError::LengthTooLarge {
                offset: 0,
                length: 5,
                maximum: 4
            })
        );
    }

    #[test]
    fn reader_rejects_invalid_bool_utf8_and_trailing_bytes() {
        let mut bool_reader = Reader::new(&[2], LIMITS).expect("input should fit");
        assert_eq!(
            bool_reader.read_bool(),
            Err(DecodeError::InvalidBool {
                offset: 0,
                value: 2
            })
        );

        let mut encoder = Encoder::new();
        encoder.write_bytes(&[0xff]);
        let invalid_utf8 = encoder.into_bytes();
        let mut string_reader = Reader::new(&invalid_utf8, LIMITS).expect("input should fit");
        assert!(matches!(
            string_reader.read_str(),
            Err(DecodeError::InvalidUtf8 { .. })
        ));

        let mut trailing_reader = Reader::new(&[1, 2], LIMITS).expect("input should fit");
        assert_eq!(trailing_reader.read_u8(), Ok(1));
        assert_eq!(
            trailing_reader.finish(),
            Err(DecodeError::TrailingBytes {
                offset: 1,
                remaining: 1
            })
        );
    }

    #[test]
    fn oversized_and_truncated_declared_lengths_are_distinct() {
        let oversized = u64::MAX.to_be_bytes();
        let mut oversized_reader = Reader::new(&oversized, LIMITS).expect("input should fit");
        assert!(matches!(
            oversized_reader.read_bytes(),
            Err(DecodeError::LengthTooLarge { .. })
        ));

        let mut encoder = Encoder::new();
        encoder.write_u64(3);
        encoder.write_fixed_bytes(&[1, 2]);
        let truncated = encoder.into_bytes();
        let mut truncated_reader = Reader::new(&truncated, LIMITS).expect("input should fit");
        assert_eq!(
            truncated_reader.read_bytes(),
            Err(DecodeError::Truncated {
                offset: 8,
                needed: 3,
                remaining: 2
            })
        );
    }
}
