"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  DIA_FAMILY,
  MAX_DIA_OFFSETS,
  MAX_SAFE_MANTISSA,
  TRIDIAGONAL_FAMILY,
  matrixSpec,
  parseOffsets,
  problemTemplate,
  structuralNonzeros,
  validationError,
} = require("../../pages/explorer.js");

function parameters(overrides = {}) {
  return {
    family: TRIDIAGONAL_FAMILY,
    dimension: 16,
    offsets: [1, 4],
    periodBits: 3,
    fractionalBits: 8,
    margin: 32,
    minimum: 8,
    maximum: 24,
    rhs: "manufactured-ones-v1",
    ...overrides,
  };
}

test("the legacy tridiagonal template remains unchanged", () => {
  const p = parameters();
  assert.equal(validationError(p), "");
  assert.equal(structuralNonzeros(p), 46);
  assert.deepEqual(matrixSpec(p), {
    kind: TRIDIAGONAL_FAMILY,
    dimension: 16,
    boundary: "truncate-v1",
    off_diagonal: {
      kind: "seeded-periodic-negative-dyadic-v1",
      period_bits: 3,
      fractional_bits: 8,
      minimum_magnitude_mantissa: "8",
      maximum_magnitude_mantissa: "24",
    },
    diagonal: {
      kind: "absolute-row-sum-plus-margin-v1",
      margin_mantissa: "32",
    },
  });
});

test("DIA templates preserve noncontiguous offsets and exact string mantissas", () => {
  const p = parameters({
    family: DIA_FAMILY,
    dimension: 65,
    offsets: parseOffsets("1, 64"),
  });
  assert.equal(validationError(p), "");
  assert.equal(structuralNonzeros(p), 195);
  assert.deepEqual(matrixSpec(p), {
    kind: DIA_FAMILY,
    dimension: 65,
    boundary: "truncate-v1",
    fractional_bits: 8,
    diagonal_shift_mantissa: "32",
    edge_diagonals: [
      {
        positive_offset: 1,
        period_bits: 3,
        minimum_weight_mantissa: "8",
        maximum_weight_mantissa: "24",
      },
      {
        positive_offset: 64,
        period_bits: 3,
        minimum_weight_mantissa: "8",
        maximum_weight_mantissa: "24",
      },
    ],
  });

  const template = problemTemplate(p, "challenge");
  assert.deepEqual(template.randomness, {
    kind: "challenge-derived-v1",
    derivation: "blake3-xof-v1",
  });
  assert.equal(template.matrix.kind, DIA_FAMILY);
});

test("DIA offset validation matches the registered schema boundary", () => {
  const dia = (offsets, overrides = {}) => parameters({
    family: DIA_FAMILY,
    dimension: 65,
    offsets,
    ...overrides,
  });

  assert.match(validationError(dia([])), /at least one/);
  assert.match(validationError(dia(parseOffsets("1, nope"))), /comma-separated integers/);
  assert.match(validationError(dia([0, 1])), /positive/);
  assert.match(validationError(dia([1, 65])), /smaller than the dimension/);
  assert.match(validationError(dia([1, 1])), /strictly increasing/);
  assert.match(validationError(dia([4, 1])), /strictly increasing/);
  assert.match(
    validationError(dia(Array.from({ length: MAX_DIA_OFFSETS + 1 }, (_, index) => index + 1))),
    /At most 16/,
  );
});

test("family-specific diagonal bounds are checked without binary64 rounding", () => {
  assert.match(
    validationError(parameters({
      maximum: MAX_SAFE_MANTISSA,
      margin: 1,
    })),
    /maximum possible diagonal/,
  );
  assert.match(
    validationError(parameters({
      family: DIA_FAMILY,
      dimension: 8,
      offsets: [1, 3],
      maximum: Math.floor(MAX_SAFE_MANTISSA / 4),
      margin: 4,
    })),
    /maximum possible diagonal/,
  );
});
