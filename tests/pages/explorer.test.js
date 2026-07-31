"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");

const {
  DIA_FAMILY,
  MAX_DIA_OFFSETS,
  MAX_NONSYMMETRIC_ROW_NONZEROS,
  MAX_SAFE_MANTISSA,
  NONSYMMETRIC_FAMILY,
  SEEDED_RHS_FAMILY,
  TRIDIAGONAL_FAMILY,
  hostedWorkflow,
  localWorkflow,
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
    maximumHalfBandwidth: 5,
    maximumRowNonzeros: 7,
    coefficientMinimum: -256,
    coefficientMaximum: 256,
    rhs: SEEDED_RHS_FAMILY,
    rhsPeriodBits: 4,
    rhsFractionalBits: 8,
    rhsMinimum: -16,
    rhsMaximum: 19,
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

test("templates use a separately parameterized seeded RHS", () => {
  const template = problemTemplate(parameters(), "literal");
  assert.deepEqual(template.rhs, {
    kind: SEEDED_RHS_FAMILY,
    period_bits: 4,
    fractional_bits: 8,
    minimum_mantissa: "-16",
    maximum_mantissa: "19",
  });
  assert.notEqual(template.rhs.kind, "manufactured-ones-v1");
});

test("nonsymmetric templates encode generated row-pattern constraints", () => {
  const p = parameters({ family: NONSYMMETRIC_FAMILY });
  assert.equal(validationError(p), "");
  assert.equal(structuralNonzeros(p), 112);
  assert.equal(
    structuralNonzeros(parameters({
      family: NONSYMMETRIC_FAMILY,
      dimension: 4,
      maximumHalfBandwidth: 3,
      maximumRowNonzeros: 7,
    })),
    16,
  );
  assert.deepEqual(matrixSpec(p), {
    kind: NONSYMMETRIC_FAMILY,
    dimension: 16,
    boundary: "truncate-v1",
    row_pattern_bits: 3,
    maximum_half_bandwidth: 5,
    maximum_nonzeros_per_row: 7,
    fractional_bits: 8,
    minimum_mantissa: "-256",
    maximum_mantissa: "256",
  });
});

test("nonsymmetric controls enforce bandwidth, row width, and the unit interval", () => {
  const sparse = (overrides = {}) => parameters({
    family: NONSYMMETRIC_FAMILY,
    ...overrides,
  });
  assert.match(validationError(sparse({ maximumHalfBandwidth: 16 })), /smaller/);
  assert.match(validationError(sparse({ maximumRowNonzeros: 0 })), /between 1/);
  assert.match(
    validationError(sparse({ maximumRowNonzeros: MAX_NONSYMMETRIC_ROW_NONZEROS + 1 })),
    /between 1/,
  );
  assert.match(
    validationError(sparse({ maximumHalfBandwidth: 1, maximumRowNonzeros: 4 })),
    /available signed offsets/,
  );
  assert.match(
    validationError(sparse({ coefficientMinimum: 1, coefficientMaximum: -1 })),
    /minimum ≤ maximum/,
  );
  assert.match(validationError(sparse({ coefficientMinimum: -257 })), /inside \[-1, 1\]/);
  assert.match(
    validationError(sparse({ coefficientMinimum: 0, coefficientMaximum: 0 })),
    /nonzero/,
  );
});

test("seeded RHS parameters are validated at the registered schema boundary", () => {
  assert.match(validationError(parameters({ rhs: "manufactured-ones-v1" })), /registered/);
  assert.match(validationError(parameters({ rhsPeriodBits: 17 })), /RHS period bits/);
  assert.match(validationError(parameters({ rhsFractionalBits: 53 })), /RHS fractional bits/);
  assert.match(
    validationError(parameters({ rhsMinimum: 2, rhsMaximum: 1 })),
    /minimum ≤ maximum/,
  );
  assert.match(
    validationError(parameters({ rhsMinimum: -MAX_SAFE_MANTISSA - 1 })),
    /integers/,
  );
});

test("workflows export generated systems and hand solver output to the prover", () => {
  const local = localWorkflow();
  assert.match(local, /sparse-problem -- export/);
  assert.match(local, /Solve A x = b here/);
  assert.match(local, /sparse-solve\/solution\/binary64-v1/);
  assert.match(local, /--solution \/tmp\/x\.json/);
  assert.doesNotMatch(local, /manufactured-solution/);

  const hosted = hostedWorkflow({
    serviceUrl: "https://validator.example",
    issuer: "issuer",
    keyId: "key-v1",
    publicKey: "/tmp/validator.pub",
    privateService: true,
  });
  assert.match(hosted, /sparse-problem -- export/);
  assert.match(hosted, /Solve A x = b here/);
  assert.match(hosted, /Authorization: Bearer/);
  assert.doesNotMatch(hosted, /manufactured-solution/);
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
