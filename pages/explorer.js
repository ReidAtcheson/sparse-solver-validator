"use strict";

let blake3 = typeof module !== "undefined" && module.exports
  ? require("./blake3.js")
  : globalThis.SsvBlake3;

const TRIDIAGONAL_FAMILY = "seeded-symmetric-tridiagonal-v1";
const DIA_FAMILY = "seeded-symmetric-dia-laplacian-v1";
const NONSYMMETRIC_FAMILY = "seeded-nonsymmetric-row-sparse-v1";
const PROJECTED_NONSYMMETRIC_FAMILY = "seeded-nonsymmetric-row-sparse-v2";
const SEEDED_RHS_FAMILY = "seeded-periodic-dyadic-v1";
const MAX_VISUALIZATION_DIMENSION = 1024;
const MAX_SAFE_MANTISSA = 9007199254740991;
const MAX_DIA_OFFSETS = 16;
const MAX_NONSYMMETRIC_ROW_NONZEROS = 32;
const DEFAULT_INSTANCE_SEED = "0101010101010101010101010101010101010101010101010101010101010101";
const SUBSEED_DERIVATION_CONTEXT = "sparse-solve/problem-subseed/v1";
const UNBIASED_STREAM_CONTEXT = "sparse-solve/unbiased-u64-stream/v1";
const MATRIX_VALUES_LABEL = "matrix/seeded-symmetric-tridiagonal-v1/off-diagonal-values";
const DIA_MATRIX_VALUES_LABEL = "matrix/seeded-symmetric-dia-laplacian-v1/edge-values";
const NONSYMMETRIC_STRUCTURE_LABEL = "matrix/seeded-nonsymmetric-row-sparse-v1/structure";
const NONSYMMETRIC_OFF_DIAGONAL_VALUES_LABEL = "matrix/seeded-nonsymmetric-row-sparse-v1/off-diagonal-values";
const NONSYMMETRIC_DIAGONAL_VALUES_LABEL = "matrix/seeded-nonsymmetric-row-sparse-v1/diagonal-values";
const PROJECTED_NONSYMMETRIC_PROJECTIONS_LABEL = "matrix/seeded-nonsymmetric-row-sparse-v2/projections";
const PROJECTED_NONSYMMETRIC_STRUCTURE_LABEL = "matrix/seeded-nonsymmetric-row-sparse-v2/structure";
const PROJECTED_NONSYMMETRIC_OFF_DIAGONAL_VALUES_LABEL = "matrix/seeded-nonsymmetric-row-sparse-v2/off-diagonal-values";
const PROJECTED_NONSYMMETRIC_DIAGONAL_VALUES_LABEL = "matrix/seeded-nonsymmetric-row-sparse-v2/diagonal-values";

function parseOffsets(value) {
  if (!value.trim()) return [];
  return value.split(",").map((part) => {
    const token = part.trim();
    return /^\d+$/.test(token) ? Number(token) : Number.NaN;
  });
}

function matrixOffsets(p) {
  if (p.family === DIA_FAMILY) return p.offsets;
  return p.family === TRIDIAGONAL_FAMILY ? [1] : [];
}

function isNonsymmetricFamily(family) {
  return family === NONSYMMETRIC_FAMILY || family === PROJECTED_NONSYMMETRIC_FAMILY;
}

function validationError(p) {
  if (![
    TRIDIAGONAL_FAMILY,
    DIA_FAMILY,
    NONSYMMETRIC_FAMILY,
    PROJECTED_NONSYMMETRIC_FAMILY,
  ].includes(p.family)) {
    return "Select a registered matrix family.";
  }
  if (p.rhs !== SEEDED_RHS_FAMILY) return "Select a registered right-hand-side family.";
  if (typeof p.seed !== "string" || !/^[0-9a-f]{64}$/.test(p.seed)) {
    return "The instance seed must be exactly 64 lowercase hexadecimal characters.";
  }

  const commonIntegers = [
    p.dimension,
    p.periodBits,
    p.fractionalBits,
    p.rhsPeriodBits,
    p.rhsFractionalBits,
    p.rhsMinimum,
    p.rhsMaximum,
  ];
  const familyIntegers = isNonsymmetricFamily(p.family)
    ? [p.maximumHalfBandwidth, p.maximumRowNonzeros, p.coefficientMinimum, p.coefficientMaximum]
    : [p.margin, p.minimum, p.maximum];
  if (![...commonIntegers, ...familyIntegers].every(Number.isSafeInteger)) {
    return "All generator parameters must be integers.";
  }
  if (p.dimension < 2 || p.dimension > MAX_VISUALIZATION_DIMENSION) {
    return `Visualization dimension must be between 2 and ${MAX_VISUALIZATION_DIMENSION}.`;
  }
  if (p.periodBits < 0 || p.periodBits > 16) return "Period bits must be between 0 and 16.";
  if (p.fractionalBits < 0 || p.fractionalBits > 52) return "Fractional bits must be between 0 and 52.";
  if (p.rhsPeriodBits < 0 || p.rhsPeriodBits > 16) {
    return "RHS period bits must be between 0 and 16.";
  }
  if (p.rhsFractionalBits < 0 || p.rhsFractionalBits > 52) {
    return "RHS fractional bits must be between 0 and 52.";
  }
  if (p.rhsMinimum > p.rhsMaximum) {
    return "RHS mantissas must satisfy minimum ≤ maximum.";
  }
  if (Math.abs(p.rhsMinimum) > MAX_SAFE_MANTISSA
      || Math.abs(p.rhsMaximum) > MAX_SAFE_MANTISSA) {
    return "RHS mantissas must fit exactly in binary64.";
  }

  if (isNonsymmetricFamily(p.family)) {
    if (p.maximumHalfBandwidth < 0 || p.maximumHalfBandwidth >= p.dimension) {
      return "Maximum half bandwidth must be nonnegative and smaller than the dimension.";
    }
    if (p.maximumRowNonzeros < 1
        || p.maximumRowNonzeros > MAX_NONSYMMETRIC_ROW_NONZEROS) {
      return `Maximum row nonzeros must be between 1 and ${MAX_NONSYMMETRIC_ROW_NONZEROS}.`;
    }
    if (p.maximumRowNonzeros > 2 * p.maximumHalfBandwidth + 1) {
      return "Maximum row nonzeros exceed the diagonal plus available signed offsets.";
    }
    if (p.coefficientMinimum > p.coefficientMaximum) {
      return "Coefficient mantissas must satisfy minimum ≤ maximum.";
    }
    const unitMantissa = 2 ** p.fractionalBits;
    if (p.coefficientMinimum < -unitMantissa || p.coefficientMaximum > unitMantissa) {
      return "Coefficient mantissas must represent values inside [-1, 1].";
    }
    if (p.coefficientMinimum === 0 && p.coefficientMaximum === 0) {
      return "The coefficient range must contain a nonzero value.";
    }
    if (p.family === PROJECTED_NONSYMMETRIC_FAMILY) {
      const rowIndexBits = Math.log2(nextPowerOfTwo(p.dimension));
      const projectedBits = Math.min(p.periodBits, rowIndexBits);
      if (projectedBits * p.maximumRowNonzeros < rowIndexBits) {
        return "The row-slot projections must collectively cover every padded row-index bit.";
      }
    }
    return "";
  }

  if (p.minimum < 1 || p.minimum > p.maximum) {
    return "Magnitudes must satisfy 1 ≤ minimum ≤ maximum.";
  }
  if (p.maximum > MAX_SAFE_MANTISSA || p.margin < 1 || p.margin > MAX_SAFE_MANTISSA) {
    return "Mantissas must fit exactly in binary64.";
  }

  if (p.family === DIA_FAMILY) {
    if (p.offsets.length === 0) return "Enter at least one positive DIA offset.";
    if (p.offsets.length > MAX_DIA_OFFSETS) return `At most ${MAX_DIA_OFFSETS} DIA offsets are supported.`;
    if (!p.offsets.every(Number.isSafeInteger)) return "Offsets must be comma-separated integers.";
    if (p.offsets.some((offset) => offset < 1 || offset >= p.dimension)) {
      return "Every DIA offset must be positive and smaller than the dimension.";
    }
    if (p.offsets.some((offset, index) => index > 0 && offset <= p.offsets[index - 1])) {
      return "DIA offsets must be unique and strictly increasing.";
    }
  }

  const offsetCount = p.family === DIA_FAMILY ? p.offsets.length : 1;
  const maximumDiagonal = (2n * BigInt(offsetCount) * BigInt(p.maximum)) + BigInt(p.margin);
  if (maximumDiagonal > BigInt(MAX_SAFE_MANTISSA)) {
    return "The maximum possible diagonal mantissa must fit exactly in binary64.";
  }
  return "";
}

function matrixSpec(p) {
  if (isNonsymmetricFamily(p.family)) {
    return {
      kind: p.family,
      dimension: p.dimension,
      boundary: "truncate-v1",
      row_pattern_bits: p.periodBits,
      maximum_half_bandwidth: p.maximumHalfBandwidth,
      maximum_nonzeros_per_row: p.maximumRowNonzeros,
      fractional_bits: p.fractionalBits,
      minimum_mantissa: String(p.coefficientMinimum),
      maximum_mantissa: String(p.coefficientMaximum),
    };
  }

  if (p.family === DIA_FAMILY) {
    return {
      kind: p.family,
      dimension: p.dimension,
      boundary: "truncate-v1",
      fractional_bits: p.fractionalBits,
      diagonal_shift_mantissa: String(p.margin),
      edge_diagonals: p.offsets.map((positiveOffset) => ({
        positive_offset: positiveOffset,
        period_bits: p.periodBits,
        minimum_weight_mantissa: String(p.minimum),
        maximum_weight_mantissa: String(p.maximum),
      })),
    };
  }

  return {
    kind: p.family,
    dimension: p.dimension,
    boundary: "truncate-v1",
    off_diagonal: {
      kind: "seeded-periodic-negative-dyadic-v1",
      period_bits: p.periodBits,
      fractional_bits: p.fractionalBits,
      minimum_magnitude_mantissa: String(p.minimum),
      maximum_magnitude_mantissa: String(p.maximum),
    },
    diagonal: {
      kind: "absolute-row-sum-plus-margin-v1",
      margin_mantissa: String(p.margin),
    },
  };
}

function rhsSpec(p) {
  return {
    kind: p.rhs,
    period_bits: p.rhsPeriodBits,
    fractional_bits: p.rhsFractionalBits,
    minimum_mantissa: String(p.rhsMinimum),
    maximum_mantissa: String(p.rhsMaximum),
  };
}

function problemTemplate(p, kind) {
  const randomness = kind === "challenge"
    ? { kind: "challenge-derived-v1", derivation: "blake3-xof-v1" }
    : { kind: "literal-v1", seed: p.seed };
  return {
    schema: "sparse-solve/problem-template/v1",
    randomness,
    matrix: matrixSpec(p),
    rhs: rhsSpec(p),
    requested_outputs: [{ kind: "squared-l2-residual-v1" }],
  };
}

function publicEvaluationTerms(p) {
  const paddedDimension = nextPowerOfTwo(p.dimension);
  let matrix;
  if (p.family === DIA_FAMILY) {
    matrix = p.offsets.reduce(
      (total, offset) => total + Math.min(2 ** p.periodBits, p.dimension - offset),
      0,
    );
  } else if (p.family === NONSYMMETRIC_FAMILY) {
    matrix = Math.min(2 ** p.periodBits, p.dimension) * p.maximumRowNonzeros;
  } else if (p.family === PROJECTED_NONSYMMETRIC_FAMILY) {
    matrix = Math.min(2 ** p.periodBits, paddedDimension) * p.maximumRowNonzeros;
  } else {
    matrix = Math.min(2 ** p.periodBits, paddedDimension);
  }
  return {
    matrix,
    rhs: Math.min(2 ** p.rhsPeriodBits, paddedDimension),
  };
}

function benchmarkConfig(p, kind, options = {}) {
  const remote = kind === "challenge";
  const terms = publicEvaluationTerms(p);
  const authority = remote
    ? {
      kind: "remote-v1",
      service_url: options.serviceUrl ?? "https://YOUR-SERVICE-URL",
      issuer: options.issuer ?? "YOUR-ISSUER",
      key_id: options.keyId ?? "YOUR-KEY-ID",
      public_key: options.publicKey ?? "YOUR-PUBLIC-KEY-HEX",
      authentication: options.privateService === false
        ? { kind: "none-v1" }
        : { kind: "gcloud-identity-token-v1", audience: null },
      maximum_future_skew_seconds: 30,
      maximum_challenge_lifetime_seconds: 3600,
    }
    : { kind: "local-v1" };
  return {
    schema: "sparse-solve/benchmark/v1",
    benchmark_id: remote ? "website-server-preview-v1" : "website-local-preview-v1",
    authority,
    problem_template: problemTemplate(p, kind),
    validation: {
      schema: "sparse-solve/validation/v1",
      protocol: "direct-reference-v1",
      max_solution_elements: p.dimension,
      max_public_matrix_terms: terms.matrix,
      max_public_rhs_terms: terms.rhs,
    },
  };
}

// This is an exact browser mirror of the frozen Rust seed derivation and
// bounded matrix generators. Cross-language test vectors protect the wire
// semantics; do not replace these streams with a presentation-only PRNG.
function deriveSubseed(seed, label) {
  const labelBytes = blake3.textEncoder.encode(label);
  const input = blake3.concatenate(
    seed,
    blake3.u64LittleEndian(BigInt(labelBytes.length)),
    labelBytes,
  );
  return blake3.deriveKey(SUBSEED_DERIVATION_CONTEXT, input, 32);
}

class UniformStream {
  constructor(seed) {
    this.reader = blake3.deriveKeyReader(UNBIASED_STREAM_CONTEXT, seed);
  }

  nextU64() {
    const bytes = this.reader.read(8);
    let value = 0n;
    for (let index = 0; index < bytes.length; index += 1) {
      value |= BigInt(bytes[index]) << BigInt(8 * index);
    }
    return value;
  }

  sampleBelow(bound) {
    if (typeof bound !== "bigint" || bound <= 0n || bound >= (1n << 64n)) {
      throw new RangeError("the unbiased sampler bound must fit a positive u64");
    }
    const rejectionThreshold = ((1n << 64n) - bound) % bound;
    for (;;) {
      const candidate = this.nextU64();
      if (candidate >= rejectionThreshold) return candidate % bound;
    }
  }
}

function negativeMantissaTable(seed, count, minimum, maximum) {
  const minimumMagnitude = BigInt(minimum);
  const width = BigInt(maximum) - minimumMagnitude + 1n;
  const stream = new UniformStream(seed);
  return Array.from(
    { length: count },
    () => -(minimumMagnitude + stream.sampleBelow(width)),
  );
}

function sampleNonzeroMantissa(stream, minimum, maximum) {
  const low = BigInt(minimum);
  const high = BigInt(maximum);
  const containsZero = low <= 0n && high >= 0n;
  const width = high - low + 1n - (containsZero ? 1n : 0n);
  const sample = stream.sampleBelow(width);
  if (!containsZero) return low + sample;
  const negativeValues = -low;
  return sample < negativeValues ? low + sample : 1n + sample - negativeValues;
}

function signedOffsetFromPopulationIndex(index, halfBandwidth) {
  const half = BigInt(halfBandwidth);
  return Number(index < half ? index - half : index - half + 1n);
}

function sampledSignedOffsets(stream, halfBandwidth, count) {
  const population = 2n * BigInt(halfBandwidth);
  const selected = [];
  for (let upper = population - BigInt(count); upper < population; upper += 1n) {
    const candidate = signedOffsetFromPopulationIndex(
      stream.sampleBelow(upper + 1n),
      halfBandwidth,
    );
    selected.push(selected.includes(candidate)
      ? signedOffsetFromPopulationIndex(upper, halfBandwidth)
      : candidate);
  }
  selected.sort((left, right) => left - right);
  return selected;
}

function nextPowerOfTwo(value) {
  let result = 1;
  while (result < value) result *= 2;
  return result;
}

function matrixEntry(row, column, mantissa) {
  return { row, column, mantissa };
}

function actualizeTridiagonal(p, instanceSeed) {
  const period = 2 ** p.periodBits;
  const activeTableLength = Math.min(period, p.dimension - 1);
  const table = negativeMantissaTable(
    deriveSubseed(instanceSeed, MATRIX_VALUES_LABEL),
    activeTableLength,
    p.minimum,
    p.maximum,
  );
  const edge = (index) => table[index & (period - 1)];
  const entries = [];
  for (let row = 0; row < p.dimension; row += 1) {
    let diagonal = BigInt(p.margin);
    if (row > 0) {
      const value = edge(row - 1);
      entries.push(matrixEntry(row, row - 1, value));
      diagonal -= value;
    }
    if (row + 1 < p.dimension) diagonal -= edge(row);
    entries.push(matrixEntry(row, row, diagonal));
    if (row + 1 < p.dimension) entries.push(matrixEntry(row, row + 1, edge(row)));
  }
  return { entries, fractionalBits: p.fractionalBits };
}

function actualizeDia(p, instanceSeed) {
  const period = 2 ** p.periodBits;
  const familySeed = deriveSubseed(instanceSeed, DIA_MATRIX_VALUES_LABEL);
  const edges = p.offsets.map((offset, index) => {
    const label = `edge-diagonal/${index}/offset/${offset}`;
    const activeTableLength = Math.min(period, p.dimension - offset);
    return {
      offset,
      table: negativeMantissaTable(
        deriveSubseed(familySeed, label),
        activeTableLength,
        p.minimum,
        p.maximum,
      ),
    };
  });
  const edgeValue = (edge, index) => edge.table[index & (period - 1)];
  const entries = [];
  for (let row = 0; row < p.dimension; row += 1) {
    let diagonal = BigInt(p.margin);
    const rowEntries = [];
    for (const edge of edges) {
      if (row >= edge.offset) {
        const value = edgeValue(edge, row - edge.offset);
        rowEntries.push(matrixEntry(row, row - edge.offset, value));
        diagonal -= value;
      }
      if (row + edge.offset < p.dimension) diagonal -= edgeValue(edge, row);
    }
    rowEntries.push(matrixEntry(row, row, diagonal));
    for (const edge of edges) {
      if (row + edge.offset < p.dimension) {
        rowEntries.push(matrixEntry(row, row + edge.offset, edgeValue(edge, row)));
      }
    }
    rowEntries.sort((left, right) => left.column - right.column);
    entries.push(...rowEntries);
  }
  return { entries, fractionalBits: p.fractionalBits };
}

function actualizeNonsymmetric(p, instanceSeed) {
  const requestedPeriod = 2 ** p.periodBits;
  const period = Math.min(requestedPeriod, nextPowerOfTwo(p.dimension));
  const offDiagonalCount = p.maximumRowNonzeros - 1;

  const structureStream = new UniformStream(
    deriveSubseed(instanceSeed, NONSYMMETRIC_STRUCTURE_LABEL),
  );
  const patterns = Array.from(
    { length: period },
    () => sampledSignedOffsets(structureStream, p.maximumHalfBandwidth, offDiagonalCount),
  );

  const offDiagonalStream = new UniformStream(
    deriveSubseed(instanceSeed, NONSYMMETRIC_OFF_DIAGONAL_VALUES_LABEL),
  );
  const offDiagonalValues = Array.from(
    { length: period * offDiagonalCount },
    () => sampleNonzeroMantissa(
      offDiagonalStream,
      p.coefficientMinimum,
      p.coefficientMaximum,
    ),
  );

  const diagonalStream = new UniformStream(
    deriveSubseed(instanceSeed, NONSYMMETRIC_DIAGONAL_VALUES_LABEL),
  );
  const diagonalValues = Array.from(
    { length: period },
    () => sampleNonzeroMantissa(
      diagonalStream,
      p.coefficientMinimum,
      p.coefficientMaximum,
    ),
  );

  const entries = [];
  for (let row = 0; row < p.dimension; row += 1) {
    const pattern = row & (period - 1);
    const rowEntries = [matrixEntry(row, row, diagonalValues[pattern])];
    for (let index = 0; index < offDiagonalCount; index += 1) {
      const column = row + patterns[pattern][index];
      if (column >= 0 && column < p.dimension) {
        rowEntries.push(matrixEntry(
          row,
          column,
          offDiagonalValues[pattern * offDiagonalCount + index],
        ));
      }
    }
    rowEntries.sort((left, right) => left.column - right.column);
    entries.push(...rowEntries);
  }
  return { entries, fractionalBits: p.fractionalBits };
}

function projectedRowBits(instanceSeed, rowIndexBits, patternBits, rowWidth) {
  const stream = new UniformStream(
    deriveSubseed(instanceSeed, PROJECTED_NONSYMMETRIC_PROJECTIONS_LABEL),
  );
  const permutation = Array.from({ length: rowIndexBits }, (_, bit) => bit);
  for (let upper = rowIndexBits - 1; upper > 0; upper -= 1) {
    const selected = Number(stream.sampleBelow(BigInt(upper + 1)));
    [permutation[upper], permutation[selected]] = [permutation[selected], permutation[upper]];
  }
  return Array.from({ length: rowWidth }, (_, slot) => {
    const windowStart = slot * patternBits;
    const rotation = slot % patternBits;
    return Array.from({ length: patternBits }, (_, patternBit) => {
      const withinWindow = (patternBit + rotation) % patternBits;
      return permutation[(windowStart + withinWindow) % rowIndexBits];
    });
  });
}

function appendOffsetPartition(buckets, populationStart, populationLength, parts) {
  if (parts === 0) return;
  const baseLength = Math.floor(populationLength / parts);
  const longerParts = populationLength % parts;
  let start = populationStart;
  for (let part = 0; part < parts; part += 1) {
    const length = baseLength + (part < longerParts ? 1 : 0);
    buckets.push({ start, length });
    start += length;
  }
}

function projectedOffsetBuckets(halfBandwidth, offDiagonalSlots) {
  if (offDiagonalSlots === 0) return [];
  const remainingSlots = offDiagonalSlots - 1;
  const positiveCapacity = halfBandwidth - 1;
  const minimumNegativeSlots = Math.max(0, remainingSlots - positiveCapacity);
  const maximumNegativeSlots = Math.min(remainingSlots, halfBandwidth);
  const balancedNegativeSlots = Math.ceil(remainingSlots / 2);
  const negativeSlots = Math.max(
    minimumNegativeSlots,
    Math.min(balancedNegativeSlots, maximumNegativeSlots),
  );
  const positiveSlots = remainingSlots - negativeSlots;
  const buckets = [];
  appendOffsetPartition(buckets, 0, halfBandwidth, negativeSlots);
  buckets.push({ start: halfBandwidth, length: 1 });
  appendOffsetPartition(
    buckets,
    halfBandwidth + 1,
    positiveCapacity,
    positiveSlots,
  );
  return buckets;
}

function projectedPattern(row, projection) {
  return projection.reduce((pattern, rowBit, patternBit) => {
    const bit = Math.floor(row / (2 ** rowBit)) % 2;
    return pattern + bit * (2 ** patternBit);
  }, 0);
}

function actualizeProjectedNonsymmetric(p, instanceSeed) {
  const rowIndexBits = Math.log2(nextPowerOfTwo(p.dimension));
  const patternBits = Math.min(p.periodBits, rowIndexBits);
  const patternCount = 2 ** patternBits;
  const offDiagonalSlots = p.maximumRowNonzeros - 1;
  const projections = projectedRowBits(
    instanceSeed,
    rowIndexBits,
    patternBits,
    p.maximumRowNonzeros,
  );

  const buckets = projectedOffsetBuckets(p.maximumHalfBandwidth, offDiagonalSlots);
  const structureStream = new UniformStream(
    deriveSubseed(instanceSeed, PROJECTED_NONSYMMETRIC_STRUCTURE_LABEL),
  );
  const signedOffsets = buckets.map((bucket) => Array.from(
    { length: patternCount },
    () => signedOffsetFromPopulationIndex(
      BigInt(bucket.start) + structureStream.sampleBelow(BigInt(bucket.length)),
      p.maximumHalfBandwidth,
    ),
  ));

  const offDiagonalStream = new UniformStream(
    deriveSubseed(instanceSeed, PROJECTED_NONSYMMETRIC_OFF_DIAGONAL_VALUES_LABEL),
  );
  const offDiagonalValues = Array.from(
    { length: patternCount * offDiagonalSlots },
    () => sampleNonzeroMantissa(
      offDiagonalStream,
      p.coefficientMinimum,
      p.coefficientMaximum,
    ),
  );
  const diagonalStream = new UniformStream(
    deriveSubseed(instanceSeed, PROJECTED_NONSYMMETRIC_DIAGONAL_VALUES_LABEL),
  );
  const diagonalValues = Array.from(
    { length: patternCount },
    () => sampleNonzeroMantissa(
      diagonalStream,
      p.coefficientMinimum,
      p.coefficientMaximum,
    ),
  );

  const entries = [];
  for (let row = 0; row < p.dimension; row += 1) {
    const diagonalPattern = projectedPattern(row, projections[0]);
    const rowEntries = [matrixEntry(row, row, diagonalValues[diagonalPattern])];
    for (let slot = 0; slot < offDiagonalSlots; slot += 1) {
      const pattern = projectedPattern(row, projections[slot + 1]);
      const column = row + signedOffsets[slot][pattern];
      if (column >= 0 && column < p.dimension) {
        rowEntries.push(matrixEntry(
          row,
          column,
          offDiagonalValues[slot * patternCount + pattern],
        ));
      }
    }
    rowEntries.sort((left, right) => left.column - right.column);
    entries.push(...rowEntries);
  }
  return { entries, fractionalBits: p.fractionalBits };
}

function actualizeMatrix(p) {
  const instanceSeed = blake3.hexToBytes(p.seed);
  if (instanceSeed.length !== 32) throw new RangeError("an instance seed must contain 32 bytes");
  if (p.family === TRIDIAGONAL_FAMILY) return actualizeTridiagonal(p, instanceSeed);
  if (p.family === DIA_FAMILY) return actualizeDia(p, instanceSeed);
  if (p.family === NONSYMMETRIC_FAMILY) return actualizeNonsymmetric(p, instanceSeed);
  if (p.family === PROJECTED_NONSYMMETRIC_FAMILY) {
    return actualizeProjectedNonsymmetric(p, instanceSeed);
  }
  throw new RangeError("cannot actualize an unregistered matrix family");
}

function nextSeedHex(seed) {
  if (typeof seed !== "string" || !/^[0-9a-f]{64}$/.test(seed)) {
    throw new TypeError("an instance seed must be exactly 64 lowercase hexadecimal characters");
  }
  const next = (BigInt(`0x${seed}`) + 1n) & ((1n << 256n) - 1n);
  return next.toString(16).padStart(64, "0");
}

function structuralNonzeros(p) {
  if (isNonsymmetricFamily(p.family)) {
    return p.dimension * Math.min(p.dimension, p.maximumRowNonzeros);
  }
  return p.dimension + matrixOffsets(p)
    .reduce((total, offset) => total + (2 * (p.dimension - offset)), 0);
}

function solverHandoff() {
  return `# start prints the exact matrix_file, rhs_file, and solution_file paths.
# Solve A x = b with any sparse solver, then write submission/x.json as:
# {"schema":"sparse-solve/solution/binary64-v1","values":["1.0","-2.5","0"]}
# The values above are only a three-entry format example. Supply exactly one
# finite binary64 decimal string per unknown.`;
}

function localWorkflow() {
  return `# In Benchmark JSON, choose Local literal seed and download benchmark.json.
cargo build --release -p sparse-benchmark

target/release/sparse-benchmark start \\
  --config benchmark.json \\
  --runs-dir runs

${solverHandoff()}

target/release/sparse-benchmark resume runs/run-...

# The completed run contains result-card.json. Local cards are reproducible
# validation records, but they are not signed by a server.`;
}

function hostedWorkflow({ privateService }) {
  const authentication = privateService
    ? "# Ensure gcloud is authenticated; the runner fetches a fresh identity token per request.\n"
    : "";
  return `# Fill the service fields above. In Benchmark JSON, choose Server-issued
# challenge and download benchmark.json.
${authentication}cargo build --release -p sparse-benchmark

target/release/sparse-benchmark start \\
  --config benchmark.json \\
  --runs-dir runs

${solverHandoff()}

target/release/sparse-benchmark resume runs/run-...

# resume constructs and locally verifies the proof, submits it, authenticates
# the signed certificate, and writes result-card.json. Re-run it after a
# network interruption; the existing proof is reused.`;
}

function initialize() {
  const form = document.querySelector("#generator-form");
  const canvas = document.querySelector("#spy-plot");
  const context = canvas.getContext("2d");
  const formError = document.querySelector("#form-error");
  const localCode = document.querySelector("#local-code");
  const hostedCode = document.querySelector("#hosted-code");
  const templateCode = document.querySelector("#template-code");
  const templateKind = document.querySelector("#template-kind");
  const seedInput = document.querySelector("#instance-seed");
  const newSeedButton = document.querySelector("#new-seed");
  const hostInputs = ["service-url", "issuer", "key-id", "public-key"]
    .map((id) => document.querySelector(`#${id}`));
  const privateService = document.querySelector("#private-service");
  const offsetsControl = document.querySelector("#offsets-control");
  const marginControl = document.querySelector("#margin-control");
  const structuredRangeControls = document.querySelector("#structured-range-controls");
  const nonsymmetricShapeControls = document.querySelector("#nonsymmetric-shape-controls");
  const nonsymmetricRangeControls = document.querySelector("#nonsymmetric-range-controls");
  const nonsymmetricNote = document.querySelector("#nonsymmetric-note");
  const periodLabel = document.querySelector("#period-label");
  const periodHint = document.querySelector("#period-hint");
  const marginLabel = document.querySelector("#margin-label");
  const minimumLabel = document.querySelector("#minimum-label");
  const maximumLabel = document.querySelector("#maximum-label");
  const plotNote = document.querySelector("#plot-note");

  function numberValue(id) {
    return Number(document.querySelector(`#${id}`).value);
  }

  function parameters() {
    return {
      family: document.querySelector("#family").value,
      seed: seedInput ? seedInput.value.trim() : DEFAULT_INSTANCE_SEED,
      dimension: numberValue("dimension"),
      offsets: parseOffsets(document.querySelector("#offsets").value),
      periodBits: numberValue("period-bits"),
      fractionalBits: numberValue("fractional-bits"),
      margin: numberValue("margin"),
      minimum: numberValue("minimum"),
      maximum: numberValue("maximum"),
      maximumHalfBandwidth: numberValue("maximum-half-bandwidth"),
      maximumRowNonzeros: numberValue("maximum-row-nonzeros"),
      coefficientMinimum: numberValue("coefficient-minimum"),
      coefficientMaximum: numberValue("coefficient-maximum"),
      rhs: document.querySelector("#rhs").value,
      rhsPeriodBits: numberValue("rhs-period-bits"),
      rhsFractionalBits: numberValue("rhs-fractional-bits"),
      rhsMinimum: numberValue("rhs-minimum"),
      rhsMaximum: numberValue("rhs-maximum"),
    };
  }

  function updateFamilyControls(p) {
    const dia = p.family === DIA_FAMILY;
    const nonsymmetric = isNonsymmetricFamily(p.family);
    const projected = p.family === PROJECTED_NONSYMMETRIC_FAMILY;
    offsetsControl.hidden = !dia;
    marginControl.hidden = nonsymmetric;
    structuredRangeControls.hidden = nonsymmetric;
    nonsymmetricShapeControls.hidden = !nonsymmetric;
    nonsymmetricRangeControls.hidden = !nonsymmetric;
    nonsymmetricNote.hidden = !nonsymmetric;
    periodLabel.textContent = dia
      ? "Edge period bits"
      : projected ? "Projection bits per entry slot"
        : nonsymmetric ? "Row pattern bits" : "Period bits";
    periodHint.textContent = dia
      ? "One shared period and range; each offset table is seeded independently"
      : projected
        ? "Seed-derived slot projections jointly cover the padded row index"
        : nonsymmetric
        ? "The generated sparsity and values repeat after 2^k rows"
        : "";
    periodHint.hidden = !dia && !nonsymmetric;
    marginLabel.textContent = dia ? "Diagonal shift" : "Dominance margin";
    minimumLabel.textContent = dia ? "Minimum edge weight" : "Minimum magnitude";
    maximumLabel.textContent = dia ? "Maximum edge weight" : "Maximum magnitude";
    document.querySelector("#maximum-half-bandwidth").max = String(p.dimension - 1);
  }

  function drawPlot(p, matrix) {
    const size = canvas.width;
    const padding = 20;
    const plotSize = size - (2 * padding);
    const cell = plotSize / p.dimension;
    context.clearRect(0, 0, size, size);
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, size, size);

    const dotSize = Math.max(1.5, Math.min(cell * 0.72, 9));
    const maximumMagnitude = matrix.entries.reduce((maximum, entry) => {
      const magnitude = entry.mantissa < 0n ? -entry.mantissa : entry.mantissa;
      return magnitude > maximum ? magnitude : maximum;
    }, 0n);
    const drawEntry = (entry) => {
      const magnitude = entry.mantissa < 0n ? -entry.mantissa : entry.mantissa;
      const relativeMagnitude = maximumMagnitude === 0n
        ? 1
        : Number(magnitude) / Number(maximumMagnitude);
      const alpha = 0.32 + 0.68 * Math.sqrt(relativeMagnitude);
      context.fillStyle = entry.mantissa > 0n
        ? `rgba(23, 35, 61, ${alpha})`
        : `rgba(228, 88, 38, ${alpha})`;
      context.fillRect(
        padding + (entry.column + 0.5) * cell - dotSize / 2,
        padding + (entry.row + 0.5) * cell - dotSize / 2,
        dotSize,
        dotSize,
      );
    };
    const nonsymmetric = isNonsymmetricFamily(p.family);
    const projected = p.family === PROJECTED_NONSYMMETRIC_FAMILY;
    const offsets = matrixOffsets(p);
    matrix.entries.forEach(drawEntry);
    context.strokeStyle = "#aeb6c5";
    context.strokeRect(padding + 0.5, padding + 0.5, plotSize - 1, plotSize - 1);

    const nonzeros = matrix.entries.length;
    const density = (100 * nonzeros / (p.dimension * p.dimension)).toFixed(1);
    document.querySelector("#plot-title").textContent = `${p.dimension} × ${p.dimension}`;
    document.querySelector("#plot-summary").textContent = `${nonzeros} structural nonzeros · ${density}% density`;
    const familyDescription = p.family === DIA_FAMILY
      ? `symmetric DIA matrix with positive offsets ${offsets.join(", ")}`
      : projected
        ? `nonsymmetric projected-pattern matrix with half bandwidth ${p.maximumHalfBandwidth}`
        : nonsymmetric
        ? `nonsymmetric generated-pattern matrix with half bandwidth ${p.maximumHalfBandwidth}`
        : "symmetric tridiagonal matrix";
    canvas.setAttribute(
      "aria-label",
      `${p.dimension} by ${p.dimension} actualized ${familyDescription} with ${nonzeros} structural nonzeros`,
    );
    const mantissas = matrix.entries.map((entry) => entry.mantissa);
    const minimumMantissa = mantissas.reduce((minimum, value) => (value < minimum ? value : minimum));
    const maximumMantissa = mantissas.reduce((maximum, value) => (value > maximum ? value : maximum));
    const familyNote = p.family === DIA_FAMILY
      ? `Positive offsets ${offsets.join(", ")} are mirrored and boundary edges truncate.`
      : projected
        ? `Each entry slot uses a separate row-bit projection; together they cover all row bits. Its MLE uses ${(2 ** Math.min(p.periodBits, Math.log2(nextPowerOfTwo(p.dimension)))) * p.maximumRowNonzeros} public pattern terms.`
        : nonsymmetric
        ? `The seed chose these entries subject to the ${p.maximumRowNonzeros}-per-row cap and required diagonal; its MLE uses ${Math.min(2 ** p.periodBits, p.dimension) * p.maximumRowNonzeros} public pattern terms.`
        : "The pattern is fixed, while the seed chooses its edge weights and resulting diagonal values.";
    const challengeNote = templateKind.value === "challenge"
      ? " The server challenge will derive a different final instance seed."
      : " This is the exact matrix in the local literal-seed template.";
    plotNote.textContent = `Actualized from seed ${p.seed.slice(0, 12)}…; navy is positive and orange is negative, with intensity showing relative magnitude. Mantissas span ${minimumMantissa} to ${maximumMantissa} at 2^-${matrix.fractionalBits}. ${familyNote}${challengeNote}`;
  }

  function update() {
    const p = parameters();
    updateFamilyControls(p);
    const error = validationError(p);
    formError.hidden = !error;
    formError.textContent = error;
    if (error) return;
    let matrix;
    try {
      matrix = actualizeMatrix(p);
    } catch (actualizationError) {
      formError.hidden = false;
      formError.textContent = `Unable to actualize this matrix: ${actualizationError.message}`;
      return;
    }
    drawPlot(p, matrix);
    localCode.textContent = localWorkflow();
    const [serviceUrl, issuer, keyId, publicKey] = hostInputs.map((input) => input.value.trim());
    hostedCode.textContent = hostedWorkflow({
      privateService: privateService.checked,
    });
    templateCode.textContent = `${JSON.stringify(benchmarkConfig(p, templateKind.value, {
      serviceUrl,
      issuer,
      keyId,
      publicKey,
      privateService: privateService.checked,
    }), null, 2)}\n`;
  }

  form.addEventListener("input", update);
  templateKind.addEventListener("change", update);
  hostInputs.forEach((input) => input.addEventListener("input", update));
  privateService.addEventListener("change", update);
  if (newSeedButton && seedInput) {
    newSeedButton.addEventListener("click", () => {
      const current = /^[0-9a-f]{64}$/.test(seedInput.value.trim())
        ? seedInput.value.trim()
        : DEFAULT_INSTANCE_SEED;
      seedInput.value = nextSeedHex(current);
      update();
    });
  }

  document.querySelectorAll("[role=tab]").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll("[role=tab]")
        .forEach((item) => item.setAttribute("aria-selected", String(item === tab)));
      document.querySelectorAll("[role=tabpanel]")
        .forEach((panel) => { panel.hidden = panel.id !== `${tab.dataset.tab}-panel`; });
    });
  });

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const original = button.textContent;
      try {
        await navigator.clipboard.writeText(
          document.querySelector(`#${button.dataset.copy}`).textContent,
        );
        button.textContent = "Copied";
      } catch {
        button.textContent = "Select text to copy";
      }
      window.setTimeout(() => { button.textContent = original; }, 1600);
    });
  });

  document.querySelector("#download-template").addEventListener("click", () => {
    const blob = new Blob([templateCode.textContent], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "benchmark.json";
    link.click();
    URL.revokeObjectURL(link.href);
  });

  update();
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    DEFAULT_INSTANCE_SEED,
    DIA_FAMILY,
    MAX_DIA_OFFSETS,
    MAX_NONSYMMETRIC_ROW_NONZEROS,
    MAX_SAFE_MANTISSA,
    MAX_VISUALIZATION_DIMENSION,
    NONSYMMETRIC_FAMILY,
    PROJECTED_NONSYMMETRIC_FAMILY,
    SEEDED_RHS_FAMILY,
    TRIDIAGONAL_FAMILY,
    actualizeMatrix,
    benchmarkConfig,
    deriveSubseed,
    hostedWorkflow,
    initialize,
    localWorkflow,
    matrixOffsets,
    matrixSpec,
    parseOffsets,
    problemTemplate,
    publicEvaluationTerms,
    nextSeedHex,
    rhsSpec,
    solverHandoff,
    structuralNonzeros,
    validationError,
  };
}

function initializeWhenReady() {
  if (blake3) {
    initialize();
    return;
  }

  const dependency = document.createElement("script");
  dependency.src = "blake3.js?v=4";
  dependency.addEventListener("load", () => {
    blake3 = globalThis.SsvBlake3;
    if (blake3) {
      initialize();
    } else {
      showDependencyError();
    }
  });
  dependency.addEventListener("error", showDependencyError);
  document.head.append(dependency);
}

function showDependencyError() {
  const formError = document.querySelector("#form-error");
  if (formError) {
    formError.hidden = false;
    formError.textContent = "Unable to load the matrix preview generator. Refresh the page.";
  }
}

if (typeof document !== "undefined") initializeWhenReady();
