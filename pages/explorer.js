"use strict";

const blake3 = typeof module !== "undefined" && module.exports
  ? require("./blake3.js")
  : globalThis.SsvBlake3;

const TRIDIAGONAL_FAMILY = "seeded-symmetric-tridiagonal-v1";
const DIA_FAMILY = "seeded-symmetric-dia-laplacian-v1";
const NONSYMMETRIC_FAMILY = "seeded-nonsymmetric-row-sparse-v1";
const SEEDED_RHS_FAMILY = "seeded-periodic-dyadic-v1";
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

function validationError(p) {
  if (![TRIDIAGONAL_FAMILY, DIA_FAMILY, NONSYMMETRIC_FAMILY].includes(p.family)) {
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
  const familyIntegers = p.family === NONSYMMETRIC_FAMILY
    ? [p.maximumHalfBandwidth, p.maximumRowNonzeros, p.coefficientMinimum, p.coefficientMaximum]
    : [p.margin, p.minimum, p.maximum];
  if (![...commonIntegers, ...familyIntegers].every(Number.isSafeInteger)) {
    return "All generator parameters must be integers.";
  }
  if (p.dimension < 2 || p.dimension > 128) return "Visualization dimension must be between 2 and 128.";
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

  if (p.family === NONSYMMETRIC_FAMILY) {
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
  if (p.family === NONSYMMETRIC_FAMILY) {
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

function actualizeMatrix(p) {
  const instanceSeed = blake3.hexToBytes(p.seed);
  if (instanceSeed.length !== 32) throw new RangeError("an instance seed must contain 32 bytes");
  if (p.family === TRIDIAGONAL_FAMILY) return actualizeTridiagonal(p, instanceSeed);
  if (p.family === DIA_FAMILY) return actualizeDia(p, instanceSeed);
  if (p.family === NONSYMMETRIC_FAMILY) return actualizeNonsymmetric(p, instanceSeed);
  throw new RangeError("cannot actualize an unregistered matrix family");
}

function randomSeedHex(randomSource) {
  if (!randomSource || typeof randomSource.getRandomValues !== "function") {
    throw new Error("secure browser randomness is unavailable");
  }
  const seed = new Uint8Array(32);
  randomSource.getRandomValues(seed);
  return blake3.bytesToHex(seed);
}

function structuralNonzeros(p) {
  if (p.family === NONSYMMETRIC_FAMILY) {
    return p.dimension * Math.min(p.dimension, p.maximumRowNonzeros);
  }
  return p.dimension + matrixOffsets(p)
    .reduce((total, offset) => total + (2 * (p.dimension - offset)), 0);
}

function solverHandoff() {
  return `cargo run -p sparse-problem -- export \\
  --problem /tmp/problem.json \\
  --matrix /tmp/A.mtx \\
  --rhs /tmp/b.mtx

# Solve A x = b here with any sparse solver.
# Write /tmp/x.json in this prover input format (the values shown are only a
# three-entry example; provide exactly one finite binary64 decimal string per unknown):
# {"schema":"sparse-solve/solution/binary64-v1","values":["1.0","-2.5","0"]}`;
}

function localWorkflow() {
  return `# Save the Local template from this explorer as /tmp/template.json.
cargo run -p sparse-problem -- finalize-local \\
  --template /tmp/template.json \\
  --problem /tmp/problem.json

${solverHandoff()}

cargo run --release -p sparse-prover -- prove \\
  --problem /tmp/problem.json \\
  --validation examples/direct-validation.json \\
  --solution /tmp/x.json \\
  --proof /tmp/validation.proof

cargo run --release -p sparse-validator -- verify \\
  --proof /tmp/validation.proof \\
  --allow-literal`;
}

function hostedWorkflow({ serviceUrl, issuer, keyId, publicKey, privateService }) {
  const authOption = privateService
    ? ` --header="Authorization: Bearer $(gcloud auth print-identity-token)"`
    : "";
  return `# Save the Server template from this explorer as /tmp/template.json.
export SERVICE_URL="${serviceUrl}"

# The service signs fresh issued-at and expiry timestamps into this challenge.
curl --fail --silent --show-error${authOption} \\
  -H 'content-type: application/json' \\
  --data-binary @/tmp/template.json \\
  "\${SERVICE_URL}/v1/challenges" \\
  -o /tmp/challenge.json

cargo run -p sparse-problem -- finalize-challenge \\
  --template /tmp/template.json \\
  --challenge /tmp/challenge.json \\
  --public-key "${publicKey}" \\
  --issuer "${issuer}" \\
  --key-id "${keyId}" \\
  --problem /tmp/problem.json

${solverHandoff()}

cargo run --release -p sparse-prover -- prove \\
  --problem /tmp/problem.json \\
  --validation examples/direct-validation.json \\
  --solution /tmp/x.json \\
  --challenge /tmp/challenge.json \\
  --proof /tmp/validation.proof

curl --fail --silent --show-error${authOption} \\
  -H 'content-type: application/octet-stream' \\
  --data-binary @/tmp/validation.proof \\
  "\${SERVICE_URL}/v1/validate" \\
  -o /tmp/certificate.json

cargo run -p sparse-validator -- verify-certificate \\
  --certificate /tmp/certificate.json \\
  --public-key "${publicKey}" \\
  --issuer "${issuer}" \\
  --key-id "${keyId}"`;
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
      seed: seedInput.value.trim(),
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
    const nonsymmetric = p.family === NONSYMMETRIC_FAMILY;
    offsetsControl.hidden = !dia;
    marginControl.hidden = nonsymmetric;
    structuredRangeControls.hidden = nonsymmetric;
    nonsymmetricShapeControls.hidden = !nonsymmetric;
    nonsymmetricRangeControls.hidden = !nonsymmetric;
    nonsymmetricNote.hidden = !nonsymmetric;
    periodLabel.textContent = dia
      ? "Edge period bits"
      : nonsymmetric ? "Row pattern bits" : "Period bits";
    periodHint.textContent = dia
      ? "One shared period and range; each offset table is seeded independently"
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
    const nonsymmetric = p.family === NONSYMMETRIC_FAMILY;
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
      serviceUrl,
      issuer,
      keyId,
      publicKey,
      privateService: privateService.checked,
    });
    templateCode.textContent = `${JSON.stringify(problemTemplate(p, templateKind.value), null, 2)}\n`;
  }

  form.addEventListener("input", update);
  templateKind.addEventListener("change", update);
  hostInputs.forEach((input) => input.addEventListener("input", update));
  privateService.addEventListener("change", update);
  newSeedButton.addEventListener("click", () => {
    try {
      seedInput.value = randomSeedHex(globalThis.crypto);
      update();
    } catch (error) {
      formError.hidden = false;
      formError.textContent = error.message;
    }
  });

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
    link.download = templateKind.value === "challenge"
      ? "challenge-template.json"
      : "local-template.json";
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
    NONSYMMETRIC_FAMILY,
    SEEDED_RHS_FAMILY,
    TRIDIAGONAL_FAMILY,
    actualizeMatrix,
    deriveSubseed,
    hostedWorkflow,
    localWorkflow,
    matrixOffsets,
    matrixSpec,
    parseOffsets,
    problemTemplate,
    randomSeedHex,
    rhsSpec,
    solverHandoff,
    structuralNonzeros,
    validationError,
  };
}

if (typeof document !== "undefined") initialize();
