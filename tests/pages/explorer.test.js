"use strict";

const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join } = require("node:path");
const test = require("node:test");
const blake3 = require("../../pages/blake3.js");

const {
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
  hostedWorkflow,
  initialize,
  localWorkflow,
  matrixSpec,
  nextSeedHex,
  parseOffsets,
  problemTemplate,
  publicEvaluationTerms,
  structuralNonzeros,
  validationError,
} = require("../../pages/explorer.js");

function parameters(overrides = {}) {
  return {
    family: TRIDIAGONAL_FAMILY,
    seed: DEFAULT_INSTANCE_SEED,
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

function fakeElement(value = "") {
  const listeners = new Map();
  return {
    checked: false,
    classList: { toggle() {} },
    hidden: false,
    listeners,
    max: "",
    textContent: "",
    value,
    addEventListener(kind, listener) { listeners.set(kind, listener); },
    setAttribute() {},
  };
}

function explorerDocument(includeSeedControls) {
  const values = {
    family: TRIDIAGONAL_FAMILY,
    dimension: "16",
    offsets: "1, 4",
    "period-bits": "3",
    "fractional-bits": "8",
    margin: "32",
    minimum: "8",
    maximum: "24",
    "maximum-half-bandwidth": "5",
    "maximum-row-nonzeros": "7",
    "coefficient-minimum": "-256",
    "coefficient-maximum": "256",
    rhs: SEEDED_RHS_FAMILY,
    "rhs-period-bits": "4",
    "rhs-fractional-bits": "8",
    "rhs-minimum": "-16",
    "rhs-maximum": "19",
    "template-kind": "literal",
    "service-url": "https://validator.example",
    issuer: "issuer",
    "key-id": "key",
    "public-key": "11".repeat(32),
  };
  const ids = [
    "generator-form", "spy-plot", "form-error", "local-code", "hosted-code",
    "template-code", "template-kind", "service-url", "issuer", "key-id", "public-key",
    "private-service", "offsets-control", "margin-control", "structured-range-controls",
    "nonsymmetric-shape-controls", "nonsymmetric-range-controls", "nonsymmetric-note",
    "period-label", "period-hint", "margin-label", "minimum-label", "maximum-label",
    "plot-note", "family", "dimension", "offsets", "period-bits", "fractional-bits",
    "margin", "minimum", "maximum", "maximum-half-bandwidth", "maximum-row-nonzeros",
    "coefficient-minimum", "coefficient-maximum", "rhs", "rhs-period-bits",
    "rhs-fractional-bits", "rhs-minimum", "rhs-maximum", "plot-title", "plot-summary",
    "download-template",
  ];
  if (includeSeedControls) ids.push("instance-seed", "new-seed");
  const elements = Object.fromEntries(ids.map((id) => [id, fakeElement(values[id] ?? "")]));
  if (includeSeedControls) elements["instance-seed"].value = DEFAULT_INSTANCE_SEED;
  elements["private-service"].checked = true;

  const context = {
    fillCount: 0,
    clearRect() {},
    fillRect() { this.fillCount += 1; },
    strokeRect() {},
  };
  elements["spy-plot"].width = 640;
  elements["spy-plot"].getContext = () => context;
  return {
    context,
    elements,
    document: {
      head: { append() {} },
      createElement: () => fakeElement(),
      querySelector(selector) {
        return selector.startsWith("#") ? elements[selector.slice(1)] ?? null : null;
      },
      querySelectorAll: () => [],
    },
  };
}

test("the static page loads exact actualization support before the explorer", () => {
  const html = readFileSync(join(__dirname, "../../pages/index.html"), "utf8");
  assert.ok(html.indexOf('src="blake3.js?v=4"') < html.indexOf('src="explorer.js?v=4"'));
  assert.match(html, /href="styles\.css\?v=4"/);
  assert.match(html, /id="instance-seed"/);
  assert.match(html, /id="new-seed"/);
  assert.match(html, /seeded-nonsymmetric-row-sparse-v2/);
  assert.match(html, /id="dimension"[^>]+max="1024"/);
  assert.match(html, /class="swatch negative off-diagonal"/);
  assert.match(html, /id="off-diagonal-legend"/);
  assert.match(html, /sparse-benchmark start/);
  assert.match(html, /Download benchmark\.json/);
  assert.doesNotMatch(html, /curl --fail/);
});

test("browser initialization renders with cached legacy markup and advances current seeds", () => {
  const legacy = explorerDocument(false);
  const current = explorerDocument(true);
  try {
    global.document = legacy.document;
    initialize();
    assert.ok(legacy.context.fillCount > 2);
    assert.equal(legacy.elements["form-error"].hidden, true);

    global.document = current.document;
    initialize();
    const before = current.elements["instance-seed"].value;
    current.elements["new-seed"].listeners.get("click")();
    assert.equal(current.elements["instance-seed"].value, nextSeedHex(before));
    assert.match(current.elements["template-code"].textContent, new RegExp(nextSeedHex(before)));
    assert.ok(current.context.fillCount > 2);
    assert.equal(current.elements["form-error"].hidden, true);
  } finally {
    delete global.document;
  }
});

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
  assert.deepEqual(template.randomness, {
    kind: "literal-v1",
    seed: DEFAULT_INSTANCE_SEED,
  });
  assert.deepEqual(template.rhs, {
    kind: SEEDED_RHS_FAMILY,
    period_bits: 4,
    fractional_bits: 8,
    minimum_mantissa: "-16",
    maximum_mantissa: "19",
  });
  assert.notEqual(template.rhs.kind, "manufactured-ones-v1");
});

test("benchmark JSON wraps the selected problem in bounded local runner policy", () => {
  const config = benchmarkConfig(parameters(), "literal");
  assert.equal(config.schema, "sparse-solve/benchmark/v1");
  assert.equal(config.benchmark_id, "website-local-preview-v1");
  assert.deepEqual(config.authority, { kind: "local-v1" });
  assert.equal(config.problem_template.randomness.kind, "literal-v1");
  assert.deepEqual(config.validation, {
    schema: "sparse-solve/validation/v1",
    protocol: "direct-reference-v1",
    max_solution_elements: 16,
    max_public_matrix_terms: 8,
    max_public_rhs_terms: 16,
  });
});

test("server benchmark JSON pins authority and Cloud Run authentication", () => {
  const config = benchmarkConfig(parameters(), "challenge", {
    serviceUrl: "https://validator.example",
    issuer: "benchmark-issuer",
    keyId: "benchmark-key-v1",
    publicKey: "11".repeat(32),
    privateService: true,
  });
  assert.deepEqual(config.authority, {
    kind: "remote-v1",
    service_url: "https://validator.example",
    issuer: "benchmark-issuer",
    key_id: "benchmark-key-v1",
    public_key: "11".repeat(32),
    authentication: {
      kind: "gcloud-identity-token-v1",
      audience: null,
    },
    maximum_future_skew_seconds: 30,
    maximum_challenge_lifetime_seconds: 3600,
  });
  assert.deepEqual(config.problem_template.randomness, {
    kind: "challenge-derived-v1",
    derivation: "blake3-xof-v1",
  });

  const publicService = benchmarkConfig(parameters(), "challenge", {
    privateService: false,
  });
  assert.deepEqual(publicService.authority.authentication, { kind: "none-v1" });
});

test("benchmark manifests use the generator's exact succinct evaluator bounds", () => {
  assert.deepEqual(publicEvaluationTerms(parameters({
    family: DIA_FAMILY,
    dimension: 65,
    offsets: [1, 64],
  })), {
    matrix: 9,
    rhs: 16,
  });
  assert.deepEqual(publicEvaluationTerms(parameters({
    family: PROJECTED_NONSYMMETRIC_FAMILY,
    dimension: 37,
    periodBits: 3,
    maximumRowNonzeros: 7,
  })), {
    matrix: 56,
    rhs: 16,
  });
});

test("seed validation and cheap advancement preserve the protocol's canonical spelling", () => {
  assert.match(validationError(parameters({ seed: "01" })), /64 lowercase hexadecimal/);
  assert.match(validationError(parameters({ seed: "AB".repeat(32) })), /lowercase hexadecimal/);
  assert.equal(validationError(parameters({ seed: "ab".repeat(32) })), "");

  assert.equal(nextSeedHex(DEFAULT_INSTANCE_SEED), `${"01".repeat(31)}02`);
  assert.equal(nextSeedHex("ff".repeat(32)), "00".repeat(32));
  assert.throws(() => nextSeedHex("not-a-seed"), /exactly 64 lowercase hexadecimal/);
});

test("the bounded browser BLAKE3 implementation matches the standard hash vectors", () => {
  assert.equal(
    blake3.bytesToHex(blake3.hash(new Uint8Array())),
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
  );
  assert.equal(
    blake3.bytesToHex(blake3.hash(new TextEncoder().encode("abc"))),
    "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
  );
});

test("browser matrix actualization matches Rust export vectors for every family", () => {
  const base = parameters({
    dimension: 8,
    offsets: [1, 3],
    periodBits: 2,
    maximumHalfBandwidth: 3,
    maximumRowNonzeros: 5,
  });
  const signature = (family) => actualizeMatrix({ ...base, family }).entries
    .map((entry) => `${entry.row},${entry.column},${entry.mantissa}`)
    .join("\n");

  assert.equal(signature(TRIDIAGONAL_FAMILY), `0,0,41
0,1,-9
1,0,-9
1,1,65
1,2,-24
2,1,-24
2,2,66
2,3,-10
3,2,-10
3,3,57
3,4,-15
4,3,-15
4,4,56
4,5,-9
5,4,-9
5,5,65
5,6,-24
6,5,-24
6,6,66
6,7,-10
7,6,-10
7,7,42`);

  assert.equal(signature(DIA_FAMILY), `0,0,73
0,1,-19
0,3,-22
1,0,-19
1,1,87
1,2,-12
1,4,-24
2,1,-12
2,2,91
2,3,-24
2,5,-23
3,0,-22
3,2,-24
3,3,111
3,4,-12
3,6,-21
4,1,-24
4,3,-12
4,4,109
4,5,-19
4,7,-22
5,2,-23
5,4,-19
5,5,86
5,6,-12
6,3,-21
6,5,-12
6,6,89
6,7,-24
7,4,-22
7,6,-24
7,7,78`);

  assert.equal(signature(NONSYMMETRIC_FAMILY), `0,0,255
0,2,58
1,1,-47
1,2,-251
1,3,-215
2,0,-254
2,2,198
2,4,-182
2,5,-135
3,1,33
3,3,-39
3,4,102
3,5,-151
3,6,-37
4,1,189
4,2,-224
4,3,-223
4,4,255
4,6,58
5,2,181
5,3,-138
5,5,-47
5,6,-251
5,7,-215
6,3,-55
6,4,-254
6,6,198
7,5,33
7,7,-39`);

  assert.equal(signature(PROJECTED_NONSYMMETRIC_FAMILY), `0,0,-181
0,1,-88
0,3,-10
1,0,202
1,1,-32
1,2,-139
1,4,-10
2,0,255
2,1,-10
2,2,97
2,3,18
2,4,168
3,1,255
3,2,202
3,3,172
3,4,-45
3,5,168
4,1,112
4,3,100
4,4,-181
4,5,-88
4,7,-28
5,2,112
5,4,-173
5,5,-32
5,6,-139
6,3,-214
6,5,100
6,6,97
6,7,18
7,4,-214
7,6,-173
7,7,172`);
});

test("actualized nonsymmetric rows obey the generated structural contract", () => {
  const p = parameters({
    family: NONSYMMETRIC_FAMILY,
    dimension: 37,
    periodBits: 3,
    maximumHalfBandwidth: 5,
    maximumRowNonzeros: 7,
  });
  const matrix = actualizeMatrix(p);
  const changedSeed = actualizeMatrix({ ...p, seed: "02".repeat(32) });
  assert.notDeepEqual(matrix.entries, changedSeed.entries);

  for (let row = 0; row < p.dimension; row += 1) {
    const entries = matrix.entries.filter((entry) => entry.row === row);
    assert.ok(entries.length >= 1 && entries.length <= p.maximumRowNonzeros);
    assert.equal(entries.filter((entry) => entry.column === row).length, 1);
    assert.equal(new Set(entries.map((entry) => entry.column)).size, entries.length);
    assert.ok(entries.every((entry) => Math.abs(entry.column - row) <= p.maximumHalfBandwidth));
    assert.ok(entries.every((entry) => entry.mantissa !== 0n));
    assert.ok(entries.every((entry) => (
      entry.mantissa >= BigInt(p.coefficientMinimum)
      && entry.mantissa <= BigInt(p.coefficientMaximum)
    )));
  }
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

test("projected nonsymmetric templates select the distinct v2 protocol family", () => {
  const p = parameters({ family: PROJECTED_NONSYMMETRIC_FAMILY });
  assert.equal(validationError(p), "");
  assert.deepEqual(matrixSpec(p), {
    kind: PROJECTED_NONSYMMETRIC_FAMILY,
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

test("projected nonsymmetric rows are bounded without the v1 translation period", () => {
  const p = parameters({
    family: PROJECTED_NONSYMMETRIC_FAMILY,
    dimension: 37,
    periodBits: 3,
    maximumHalfBandwidth: 5,
    maximumRowNonzeros: 7,
  });
  const matrix = actualizeMatrix(p);
  const changedSeed = actualizeMatrix({ ...p, seed: "02".repeat(32) });
  assert.notDeepEqual(matrix.entries, changedSeed.entries);

  const normalizedRow = (row) => matrix.entries
    .filter((entry) => entry.row === row)
    .map((entry) => [entry.column - row, entry.mantissa]);
  assert.notDeepEqual(normalizedRow(5), normalizedRow(13));

  for (let row = 0; row < p.dimension; row += 1) {
    const entries = matrix.entries.filter((entry) => entry.row === row);
    assert.ok(entries.length >= 1 && entries.length <= p.maximumRowNonzeros);
    assert.equal(entries.filter((entry) => entry.column === row).length, 1);
    assert.equal(new Set(entries.map((entry) => entry.column)).size, entries.length);
    assert.ok(entries.every((entry) => Math.abs(entry.column - row) <= p.maximumHalfBandwidth));
    assert.ok(entries.every((entry) => entry.mantissa !== 0n));
    if (row + 1 < p.dimension) {
      assert.ok(entries.some((entry) => entry.column === row + 1));
    }
  }
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
  assert.match(
    validationError(sparse({
      family: PROJECTED_NONSYMMETRIC_FAMILY,
      dimension: 1024,
      periodBits: 1,
    })),
    /collectively cover/,
  );
  assert.equal(validationError(sparse({
    family: PROJECTED_NONSYMMETRIC_FAMILY,
    dimension: 1024,
    periodBits: 2,
  })), "");
});

test("the browser admits matrix previews through dimension 1024", () => {
  assert.equal(MAX_VISUALIZATION_DIMENSION, 1024);
  assert.equal(validationError(parameters({ dimension: 1024 })), "");
  assert.match(validationError(parameters({ dimension: 1025 })), /between 2 and 1024/);
  const projected = parameters({
    family: PROJECTED_NONSYMMETRIC_FAMILY,
    dimension: 1024,
    periodBits: 2,
  });
  assert.equal(validationError(projected), "");
  const matrix = actualizeMatrix(projected);
  assert.ok(matrix.entries.length >= 1024);
  assert.ok(matrix.entries.length <= 1024 * projected.maximumRowNonzeros);
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

test("workflows hand one resumable run to the solver and back to the runner", () => {
  const local = localWorkflow();
  assert.match(local, /sparse-benchmark start/);
  assert.match(local, /sparse-benchmark resume/);
  assert.match(local, /Solve A x = b/);
  assert.match(local, /sparse-solve\/solution\/binary64-v1/);
  assert.match(local, /submission\/x\.json/);
  assert.match(local, /result-card\.json/);
  assert.doesNotMatch(local, /sparse-problem|sparse-prover|curl --fail/);
  assert.doesNotMatch(local, /manufactured-solution/);

  const hosted = hostedWorkflow({
    privateService: true,
  });
  assert.match(hosted, /sparse-benchmark start/);
  assert.match(hosted, /sparse-benchmark resume/);
  assert.match(hosted, /Solve A x = b/);
  assert.match(hosted, /fresh identity token per request/);
  assert.match(hosted, /existing proof is reused/);
  assert.doesNotMatch(hosted, /sparse-problem|sparse-prover|curl --fail/);
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
