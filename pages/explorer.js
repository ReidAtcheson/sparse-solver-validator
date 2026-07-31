"use strict";

const TRIDIAGONAL_FAMILY = "seeded-symmetric-tridiagonal-v1";
const DIA_FAMILY = "seeded-symmetric-dia-laplacian-v1";
const NONSYMMETRIC_FAMILY = "seeded-nonsymmetric-row-sparse-v1";
const SEEDED_RHS_FAMILY = "seeded-periodic-dyadic-v1";
const MAX_SAFE_MANTISSA = 9007199254740991;
const MAX_DIA_OFFSETS = 16;
const MAX_NONSYMMETRIC_ROW_NONZEROS = 32;
const LOCAL_SEED = "0101010101010101010101010101010101010101010101010101010101010101";

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
    : { kind: "literal-v1", seed: LOCAL_SEED };
  return {
    schema: "sparse-solve/problem-template/v1",
    randomness,
    matrix: matrixSpec(p),
    rhs: rhsSpec(p),
    requested_outputs: [{ kind: "squared-l2-residual-v1" }],
  };
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
  const offDiagonalLegend = document.querySelector("#off-diagonal-legend");
  const offDiagonalSwatch = document.querySelector(".swatch.off-diagonal");
  const plotNote = document.querySelector("#plot-note");

  function numberValue(id) {
    return Number(document.querySelector(`#${id}`).value);
  }

  function parameters() {
    return {
      family: document.querySelector("#family").value,
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
    offDiagonalLegend.textContent = nonsymmetric ? "eligible off-diagonal" : "off-diagonal";
    offDiagonalSwatch.classList.toggle("eligible", nonsymmetric);
    document.querySelector("#maximum-half-bandwidth").max = String(p.dimension - 1);
  }

  function drawPlot(p) {
    const size = canvas.width;
    const padding = 20;
    const plotSize = size - (2 * padding);
    const cell = plotSize / p.dimension;
    context.clearRect(0, 0, size, size);
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, size, size);

    const dotSize = Math.max(1.5, Math.min(cell * 0.72, 9));
    const drawEntry = (row, column, color) => {
      context.fillStyle = color;
      context.fillRect(
        padding + (column + 0.5) * cell - dotSize / 2,
        padding + (row + 0.5) * cell - dotSize / 2,
        dotSize,
        dotSize,
      );
    };
    const nonsymmetric = p.family === NONSYMMETRIC_FAMILY;
    const offsets = matrixOffsets(p);
    for (let row = 0; row < p.dimension; row += 1) {
      if (nonsymmetric) {
        const first = Math.max(0, row - p.maximumHalfBandwidth);
        const last = Math.min(p.dimension - 1, row + p.maximumHalfBandwidth);
        for (let column = first; column <= last; column += 1) {
          if (column !== row) drawEntry(row, column, "#efb39d");
        }
      } else {
        for (const offset of offsets) {
          if (row >= offset) drawEntry(row, row - offset, "#e45826");
        }
      }
      drawEntry(row, row, "#17233d");
      if (!nonsymmetric) {
        for (const offset of offsets) {
          if (row + offset < p.dimension) drawEntry(row, row + offset, "#e45826");
        }
      }
    }
    context.strokeStyle = "#aeb6c5";
    context.strokeRect(padding + 0.5, padding + 0.5, plotSize - 1, plotSize - 1);

    const nonzeros = structuralNonzeros(p);
    const density = (100 * nonzeros / (p.dimension * p.dimension)).toFixed(1);
    document.querySelector("#plot-title").textContent = `${p.dimension} × ${p.dimension}`;
    document.querySelector("#plot-summary").textContent = nonsymmetric
      ? `at most ${nonzeros} structural nonzeros · at most ${density}% density`
      : `${nonzeros} structural nonzeros · ${density}% density`;
    const familyDescription = p.family === DIA_FAMILY
      ? `symmetric DIA matrix with positive offsets ${offsets.join(", ")}`
      : nonsymmetric
        ? `nonsymmetric generated-pattern matrix with half bandwidth ${p.maximumHalfBandwidth}`
        : "symmetric tridiagonal matrix";
    canvas.setAttribute(
      "aria-label",
      nonsymmetric
        ? `${p.dimension} by ${p.dimension} ${familyDescription} eligible sparsity envelope`
        : `${p.dimension} by ${p.dimension} ${familyDescription} spy plot with ${nonzeros} structural nonzeros`,
    );
    plotNote.textContent = p.family === DIA_FAMILY
      ? `Positive offsets ${offsets.join(", ")} are mirrored; boundary edges truncate without wrapping.`
      : nonsymmetric
        ? `The plot shows the eligible bandwidth envelope, not realized entries. The finalized seed chooses at most ${p.maximumRowNonzeros} entries per row, including a required diagonal; boundaries truncate without wrapping. Its MLE uses ${Math.min(2 ** p.periodBits, p.dimension) * p.maximumRowNonzeros} public pattern terms.`
        : "Rows run top to bottom; columns run left to right. Values vary with the finalized seed, but this family’s sparsity pattern does not.";
  }

  function update() {
    const p = parameters();
    updateFamilyControls(p);
    const error = validationError(p);
    formError.hidden = !error;
    formError.textContent = error;
    if (error) return;
    drawPlot(p);
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
    DIA_FAMILY,
    MAX_DIA_OFFSETS,
    MAX_NONSYMMETRIC_ROW_NONZEROS,
    MAX_SAFE_MANTISSA,
    NONSYMMETRIC_FAMILY,
    SEEDED_RHS_FAMILY,
    TRIDIAGONAL_FAMILY,
    hostedWorkflow,
    localWorkflow,
    matrixOffsets,
    matrixSpec,
    parseOffsets,
    problemTemplate,
    rhsSpec,
    solverHandoff,
    structuralNonzeros,
    validationError,
  };
}

if (typeof document !== "undefined") initialize();
