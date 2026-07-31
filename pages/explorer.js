"use strict";

const TRIDIAGONAL_FAMILY = "seeded-symmetric-tridiagonal-v1";
const DIA_FAMILY = "seeded-symmetric-dia-laplacian-v1";
const MAX_SAFE_MANTISSA = 9007199254740991;
const MAX_DIA_OFFSETS = 16;
const LOCAL_SEED = "0101010101010101010101010101010101010101010101010101010101010101";

function parseOffsets(value) {
  if (!value.trim()) return [];
  return value.split(",").map((part) => {
    const token = part.trim();
    return /^\d+$/.test(token) ? Number(token) : Number.NaN;
  });
}

function matrixOffsets(p) {
  return p.family === DIA_FAMILY ? p.offsets : [1];
}

function validationError(p) {
  if (p.family !== TRIDIAGONAL_FAMILY && p.family !== DIA_FAMILY) {
    return "Select a registered matrix family.";
  }

  const integers = [p.dimension, p.periodBits, p.fractionalBits, p.margin, p.minimum, p.maximum];
  if (!integers.every(Number.isSafeInteger)) return "All generator parameters must be integers.";
  if (p.dimension < 2 || p.dimension > 128) return "Visualization dimension must be between 2 and 128.";
  if (p.periodBits < 0 || p.periodBits > 16) return "Period bits must be between 0 and 16.";
  if (p.fractionalBits < 0 || p.fractionalBits > 52) return "Fractional bits must be between 0 and 52.";
  if (p.minimum < 1 || p.minimum > p.maximum) return "Magnitudes must satisfy 1 ≤ minimum ≤ maximum.";
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

function problemTemplate(p, kind) {
  const randomness = kind === "challenge"
    ? { kind: "challenge-derived-v1", derivation: "blake3-xof-v1" }
    : { kind: "literal-v1", seed: LOCAL_SEED };
  return {
    schema: "sparse-solve/problem-template/v1",
    randomness,
    matrix: matrixSpec(p),
    rhs: { kind: p.rhs },
    requested_outputs: [{ kind: "squared-l2-residual-v1" }],
  };
}

function structuralNonzeros(p) {
  return p.dimension + matrixOffsets(p)
    .reduce((total, offset) => total + (2 * (p.dimension - offset)), 0);
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
      dimension: numberValue("dimension"),
      offsets: parseOffsets(document.querySelector("#offsets").value),
      periodBits: numberValue("period-bits"),
      fractionalBits: numberValue("fractional-bits"),
      margin: numberValue("margin"),
      minimum: numberValue("minimum"),
      maximum: numberValue("maximum"),
      rhs: document.querySelector("#rhs").value,
    };
  }

  function updateFamilyControls(p) {
    const dia = p.family === DIA_FAMILY;
    offsetsControl.hidden = !dia;
    periodLabel.textContent = dia ? "Edge period bits" : "Period bits";
    periodHint.textContent = dia
      ? "One shared period and range; each offset table is seeded independently"
      : "";
    periodHint.hidden = !dia;
    marginLabel.textContent = dia ? "Diagonal shift" : "Dominance margin";
    minimumLabel.textContent = dia ? "Minimum edge weight" : "Minimum magnitude";
    maximumLabel.textContent = dia ? "Maximum edge weight" : "Maximum magnitude";
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
    const offsets = matrixOffsets(p);
    for (let row = 0; row < p.dimension; row += 1) {
      for (const offset of offsets) {
        if (row >= offset) drawEntry(row, row - offset, "#e45826");
      }
      drawEntry(row, row, "#17233d");
      for (const offset of offsets) {
        if (row + offset < p.dimension) drawEntry(row, row + offset, "#e45826");
      }
    }
    context.strokeStyle = "#aeb6c5";
    context.strokeRect(padding + 0.5, padding + 0.5, plotSize - 1, plotSize - 1);

    const nonzeros = structuralNonzeros(p);
    const density = (100 * nonzeros / (p.dimension * p.dimension)).toFixed(1);
    document.querySelector("#plot-title").textContent = `${p.dimension} × ${p.dimension}`;
    document.querySelector("#plot-summary").textContent = `${nonzeros} structural nonzeros · ${density}% density`;
    const familyDescription = p.family === DIA_FAMILY
      ? `symmetric DIA matrix with positive offsets ${offsets.join(", ")}`
      : "symmetric tridiagonal matrix";
    canvas.setAttribute(
      "aria-label",
      `${p.dimension} by ${p.dimension} ${familyDescription} spy plot with ${nonzeros} structural nonzeros`,
    );
    plotNote.textContent = p.family === DIA_FAMILY
      ? `Positive offsets ${offsets.join(", ")} are mirrored; boundary edges truncate without wrapping.`
      : "Rows run top to bottom; columns run left to right. Values vary with the finalized seed, but this family’s sparsity pattern does not.";
  }

  function localWorkflow() {
    return `# Save the Local template from this explorer as /tmp/template.json.
cargo run -p sparse-problem -- finalize-local \\
  --template /tmp/template.json \\
  --problem /tmp/problem.json

# Replace this fixture helper with your solver for a real workflow.
cargo run -p sparse-problem -- manufactured-solution \\
  --problem /tmp/problem.json \\
  --solution /tmp/x.json

cargo run --release -p sparse-prover -- prove \\
  --problem /tmp/problem.json \\
  --validation examples/direct-validation.json \\
  --solution /tmp/x.json \\
  --proof /tmp/validation.proof

cargo run --release -p sparse-validator -- verify \\
  --proof /tmp/validation.proof \\
  --allow-literal`;
  }

  function hostedWorkflow() {
    const [serviceUrl, issuer, keyId, publicKey] = hostInputs.map((input) => input.value.trim());
    const authOption = privateService.checked
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

# Replace this fixture helper with your solver for a real workflow.
cargo run -p sparse-problem -- manufactured-solution \\
  --problem /tmp/problem.json \\
  --solution /tmp/x.json

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

  function update() {
    const p = parameters();
    updateFamilyControls(p);
    const error = validationError(p);
    formError.hidden = !error;
    formError.textContent = error;
    if (error) return;
    drawPlot(p);
    localCode.textContent = localWorkflow();
    hostedCode.textContent = hostedWorkflow();
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
    MAX_SAFE_MANTISSA,
    TRIDIAGONAL_FAMILY,
    matrixOffsets,
    matrixSpec,
    parseOffsets,
    problemTemplate,
    structuralNonzeros,
    validationError,
  };
}

if (typeof document !== "undefined") initialize();
