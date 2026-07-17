"use strict";

const form = document.querySelector("#generator-form");
const canvas = document.querySelector("#spy-plot");
const context = canvas.getContext("2d");
const formError = document.querySelector("#form-error");
const localCode = document.querySelector("#local-code");
const hostedCode = document.querySelector("#hosted-code");
const templateCode = document.querySelector("#template-code");
const templateKind = document.querySelector("#template-kind");
const hostInputs = ["service-url", "issuer", "key-id", "public-key"].map((id) => document.querySelector(`#${id}`));
const privateService = document.querySelector("#private-service");

const MAX_SAFE_MANTISSA = 9007199254740991;
const LOCAL_SEED = "0101010101010101010101010101010101010101010101010101010101010101";

function integerValue(id) {
  return Number.parseInt(document.querySelector(`#${id}`).value, 10);
}

function parameters() {
  return {
    family: document.querySelector("#family").value,
    dimension: integerValue("dimension"),
    periodBits: integerValue("period-bits"),
    fractionalBits: integerValue("fractional-bits"),
    margin: integerValue("margin"),
    minimum: integerValue("minimum"),
    maximum: integerValue("maximum"),
    rhs: document.querySelector("#rhs").value,
  };
}

function validationError(p) {
  const integers = [p.dimension, p.periodBits, p.fractionalBits, p.margin, p.minimum, p.maximum];
  if (!integers.every(Number.isSafeInteger)) return "All generator parameters must be integers.";
  if (p.dimension < 2 || p.dimension > 128) return "Visualization dimension must be between 2 and 128.";
  if (p.periodBits < 0 || p.periodBits > 16) return "Period bits must be between 0 and 16.";
  if (p.fractionalBits < 0 || p.fractionalBits > 52) return "Fractional bits must be between 0 and 52.";
  if (p.minimum < 1 || p.minimum > p.maximum) return "Magnitudes must satisfy 1 ≤ minimum ≤ maximum.";
  if (p.maximum > MAX_SAFE_MANTISSA || p.margin < 1 || p.margin > MAX_SAFE_MANTISSA) return "Mantissas must fit exactly in binary64.";
  if ((2 * p.maximum) + p.margin > MAX_SAFE_MANTISSA) return "Two off-diagonal magnitudes plus the margin must fit exactly in binary64.";
  return "";
}

function template(p, kind) {
  const randomness = kind === "challenge"
    ? { kind: "challenge-derived-v1", derivation: "blake3-xof-v1" }
    : { kind: "literal-v1", seed: LOCAL_SEED };
  return {
    schema: "sparse-solve/problem-template/v1",
    randomness,
    matrix: {
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
    },
    rhs: { kind: p.rhs },
    requested_outputs: [{ kind: "squared-l2-residual-v1" }],
  };
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
  for (let row = 0; row < p.dimension; row += 1) {
    if (row > 0) drawEntry(row, row - 1, "#e45826");
    drawEntry(row, row, "#17233d");
    if (row + 1 < p.dimension) drawEntry(row, row + 1, "#e45826");
  }
  context.strokeStyle = "#aeb6c5";
  context.strokeRect(padding + 0.5, padding + 0.5, plotSize - 1, plotSize - 1);

  const nonzeros = (3 * p.dimension) - 2;
  const density = (100 * nonzeros / (p.dimension * p.dimension)).toFixed(1);
  document.querySelector("#plot-title").textContent = `${p.dimension} × ${p.dimension}`;
  document.querySelector("#plot-summary").textContent = `${nonzeros} structural nonzeros · ${density}% density`;
  canvas.setAttribute("aria-label", `${p.dimension} by ${p.dimension} symmetric tridiagonal matrix spy plot with ${nonzeros} structural nonzeros`);
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
  const error = validationError(p);
  formError.hidden = !error;
  formError.textContent = error;
  if (error) return;
  drawPlot(p);
  localCode.textContent = localWorkflow();
  hostedCode.textContent = hostedWorkflow();
  templateCode.textContent = `${JSON.stringify(template(p, templateKind.value), null, 2)}\n`;
}

form.addEventListener("input", update);
templateKind.addEventListener("change", update);
hostInputs.forEach((input) => input.addEventListener("input", update));
privateService.addEventListener("change", update);

document.querySelectorAll("[role=tab]").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll("[role=tab]").forEach((item) => item.setAttribute("aria-selected", String(item === tab)));
    document.querySelectorAll("[role=tabpanel]").forEach((panel) => { panel.hidden = panel.id !== `${tab.dataset.tab}-panel`; });
  });
});

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.addEventListener("click", async () => {
    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(document.querySelector(`#${button.dataset.copy}`).textContent);
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
  link.download = templateKind.value === "challenge" ? "challenge-template.json" : "local-template.json";
  link.click();
  URL.revokeObjectURL(link.href);
});

update();
