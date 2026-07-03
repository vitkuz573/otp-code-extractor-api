// Minimal fetch-based client for the OTP Code Extractor API.
// Run with: node examples/javascript_client.js
// (Requires Node 18+ for the global `fetch`.)

const BASE_URL = "http://localhost:8000";

async function fromUri(uri) {
  const r = await fetch(`${BASE_URL}/v1/otp/from-uri`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ uri }),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

async function fromSecret(secret) {
  const r = await fetch(`${BASE_URL}/v1/otp/from-secret`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ secret }),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

async function fromQrBase64(imageBase64, mimeType = "image/png") {
  const r = await fetch(`${BASE_URL}/v1/otp/from-qr-base64`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ image_base64: imageBase64, mime_type: mimeType }),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

async function batch(items) {
  const r = await fetch(`${BASE_URL}/v1/otp/batch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ items }),
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}: ${await r.text()}`);
  return r.json();
}

(async () => {
  const sampleUri =
    "otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME";
  const code = await fromUri(sampleUri);
  console.log(`URI -> code=${code.code} remaining=${code.remaining_seconds}s`);

  const secret = await fromSecret("JBSWY3DPEHPK3PXP");
  console.log(`secret -> code=${secret.code}`);

  const b = await batch([
    { kind: "uri", uri: sampleUri, label: "alice" },
    { kind: "secret", secret: "JBSWY3DPEHPK3PXP", label: "bob" },
  ]);
  console.log(`batch -> total=${b.total} ok=${b.succeeded} failed=${b.failed}`);

  // QR example (expects data/sample_otp.png to exist).
  const fs = await import("node:fs/promises");
  try {
    const png = await fs.readFile("data/sample_otp.png");
    const b64 = png.toString("base64");
    const qr = await fromQrBase64(b64);
    console.log(`qr -> code=${qr.code} issuer=${qr.issuer}`);
  } catch (err) {
    console.log(`qr -> skipped (${err.message})`);
  }
})();
