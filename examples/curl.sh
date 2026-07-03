#!/usr/bin/env bash
# Example curl calls for the OTP Code Extractor API.
# Make sure the service is running on http://localhost:8000.

set -euo pipefail
BASE_URL="${BASE_URL:-http://localhost:8000}"

echo "==> 1. Health"
curl -fsS "${BASE_URL}/health" | python -m json.tool

echo
echo "==> 2. Extract a code from an otpauth:// URI"
curl -fsS -X POST "${BASE_URL}/v1/otp/from-uri" \
    -H "Content-Type: application/json" \
    -d '{
          "uri": "otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30"
        }' | python -m json.tool

echo
echo "==> 3. Extract a code from a raw base32 secret"
curl -fsS -X POST "${BASE_URL}/v1/otp/from-secret" \
    -H "Content-Type: application/json" \
    -d '{"secret":"JBSWY3DPEHPK3PXP","digits":6,"period":30}' | python -m json.tool

echo
echo "==> 4. Parse a URI without generating a code (secret redacted)"
curl -fsS -X POST "${BASE_URL}/v1/otp/parse" \
    -H "Content-Type: application/json" \
    -d '{
          "uri": "otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP"
        }' | python -m json.tool

echo
echo "==> 5. Auto-detect from a raw secret"
curl -fsS -X POST "${BASE_URL}/v1/otp/from-string" \
    -H "Content-Type: application/json" \
    -d '{"input":"JBSWY3DPEHPK3PXP"}' | python -m json.tool

echo
echo "==> 6. Batch extraction"
curl -fsS -X POST "${BASE_URL}/v1/otp/batch" \
    -H "Content-Type: application/json" \
    -d '{
          "items": [
            {"kind":"uri","uri":"otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP","label":"alice"},
            {"kind":"secret","secret":"JBSWY3DPEHPK3PXP","label":"bob"}
          ]
        }' | python -m json.tool

echo
echo "==> 7. Extract a code from a QR PNG (multipart)"
curl -fsS -X POST "${BASE_URL}/v1/otp/from-qr" \
    -F "file=@${1:-data/sample_otp.png}" | python -m json.tool

echo
echo "==> 8. Extract a code from a QR PNG (JSON base64)"
QR_B64="$(base64 "${1:-data/sample_otp.png}" 2>/dev/null || true)"
if [ -n "${QR_B64}" ]; then
    curl -fsS -X POST "${BASE_URL}/v1/otp/from-qr-base64" \
        -H "Content-Type: application/json" \
        -d "{\"image_base64\": \"${QR_B64}\", \"mime_type\": \"image/png\"}" \
        | python -m json.tool
else
    echo "    (skipped — file not found)"
fi

echo
echo "Done."
