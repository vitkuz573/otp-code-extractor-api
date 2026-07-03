"""Python client example for the OTP Code Extractor API.

Requires:
    pip install requests
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

import requests

BASE_URL = "http://localhost:8000"


def _post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = requests.post(f"{BASE_URL}{path}", json=payload, timeout=10)
    response.raise_for_status()
    return response.json()


def _post_file(path: str, file_path: Path) -> dict[str, Any]:
    with file_path.open("rb") as fh:
        response = requests.post(
            f"{BASE_URL}{path}",
            files={"file": (file_path.name, fh, "image/png")},
            timeout=30,
        )
    response.raise_for_status()
    return response.json()


def from_uri() -> None:
    """Extract a code from an otpauth:// URI."""
    result = _post(
        "/v1/otp/from-uri",
        {
            "uri": (
                "otpauth://totp/ACME:alice@example.com"
                "?secret=JBSWY3DPEHPK3PXP&issuer=ACME"
            )
        },
    )
    print(f"code: {result['code']}  type={result['type']}  "
          f"remaining={result['remaining_seconds']}s")


def from_secret() -> None:
    """Extract a code from a raw base32 secret."""
    result = _post(
        "/v1/otp/from-secret",
        {"secret": "JBSWY3DPEHPK3PXP", "digits": 6, "period": 30},
    )
    print(f"code: {result['code']}")


def from_qr(path: Path) -> None:
    """Extract a code from a QR PNG via the JSON base64 endpoint."""
    data = path.read_bytes()
    b64 = base64.b64encode(data).decode()
    result = _post(
        "/v1/otp/from-qr-base64",
        {"image_base64": b64, "mime_type": "image/png"},
    )
    print(f"code: {result['code']}  issuer={result['issuer']}")


def parse_only() -> None:
    """Parse a URI without generating a code (secret redacted)."""
    result = _post(
        "/v1/otp/parse",
        {
            "uri": (
                "otpauth://totp/ACME:alice@example.com"
                "?secret=JBSWY3DPEHPK3PXP"
            )
        },
    )
    print("parse:", json.dumps(result, indent=2))


def batch() -> None:
    """Run a small batch of mixed extractions."""
    result = _post(
        "/v1/otp/batch",
        {
            "items": [
                {
                    "kind": "uri",
                    "uri": (
                        "otpauth://totp/ACME:alice@example.com"
                        "?secret=JBSWY3DPEHPK3PXP"
                    ),
                    "label": "alice",
                },
                {"kind": "secret", "secret": "JBSWY3DPEHPK3PXP", "label": "bob"},
            ]
        },
    )
    print(f"batch: total={result['total']} ok={result['succeeded']} "
          f"failed={result['failed']}")


if __name__ == "__main__":
    from_uri()
    from_secret()
    parse_only()
    batch()
    if len(sys.argv) > 1 and Path(sys.argv[1]).exists():
        from_qr(Path(sys.argv[1]))
