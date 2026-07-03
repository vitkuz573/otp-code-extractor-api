"""Render a sample otpauth:// URI to a PNG file for testing or demos."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

DEFAULT_URI = (
    "otpauth://totp/ACME:alice@example.com"
    "?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30"
)
DEFAULT_OUT = Path("data/sample_otp.png")


def render(uri: str, dest: Path) -> Path:
    """Render ``uri`` to ``dest`` and return the path."""
    try:
        import qrcode  # type: ignore[import-not-found]
    except ImportError as exc:
        print(f"qrcode is required: {exc}", file=sys.stderr)
        raise SystemExit(1)

    dest.parent.mkdir(parents=True, exist_ok=True)
    image = qrcode.make(uri)
    image.save(dest)
    return dest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri", default=DEFAULT_URI, help="otpauth:// URI to encode")
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Output PNG path (default: data/sample_otp.png)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    dest = render(args.uri, args.out)
    print(f"Saved {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
