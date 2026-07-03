"""Command-line interface for offline use.

The CLI wraps the core code extraction features so the tool can be used without
running a web server.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from .config import get_settings
from .models import OtpAlgorithm, OtpType
from .otp import extract_code_from_qr, extract_code_from_secret, extract_code_from_uri, parse_only


def _print_json(data: dict) -> None:
    json.dump(data, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def _format_response(config, code: str | None) -> dict:
    """Build a JSON-friendly dict from a config and an optional code."""
    payload = config.to_response_dict()
    if code is not None:
        payload["code"] = code
    return payload


def cmd_code(args: argparse.Namespace) -> int:
    """Generate a single OTP code."""
    if args.uri:
        config, code = extract_code_from_uri(args.uri)
    elif args.secret:
        config, code = extract_code_from_secret(
            args.secret,
            algorithm=OtpAlgorithm(args.algorithm) if args.algorithm else None,
            digits=args.digits,
            period=args.period,
            counter=args.counter,
        )
    elif args.qr:
        image_bytes = Path(args.qr).read_bytes()
        config, code = extract_code_from_qr(image_bytes, mime_type=args.mime)
    else:
        print(
            "Provide --uri, --secret or --qr.",
            file=sys.stderr,
        )
        return 2

    if args.json:
        _print_json(_format_response(config, code))
    else:
        print(
            f"[{config.type.value.upper()}] {code}  "
            f"digits={config.digits} algo={config.algorithm.value}"
        )
    return 0


def cmd_parse(args: argparse.Namespace) -> int:
    """Parse a URI / secret without generating a code."""
    settings = get_settings()
    data = parse_only(
        uri=args.uri,
        secret=args.secret,
        algorithm=OtpAlgorithm(args.algorithm) if args.algorithm else None,
        digits=args.digits,
        period=args.period,
        counter=args.counter,
        redact=not args.show_secret,
        settings=settings,
    )
    _print_json(data)
    return 0


def cmd_qr(args: argparse.Namespace) -> int:
    """Render an otpauth:// URI to a QR PNG file."""
    try:
        import qrcode  # type: ignore[import-not-found]
    except ImportError as exc:
        print(f"qrcode is required: {exc}", file=sys.stderr)
        return 1
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    image = qrcode.make(args.uri)
    image.save(target)
    print(f"Saved {target}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="otp-extractor",
        description="Offline OTP code extractor and QR generator.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON output")

    sub = parser.add_subparsers(dest="command", required=True)

    p_code = sub.add_parser("code", help="Generate a single OTP code")
    src = p_code.add_mutually_exclusive_group(required=True)
    src.add_argument("--uri", help="otpauth:// URI")
    src.add_argument("--secret", help="Raw base32 secret")
    src.add_argument("--qr", help="Path to a QR image (PNG / JPEG / ...)")
    p_code.add_argument(
        "--algorithm",
        choices=[a.value for a in OtpAlgorithm],
        default=None,
        help="HMAC algorithm (default SHA1)",
    )
    p_code.add_argument("--digits", type=int, default=None, help="Code length")
    p_code.add_argument("--period", type=int, default=None, help="TOTP period in seconds")
    p_code.add_argument("--counter", type=int, default=None, help="HOTP counter")
    p_code.add_argument("--mime", default=None, help="Override mime type for --qr")
    p_code.set_defaults(func=cmd_code)

    p_parse = sub.add_parser("parse", help="Parse a URI / secret without a code")
    src2 = p_parse.add_mutually_exclusive_group(required=True)
    src2.add_argument("--uri", help="otpauth:// URI")
    src2.add_argument("--secret", help="Raw base32 secret")
    p_parse.add_argument("--algorithm", choices=[a.value for a in OtpAlgorithm], default=None)
    p_parse.add_argument("--digits", type=int, default=None)
    p_parse.add_argument("--period", type=int, default=None)
    p_parse.add_argument("--counter", type=int, default=None)
    p_parse.add_argument(
        "--show-secret",
        action="store_true",
        help="Include the secret in the output (default: redacted)",
    )
    p_parse.set_defaults(func=cmd_parse)

    p_qr = sub.add_parser("qr", help="Render an otpauth:// URI to a PNG")
    p_qr.add_argument("--uri", required=True, help="otpauth:// URI to encode")
    p_qr.add_argument("--out", required=True, help="Output PNG path")
    p_qr.set_defaults(func=cmd_qr)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
