# Contributing

Thanks for your interest in improving the OTP Code Extractor API!

## Development setup

```bash
git clone https://github.com/vitkuz573/otp-code-extractor-api.git
cd otp-code-extractor-api
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pre-commit install
```

The QR decoder depends on `libgl1` and `libglib2.0-0`. On Debian/Ubuntu:

```bash
sudo apt-get install -y libgl1 libglib2.0-0
```

## Workflow

1. Create a feature branch from `main`.
2. Make your change with tests.
3. Run `make lint typecheck test` locally.
4. Open a pull request against `main`.

## Style

- Line length: **100** (`ruff format`).
- Type hints everywhere on public APIs.
- Pydantic v2 models for all request / response bodies.
- New domain exceptions extend `OtpExtractorError` and declare a `code` plus
  `http_status`.
- Public functions get a one-line docstring; non-obvious internals get a full
  docstring.

## Tests

- One test file per module, named `test_<module>.py`.
- Use fixtures from `tests/conftest.py` rather than constructing settings
  manually.
- Tests must run offline — no real network calls, no real Redis, no real
  database files outside `tmp_path`.

## Commit messages

- Imperative mood ("Add batch endpoint", not "Added").
- Wrap at 72 characters.
- Reference the issue if one exists (`#123`).
