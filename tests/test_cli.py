"""Tests for the argparse CLI."""

from __future__ import annotations

import json

import pytest

from otp_code_extractor.cli import build_parser, main


class TestCliCode:
    def test_code_from_uri_text(self, capsys, sample_uri_totp):
        rc = main(["code", "--uri", sample_uri_totp])
        assert rc == 0
        out = capsys.readouterr().out
        assert "TOTP" in out

    def test_code_from_uri_json(self, capsys, sample_uri_totp):
        rc = main(["code", "--uri", sample_uri_totp, "--json"])
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        assert body["type"].lower() == "totp"
        assert body["code"].isdigit()

    def test_code_from_secret_json(self, capsys):
        rc = main(["code", "--secret", "JBSWY3DPEHPK3PXP", "--json"])
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        assert body["digits"] == 6
        assert body["algorithm"] == "SHA1"

    def test_code_hotp_with_counter(self, capsys):
        rc = main(
            [
                "code",
                "--secret",
                "JBSWY3DPEHPK3PXP",
                "--counter",
                "5",
                "--json",
            ]
        )
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        assert body["type"].lower() == "hotp"
        assert body["counter"] == 5

    def test_code_no_input_returns_2(self, capsys):
        with pytest.raises(SystemExit):
            main(["code"])


class TestCliParse:
    def test_parse_uri_redacted_by_default(self, capsys, sample_uri_totp):
        rc = main(["parse", "--uri", sample_uri_totp])
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        assert body["secret"] is None
        assert body["secret_redacted"] is True

    def test_parse_uri_with_show_secret(self, capsys, sample_uri_totp):
        rc = main(["parse", "--uri", sample_uri_totp, "--show-secret"])
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        assert body["secret"] == "JBSWY3DPEHPK3PXP"

    def test_parse_secret_with_options(self, capsys):
        rc = main(
            [
                "parse",
                "--secret",
                "JBSWY3DPEHPK3PXP",
                "--digits",
                "8",
                "--algorithm",
                "SHA256",
                "--show-secret",
            ]
        )
        assert rc == 0
        body = json.loads(capsys.readouterr().out)
        assert body["digits"] == 8
        assert body["algorithm"] == "SHA256"


class TestCliQr:
    def test_qr_writes_file(self, tmp_path, sample_uri_totp):
        out = tmp_path / "qr.png"
        rc = main(["qr", "--uri", sample_uri_totp, "--out", str(out)])
        assert rc == 0
        assert out.exists()
        assert out.stat().st_size > 0


class TestParser:
    def test_build_parser(self):
        parser = build_parser()
        assert parser.prog == "otp-extractor"
