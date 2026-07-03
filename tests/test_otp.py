"""Tests for the OTP domain module."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from otp_code_extractor.exceptions import (
    InvalidOtpInputError,
    OtpGenerationError,
)
from otp_code_extractor.models import OtpAlgorithm
from otp_code_extractor.otp import (
    OtpConfig,
    extract_code_from_secret,
    extract_code_from_string,
    extract_code_from_uri,
    generate_code,
    parse_only,
    remaining_seconds,
)


class TestTotpExtraction:
    def test_extract_from_uri(self, sample_uri_totp):
        config, code = extract_code_from_uri(sample_uri_totp)
        assert config.type.value == "totp"
        assert len(code) == 6
        assert code.isdigit()

    def test_extract_from_secret(self):
        config, code = extract_code_from_secret("JBSWY3DPEHPK3PXP")
        assert config.type.value == "totp"
        assert config.algorithm == OtpAlgorithm.SHA1
        assert config.digits == 6
        assert config.period == 30
        assert len(code) == 6

    def test_extract_from_secret_sha256(self):
        config, code = extract_code_from_secret(
            "JBSWY3DPEHPK3PXP", algorithm=OtpAlgorithm.SHA256, digits=8
        )
        assert config.algorithm == OtpAlgorithm.SHA256
        assert config.digits == 8
        assert len(code) == 8

    def test_extract_from_secret_invalid(self):
        with pytest.raises(Exception):
            extract_code_from_secret("NOT_BASE32!!!")

    def test_extract_rejects_both_uri_and_secret(self):
        with pytest.raises(InvalidOtpInputError):
            extract_code_from_string("")  # first validates

    def test_extract_string_secret(self):
        config, code = extract_code_from_string("JBSWY3DPEHPK3PXP")
        assert code.isdigit() and len(code) == 6

    def test_extract_string_uri(self, sample_uri_totp):
        config, code = extract_code_from_string(sample_uri_totp)
        assert code.isdigit() and len(code) == 6

    def test_extract_string_unknown_raises(self):
        with pytest.raises(InvalidOtpInputError):
            extract_code_from_string("hello world this is not a secret")


class TestHotpExtraction:
    def test_extract_hotp_with_counter(self):
        config, code = extract_code_from_secret(
            "JBSWY3DPEHPK3PXP", counter=42
        )
        assert config.type.value == "hotp"
        assert config.counter == 42
        assert len(code) == 6

    def test_extract_hotp_from_uri(self, sample_uri_hotp):
        config, code = extract_code_from_uri(sample_uri_hotp)
        assert config.type.value == "hotp"
        assert config.counter == 42
        assert code.isdigit()

    def test_hotp_deterministic_for_same_counter(self):
        config1, code1 = extract_code_from_secret("JBSWY3DPEHPK3PXP", counter=7)
        config2, code2 = extract_code_from_secret("JBSWY3DPEHPK3PXP", counter=7)
        assert code1 == code2
        assert config1.counter == 7

    def test_hotp_different_counters_differ(self):
        _, code1 = extract_code_from_secret("JBSWY3DPEHPK3PXP", counter=1)
        _, code2 = extract_code_from_secret("JBSWY3DPEHPK3PXP", counter=2)
        assert code1 != code2


class TestParseOnly:
    def test_parse_totp_uri(self, sample_uri_totp):
        data = parse_only(uri=sample_uri_totp)
        assert data["type"].value == "totp"
        assert data["secret"] is None
        assert data["secret_redacted"] is True

    def test_parse_with_secret_when_allowed(self, sample_uri_totp):
        data = parse_only(uri=sample_uri_totp, redact=False)
        assert data["secret"] == "JBSWY3DPEHPK3PXP"
        assert data["secret_redacted"] is False

    def test_parse_from_secret(self):
        data = parse_only(secret="JBSWY3DPEHPK3PXP", digits=8, algorithm="SHA256")
        assert data["type"].value == "totp"
        assert data["digits"] == 8
        assert data["algorithm"] == OtpAlgorithm.SHA256

    def test_parse_missing_both(self):
        with pytest.raises(InvalidOtpInputError):
            parse_only()


class TestGenerateCode:
    def test_generate_at_specific_time(self):
        config = OtpConfig(
            type=__import__("otp_code_extractor.models", fromlist=["OtpType"]).OtpType.TOTP,
            secret="JBSWY3DPEHPK3PXP",
            algorithm=OtpAlgorithm.SHA1,
            digits=6,
            period=30,
        )
        at = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        code = generate_code(config, now=at)
        assert code.isdigit() and len(code) == 6

    def test_hotp_generate_without_counter(self):
        config = OtpConfig(
            type=__import__("otp_code_extractor.models", fromlist=["OtpType"]).OtpType.HOTP,
            secret="JBSWY3DPEHPK3PXP",
            counter=None,
        )
        with pytest.raises(OtpGenerationError):
            generate_code(config)


class TestRemainingSeconds:
    def test_remaining_seconds_positive(self):
        remaining = remaining_seconds(30)
        assert 0 <= remaining <= 30

    def test_remaining_seconds_at_boundary(self):
        at = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        remaining = remaining_seconds(30, now=at)
        assert remaining == 30 - (at.timestamp() % 30)
