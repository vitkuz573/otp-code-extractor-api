"""Tests for validators and URI parsing."""

from __future__ import annotations

import pytest

from otp_code_extractor.exceptions import (
    InvalidOtpUriError,
    InvalidSecretError,
    UnsupportedAlgorithmError,
    UnsupportedDigitsError,
    UnsupportedPeriodError,
)
from otp_code_extractor.models import OtpAlgorithm
from otp_code_extractor.validators import (
    detect_input_kind,
    is_valid_base32,
    normalize_secret,
    parse_otpauth_uri,
    split_otpauth_label,
    validate_algorithm,
    validate_digits,
    validate_period,
    validate_secret,
)


class TestSecretNormalization:
    def test_normalize_uppercases_and_strips(self):
        assert normalize_secret(" jbswy3dpehpk3pxp\n") == "JBSWY3DPEHPK3PXP"

    def test_normalize_empty_raises(self):
        with pytest.raises(InvalidSecretError):
            normalize_secret("   ")

    def test_normalize_none_raises(self):
        with pytest.raises(InvalidSecretError):
            normalize_secret(None)

    def test_is_valid_base32_true(self):
        assert is_valid_base32("JBSWY3DPEHPK3PXP")
        assert is_valid_base32("JBSWY3DPEHPK3PXP", allow_padding=False)
        assert is_valid_base32("JBSWY3DP")
        assert is_valid_base32("ABCDABCD")

    def test_is_valid_base32_false(self):
        assert not is_valid_base32("JBSWY3DPEHPK3PXP1")  # '1' is not valid base32
        assert not is_valid_base32("")
        assert not is_valid_base32("JBSWY3DPEHPK3PXP====")  # 20 chars not multiple of 8

    def test_validate_secret_ok(self):
        assert validate_secret("JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP"

    @pytest.mark.parametrize("bad", ["", "SHORT", "1234567890ABCDEFG"])
    def test_validate_secret_rejects(self, bad):
        with pytest.raises(InvalidSecretError):
            validate_secret(bad)


class TestAlgorithmsDigitsPeriods:
    def test_algorithm_passthrough(self):
        assert validate_algorithm(OtpAlgorithm.SHA256) == OtpAlgorithm.SHA256

    def test_algorithm_default(self):
        assert validate_algorithm(None) == OtpAlgorithm.SHA1

    def test_algorithm_uppercase_string(self):
        assert validate_algorithm("sha512") == OtpAlgorithm.SHA512

    def test_algorithm_unsupported(self):
        with pytest.raises(UnsupportedAlgorithmError):
            validate_algorithm("MD5")

    def test_digits_default(self):
        assert validate_digits(None) == 6
        assert validate_digits(8) == 8

    def test_digits_unsupported(self):
        with pytest.raises(UnsupportedDigitsError):
            validate_digits(7)

    def test_period_default(self):
        assert validate_period(None) == 30

    def test_period_unsupported(self):
        with pytest.raises(UnsupportedPeriodError):
            validate_period(45)


class TestOtpauthUri:
    def test_parse_totp_minimal(self):
        result = parse_otpauth_uri("otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP")
        assert result["type"] == "totp"
        assert result["secret"] == "JBSWY3DPEHPK3PXP"
        assert result["issuer"] == "ACME"
        assert result["account"] == "alice@example.com"
        assert result["algorithm"] == OtpAlgorithm.SHA1
        assert result["digits"] == 6
        assert result["period"] == 30
        assert result["counter"] is None

    def test_parse_totp_with_issuer_query(self):
        result = parse_otpauth_uri(
            "otpauth://totp/Provider:user@example.com"
            "?secret=JBSWY3DPEHPK3PXP&issuer=Provider&digits=8&period=60&algorithm=SHA256"
        )
        assert result["issuer"] == "Provider"
        assert result["digits"] == 8
        assert result["period"] == 60
        assert result["algorithm"] == OtpAlgorithm.SHA256

    def test_parse_hotp(self):
        result = parse_otpauth_uri(
            "otpauth://hotp/ACME:bob@example.com?secret=JBSWY3DPEHPK3PXP&counter=10"
        )
        assert result["type"] == "hotp"
        assert result["counter"] == 10
        assert result["period"] is None

    def test_parse_hotp_missing_counter(self):
        with pytest.raises(InvalidOtpUriError):
            parse_otpauth_uri("otpauth://hotp/ACME:bob@example.com?secret=JBSWY3DPEHPK3PXP")

    def test_parse_wrong_scheme(self):
        with pytest.raises(InvalidOtpUriError):
            parse_otpauth_uri("https://example.com/?secret=JBSWY3DPEHPK3PXP")

    def test_parse_missing_secret(self):
        with pytest.raises(InvalidOtpUriError):
            parse_otpauth_uri("otpauth://totp/ACME:alice@example.com")

    def test_parse_invalid_type(self):
        with pytest.raises(InvalidOtpUriError):
            parse_otpauth_uri("otpauth://foo/ACME?secret=JBSWY3DPEHPK3PXP")

    def test_parse_lowercase_secret_padded(self):
        result = parse_otpauth_uri("otpauth://totp/ACME:alice@example.com?secret=jbswy3dpehpk3pxp")
        assert result["secret"] == "JBSWY3DPEHPK3PXP"

    def test_parse_label_with_slash(self):
        result = parse_otpauth_uri(
            "otpauth://totp/ACME/Sub:alice@example.com?secret=JBSWY3DPEHPK3PXP"
        )
        assert result["issuer"] == "ACME/Sub"
        assert result["account"] == "alice@example.com"

    def test_split_label(self):
        assert split_otpauth_label("ACME:alice@example.com") == ("ACME", "alice@example.com")
        assert split_otpauth_label("/ACME:alice") == ("ACME", "alice")
        assert split_otpauth_label("alice") == (None, "alice")
        assert split_otpauth_label("") == (None, None)
        assert split_otpauth_label(None) == (None, None)


class TestDetectInputKind:
    def test_uri(self):
        assert (
            detect_input_kind("otpauth://totp/ACME:alice@example.com?secret=JBSWY3DPEHPK3PXP")
            == "uri"
        )

    def test_secret(self):
        assert detect_input_kind("JBSWY3DPEHPK3PXP") == "secret"

    def test_data_uri(self):
        assert detect_input_kind("data:image/png;base64,AAA") == "data_uri"

    def test_unknown(self):
        assert detect_input_kind("hello world") == "unknown"
