"""Tests for security hardening features: API key detection and sysctl checker."""

import os
from pathlib import Path

import pytest

from app.ai.tools.strings import _API_KEY_PATTERNS, _shannon_entropy
from app.ai.tools.security import _parse_sysctl_files, _SYSCTL_CHECKS


def _build_test_key(prefix: str, fill_char: str, length: int) -> str:
    """Build a fake API key for testing without triggering GitHub secret scanning."""
    suffix = (fill_char * length)[:length]
    return prefix + suffix


class TestApiKeyPatterns:
    """Test that API key patterns match real-format keys and reject noise."""

    @pytest.mark.parametrize("key,category", [
        ("AKIA" + "X" * 16, "aws_access_key"),
        ("ghp_" + "A" * 36, "github_pat"),
        ("gho_" + "A" * 36, "github_oauth"),
        ("ghs_" + "A" * 36, "github_app_token"),
        (_build_test_key("sk_" + "live_", "A", 24), "stripe_secret_key"),
        (_build_test_key("pk_" + "live_", "A", 24), "stripe_publishable_key"),
        ("AIza" + "A" * 35, "gcp_api_key"),
        ("AC" + "a1b2c3d4" * 4, "twilio_account_sid"),
    ])
    def test_pattern_matches(self, key: str, category: str):
        """Known API key formats should match their pattern."""
        matched = False
        for pat, cat, _sev in _API_KEY_PATTERNS:
            if pat.search(key):
                assert cat == category, f"Key matched {cat} instead of {category}"
                matched = True
                break
        assert matched, f"No pattern matched key for {category}"

    def test_aws_key_in_config_line(self):
        """AWS key embedded in a config line should be detected."""
        line = 'aws_access_key_id = AKIA' + 'X' * 16
        matches = [(pat, cat) for pat, cat, _ in _API_KEY_PATTERNS if pat.search(line)]
        assert any(cat == "aws_access_key" for _, cat in matches)

    def test_jwt_three_segments(self):
        """JWT with three base64url segments should match."""
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        matches = [(pat, cat) for pat, cat, _ in _API_KEY_PATTERNS if pat.search(jwt)]
        assert any(cat == "jwt_token" for _, cat in matches)

    def test_random_string_no_match(self):
        """Random strings should not match any API key pattern."""
        noise = "this is just a normal config line with value=12345"
        for pat, cat, _ in _API_KEY_PATTERNS:
            assert not pat.search(noise), f"False positive: {cat} matched noise"

    def test_azure_connection_string(self):
        """Azure storage connection string should match."""
        conn = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123+def456/ghi789=="
        matches = [(pat, cat) for pat, cat, _ in _API_KEY_PATTERNS if pat.search(conn)]
        assert any(cat == "azure_connection_string" for _, cat in matches)

    def test_gcp_service_account(self):
        """GCP service account JSON marker should match."""
        line = '  "type": "service_account",'
        matches = [(pat, cat) for pat, cat, _ in _API_KEY_PATTERNS if pat.search(line)]
        assert any(cat == "gcp_service_account" for _, cat in matches)

    def test_slack_bot_token(self):
        """Slack bot token should match."""
        # Build token dynamically to avoid GitHub secret scanning
        token = "xox" + "b-" + "1234567890-9876543210-" + "A" * 24
        matches = [(pat, cat) for pat, cat, _ in _API_KEY_PATTERNS if pat.search(token)]
        assert any(cat == "slack_bot_token" for _, cat in matches)


class TestSysctlParser:
    """Test sysctl.conf parsing and parameter extraction."""

    def test_parse_basic_sysctl_conf(self, tmp_path: Path):
        """Parse a basic sysctl.conf with key=value format."""
        (tmp_path / "etc").mkdir()
        (tmp_path / "etc" / "sysctl.conf").write_text(
            "# Comment\n"
            "kernel.randomize_va_space = 2\n"
            "net.ipv4.tcp_syncookies=1\n"
            "; Another comment\n"
            "kernel.kptr_restrict = 0\n"
        )
        params = _parse_sysctl_files(str(tmp_path))
        assert params["kernel.randomize_va_space"] == "2"
        assert params["net.ipv4.tcp_syncookies"] == "1"
        assert params["kernel.kptr_restrict"] == "0"

    def test_parse_sysctl_d_overrides(self, tmp_path: Path):
        """sysctl.d files should override sysctl.conf (alphabetical order)."""
        (tmp_path / "etc").mkdir()
        (tmp_path / "etc" / "sysctl.conf").write_text(
            "kernel.kptr_restrict = 0\n"
        )
        (tmp_path / "etc" / "sysctl.d").mkdir()
        (tmp_path / "etc" / "sysctl.d" / "99-hardening.conf").write_text(
            "kernel.kptr_restrict = 2\n"
        )
        params = _parse_sysctl_files(str(tmp_path))
        assert params["kernel.kptr_restrict"] == "2"

    def test_parse_init_script_sysctl_w(self, tmp_path: Path):
        """Init scripts with sysctl -w should be detected."""
        (tmp_path / "etc").mkdir()
        (tmp_path / "etc" / "init.d").mkdir()
        (tmp_path / "etc" / "init.d" / "S99sysctl").write_text(
            "#!/bin/sh\n"
            "sysctl -w kernel.dmesg_restrict=1\n"
            "sysctl -w net.ipv4.ip_forward=1\n"
        )
        params = _parse_sysctl_files(str(tmp_path))
        assert params["kernel.dmesg_restrict"] == "1"
        assert params["net.ipv4.ip_forward"] == "1"

    def test_empty_filesystem(self, tmp_path: Path):
        """Empty filesystem should return empty params."""
        params = _parse_sysctl_files(str(tmp_path))
        assert params == {}

    def test_comments_and_blank_lines_skipped(self, tmp_path: Path):
        """Comments and blank lines should not appear in results."""
        (tmp_path / "etc").mkdir()
        (tmp_path / "etc" / "sysctl.conf").write_text(
            "# This is a comment\n"
            "\n"
            "; This is also a comment\n"
            "kernel.randomize_va_space = 2\n"
            "\n"
        )
        params = _parse_sysctl_files(str(tmp_path))
        assert len(params) == 1
        assert "kernel.randomize_va_space" in params


class TestSysctlChecksTable:
    """Verify the sysctl checks table is well-formed."""

    def test_all_checks_have_required_fields(self):
        """Each check should have param, secure_val, default, severity, desc."""
        for param, secure, default, severity, desc in _SYSCTL_CHECKS:
            assert param, "Parameter name must not be empty"
            assert secure, "Secure value must not be empty"
            assert severity in ("critical", "high", "medium", "low"), f"Invalid severity: {severity}"
            assert desc, "Description must not be empty"

    def test_no_duplicate_parameters(self):
        """No parameter should be checked twice."""
        params = [p for p, _, _, _, _ in _SYSCTL_CHECKS]
        assert len(params) == len(set(params)), f"Duplicate params: {[p for p in params if params.count(p) > 1]}"


class TestShannonEntropy:
    """Test entropy calculation for credential scoring."""

    def test_high_entropy_random(self):
        """Random-looking strings should have high entropy."""
        assert _shannon_entropy("aK3mN9xQ2wR7yB4j") > 3.5

    def test_low_entropy_repeated(self):
        """Repeated characters should have low entropy."""
        assert _shannon_entropy("aaaaaaaaaa") == 0.0

    def test_empty_string(self):
        """Empty string should have zero entropy."""
        assert _shannon_entropy("") == 0.0
