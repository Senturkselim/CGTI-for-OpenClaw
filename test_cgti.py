#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026  Selim Şentürk
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
"""Unit tests for CGTI Lite — validates critical fixes."""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import cgti_lite


class TestValidateIP(unittest.TestCase):
    """P0: IP validation prevents injection attacks."""

    def test_valid_ipv4(self):
        self.assertTrue(cgti_lite._validate_ip("192.168.1.1"))
        self.assertTrue(cgti_lite._validate_ip("10.0.0.1"))
        self.assertTrue(cgti_lite._validate_ip("255.255.255.255"))
        self.assertTrue(cgti_lite._validate_ip("0.0.0.0"))

    def test_valid_ipv6(self):
        self.assertTrue(cgti_lite._validate_ip("::1"))
        self.assertTrue(cgti_lite._validate_ip("fe80::1"))
        self.assertTrue(cgti_lite._validate_ip("2001:db8::1"))

    def test_invalid_injection_strings(self):
        self.assertFalse(cgti_lite._validate_ip(""))
        self.assertFalse(cgti_lite._validate_ip(None))
        self.assertFalse(cgti_lite._validate_ip("1.2.3.4; rm -rf /"))
        self.assertFalse(cgti_lite._validate_ip("$(whoami)"))
        self.assertFalse(cgti_lite._validate_ip("1.2.3.4 && echo pwned"))
        self.assertFalse(cgti_lite._validate_ip("not-an-ip"))
        self.assertFalse(cgti_lite._validate_ip("1.2.3.999"))  # octet > 255

    def test_ipv4_boundary(self):
        self.assertFalse(cgti_lite._validate_ip("256.1.1.1"))
        self.assertFalse(cgti_lite._validate_ip("1.2.3"))
        self.assertFalse(cgti_lite._validate_ip("1.2.3.4.5"))


class TestTailLines(unittest.TestCase):
    """P0: Memory-safe log reading from end of file."""

    def test_basic_tail(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            for i in range(100):
                f.write(f"line {i}\n")
            f.flush()
            path = f.name

        try:
            result = cgti_lite._tail_lines(path, max_lines=10)
            self.assertEqual(len(result), 10)
            # Lines should be from the end (most recent first)
            self.assertIn("line 99", result[0])
        finally:
            os.unlink(path)

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        try:
            result = cgti_lite._tail_lines(path, max_lines=10)
            self.assertEqual(result, [])
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        result = cgti_lite._tail_lines("/nonexistent/file.log", max_lines=10)
        self.assertEqual(result, [])

    def test_fewer_lines_than_requested(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
            f.write("only one line\n")
            f.flush()
            path = f.name
        try:
            result = cgti_lite._tail_lines(path, max_lines=100)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0], "only one line")
        finally:
            os.unlink(path)


class TestToggleRule(unittest.TestCase):
    """P1: toggle_rule lstrip fix — regex should not eat rule characters."""

    def test_pass_rule_not_corrupted(self):
        """A '# pass tcp...' rule should keep 'pass' intact after uncommenting."""
        with tempfile.TemporaryDirectory() as td:
            rf = Path(td) / "test.rules"
            rf.write_text("# pass tcp any any -> any any (msg:\"Test\"; sid:999999; rev:1;)\n")

            cfg = cgti_lite.ConfigManager()
            cfg.data["cgti"]["rules_dir"] = td
            rm = cgti_lite.RuleManager(cfg)

            rm.toggle_rule("999999", True)
            content = rf.read_text()
            self.assertTrue(content.strip().startswith("pass tcp"),
                            f"Rule corrupted: {content.strip()!r}")

    def test_comment_rule(self):
        with tempfile.TemporaryDirectory() as td:
            rf = Path(td) / "test.rules"
            rf.write_text("alert tcp any any -> any any (msg:\"Test\"; sid:888888; rev:1;)\n")

            cfg = cgti_lite.ConfigManager()
            cfg.data["cgti"]["rules_dir"] = td
            rm = cgti_lite.RuleManager(cfg)

            rm.toggle_rule("888888", False)
            content = rf.read_text()
            self.assertTrue(content.strip().startswith("# alert tcp"),
                            f"Rule not commented: {content.strip()!r}")


class TestConfigValidation(unittest.TestCase):
    """P1: Config validation schema."""

    def test_valid_keys_defined(self):
        self.assertIn("suricata.mode", cgti_lite.ConfigManager.VALID_KEYS)
        self.assertEqual(
            cgti_lite.ConfigManager.VALID_KEYS["suricata.mode"],
            ["IDS", "IPS"],
        )

    def test_whitelist_key_exists(self):
        self.assertIn("network.whitelist_ips", cgti_lite.ConfigManager.VALID_KEYS)

    def test_default_has_whitelist(self):
        self.assertIn("whitelist_ips", cgti_lite.ConfigManager.DEFAULT["network"])


class TestIPBlockManagerValidation(unittest.TestCase):
    """P0: IPBlockManager rejects invalid IPs."""

    def test_block_rejects_injection(self):
        ipm = cgti_lite.IPBlockManager()
        result = ipm.block("1.2.3.4; rm -rf /", "test")
        self.assertFalse(result)

    def test_block_accepts_valid_ip(self):
        with tempfile.TemporaryDirectory() as td:
            tmp_blocked = Path(td) / "blocked_ips.json"
            tmp_config_dir = Path(td)
            with patch.object(cgti_lite, 'BLOCKED_FILE', tmp_blocked), \
                 patch.object(cgti_lite, 'CONFIG_DIR', tmp_config_dir):
                ipm = cgti_lite.IPBlockManager()
                with patch.object(ipm, '_fw'):
                    result = ipm.block("10.20.30.40", "test")
                    self.assertTrue(result)
                    ipm.unblock("10.20.30.40")


class TestLogRotation(unittest.TestCase):
    """P2: Log rotation constant defined."""

    def test_log_max_bytes_defined(self):
        self.assertEqual(cgti_lite.LOG_MAX_BYTES, 5 * 1024 * 1024)


# ── IPS Tests ─────────────────────────────────────────────────────────────────

class TestDropRuleGeneration(unittest.TestCase):
    """Test _generate_drop_rules() alert → drop conversion."""

    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        # Create a sample alert rule file
        sample = (
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 13338 '
            '(msg:"OC Test Rule"; sid:9200501; rev:1;)\n'
            '# alert tcp any any -> any any (msg:"Disabled"; sid:9200502; rev:1;)\n'
            '# This is a comment\n'
        )
        (self.tmpdir / "oc-test.rules").write_text(sample, encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(str(self.tmpdir), ignore_errors=True)

    def test_generates_ips_file(self):
        """Drop rules file is created with -ips.rules suffix."""
        files, err = cgti_lite._generate_drop_rules(self.tmpdir)
        self.assertEqual(err, "")
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0], "oc-test-ips.rules")
        self.assertTrue((self.tmpdir / "oc-test-ips.rules").exists())

    def test_alert_converted_to_drop(self):
        """Active alert rules become drop rules."""
        cgti_lite._generate_drop_rules(self.tmpdir)
        content = (self.tmpdir / "oc-test-ips.rules").read_text(encoding="utf-8")
        self.assertIn("drop tcp $HOME_NET any -> $EXTERNAL_NET 13338", content)
        self.assertNotIn("alert tcp $HOME_NET", content)

    def test_disabled_alert_becomes_disabled_drop(self):
        """Commented-out alert rules become commented-out drop rules."""
        cgti_lite._generate_drop_rules(self.tmpdir)
        content = (self.tmpdir / "oc-test-ips.rules").read_text(encoding="utf-8")
        self.assertIn('# drop tcp any any -> any any (msg:"Disabled"', content)

    def test_header_present(self):
        """Generated file has AUTO-GENERATED header."""
        cgti_lite._generate_drop_rules(self.tmpdir)
        content = (self.tmpdir / "oc-test-ips.rules").read_text(encoding="utf-8")
        self.assertIn("AUTO-GENERATED by CGTI Lite IPS Mode", content)
        self.assertIn("Source: oc-test.rules", content)

    def test_skips_already_generated(self):
        """Running twice doesn't duplicate generation."""
        cgti_lite._generate_drop_rules(self.tmpdir)
        files2, _ = cgti_lite._generate_drop_rules(self.tmpdir)
        # Should regenerate (overwrite) but still only 1 file
        self.assertEqual(len(files2), 1)

    def test_cleanup_removes_ips_files(self):
        """_cleanup_drop_rules removes generated files."""
        cgti_lite._generate_drop_rules(self.tmpdir)
        self.assertTrue((self.tmpdir / "oc-test-ips.rules").exists())
        cgti_lite._cleanup_drop_rules(self.tmpdir)
        self.assertFalse((self.tmpdir / "oc-test-ips.rules").exists())

    def test_original_file_unchanged(self):
        """Original rule file is not modified."""
        original = (self.tmpdir / "oc-test.rules").read_text(encoding="utf-8")
        cgti_lite._generate_drop_rules(self.tmpdir)
        after = (self.tmpdir / "oc-test.rules").read_text(encoding="utf-8")
        self.assertEqual(original, after)

    def test_empty_dir(self):
        """Empty directory produces no files."""
        empty = Path(tempfile.mkdtemp())
        try:
            files, err = cgti_lite._generate_drop_rules(empty)
            self.assertEqual(files, [])
            self.assertEqual(err, "")
        finally:
            shutil.rmtree(str(empty), ignore_errors=True)




class TestIPSSetup(unittest.TestCase):
    """Test IPS setup functions."""

    def test_linux_ips_rejects_non_linux(self):
        """_setup_linux_ips returns False on non-Linux OS."""
        original_os = cgti_lite.OS
        try:
            cgti_lite.OS = "Windows"
            ok, err = cgti_lite._setup_linux_ips("eth0", 0)
            self.assertFalse(ok)
            self.assertIn("Linux", err)
        finally:
            cgti_lite.OS = original_os

    def test_configure_nfq_nonexistent_file(self):
        """_configure_suricata_nfq handles missing file gracefully."""
        result = cgti_lite._configure_suricata_nfq("/nonexistent/path.yaml", 0)
        self.assertFalse(result)

    def test_configure_nfq_adds_section(self):
        """_configure_suricata_nfq adds nfq section to yaml."""
        tmpdir = Path(tempfile.mkdtemp())
        try:
            yaml_file = tmpdir / "suricata.yaml"
            yaml_file.write_text("# Suricata config\ndefault-log-dir: /var/log/suricata\n",
                                 encoding="utf-8")
            result = cgti_lite._configure_suricata_nfq(str(yaml_file), 0)
            self.assertTrue(result)
            content = yaml_file.read_text(encoding="utf-8")
            self.assertIn("nfq:", content)
            self.assertIn("fail-open: yes", content)
            self.assertIn("mode: accept", content)
        finally:
            shutil.rmtree(str(tmpdir), ignore_errors=True)

    def test_revert_nfq_removes_ips_rules(self):
        """_revert_suricata_nfq removes IPS rule references."""
        tmpdir = Path(tempfile.mkdtemp())
        try:
            yaml_file = tmpdir / "suricata.yaml"
            yaml_file.write_text(
                "rule-files:\n"
                "  - oc-test.rules\n"
                "  - oc-test-ips.rules\n"
                "  - other.rules\n",
                encoding="utf-8"
            )
            cgti_lite._revert_suricata_nfq(str(yaml_file))
            content = yaml_file.read_text(encoding="utf-8")
            self.assertNotIn("oc-test-ips.rules", content)
            self.assertIn("oc-test.rules", content)
            self.assertIn("other.rules", content)
        finally:
            shutil.rmtree(str(tmpdir), ignore_errors=True)


class TestSuricataEnhancements(unittest.TestCase):
    """Tests for _configure_suricata_enhancements (JA3 + DNS_SERVERS)."""

    def test_adds_ja3_and_dns_servers(self):
        """JA3 and DNS_SERVERS are added to a yaml with tls and address-groups."""
        tmpdir = Path(tempfile.mkdtemp())
        try:
            yaml_file = tmpdir / "suricata.yaml"
            yaml_file.write_text(
                "app-layer:\n"
                "  protocols:\n"
                "    tls:\n"
                "      enabled: yes\n"
                "\n"
                "vars:\n"
                "  address-groups:\n"
                '    HOME_NET: "[192.168.0.0/16]"\n'
                '    EXTERNAL_NET: "!$HOME_NET"\n',
                encoding="utf-8",
            )
            changes = cgti_lite._configure_suricata_enhancements(str(yaml_file))
            content = yaml_file.read_text(encoding="utf-8")
            self.assertEqual(len(changes), 2)
            self.assertIn("ja3-fingerprints: yes", content)
            self.assertIn("DNS_SERVERS", content)
        finally:
            shutil.rmtree(str(tmpdir), ignore_errors=True)

    def test_idempotent(self):
        """Running twice produces no additional changes."""
        tmpdir = Path(tempfile.mkdtemp())
        try:
            yaml_file = tmpdir / "suricata.yaml"
            yaml_file.write_text(
                "app-layer:\n"
                "  protocols:\n"
                "    tls:\n"
                "      ja3-fingerprints: yes\n"
                "\n"
                "vars:\n"
                "  address-groups:\n"
                '    HOME_NET: "[192.168.0.0/16]"\n'
                '    DNS_SERVERS: "[8.8.8.8]"\n',
                encoding="utf-8",
            )
            changes = cgti_lite._configure_suricata_enhancements(str(yaml_file))
            self.assertEqual(len(changes), 0)
        finally:
            shutil.rmtree(str(tmpdir), ignore_errors=True)

    def test_ja3_disabled_to_enabled(self):
        """ja3-fingerprints: no is changed to yes."""
        tmpdir = Path(tempfile.mkdtemp())
        try:
            yaml_file = tmpdir / "suricata.yaml"
            yaml_file.write_text(
                "app-layer:\n"
                "  protocols:\n"
                "    tls:\n"
                "      ja3-fingerprints: no\n"
                "\n"
                "vars:\n"
                "  address-groups:\n"
                '    HOME_NET: "[192.168.0.0/16]"\n'
                '    DNS_SERVERS: "[8.8.8.8]"\n',
                encoding="utf-8",
            )
            changes = cgti_lite._configure_suricata_enhancements(str(yaml_file))
            content = yaml_file.read_text(encoding="utf-8")
            self.assertEqual(len(changes), 1)
            self.assertIn("was disabled", changes[0])
            self.assertIn("ja3-fingerprints: yes", content)
            self.assertNotIn("ja3-fingerprints: no", content)
        finally:
            shutil.rmtree(str(tmpdir), ignore_errors=True)

    def test_custom_dns_servers(self):
        """Custom DNS servers are used when provided."""
        tmpdir = Path(tempfile.mkdtemp())
        try:
            yaml_file = tmpdir / "suricata.yaml"
            yaml_file.write_text(
                "app-layer:\n"
                "  protocols:\n"
                "    tls:\n"
                "      ja3-fingerprints: yes\n"
                "\n"
                "vars:\n"
                "  address-groups:\n"
                '    HOME_NET: "[192.168.0.0/16]"\n',
                encoding="utf-8",
            )
            changes = cgti_lite._configure_suricata_enhancements(
                str(yaml_file), dns_servers="9.9.9.9,149.112.112.112"
            )
            content = yaml_file.read_text(encoding="utf-8")
            self.assertEqual(len(changes), 1)
            self.assertIn("9.9.9.9", content)
            self.assertIn("149.112.112.112", content)
        finally:
            shutil.rmtree(str(tmpdir), ignore_errors=True)

    def test_update_existing_dns(self):
        """Existing DNS_SERVERS are updated when custom dns_servers provided."""
        tmpdir = Path(tempfile.mkdtemp())
        try:
            yaml_file = tmpdir / "suricata.yaml"
            yaml_file.write_text(
                "app-layer:\n"
                "  protocols:\n"
                "    tls:\n"
                "      ja3-fingerprints: yes\n"
                "\n"
                "vars:\n"
                "  address-groups:\n"
                '    HOME_NET: "[192.168.0.0/16]"\n'
                '    DNS_SERVERS: "[8.8.8.8]"\n',
                encoding="utf-8",
            )
            changes = cgti_lite._configure_suricata_enhancements(
                str(yaml_file), dns_servers="9.9.9.9"
            )
            content = yaml_file.read_text(encoding="utf-8")
            self.assertEqual(len(changes), 1)
            self.assertIn("updated", changes[0])
            self.assertIn("9.9.9.9", content)
            self.assertNotIn("8.8.8.8", content)
        finally:
            shutil.rmtree(str(tmpdir), ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
