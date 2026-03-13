"""
tests/test_target_manager.py
============================
Unit tests for target validation and context building.
"""

import sys
import os
import unittest
from pathlib import Path

# Make project root importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.target_manager import _classify_input, build_target_context
from models.schema import InputType


class TestInputClassification(unittest.TestCase):

    def test_valid_domain(self):
        self.assertEqual(_classify_input("example.com"),     InputType.DOMAIN)
        self.assertEqual(_classify_input("sub.example.com"), InputType.DOMAIN)
        self.assertEqual(_classify_input("a.b.c.example.io"),InputType.DOMAIN)

    def test_valid_ip(self):
        self.assertEqual(_classify_input("192.168.1.1"),     InputType.IP)
        self.assertEqual(_classify_input("203.0.113.10"),    InputType.IP)
        self.assertEqual(_classify_input("::1"),             InputType.IP)  # IPv6

    def test_valid_cidr(self):
        self.assertEqual(_classify_input("10.0.0.0/8"),      InputType.CIDR)
        self.assertEqual(_classify_input("192.168.1.0/24"),  InputType.CIDR)

    def test_invalid_input(self):
        self.assertEqual(_classify_input("not_a_domain"),    InputType.UNKNOWN)
        self.assertEqual(_classify_input(""),                InputType.UNKNOWN)
        self.assertEqual(_classify_input("http://example.com"), InputType.UNKNOWN)

    def test_whitespace_stripped(self):
        self.assertEqual(_classify_input("  example.com  "), InputType.DOMAIN)
        self.assertEqual(_classify_input(" 1.2.3.4 "),       InputType.IP)


class TestBuildTargetContext(unittest.TestCase):

    def setUp(self):
        self.output_dir = "/tmp/alr_test_output"

    def test_domain_context(self):
        ctx = build_target_context("example.com", output_dir=self.output_dir)
        self.assertEqual(ctx.input_type, "domain")
        self.assertEqual(ctx.domain, "example.com")
        self.assertIsNone(ctx.ip)
        self.assertTrue(len(ctx.run_id) == 12)

    def test_ip_context(self):
        ctx = build_target_context("203.0.113.10", output_dir=self.output_dir)
        self.assertEqual(ctx.input_type, "ip")
        self.assertEqual(ctx.ip, "203.0.113.10")
        self.assertIsNone(ctx.domain)

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            build_target_context("not_valid!!", output_dir=self.output_dir)

    def test_output_dir_created(self):
        ctx = build_target_context("test.example.com", output_dir=self.output_dir)
        self.assertTrue(Path(ctx.output_dir).exists())

    def test_options_propagated(self):
        ctx = build_target_context(
            "example.com",
            output_dir=self.output_dir,
            timeout=120,
            verbose=True,
            enable_ai=True,
            enable_github=True,
        )
        self.assertEqual(ctx.timeout, 120)
        self.assertTrue(ctx.verbose)
        self.assertTrue(ctx.enable_ai)
        self.assertTrue(ctx.enable_github)


if __name__ == "__main__":
    unittest.main()
