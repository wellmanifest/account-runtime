#!/usr/bin/env python3
"""Standalone unittest and pytest suite for Wellmanifest account-runtime and service-access v1."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from standard import account_fixtures as fx
from standard import account_primitives as pr
from standard import conformance as conf
from standard import service_access_conformance as sa

ROOT = Path(__file__).resolve().parents[1]


class AccountRuntimeConformanceTests(unittest.TestCase):
    def test_run_all_passes_both_suites_and_freshness(self) -> None:
        report = conf.run_all()
        self.assertTrue(report["ok"])
        self.assertEqual(report["positiveVariants"], 5)
        self.assertGreaterEqual(len(report["adversarialRejected"]), 21)
        self.assertTrue(report["observationFreshness"]["ok"])
        self.assertEqual(
            report["serviceAccess"]["schema"], "wellmanifest.service-access-conformance/v1"
        )
        self.assertGreaterEqual(report["serviceAccess"]["profilesAccepted"], 1)
        self.assertGreaterEqual(len(report["serviceAccess"]["adversarialRejected"]), 14)

    def test_contracts_integrity_and_positive_documents(self) -> None:
        contracts = conf.Contracts()
        contracts.integrity()
        for doc in (
            fx.graph_example(),
            fx.runtime_example(),
            fx.request_example(),
            fx.receipt_example(),
            sa.ServiceAccessContracts().example,
        ):
            conf.validate_document(copy.deepcopy(doc))

    def test_closed_schema_helper_recurses_into_lists(self) -> None:
        open_variant_schema = {
            "oneOf": [
                {"type": "object", "additionalProperties": False},
                {"type": "object"},
            ]
        }
        with self.assertRaisesRegex(pr.ContractError, "not closed"):
            pr.assert_closed_schema(open_variant_schema)

    def test_strict_loads_rejects_duplicate_json_keys(self) -> None:
        with self.assertRaisesRegex(pr.ContractError, "duplicate JSON key"):
            pr.strict_loads('{"schema": "a", "schema": "b"}')

    def test_request_limits_reject_boolean_and_string_values(self) -> None:
        contracts = conf.Contracts()
        for bad_value in (True, False, "60", 0, 3601):
            with self.subTest(bad_value=bad_value):
                doc = fx.request_example()
                doc["limits"]["timeoutSeconds"] = bad_value
                with self.assertRaises(pr.ContractError):
                    conf.validate_request(contracts, doc)

    def test_inline_secret_material_rejected_across_documents(self) -> None:
        contracts = conf.Contracts()
        canary = "gh" + "p_" + ("A1b2C3" * 5)
        graph = fx.graph_example()
        graph["services"][0]["accountLabel"] = canary
        with self.assertRaisesRegex(pr.ContractError, "credential material"):
            conf.validate_graph(contracts, graph)

        receipt = fx.receipt_example()
        receipt["resultSummary"] = canary
        with self.assertRaisesRegex(pr.ContractError, "credential material"):
            conf.validate_receipt(contracts, receipt)

    def test_observation_freshness_rejects_naive_and_space_timestamps(self) -> None:
        now_ref = 1760000000.0
        self.assertEqual(
            conf.validate_observation_freshness("2026-08-12T12:00:00", now_epoch=now_ref),
            ("unknown", False),
        )
        self.assertEqual(
            conf.validate_observation_freshness("2026-08-12 12:00:00Z", now_epoch=now_ref),
            ("unknown", False),
        )
        self.assertEqual(
            conf.validate_observation_freshness(
                "2025-10-09T08:00:00Z",
                reset_at_str="2026-08-12T12:00:00",
                now_epoch=now_ref,
            ),
            ("unknown", False),
        )

    def test_cli_file_validation_and_rejection_exit_codes(self) -> None:
        script = ROOT / "standard" / "conformance.py"
        valid_example = ROOT / "standard" / "service-access.example.json"
        ok = subprocess.run(
            [sys.executable, str(script), "--file", str(valid_example)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(ok.returncode, 0, msg=ok.stdout + ok.stderr)
        self.assertIn("PASS:", ok.stdout)

        with tempfile.TemporaryDirectory() as tmp:
            dup_file = Path(tmp) / "dup.json"
            dup_file.write_text('{"schema": "x", "schema": "y"}\n', encoding="utf-8")
            bad = subprocess.run(
                [sys.executable, str(script), "--file", str(dup_file)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(bad.returncode, 1)
            self.assertIn("FAIL:", bad.stdout)

            valid_req = Path(tmp) / "request.json"
            valid_req.write_text(json.dumps(fx.request_example()), encoding="utf-8")
            req_ok = subprocess.run(
                [sys.executable, str(script), "--file", str(valid_req)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(req_ok.returncode, 0, msg=req_ok.stdout + req_ok.stderr)


if __name__ == "__main__":
    unittest.main()
