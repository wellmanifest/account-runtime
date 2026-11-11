#!/usr/bin/env python3
"""Security, bounds, freshness, and schema-parity hardening tests for account-runtime v1."""

from __future__ import annotations

import copy
import math
import tempfile
import unittest
from pathlib import Path

from standard import account_fixtures as fx
from standard import account_primitives as pr
from standard import conformance as conf
from standard import service_access_conformance as sa

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_PATH = ROOT / "standard" / "service-access.example.json"


class AccountRuntimeHardeningTests(unittest.TestCase):
    def test_read_regular_utf8_rejects_symlinks_directories_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            link_path = tmp_dir / "linked.json"
            link_path.symlink_to(EXAMPLE_PATH)
            with self.assertRaises(pr.ContractError):
                pr.load_strict_json(link_path)
            with self.assertRaises(pr.ContractError):
                pr.load_strict_json(tmp_dir)
            big = tmp_dir / "big.json"
            big.write_text('{"x":"' + ("a" * 128) + '"}', encoding="utf-8")
            with self.assertRaises(pr.ContractError):
                pr.read_regular_utf8(big, max_bytes=64)

    def test_strict_loads_and_canonical_reject_non_finite_and_deep_json(self) -> None:
        for raw in ('{"x": NaN}', '{"x": Infinity}', '{"x": -Infinity}'):
            with self.subTest(raw=raw):
                with self.assertRaises(pr.ContractError):
                    pr.strict_loads(raw)
        with self.assertRaises(pr.ContractError):
            pr.canonical({"x": math.nan})
        deep_raw = "[" * 80 + "1" + "]" * 80
        with self.assertRaises(pr.ContractError):
            pr.strict_loads(deep_raw)

    def test_tree_walkers_enforce_depth_and_non_string_keys_without_recursion_error(self) -> None:
        deep: object = "ok"
        for _ in range(80):
            deep = [deep]
        for fn in (
            pr.assert_closed_schema,
            pr.reject_sensitive_keys,
            pr.reject_secret_material,
            pr.canonical,
        ):
            with self.assertRaises(pr.ContractError):
                fn(deep)
        with self.assertRaises(pr.ContractError):
            pr.exact({1: "x"}, {"1"})
        with self.assertRaises(pr.ContractError):
            conf.validate_document({"schema": ["unhashable"]})

    def test_observation_freshness_fails_closed_on_nan_inf_bool_and_negative_bounds(self) -> None:
        ts = "2025-10-09T08:00:00Z"
        self.assertEqual(
            pr.validate_observation_freshness(ts, now_epoch=math.nan), ("unknown", False)
        )
        self.assertEqual(
            pr.validate_observation_freshness(ts, now_epoch=1760000000.0, ttl_seconds=math.inf),
            ("unknown", False),
        )
        self.assertEqual(
            pr.validate_observation_freshness(ts, now_epoch=True),  # type: ignore[arg-type]
            ("unknown", False),
        )
        self.assertEqual(
            pr.validate_observation_freshness(ts, now_epoch=1760000000.0, ttl_seconds=-1.0),
            ("unknown", False),
        )

    def test_schema_parity_enums_prefix_collision_and_uri_traversal(self) -> None:
        c = conf.Contracts()

        graph = fx.graph_example()
        graph["services"][0]["classification"] = "unclassified-custom"
        with self.assertRaises(pr.ContractError):
            conf.validate_graph(c, graph)

        bad_store = fx.graph_example()
        bad_store["identities"][0]["storeRefs"] = ["not-a-store-uri"]
        with self.assertRaises(pr.ContractError):
            conf.validate_graph(c, bad_store)

        runtime = fx.runtime_example()
        runtime["persistence"]["hostExposure"] = "public-internet"
        with self.assertRaises(pr.ContractError):
            conf.validate_runtime(c, runtime)

        bad_ops = fx.runtime_example()
        bad_ops["control"]["operations"] = ["exec-shell"]
        with self.assertRaises(pr.ContractError):
            conf.validate_runtime(c, bad_ops)

        bad_vis = fx.runtime_example()
        bad_vis["control"]["humanVisible"] = False
        with self.assertRaises(pr.ContractError):
            conf.validate_runtime(c, bad_vis)

        prefix_req = fx.request_example()
        prefix_req["target"]["identityRef"] = "identity://example.test/account"
        prefix_req["endpointRef"] = (
            "mcp://example.test/accounts/account-001/providers/anthropic/tools/claude"
        )
        with self.assertRaises(pr.ContractError):
            conf.validate_request(c, prefix_req)

        trav_req = fx.request_example()
        trav_req["task"]["promptRef"] = "artifact://example.test/prompts/../etc/r1"
        with self.assertRaises(pr.ContractError):
            conf.validate_request(c, trav_req)

        bad_rcpt = fx.receipt_example()
        bad_rcpt["outcome"] = "arbitrary_outcome"
        with self.assertRaises(pr.ContractError):
            conf.validate_receipt(c, bad_rcpt)

        svc = sa.ServiceAccessContracts()
        bad_cat = copy.deepcopy(svc.example)
        bad_cat["profiles"][0]["mode"] = ["unhashable"]
        with self.assertRaises(pr.ContractError):
            sa.validate_service_access(svc, bad_cat)


if __name__ == "__main__":
    unittest.main()
