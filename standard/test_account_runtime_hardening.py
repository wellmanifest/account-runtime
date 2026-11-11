#!/usr/bin/env python3
"""Security, bounds, freshness, and schema-parity hardening tests for account-runtime v1."""

from __future__ import annotations

import copy
import math
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from standard import account_fixtures as fx
from standard import account_io as aio
from standard import account_primitives as pr
from standard import conformance as conf
from standard import service_access_conformance as sa

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE_PATH = ROOT / "standard" / "service-access.example.json"


class AccountRuntimeHardeningTests(unittest.TestCase):
    def test_all_standard_modules_stay_strictly_under_500_lines(self) -> None:
        for py_file in sorted((ROOT / "standard").glob("*.py")):
            line_count = len(py_file.read_text(encoding="utf-8").splitlines())
            self.assertLess(line_count, 500, f"{py_file.name} exceeded 500 lines ({line_count})")

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
        for raw in (
            '{"x": NaN}',
            '{"x": Infinity}',
            '{"x": -Infinity}',
            '{"x": 1e999}',
            '{"x": -1e999}',
        ):
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
        self.assertEqual(
            pr.validate_observation_freshness(ts, now_epoch=10**400),
            ("unknown", False),
        )
        self.assertEqual(
            pr.validate_observation_freshness(ts, now_epoch=1760000000.0, ttl_seconds=10**400),
            ("unknown", False),
        )

    def test_schema_parity_enums_prefix_collision_and_uri_traversal(self) -> None:
        c = conf.Contracts()

        graph = fx.graph_example()
        graph["services"][0]["classification"] = "unclassified-custom"
        with self.assertRaises(pr.ContractError):
            conf.validate_graph(c, graph)

        for bad_sname in ("svc\x00name", "svc\nname", "svc\x1bname", "svc\x7fname"):
            bad_name_graph = fx.graph_example()
            bad_name_graph["services"][0]["name"] = bad_sname
            with self.subTest(kind=repr(bad_sname)), self.assertRaises(pr.ContractError):
                conf.validate_graph(c, bad_name_graph)

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

        over_providers = copy.deepcopy(svc.example)
        over_providers["profiles"][0]["providerRefs"] = [
            f"provider://example.test/p-{idx}" for idx in range(17)
        ]
        with self.assertRaises(pr.ContractError):
            sa.validate_service_access(svc, over_providers)

        with self.assertRaises(pr.ContractError):
            pr.validate_safe_uri_segments("provider://example.test/a b")

        pr.assert_closed_schema(
            {
                "type": "object",
                "additionalProperties": False,
                "if": {"properties": {"items": {"contains": {"type": "object"}}}},
            }
        )
        with self.assertRaises(pr.ContractError):
            pr.assert_closed_schema(
                {"$defs": {"openDef": {"properties": {"mode": {"type": "string"}}}}}
            )

    def test_inode_swap_ancestor_symlinks_huge_int_json_and_uri_anchors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_dir = root / "real_dir"
            real_dir.mkdir()
            target = real_dir / "doc.json"
            target.write_text('{"ok": true}', encoding="utf-8")

            for bad_max in (True, False, 0, -3):
                with self.subTest(max_bytes=bad_max), self.assertRaises(pr.ContractError):
                    pr.read_regular_utf8(target, max_bytes=bad_max)  # type: ignore[arg-type]

            link_dir = root / "link_dir"
            link_dir.symlink_to(real_dir)
            sub_dir = root / "sub_dir"
            sub_dir.mkdir()
            prev_cwd = Path.cwd()
            try:
                os.chdir(root)
                with self.assertRaises(pr.ContractError):
                    pr.read_regular_utf8(Path("link_dir/doc.json"))
                with self.assertRaises(pr.ContractError):
                    pr.read_regular_utf8(Path("link_dir/../real_dir/doc.json"))
                os.chdir(sub_dir)
                with self.assertRaises(pr.ContractError):
                    pr.read_regular_utf8(Path("../link_dir/doc.json"))
            finally:
                os.chdir(prev_cwd)

            with self.assertRaises(pr.ContractError):
                pr.read_regular_utf8(Path(f"{link_dir}/../real_dir/doc.json"))

            real_fstat = os.fstat

            def swapped_fstat(fd: int) -> os.stat_result:
                st = real_fstat(fd)
                return os.stat_result(
                    (
                        st.st_mode,
                        st.st_ino + 777777,
                        st.st_dev,
                        st.st_nlink,
                        st.st_uid,
                        st.st_gid,
                        st.st_size,
                        st.st_atime,
                        st.st_mtime,
                        st.st_ctime,
                    )
                )

            with (
                patch.object(aio.os, "fstat", side_effect=swapped_fstat),
                self.assertRaises(pr.ContractError),
            ):
                pr.read_regular_utf8(target)

        for bad_json in (f'{{"n": {"9" * 310}}}', f'{{"n": {"9" * 400}}}', '"\\ud800"'):
            with self.subTest(raw=bad_json), self.assertRaises(pr.ContractError):
                pr.strict_loads(bad_json)

        c = conf.Contracts()
        for bad_store in (
            "store://../secret",
            "store://vault/foo:..:bar",
            "store://vault/foo::bar",
            "store://vault/trailing/",
            r"store://vault/bad\slash",
            "store://vault/bad?query=1",
            "store://vault/bad#frag",
        ):
            g = fx.graph_example()
            g["identities"][0]["storeRefs"] = [bad_store]
            with self.subTest(store=bad_store), self.assertRaises(pr.ContractError):
                conf.validate_graph(c, g)

        for bad_origin in ("https://..", "https://example.test:0", "https://example.test:99999"):
            g = fx.graph_example()
            g["services"][0]["origins"] = [bad_origin]
            with self.subTest(origin=bad_origin), self.assertRaises(pr.ContractError):
                conf.validate_graph(c, g)

        for bad_email in ("user..name@example.com", "user@..example.com", "user@example.com\n"):
            g = fx.graph_example()
            g["identities"][0]["handle"]["value"] = bad_email
            with self.subTest(email=bad_email), self.assertRaises(pr.ContractError):
                conf.validate_graph(c, g)

        svc = sa.ServiceAccessContracts()
        samples = [
            (pr.RFC3339_DT, "2026-08-12T12:00:00Z"),
            (pr.EMAIL_RE, "alice@example.com"),
            (conf.STORE_REF_RE, "store://vault.local/item-1"),
            (c.patterns["sha256"], "a" * 64),
            (c.patterns["origin"], "https://example.test:8443"),
            (svc.patterns["providerRef"], "provider://example.test/hosting"),
        ]
        for pattern, valid_text in samples:
            with self.subTest(pattern=pattern.pattern):
                self.assertIsNotNone(pattern.match(valid_text))
                self.assertIsNone(pattern.match(valid_text + "\n"))

    def test_4300_digit_ints_abs_ancestor_symlinks_key_secrets_and_digest_utf8(self) -> None:
        for bad_json in (
            '{"n": ' + ("9" * 5000) + "}",
            '{"\\udfff": 1}',
            '{"a": "\\ud800"}',
        ):
            with self.subTest(sample=bad_json[:24]), self.assertRaises(pr.ContractError):
                pr.strict_loads(bad_json)

        with self.assertRaises(pr.ContractError):
            pr.digest("bad-\ud800")
        with self.assertRaises(pr.ContractError):
            pr.digest(123)  # type: ignore[arg-type]

        synthetic_cred = "gh" + "p_" + ("A" * 24)
        with self.assertRaises(pr.ContractError):
            pr.reject_secret_material({synthetic_cred: "ok"})
        for bad_obj in ({"a": "\ud800"}, {"\udfff": 1}):
            with self.assertRaises(pr.ContractError):
                pr.reject_secret_material(bad_obj)
            with self.assertRaises(pr.ContractError):
                pr.reject_sensitive_keys(bad_obj)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real_dir = root / "real_dir" / "sub"
            real_dir.mkdir(parents=True)
            doc = real_dir / "account.json"
            doc.write_text('{"ok": 1}', encoding="utf-8")
            sym_dir = root / "sym_dir"
            sym_dir.symlink_to(root / "real_dir")
            with self.assertRaises(pr.ContractError):
                pr.read_regular_utf8(sym_dir / "sub" / "account.json")


if __name__ == "__main__":
    unittest.main()
