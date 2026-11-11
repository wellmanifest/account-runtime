#!/usr/bin/env python3
"""Service-access v1 conformance checks for Wellmanifest account-runtime."""

from __future__ import annotations

import copy
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    from standard import account_primitives as _pr
except ImportError:
    import account_primitives as _pr  # type: ignore[no-redef]

ContractError = _pr.ContractError
exact = _pr.exact
bounded_list = _pr.bounded_list
unique_list = _pr.unique_list
str_choice = _pr.str_choice

ROOT = Path(__file__).resolve().parent
SERVICE_ACCESS_SCHEMA_PATH = ROOT / "service-access.schema.json"
SERVICE_ACCESS_EXAMPLE_PATH = ROOT / "service-access.example.json"
SERVICE_ACCESS_SCHEMA_URI = "https://wellmanifest.dev/schemas/service-access/v1"
SERVICE_ACCESS_SCHEMA_DIGEST = "5deb3dd610124c391dcca548aded18ef3a1c2dd7a0b2e4fa4c4b770da3a796e3"
SERVICE_ACCESS_EXAMPLE_DIGEST = "e6fb640b1e8a2ea83a9c90c70ee97c30a79d021a52e6727e74455e8c9a3b5ecc"

EXPECTED_BOUNDARY = {
    "acts": False,
    "authority": "evidence-only",
    "knowledgeGrantsAuthority": False,
    "credentialValuesAllowed": False,
    "providerAccountCreationAllowed": False,
    "gapFallback": "knowledge-gap",
    "supervisorDecisionScope": "declared-profiles-only",
    "supervisorMayAddOperations": False,
    "supervisorMayGrantAuthority": False,
}
NO_EFFECT_CONTROL = {
    "mode": "none",
    "twoPhase": False,
    "planHashRequired": False,
    "externalSingleUseGrantRequired": False,
    "applyReceiptRequired": False,
}
EXACT_PLAN_CONTROL = {
    "mode": "exact-plan-single-use-grant",
    "twoPhase": True,
    "planHashRequired": True,
    "externalSingleUseGrantRequired": True,
    "applyReceiptRequired": True,
}
PINNED_BLUEPRINT = {
    "blueprintId": "service-observe-repair",
    "version": "v1",
    "definitionUri": "lifecycle://wellmanifest.com/service-observe-repair/v1",
    "definitionDigest": "sha256:36aba6a39af52a1d485da3ad48aa7e5fa671472be76090e9fef1ae39bb5b6870",
    "immutable": True,
}


class ServiceAccessContracts:
    def __init__(self) -> None:
        self.schema = _pr.load_strict_json(SERVICE_ACCESS_SCHEMA_PATH)
        self.example = _pr.load_strict_json(SERVICE_ACCESS_EXAMPLE_PATH)
        defs = self.schema.get("$defs", {})
        names = (
            "identifier", "sha256Ref", "providerRef", "schemaRef", "connectorRef",
            "operationRef", "producerRef", "policyRef", "registryRef", "strategyRef",
            "repositoryRef", "twinRef",
        )
        self.patterns = {name: re.compile(defs[name]["pattern"]) for name in names}
        self.max_lengths: dict[str, int | None] = {
            name: defs[name].get("maxLength") for name in names
        }

    def ref(self, name: str, value: Any) -> str:
        max_len = self.max_lengths[name]
        if (
            not isinstance(value, str)
            or (max_len is not None and len(value) > max_len)
            or self.patterns[name].fullmatch(value) is None
        ):
            raise ContractError(f"SVCACCESS-REF-001: invalid {name}")
        return _pr.validate_safe_uri_segments(value, f"SVCACCESS-REF-001: invalid {name}")

    def integrity(self) -> None:
        if self.schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ContractError("SVCACCESS-DOC-001: unexpected schema dialect")
        if self.schema.get("$id") != SERVICE_ACCESS_SCHEMA_URI:
            raise ContractError("SVCACCESS-DOC-001: unexpected schema identifier")
        if _pr.digest(_pr.canonical(self.schema)) != SERVICE_ACCESS_SCHEMA_DIGEST:
            raise ContractError("SVCACCESS-DOC-001: schema digest mismatch")
        if _pr.digest(_pr.canonical(self.example)) != SERVICE_ACCESS_EXAMPLE_DIGEST:
            raise ContractError("SVCACCESS-DOC-001: example digest mismatch")
        _pr.assert_closed_schema(self.schema, "SVCACCESS-DOC-001: object schema is not closed")


def _validate_service_profile(
    c: ServiceAccessContracts,
    profile: Any,
    service_types: set[str],
    profile_ids: set[str],
    covered: set[str],
    profile_keys: set[tuple[str, str, str]],
) -> None:
    keys = {
        "id", "providerRefs", "serviceTypes", "mode", "accountEvidence",
        "credentialEvidence", "governance", "connector", "mutationControl",
        "readback", "producedCredentialKinds", "boundary",
    }
    profile = exact(profile, keys)
    profile_id = c.ref("identifier", profile["id"])
    if profile_id in profile_ids:
        raise ContractError("SVCACCESS-DOC-001: duplicate profile")
    profile_ids.add(profile_id)
    providers = unique_list(
        profile["providerRefs"], "SVCACCESS-REF-001", minimum=1, maximum=16
    )
    for ref in providers:
        c.ref("providerRef", ref)
    profile_services = unique_list(
        profile["serviceTypes"], "SVCACCESS-DOC-001", minimum=1, maximum=32
    )
    for service_type in profile_services:
        c.ref("identifier", service_type)
        if service_type not in service_types:
            raise ContractError("SVCACCESS-DOC-001: profile uses undeclared service type")
        covered.add(service_type)
    mode = str_choice(
        profile["mode"], {"observe", "provision"}, "SVCACCESS-DOC-001: unsupported profile mode"
    )
    for provider in providers:
        for service_type in profile_services:
            key = (provider, service_type, mode)
            if key in profile_keys:
                raise ContractError("SVCACCESS-DOC-001: ambiguous profile coverage")
            profile_keys.add(key)

    acct_keys = {
        "accountContractRef", "accountQueryOperationRefs",
        "requiredRelation", "liveObservationRequired", "freshnessRequired",
    }
    account = exact(profile["accountEvidence"], acct_keys)
    c.ref("schemaRef", account["accountContractRef"])
    if account["accountContractRef"] != "schema://wellmanifest.dev/account-runtime/v1":
        raise ContractError("SVCACCESS-ACCOUNT-001: parent account contract is not pinned")
    for ref in unique_list(
        account["accountQueryOperationRefs"], "SVCACCESS-REF-001", minimum=1, maximum=32
    ):
        c.ref("operationRef", ref)
    if (
        account["requiredRelation"] != "account_verified"
        or account["liveObservationRequired"] is not True
        or account["freshnessRequired"] is not True
    ):
        raise ContractError("SVCACCESS-ACCOUNT-001: parent account evidence is insufficient")

    cred_keys = {
        "metadataQueryOperationRef", "metadataOnly",
        "requiredFieldKinds", "targetBindingRequired",
    }
    credential = exact(profile["credentialEvidence"], cred_keys)
    c.ref("operationRef", credential["metadataQueryOperationRef"])
    if credential["metadataOnly"] is not True or credential["targetBindingRequired"] is not True:
        raise ContractError("SVCACCESS-SECRET-001: credential evidence is not metadata-only")
    for kind in unique_list(
        credential["requiredFieldKinds"], "SVCACCESS-DOC-001", maximum=64
    ):
        c.ref("identifier", kind)

    governance = exact(profile["governance"], {"policyRefs", "registryRefs", "strategyRefs"})
    for field, ref_type in (
        ("policyRefs", "policyRef"),
        ("registryRefs", "registryRef"),
        ("strategyRefs", "strategyRef"),
    ):
        for ref in unique_list(
            governance[field], "SVCACCESS-REF-001", minimum=1, maximum=16
        ):
            c.ref(ref_type, ref)

    connector = exact(
        profile["connector"],
        {"connectorRef", "capabilities", "preflightOperationRefs"},
        {"mutationOperationRef", "producerIntentRef"},
    )
    c.ref("connectorRef", connector["connectorRef"])
    for capability in unique_list(
        connector["capabilities"], "SVCACCESS-DOC-001", minimum=1, maximum=64
    ):
        c.ref("identifier", capability)
    for ref in unique_list(
        connector["preflightOperationRefs"], "SVCACCESS-REF-001", minimum=1, maximum=32
    ):
        c.ref("operationRef", ref)
    if "mutationOperationRef" in connector:
        c.ref("operationRef", connector["mutationOperationRef"])
    if "producerIntentRef" in connector:
        c.ref("producerRef", connector["producerIntentRef"])

    ctrl_keys = {
        "mode", "twoPhase", "planHashRequired",
        "externalSingleUseGrantRequired", "applyReceiptRequired",
    }
    control = exact(profile["mutationControl"], ctrl_keys)

    rb_keys = {
        "queryOperationRefs", "twinRef", "blueprintRef",
        "revisionRequired", "independentObservationRequired", "updatesInventory",
    }
    readback = exact(profile["readback"], rb_keys)
    for ref in unique_list(
        readback["queryOperationRefs"], "SVCACCESS-REF-001", minimum=1, maximum=32
    ):
        c.ref("operationRef", ref)
    c.ref("twinRef", readback["twinRef"])
    bp_keys = {"blueprintId", "version", "definitionUri", "definitionDigest", "immutable"}
    blueprint = exact(readback["blueprintRef"], bp_keys)
    if blueprint != PINNED_BLUEPRINT:
        raise ContractError("SVCACCESS-READBACK-001: Twin lifecycle blueprint is not pinned")
    if (
        readback["revisionRequired"] is not True
        or readback["independentObservationRequired"] is not True
        or readback["updatesInventory"] is not True
    ):
        raise ContractError(
            "SVCACCESS-READBACK-001: Twin readback is not independent and revisioned"
        )

    produced = unique_list(
        profile["producedCredentialKinds"], "SVCACCESS-DOC-001", maximum=64
    )
    for kind in produced:
        c.ref("identifier", kind)
    pb_keys = {
        "knowledgeGrantsAuthority", "credentialValuesAllowed",
        "parentAccountMustBeVerified", "accountCreation",
    }
    profile_boundary = exact(profile["boundary"], pb_keys)
    if (
        profile_boundary["knowledgeGrantsAuthority"] is not False
        or profile_boundary["credentialValuesAllowed"] is not False
        or profile_boundary["parentAccountMustBeVerified"] is not True
    ):
        raise ContractError("SVCACCESS-AUTHORITY-001: profile boundary is unsafe")
    account_creation = str_choice(
        profile_boundary["accountCreation"],
        {"none", "provider-child"},
        "SVCACCESS-ACCOUNT-001: provider account creation is forbidden",
    )

    if mode == "observe":
        if (
            "mutationOperationRef" in connector
            or "producerIntentRef" in connector
            or control != NO_EFFECT_CONTROL
            or produced
            or account_creation != "none"
        ):
            raise ContractError("SVCACCESS-MUTATION-001: observe profile contains an effect path")
    elif "mutationOperationRef" not in connector or control != EXACT_PLAN_CONTROL:
        raise ContractError("SVCACCESS-MUTATION-001: provision profile lacks exact-plan control")
    if produced and "producerIntentRef" not in connector:
        raise ContractError("SVCACCESS-MUTATION-001: credential output lacks a reviewed producer")
    if account_creation == "provider-child" and (
        mode != "provision" or not produced or "producerIntentRef" not in connector
    ):
        raise ContractError("SVCACCESS-ACCOUNT-001: child account lacks its parent-bound producer")


def validate_service_access(c: ServiceAccessContracts, value: Any) -> None:
    _pr.reject_secret_material(value, "SVCACCESS-SECRET-001: credential material is forbidden")
    keys = {
        "$schema", "schema", "catalogId", "sourceRevision",
        "serviceTypes", "profiles", "gaps", "boundary",
    }
    value = exact(value, keys)
    if (
        value["$schema"] != SERVICE_ACCESS_SCHEMA_URI
        or value["schema"] != "wellmanifest.service-access-catalog/v1"
    ):
        raise ContractError("SVCACCESS-DOC-001: unsupported catalog schema")
    c.ref("identifier", value["catalogId"])
    c.ref("sha256Ref", value["sourceRevision"])

    boundary = exact(value["boundary"], set(EXPECTED_BOUNDARY))
    if boundary != EXPECTED_BOUNDARY:
        raise ContractError("SVCACCESS-AUTHORITY-001: catalog boundary is unsafe")

    service_types: set[str] = set()
    for item in bounded_list(
        value["serviceTypes"], "SVCACCESS-DOC-001", minimum=1, maximum=128
    ):
        item = exact(item, {"id", "protocols", "credentialKinds"})
        service_type = c.ref("identifier", item["id"])
        if service_type in service_types:
            raise ContractError("SVCACCESS-DOC-001: duplicate service type")
        service_types.add(service_type)
        for protocol in unique_list(
            item["protocols"], "SVCACCESS-DOC-001", minimum=1, maximum=32
        ):
            c.ref("identifier", protocol)
        for kind in unique_list(
            item["credentialKinds"], "SVCACCESS-DOC-001", maximum=64
        ):
            c.ref("identifier", kind)

    profile_ids: set[str] = set()
    covered: set[str] = set()
    profile_keys: set[tuple[str, str, str]] = set()
    for profile in bounded_list(value["profiles"], "SVCACCESS-DOC-001", maximum=256):
        _validate_service_profile(c, profile, service_types, profile_ids, covered, profile_keys)

    gap_keys: set[tuple[str, str, str]] = set()
    for gap in bounded_list(value["gaps"], "SVCACCESS-GAP-001", maximum=256):
        gap = exact(
            gap,
            {
                "serviceType", "providerRef", "mode",
                "reasonCode", "requiredOwnerRef", "requiredCapability",
            },
        )
        service_type = c.ref("identifier", gap["serviceType"])
        if service_type not in service_types:
            raise ContractError("SVCACCESS-GAP-001: gap uses undeclared service type")
        covered.add(service_type)
        provider = c.ref("providerRef", gap["providerRef"])
        gap_mode = str_choice(
            gap["mode"], {"observe", "provision"}, "SVCACCESS-GAP-001: unsupported gap mode"
        )
        c.ref("identifier", gap["reasonCode"])
        c.ref("repositoryRef", gap["requiredOwnerRef"])
        c.ref("identifier", gap["requiredCapability"])
        key = (provider, service_type, gap_mode)
        if key in gap_keys or key in profile_keys:
            raise ContractError("SVCACCESS-GAP-001: gap contradicts declared profile coverage")
        gap_keys.add(key)

    if covered != service_types:
        raise ContractError("SVCACCESS-GAP-001: service type has neither profile nor explicit gap")


def run_service_access_conformance() -> dict[str, Any]:
    service = ServiceAccessContracts()
    service.integrity()
    validate_service_access(service, service.example)
    service_rejected: list[str] = []

    def reject_case(name: str, code: str, mutate: Callable[[dict[str, Any]], Any]) -> None:
        candidate = copy.deepcopy(service.example)
        mutate(candidate)
        try:
            validate_service_access(service, candidate)
        except ContractError as error:
            if not str(error).startswith(code + ":"):
                raise AssertionError(f"{name} rejected as {error}, expected {code}") from error
            service_rejected.append(name)
        else:
            raise AssertionError(f"service-access adversarial case accepted: {name}")

    cases: tuple[tuple[str, str, Callable[[dict[str, Any]], Any]], ...] = (
        ("catalog-acts", "SVCACCESS-AUTHORITY-001", lambda d: d["boundary"].update(acts=True)),
        (
            "supervisor-adds-operation",
            "SVCACCESS-AUTHORITY-001",
            lambda d: d["boundary"].update(supervisorMayAddOperations=True),
        ),
        (
            "unverified-parent-account",
            "SVCACCESS-ACCOUNT-001",
            lambda d: d["profiles"][0]["accountEvidence"].update(
                requiredRelation="account_inferred"
            ),
        ),
        (
            "stale-parent-account",
            "SVCACCESS-ACCOUNT-001",
            lambda d: d["profiles"][0]["accountEvidence"].update(freshnessRequired=False),
        ),
        (
            "observe-mutation",
            "SVCACCESS-MUTATION-001",
            lambda d: d["profiles"][1]["connector"].update(
                mutationOperationRef="operation://example.test/hosting/subscription/create/v1"
            ),
        ),
        (
            "provision-without-two-phase",
            "SVCACCESS-MUTATION-001",
            lambda d: d["profiles"][0]["mutationControl"].update(twoPhase=False),
        ),
        (
            "mutable-operation-ref",
            "SVCACCESS-REF-001",
            lambda d: d["profiles"][0]["connector"].update(
                mutationOperationRef="operation://example.test/hosting/api-key/bootstrap"
            ),
        ),
        (
            "missing-revisioned-readback",
            "SVCACCESS-READBACK-001",
            lambda d: d["profiles"][0]["readback"].update(revisionRequired=False),
        ),
        (
            "unpinned-twin-lifecycle",
            "SVCACCESS-READBACK-001",
            lambda d: d["profiles"][0]["readback"]["blueprintRef"].update(immutable=False),
        ),
        (
            "credential-without-producer",
            "SVCACCESS-MUTATION-001",
            lambda d: d["profiles"][0]["connector"].pop("producerIntentRef"),
        ),
        (
            "child-without-produced-credential",
            "SVCACCESS-ACCOUNT-001",
            lambda d: d["profiles"][2].update(producedCredentialKinds=[]),
        ),
        (
            "provider-account-creation",
            "SVCACCESS-ACCOUNT-001",
            lambda d: d["profiles"][2]["boundary"].update(accountCreation="provider-tenant"),
        ),
        (
            "secret-material",
            "SVCACCESS-SECRET-001",
            lambda d: d.update(secretMaterial="s" + "k-" + ("a" * 30)),
        ),
        (
            "undeclared-service-type",
            "SVCACCESS-DOC-001",
            lambda d: d["profiles"][0].update(serviceTypes=["undeclared-service"]),
        ),
        (
            "gap-profile-contradiction",
            "SVCACCESS-GAP-001",
            lambda d: d["gaps"].append(
                {
                    "serviceType": "subscription",
                    "providerRef": "provider://example.test/hosting-control-plane",
                    "mode": "observe",
                    "reasonCode": "operation-not-reviewed",
                    "requiredOwnerRef": "repository://example.test/connectors",
                    "requiredCapability": "subscription.inventory",
                }
            ),
        ),
        ("uncovered-service-type", "SVCACCESS-GAP-001", lambda d: d.update(gaps=[])),
    )
    for name, code, mutate in cases:
        reject_case(name, code, mutate)

    return {
        "schema": "wellmanifest.service-access-conformance/v1",
        "schemaDigest": "sha256:" + SERVICE_ACCESS_SCHEMA_DIGEST,
        "exampleDigest": "sha256:" + SERVICE_ACCESS_EXAMPLE_DIGEST,
        "profilesAccepted": len(service.example["profiles"]),
        "gapsAccepted": len(service.example["gaps"]),
        "adversarialRejected": service_rejected,
    }
