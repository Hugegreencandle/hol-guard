"""Launcher and tool-state validation for the Xahau MCP and Evernode MCP contributions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.local_cli_trust import apply_local_mcp_extension_decision, utc_now
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import (
    AuthorityHealth,
    ExtensionControlAuthorityView,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    CONTROL_SCHEMA_VERSION,
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)
from codex_plugin_scanner.guard.runtime.extension_trust import trust_class_for
from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import mcp_tool_state, validate_mcp_contribution
from codex_plugin_scanner.guard.store import GuardStore
from tests.support.extension_freshness import requires_fresh_projections

_ROOT = Path(__file__).resolve().parents[1] / "contributions/mcp-servers"

# Literal expectations, recorded from each package's tools/list (xahau-mcp 2.2.0, evernode-mcp 0.6.0).
_XAHAU_ALLOW = (
    "decode_hook_on",
    "encode_hook_on",
    "decode_hook_can_emit",
    "encode_hook_can_emit",
    "estimate_hook_state_cost",
    "simulate_hook_trigger",
    "decode_sethook",
    "decode_tx_blob",
    "decode_uritoken_id",
    "xah_amount",
    "validate_address",
    "xaddress",
    "currency_code",
    "decode_result",
    "ripple_time",
    "decode_xpop",
    "inspect_emitted_tx",
    "decode_lease_uri",
    "decode_amount",
    "decode_sign_request",
    "scam_check",
    "inspect_hook_wasm",
    "analyze_hook",
    "list_rules",
    "hook_dry_run",
    "annotate_hook_trace",
    "fuzz_hook",
    "estimate_hook_fee",
    "hook_report",
    "classify_hook",
    "hook_diff",
    "hook_api_lookup",
    "decode_b2m",
    "vm_fidelity_report",
)
_XAHAU_REVIEW_LISTED = (
    "build_sethook_unsigned",
    "build_claimreward_unsigned",
    "build_import_unsigned",
    "build_set_regular_key_unsigned",
    "build_disable_master_unsigned",
    "build_signer_list_set_unsigned",
    "build_payment_unsigned",
    "build_remit_unsigned",
    "build_set_remarks_unsigned",
    "build_clawback_unsigned",
    "build_deepfreeze_unsigned",
    "build_cronset_unsigned",
    "prepare_transaction",
    "encode_tx_blob",
    "scaffold_hook",
)
# Live JSON-RPC readers that rely on the `other` row (schema caps tools at 80; the server has 87).
_XAHAU_REVIEW_VIA_OTHER = (
    "xahau_server_info",
    "get_account_info",
    "get_account_objects",
    "get_account_hooks",
    "get_hook_definition",
    "get_hook_state",
    "get_transaction",
    "get_ledger",
    "get_fee",
    "get_account_lines",
    "get_account_offers",
    "explain_account",
    "get_account_uritokens",
    "audit_account_hooks",
    "execute_hook",
    "compute_reward",
    "reward_status",
    "evernode_host_diagnostics",
    "diagnose_failed_tx",
    "trace_transaction_stakeholders",
    "verify_double_threading",
    "audit_account_remarks",
    "simulate_transaction",
    "what_if",
    "quantum_grade",
    "quantum_config_census",
    "quantum_scorecard",
    "hndl_exposure",
    "governance_state",
    "get_amendment_status",
    "predict_amendment_activation",
    "check_amendment_blocked",
    "diff_node_amendments",
    "master_pubkey",
    "disable_master_readiness",
    "list_cron_jobs",
    "monitor_cron_health",
    "hook_execution_postmortem",
)
_EVERNODE_ALLOW = (
    "list_templates",
    "check_determinism",
    "check_contract_api",
    "recommend_pattern",
    "check_hook_compat",
    "estimate_lease_cost",
    "explain_error",
)
_EVERNODE_REVIEW = (
    "generate_contract",
    "generate_settlement",
    "generate_deploy_commands",
    "recommend_hosts",
    "host_diagnostics",
)

_CASES = {
    "xahau": ("mcp.xahau-mcp.json", "command.mcp-xahau-mcp", "xahau-mcp"),
    "evernode": ("mcp.evernode-mcp.json", "command.mcp-evernode-mcp", "evernode-mcp"),
}


def _payload(key: str) -> dict[str, object]:
    payload = json.loads((_ROOT / _CASES[key][0]).read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _identity(key: str):
    return build_mcp_server_identity(
        config_path="",
        command="npx",
        args=("-y", _CASES[key][2]),
        transport="stdio",
    )


def _artifact(key: str, tool_name: str):
    return build_tool_call_artifact(
        harness="claude-code",
        server_name=_CASES[key][2],
        tool_name=tool_name,
        source_scope="user",
        config_path=".claude.json",
        transport="stdio",
        server_identity=_identity(key),
    )


class _AuthorityStore:
    def __init__(self, layers: tuple[ExtensionControlLayer, ...] = ()) -> None:
        self.layers = layers

    def read_local_mcp_grant(self, *_args: object, **_kwargs: object) -> None:
        return None

    def read_extension_control_authority_for_registry(self, registry: object) -> ExtensionControlAuthorityView:
        digest = getattr(registry, "catalog_digest", "0" * 64)
        assert isinstance(digest, str)
        return ExtensionControlAuthorityView(
            health=AuthorityHealth.PROTECTED,
            revision=1,
            catalog_digest=digest,
            layers=self.layers,
        )


def _enabled(key: str, kind: ControlLayerKind) -> _AuthorityStore:
    return _AuthorityStore(
        (
            ExtensionControlLayer(
                schema_version=CONTROL_SCHEMA_VERSION,
                kind=kind,
                catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
                global_lockdown=False,
                controls=(
                    ExtensionControl(
                        target=ControlTarget(ControlTargetKind.EXTENSION, _CASES[key][1]),
                        state=ControlState.ENABLED,
                    ),
                ),
            ),
        )
    )


def _state_cases() -> list[tuple[str, str, str]]:
    return (
        [("xahau", name, "allow") for name in _XAHAU_ALLOW]
        + [("xahau", name, "review") for name in _XAHAU_REVIEW_LISTED + _XAHAU_REVIEW_VIA_OTHER]
        + [("evernode", name, "allow") for name in _EVERNODE_ALLOW]
        + [("evernode", name, "review") for name in _EVERNODE_REVIEW]
    )


@pytest.mark.parametrize("key", sorted(_CASES))
def test_contribution_validates(key: str) -> None:
    validate_mcp_contribution(_payload(key), filename=_CASES[key][0])


@requires_fresh_projections
@pytest.mark.parametrize("key", sorted(_CASES))
def test_catalog_item_is_external_opt_in_npx_launch(key: str) -> None:
    _, catalog_id, package = _CASES[key]
    extension = BUILT_IN_COMMAND_EXTENSION_REGISTRY.get(catalog_id)
    assert extension is not None
    payload = extension.to_dict()
    assert payload["enabled"] is False
    assert payload["trust_class"] == "external"
    assert payload["activation"] == "opt-in"
    assert payload["surface"] == "mcp"
    assert payload["mcp_launch"] == {"kind": "package-launcher", "command": "npx", "package": package}
    assert trust_class_for(catalog_id) == "external"


def test_declared_tools_match_recorded_inventory() -> None:
    xahau = {tool["name"]: tool["state"] for tool in _payload("xahau")["tools"]}
    assert xahau == {
        **dict.fromkeys(_XAHAU_ALLOW, "allow"),
        **dict.fromkeys(_XAHAU_REVIEW_LISTED, "review"),
        "other": "review",
    }
    evernode = {tool["name"]: tool["state"] for tool in _payload("evernode")["tools"]}
    assert evernode == {
        **dict.fromkeys(_EVERNODE_ALLOW, "allow"),
        **dict.fromkeys(_EVERNODE_REVIEW, "review"),
        "other": "review",
    }
    assert len(_XAHAU_ALLOW) + len(_XAHAU_REVIEW_LISTED) + len(_XAHAU_REVIEW_VIA_OTHER) == 87
    assert len(_EVERNODE_ALLOW) + len(_EVERNODE_REVIEW) == 12


@pytest.mark.parametrize(("key", "tool_name", "state"), _state_cases())
def test_tool_state(key: str, tool_name: str, state: str) -> None:
    assert mcp_tool_state(_payload(key), tool_name) == state


@pytest.mark.parametrize("key", sorted(_CASES))
def test_unknown_tool_falls_to_review(key: str) -> None:
    assert mcp_tool_state(_payload(key), "tool_added_in_a_future_release") == "review"


@requires_fresh_projections
@pytest.mark.parametrize(
    ("key", "tool_name"),
    [
        ("xahau", "build_payment_unsigned"),
        ("xahau", "get_account_info"),
        ("evernode", "generate_deploy_commands"),
        ("evernode", "recommend_hosts"),
    ],
)
def test_review_applies_only_after_local_admin_enable(key: str, tool_name: str) -> None:
    artifact = _artifact(key, tool_name)
    assert apply_local_mcp_extension_decision(_AuthorityStore(), artifact, "allow") is None
    assert apply_local_mcp_extension_decision(_enabled(key, ControlLayerKind.SIGNED_CLOUD), artifact, "allow") is None
    reviewed = apply_local_mcp_extension_decision(_enabled(key, ControlLayerKind.LOCAL_ADMIN), artifact, "allow")
    assert reviewed is not None
    assert reviewed[0] == "review"
    assert reviewed[1] == "catalog-mcp-extension"


@requires_fresh_projections
@pytest.mark.parametrize(("key", "tool_name"), [("xahau", "decode_tx_blob"), ("evernode", "check_determinism")])
def test_allow_applies_only_after_local_admin_enable_and_never_lowers_block(key: str, tool_name: str) -> None:
    artifact = _artifact(key, tool_name)
    assert apply_local_mcp_extension_decision(_AuthorityStore(), artifact, "review") is None
    assert apply_local_mcp_extension_decision(_enabled(key, ControlLayerKind.SIGNED_CLOUD), artifact, "review") is None
    enabled = _enabled(key, ControlLayerKind.LOCAL_ADMIN)
    allowed = apply_local_mcp_extension_decision(enabled, artifact, "review")
    assert allowed is not None
    assert allowed[0] == "allow"
    assert allowed[1] == "catalog-mcp-extension"
    assert apply_local_mcp_extension_decision(enabled, artifact, "block") is None


@requires_fresh_projections
def test_this_device_custom_grant_overrides_contributed_allow(tmp_path: Path) -> None:
    identity = _identity("xahau")
    store = GuardStore(tmp_path / "guard-home")
    cli_identity = UnlistedCliIdentity(
        cli_id=f"local-cli.mcp-{identity.identity_hash[:8]}",
        name=identity.package_name or "mcp-server",
        kind="executable",
        identity_hash=identity.identity_hash,
        example_label="npx -y xahau-mcp",
    )
    store.record_local_cli_observation(
        cli_identity,
        seen_at=utc_now(),
        surface="mcp",
        server_identity_hash=identity.identity_hash,
        server_command=identity.command,
        server_args_hash=identity.args_hash,
        help_status="ok",
    )
    store.replace_local_cli_commands(
        cli_identity.cli_id,
        (LocalCliCommand("decode_tx_blob", "decode_tx_blob", "decode_tx_blob", "Decode a transaction blob"),),
    )
    store.upsert_local_cli_grant(
        identity=cli_identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
        command_states={"decode_tx_blob": "block"},
    )
    granted = apply_local_mcp_extension_decision(store, _artifact("xahau", "decode_tx_blob"), "allow")
    assert granted is not None
    assert granted[0] == "block"
    assert granted[1] == "local-mcp-extension"
