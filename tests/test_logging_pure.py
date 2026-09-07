# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Unit tests for log-path resolution and run-ID propagation."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from re_mcp import _sanitize_label, configure_logging, ensure_run_id, resolve_log_file
from re_mcp.worker_provider import WorkerPoolProvider, _enrich_spawn_error
from re_mcp_ghidra.backend import GhidraBackend
from re_mcp_ida.backend import IDABackend
from re_mcp_ida.server import main as ida_worker_main


@pytest.fixture(autouse=True)
def _clear_env(monkeypatch):
    monkeypatch.delenv("RE_MCP_LOG_RUN", raising=False)
    monkeypatch.delenv("RE_MCP_LOG_DIR", raising=False)
    monkeypatch.delenv("IDA_MCP_LOG_RUN", raising=False)
    monkeypatch.delenv("IDA_MCP_LOG_DIR", raising=False)
    monkeypatch.delenv("GHIDRA_MCP_LOG_RUN", raising=False)
    monkeypatch.delenv("GHIDRA_MCP_LOG_DIR", raising=False)
    monkeypatch.delenv("GHIDRA_MCP_LABEL", raising=False)
    monkeypatch.delenv("GHIDRA_MCP_LOG_LEVEL", raising=False)


def test_resolve_log_file_unset_returns_none():
    assert resolve_log_file("supervisor") is None


def test_resolve_log_file_builds_path(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    result = resolve_log_file("supervisor")
    assert result is not None
    assert os.path.dirname(result) == str(tmp_path)
    assert result.endswith("-supervisor.log")
    run_id = os.environ["RE_MCP_LOG_RUN"]
    assert os.path.basename(result) == f"{run_id}-supervisor.log"


def test_resolve_log_file_custom_suffix(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    result = resolve_log_file("worker-abc", suffix=".stderr")
    assert result.endswith("-worker-abc.stderr")


def test_resolve_log_file_creates_missing_directory(monkeypatch, tmp_path):
    target = tmp_path / "nested" / "logs"
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(target))
    result = resolve_log_file("supervisor")
    assert os.path.isdir(target)
    assert result.startswith(str(target))


def test_resolve_log_file_sanitizes_label(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    # Path separators must not leak into the filename — the resolved path
    # must stay inside the configured directory.
    result = resolve_log_file("worker-../evil/db")
    assert os.path.dirname(result) == str(tmp_path)
    assert os.sep not in os.path.basename(result)


def test_resolve_log_file_empty_label(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    result = resolve_log_file("")
    run_id = os.environ["RE_MCP_LOG_RUN"]
    assert os.path.basename(result) == f"{run_id}.log"


def test_resolve_log_file_shares_run_id_across_calls(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    first = resolve_log_file("supervisor")
    second = resolve_log_file("worker-x")
    prefix_first = os.path.basename(first).split("-supervisor")[0]
    prefix_second = os.path.basename(second).split("-worker-x")[0]
    assert prefix_first == prefix_second


def test_resolve_log_file_uses_backend_specific_directory_and_run(monkeypatch, tmp_path):
    generic_dir = tmp_path / "generic"
    ghidra_dir = tmp_path / "ghidra"
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(generic_dir))
    monkeypatch.setenv("RE_MCP_LOG_RUN", "generic-run")
    monkeypatch.setenv("GHIDRA_MCP_LOG_DIR", str(ghidra_dir))
    monkeypatch.setenv("GHIDRA_MCP_LOG_RUN", "ghidra-run")

    result = resolve_log_file("supervisor", env_key="GHIDRA_MCP_LOG_DIR")

    assert result == str(ghidra_dir / "ghidra-run-supervisor.log")
    assert not generic_dir.exists()


def test_backend_log_directory_falls_back_to_generic(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("RE_MCP_LOG_RUN", "generic-run")

    result = resolve_log_file("supervisor", env_key="GHIDRA_MCP_LOG_DIR")

    assert result == str(tmp_path / "generic-run-supervisor.log")
    assert os.environ["GHIDRA_MCP_LOG_RUN"] == "generic-run"


def test_ida_log_directory_falls_back_to_generic(monkeypatch, tmp_path):
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("RE_MCP_LOG_RUN", "generic-run")

    result = resolve_log_file("worker", env_key="IDA_MCP_LOG_DIR")

    assert result == str(tmp_path / "generic-run-worker.log")
    assert os.environ["IDA_MCP_LOG_RUN"] == "generic-run"


def test_default_log_directory_still_falls_back_to_ida(monkeypatch, tmp_path):
    monkeypatch.setenv("IDA_MCP_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("IDA_MCP_LOG_RUN", "ida-run")

    result = resolve_log_file("supervisor")

    assert result == str(tmp_path / "ida-run-supervisor.log")
    assert os.environ["RE_MCP_LOG_RUN"] == "ida-run"


def test_resolve_log_file_propagates_directory_creation_error(monkeypatch, tmp_path):
    monkeypatch.setenv("GHIDRA_MCP_LOG_DIR", str(tmp_path / "unwritable"))

    with (
        patch("re_mcp.os.makedirs", side_effect=PermissionError("denied")),
        pytest.raises(PermissionError, match="denied"),
    ):
        resolve_log_file("supervisor", env_key="GHIDRA_MCP_LOG_DIR")


def test_configure_logging_uses_backend_directory_without_logging_secrets(monkeypatch, tmp_path):
    sentinel = "SENTINEL_BEARER_MUST_NOT_APPEAR"
    monkeypatch.setenv("GHIDRA_MCP_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("GHIDRA_MCP_LOG_RUN", "ghidra-run")
    monkeypatch.setenv("RE_MCP_BEARER_TOKEN", sentinel)
    monkeypatch.setenv("HTTP_AUTHORIZATION", f"Bearer {sentinel}")

    root = logging.getLogger()
    existing_handlers = list(root.handlers)
    try:
        configure_logging(label="supervisor", env_prefix="GHIDRA_MCP_")
        logging.getLogger("re_mcp.logging_test").error("safe diagnostic marker")
        for handler in root.handlers:
            handler.flush()

        content = (tmp_path / "ghidra-run-supervisor.log").read_text()
    finally:
        for handler in list(root.handlers):
            if handler not in existing_handlers:
                root.removeHandler(handler)
                handler.close()

    assert "safe diagnostic marker" in content
    assert sentinel not in content
    assert "RE_MCP_BEARER_TOKEN" not in content
    assert "HTTP_AUTHORIZATION" not in content


def test_ida_components_use_one_backend_log_directory_and_run(monkeypatch, tmp_path):
    ida_dir = tmp_path / "ida"
    generic_dir = tmp_path / "generic"
    monkeypatch.setenv("IDA_MCP_LOG_DIR", str(ida_dir))
    monkeypatch.setenv("IDA_MCP_LOG_RUN", "ida-run")
    monkeypatch.setenv("RE_MCP_LOG_DIR", str(generic_dir))
    monkeypatch.setenv("RE_MCP_LOG_RUN", "generic-run")

    root = logging.getLogger()
    existing_handlers = list(root.handlers)
    try:
        # These are the labels used by the direct supervisor, HTTP daemon,
        # and IDA worker respectively.
        configure_logging(label="supervisor", env_prefix="IDA_MCP_")
        configure_logging(label="daemon", env_prefix="IDA_MCP_")
        configure_logging(label="worker-ntoskrnl", env_prefix="IDA_MCP_")

        pool = WorkerPoolProvider(backend=IDABackend)
        with patch("re_mcp.worker_provider.StdioTransport") as transport_class:
            pool._worker_transport("ntoskrnl")
        transport_kwargs = transport_class.call_args.kwargs

        hint = _enrich_spawn_error(
            BrokenPipeError("closed"),
            label="ntoskrnl",
            log_dir_env_key="IDA_MCP_LOG_DIR",
        )
    finally:
        for handler in list(root.handlers):
            if handler not in existing_handlers:
                root.removeHandler(handler)
                handler.close()

    assert (ida_dir / "ida-run-supervisor.log").is_file()
    assert (ida_dir / "ida-run-daemon.log").is_file()
    assert (ida_dir / "ida-run-worker-ntoskrnl.log").is_file()
    assert transport_kwargs["log_file"] == Path(ida_dir / "ida-run-worker-ntoskrnl.stderr")
    assert transport_kwargs["env"]["IDA_MCP_LOG_RUN"] == "ida-run"
    assert str(ida_dir / "ida-run-worker-ntoskrnl.stderr") in hint
    assert not generic_dir.exists()


def test_ida_worker_entrypoint_selects_ida_logging_prefix():
    with (
        patch("re_mcp_ida.configure_logging") as configure,
        patch("re_mcp_ida.bootstrap", side_effect=SystemExit),
        pytest.raises(SystemExit),
    ):
        ida_worker_main()

    configure.assert_called_once_with(env_prefix="IDA_MCP_")


def test_ghidra_worker_transport_shares_backend_directory_and_run(monkeypatch, tmp_path):
    monkeypatch.setenv("GHIDRA_MCP_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("GHIDRA_MCP_LOG_RUN", "ghidra-run")
    pool = WorkerPoolProvider(backend=GhidraBackend)

    with patch("re_mcp.worker_provider.StdioTransport") as transport_class:
        pool._worker_transport("ntoskrnl")

    kwargs = transport_class.call_args.kwargs
    assert kwargs["log_file"] == Path(tmp_path / "ghidra-run-worker-ntoskrnl.stderr")
    assert kwargs["env"]["GHIDRA_MCP_LOG_RUN"] == "ghidra-run"
    assert kwargs["env"]["GHIDRA_MCP_LABEL"] == "worker-ntoskrnl"


def test_spawn_error_hint_uses_backend_log_directory(monkeypatch, tmp_path):
    monkeypatch.setenv("GHIDRA_MCP_LOG_DIR", str(tmp_path))
    monkeypatch.setenv("GHIDRA_MCP_LOG_RUN", "ghidra-run")

    result = _enrich_spawn_error(
        BrokenPipeError("closed"),
        label="ntoskrnl",
        log_dir_env_key="GHIDRA_MCP_LOG_DIR",
    )

    assert str(tmp_path / "ghidra-run-worker-ntoskrnl.stderr") in result


def test_ensure_run_id_respects_preexisting_env(monkeypatch):
    monkeypatch.setenv("RE_MCP_LOG_RUN", "preset-run-id")
    assert ensure_run_id() == "preset-run-id"


def test_ensure_run_id_generates_and_persists():
    run_id = ensure_run_id()
    assert run_id
    assert os.environ["RE_MCP_LOG_RUN"] == run_id
    assert ensure_run_id() == run_id


def test_sanitize_label_replaces_unsafe_chars():
    # Dots are kept (safe in a leaf filename); separators are scrubbed.
    assert _sanitize_label("worker/db.i64") == "worker_db.i64"
    assert _sanitize_label("safe-label_1.2") == "safe-label_1.2"
    assert _sanitize_label("a b:c") == "a_b_c"
    assert "/" not in _sanitize_label("../evil/x")
