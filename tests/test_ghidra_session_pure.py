# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Pure unit tests for Ghidra project reopen behavior."""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest
from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.session import Session


class _JavaFileNotFoundException(Exception):
    """Stand-in for ``java.io.FileNotFoundException`` without a JVM."""


def _install_ghidra_stubs(monkeypatch, ghidra_project) -> None:
    modules = {
        "ghidra": ModuleType("ghidra"),
        "ghidra.base": ModuleType("ghidra.base"),
        "ghidra.base.project": ModuleType("ghidra.base.project"),
        "ghidra.program": ModuleType("ghidra.program"),
        "ghidra.program.flatapi": ModuleType("ghidra.program.flatapi"),
        "ghidra.program.model": ModuleType("ghidra.program.model"),
        "ghidra.program.model.lang": ModuleType("ghidra.program.model.lang"),
        "ghidra.util": ModuleType("ghidra.util"),
        "ghidra.util.task": ModuleType("ghidra.util.task"),
        "java": ModuleType("java"),
        "java.io": ModuleType("java.io"),
    }
    modules["ghidra.base.project"].GhidraProject = ghidra_project
    modules["ghidra.program.flatapi"].FlatProgramAPI = lambda program, monitor: (program, monitor)
    modules["ghidra.program.model.lang"].CompilerSpecID = str
    modules["ghidra.program.model.lang"].LanguageID = str
    modules["ghidra.util.task"].TaskMonitor = type("TaskMonitor", (), {"DUMMY": object()})
    modules["java.io"].File = str
    modules["java.io"].FileNotFoundException = _JavaFileNotFoundException

    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)


def _existing_project(tmp_path):
    binary = tmp_path / "ntoskrnl.exe"
    binary.write_bytes(b"synthetic PE fixture")
    project_dir = tmp_path / "ghidra_projects"
    project_dir.mkdir()
    (project_dir / "ntoskrnl.exe.gpr").write_bytes(b"project fixture")
    return binary


def test_existing_project_reimports_when_root_program_is_missing(monkeypatch, tmp_path):
    binary = _existing_project(tmp_path)
    program = object()
    project = MagicMock()
    project.openProgram.side_effect = _JavaFileNotFoundException("File not found: //ntoskrnl.exe")
    project.importProgram.return_value = program
    ghidra_project = MagicMock()
    ghidra_project.openProject.return_value = project
    _install_ghidra_stubs(monkeypatch, ghidra_project)

    session = Session()
    result = session.open(str(binary))

    ghidra_project.openProject.assert_called_once_with(
        str(tmp_path / "ghidra_projects"), "ntoskrnl.exe"
    )
    project.openProgram.assert_called_once_with("/", "ntoskrnl.exe", False)
    project.importProgram.assert_called_once_with(str(binary))
    assert result["status"] == "ok"
    assert session.program is program
    assert session.current_path == str(binary)


def test_existing_project_keeps_present_root_program(monkeypatch, tmp_path):
    binary = _existing_project(tmp_path)
    program = object()
    project = MagicMock()
    project.openProgram.return_value = program
    ghidra_project = MagicMock()
    ghidra_project.openProject.return_value = project
    _install_ghidra_stubs(monkeypatch, ghidra_project)

    session = Session()
    session.open(str(binary))

    project.importProgram.assert_not_called()
    assert session.program is program


def test_missing_root_program_import_failure_remains_fail_closed(monkeypatch, tmp_path):
    binary = _existing_project(tmp_path)
    project = MagicMock()
    project.openProgram.side_effect = _JavaFileNotFoundException("File not found: //ntoskrnl.exe")
    project.importProgram.return_value = None
    ghidra_project = MagicMock()
    ghidra_project.openProject.return_value = project
    _install_ghidra_stubs(monkeypatch, ghidra_project)

    with pytest.raises(GhidraError) as exc_info:
        Session().open(str(binary))

    assert exc_info.value.error_type == "ImportFailed"
    project.close.assert_called_once_with()


def test_existing_project_does_not_mask_other_open_failures(monkeypatch, tmp_path):
    binary = _existing_project(tmp_path)
    project = MagicMock()
    project.openProgram.side_effect = RuntimeError("project lock failure")
    ghidra_project = MagicMock()
    ghidra_project.openProject.return_value = project
    _install_ghidra_stubs(monkeypatch, ghidra_project)

    with pytest.raises(GhidraError, match="Failed to open database"):
        Session().open(str(binary))

    project.importProgram.assert_not_called()
