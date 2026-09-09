from __future__ import annotations

import pytest
from fastmcp import FastMCP
from re_mcp_ghidra.tools import data, operands, search, typeinf, xrefs
from re_mcp_ghidra.tools.functions import (
    MAX_PHASE06_DECOMPILE_CHARS,
    MAX_PHASE06_INSTRUCTIONS,
)
from re_mcp_ghidra.transforms import PINNED_TOOLS

PHASE06_STATIC_TOOLS = frozenset(
    {
        "get_function",
        "get_call_graph",
        "decompile_function",
        "disassemble_function",
        "get_xrefs_to",
        "get_xrefs_from",
        "read_data",
        "get_address_info",
        "get_type_info",
        "get_local_type",
        "get_function_vars",
        "get_stack_frame",
        "decode_instruction",
        "get_operand_value",
        "get_basic_blocks",
        "get_switch_info",
        "get_strings",
        "find_code_by_string",
    }
)


def test_phase06_static_tools_are_directly_visible_named_reads() -> None:
    assert len(PHASE06_STATIC_TOOLS) == 18
    assert PHASE06_STATIC_TOOLS <= PINNED_TOOLS
    assert "call" not in PHASE06_STATIC_TOOLS


def test_read_data_numeric_views_are_bounded_and_little_endian() -> None:
    decoded = data.decode_data_view(
        bytes(range(130)),
        view="u16",
        byte_order="little",
        pointer_size=8,
    )

    assert decoded["element_count"] == 64
    assert decoded["values"][:2] == [0x0100, 0x0302]
    assert decoded["text"] == ""
    assert decoded["terminated"] is False
    assert decoded["truncated"] is True


def test_read_data_string_views_retain_termination_and_truncation() -> None:
    terminated = data.decode_data_view(
        b"hello\x00ignored",
        view="ascii",
        byte_order="little",
        pointer_size=8,
    )
    truncated = data.decode_data_view(
        "A".encode("utf-16le") * 65,
        view="utf-16le",
        byte_order="little",
        pointer_size=8,
    )

    assert terminated == {
        "values": [],
        "text": "hello",
        "element_count": 5,
        "terminated": True,
        "truncated": False,
    }
    assert truncated["element_count"] == 64
    assert truncated["text"] == "A" * 64
    assert truncated["terminated"] is False
    assert truncated["truncated"] is True


@pytest.mark.asyncio
async def test_read_data_schema_is_closed_and_bounded() -> None:
    server = FastMCP("phase06-read-data-contract")
    data.register(server)
    tool = await server.get_tool("read_data")

    assert tool.parameters == {
        "type": "object",
        "properties": {
            "address": {
                "type": "string",
                "description": "Address (hex string, decimal, or symbol name).",
            },
            "size": {"type": "integer", "minimum": 1, "maximum": 512},
            "view": {
                "type": "string",
                "enum": [
                    "u8",
                    "i8",
                    "u16",
                    "i16",
                    "u32",
                    "i32",
                    "u64",
                    "i64",
                    "pointer",
                    "ascii",
                    "utf-8",
                    "utf-16le",
                ],
            },
        },
        "required": ["address", "size", "view"],
        "additionalProperties": False,
    }
    assert set(tool.output_schema["properties"]) == {
        "address",
        "size",
        "hex_data",
        "view",
        "byte_order",
        "element_width",
        "values",
        "text",
        "element_count",
        "terminated",
        "truncated",
    }


@pytest.mark.asyncio
async def test_selected_pagination_and_function_reads_have_hard_bounds() -> None:
    server = FastMCP("phase06-bounded-read-contract")
    xrefs.register(server)
    search.register(server)
    operands.register(server)
    typeinf.register(server)

    xrefs_to = await server.get_tool("get_xrefs_to")
    call_graph = await server.get_tool("get_call_graph")
    strings = await server.get_tool("get_strings")
    string_refs = await server.get_tool("find_code_by_string")
    operand = await server.get_tool("get_operand_value")
    local_type = await server.get_tool("get_local_type")

    assert xrefs_to.parameters["properties"]["limit"]["maximum"] == 64
    assert xrefs_to.parameters["properties"]["offset"]["maximum"] == 1_000_000
    assert call_graph.parameters["properties"]["depth"] == {
        "default": 1,
        "description": "Call graph depth (exactly 1).",
        "maximum": 1,
        "minimum": 1,
        "type": "integer",
    }
    assert strings.parameters["properties"]["limit"]["maximum"] == 32
    assert strings.parameters["properties"]["offset"]["maximum"] == 1_000_000
    assert strings.parameters["properties"]["filter_pattern"]["maxLength"] == 256
    assert strings.parameters["properties"]["min_length"]["maximum"] == 512
    assert string_refs.parameters["properties"]["limit"]["maximum"] == 32
    assert string_refs.parameters["properties"]["pattern"]["maxLength"] == 256
    assert operand.parameters["properties"]["operand_index"]["maximum"] == 15
    assert local_type.parameters["properties"]["name"]["maxLength"] == 256
    assert MAX_PHASE06_DECOMPILE_CHARS == 20_000
    assert MAX_PHASE06_INSTRUCTIONS == 512
