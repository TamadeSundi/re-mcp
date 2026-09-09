# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Data and memory tools — read bytes, segments, etc."""

from __future__ import annotations

from typing import Annotated, Literal

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ghidra.exceptions import GhidraError
from re_mcp_ghidra.helpers import (
    ANNO_READ_ONLY,
    Address,
    Limit,
    Offset,
    format_address,
    format_permissions,
    paginate,
    read_memory,
    resolve_address,
)
from re_mcp_ghidra.session import session


class ReadBytesResult(BaseModel):
    address: str
    size: int
    hex_data: str
    ascii: str = ""


DataView = Literal[
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
]


class ReadDataResult(BaseModel):
    address: str
    size: int
    hex_data: str
    view: DataView
    byte_order: Literal["little", "big"]
    element_width: int
    values: list[int]
    text: str
    element_count: int
    terminated: bool
    truncated: bool


class SegmentInfo(BaseModel):
    name: str
    start: str
    end: str
    size: int
    permissions: str
    type: str = ""
    initialized: bool = True


def decode_data_view(
    data: bytes,
    *,
    view: DataView,
    byte_order: Literal["little", "big"],
    pointer_size: int,
) -> dict:
    widths = {
        "u8": (1, False),
        "i8": (1, True),
        "u16": (2, False),
        "i16": (2, True),
        "u32": (4, False),
        "i32": (4, True),
        "u64": (8, False),
        "i64": (8, True),
        "pointer": (pointer_size, False),
    }
    numeric = widths.get(view)
    if numeric is not None:
        width, signed = numeric
        total = len(data) // width
        count = min(total, 64)
        return {
            "values": [
                int.from_bytes(
                    data[offset : offset + width], byte_order, signed=signed
                )
                for offset in range(0, count * width, width)
            ],
            "text": "",
            "element_count": count,
            "terminated": False,
            "truncated": total > count or len(data) % width != 0,
        }

    unit = 2 if view == "utf-16le" else 1
    terminator = None
    for offset in range(0, len(data) - unit + 1, unit):
        if data[offset : offset + unit] == b"\x00" * unit:
            terminator = offset
            break
    payload = data if terminator is None else data[:terminator]
    encoding = {"ascii": "ascii", "utf-8": "utf-8", "utf-16le": "utf-16le"}[view]
    text = payload.decode(encoding, errors="replace")
    bounded = text[:64]
    return {
        "values": [],
        "text": bounded,
        "element_count": len(bounded),
        "terminated": terminator is not None,
        "truncated": terminator is None or len(text) > len(bounded),
    }


def register(mcp: FastMCP) -> None:
    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"data"})
    @session.require_open
    def read_bytes(
        address: Address,
        size: int = 256,
    ) -> ReadBytesResult:
        """Read raw bytes from the database.

        Args:
            address: Start address.
            size: Number of bytes to read (max 4096).
        """
        if size > 4096:
            size = 4096
        if size < 1:
            raise GhidraError("size must be >= 1", error_type="InvalidArgument")

        program = session.program
        mem = program.getMemory()
        addr = resolve_address(address)

        try:
            data = read_memory(mem, addr, size)
        except Exception:
            buf = bytearray()
            for i in range(size):
                try:
                    buf.append(mem.getByte(addr.add(i)) & 0xFF)
                except Exception:
                    break
            data = bytes(buf)

        hex_str = " ".join(f"{b:02X}" for b in data)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)

        return ReadBytesResult(
            address=format_address(addr.getOffset()),
            size=len(data),
            hex_data=hex_str,
            ascii=ascii_str,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"data", "phase06"})
    @session.require_open
    def read_data(
        address: Address,
        size: Annotated[int, Field(ge=1, le=512)],
        view: DataView,
    ) -> ReadDataResult:
        """Read at most 512 bytes and return one bounded typed/string view."""
        program = session.program
        addr = resolve_address(address)
        raw = read_memory(program.getMemory(), addr, size)
        if len(raw) != size:
            raise GhidraError("read_data returned a partial range", error_type="ReadFailed")
        byte_order = "big" if program.getLanguage().isBigEndian() else "little"
        pointer_size = int(program.getDefaultPointerSize())
        if pointer_size not in {4, 8}:
            raise GhidraError(
                "read_data observed an unsupported pointer size",
                error_type="UnsupportedArchitecture",
            )
        decoded = decode_data_view(
            raw,
            view=view,
            byte_order=byte_order,
            pointer_size=pointer_size,
        )
        element_width = {
            "u8": 1,
            "i8": 1,
            "u16": 2,
            "i16": 2,
            "u32": 4,
            "i32": 4,
            "u64": 8,
            "i64": 8,
            "pointer": pointer_size,
            "ascii": 1,
            "utf-8": 1,
            "utf-16le": 2,
        }[view]
        return ReadDataResult(
            address=format_address(addr.getOffset()),
            size=size,
            hex_data=raw.hex(),
            view=view,
            byte_order=byte_order,
            element_width=element_width,
            **decoded,
        )

    @mcp.tool(annotations=ANNO_READ_ONLY, tags={"data"})
    @session.require_open
    def get_segments(
        offset: Offset = 0,
        limit: Limit = 100,
    ) -> dict:
        """List all memory segments/blocks."""
        program = session.program
        mem = program.getMemory()
        blocks = list(mem.getBlocks())

        items = []
        for block in blocks:
            start = block.getStart()
            end = block.getEnd()
            items.append(
                SegmentInfo(
                    name=block.getName(),
                    start=format_address(start.getOffset()),
                    end=format_address(end.getOffset()),
                    size=int(block.getSize()),
                    permissions=format_permissions(
                        block.isRead(),
                        block.isWrite(),
                        block.isExecute(),
                    ),
                    type=str(block.getType()) if block.getType() else "",
                    initialized=block.isInitialized(),
                ).model_dump()
            )

        return paginate(items, offset, limit)
