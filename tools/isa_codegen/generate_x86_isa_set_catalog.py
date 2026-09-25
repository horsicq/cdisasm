#!/usr/bin/env python3
"""Generate the exact XED ISA_SET to cdisasm family catalog.

The input is the compact JSON produced by the pinned Intel XED exporter.  The
generator preserves every hand-written public group ID and logical decode-bit
ID, appends exact ISA_SET identities which are not already represented, and
emits numeric descriptor metadata for the generated fallback.  It does not
emit matching code and it never introduces a run-time XED dependency.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
import re
import sys
from typing import Any


GENERATOR_VERSION = 1
EXPECTED_XED_VERSION = "v2026.08.23"
EXPECTED_XED_SHA256 = (
    "35365a46b4375411dc418f4d1b2c80f66117f5dc66df4280b138d16d2440c6bb"
)
EXPECTED_RECORD_COUNT = 10994
EXPECTED_ISA_SET_COUNT = 285
BIT_CAPACITY = 512
NO_BIT = 0xFFFFFFFF

GROUP_RE = re.compile(
    r"^#define CDISASM_X86_GROUP_([A-Z0-9_]+) UINT16_C\(([0-9]+)\)$",
    re.MULTILINE,
)
GROUP_ALIAS_RE = re.compile(
    r"^#define CDISASM_X86_GROUP_([A-Z0-9_]+) "
    r"CDISASM_X86_GROUP_([A-Z0-9_]+)$",
    re.MULTILINE,
)
BIT_RE = re.compile(
    r"^#define CDISASM_X86_DECODE_BIT_([A-Z0-9_]+) "
    r"UINT32_C\(([0-9]+)\)$",
    re.MULTILINE,
)
METADATA_TOKENS = {"NONE", "FIRST", "LAST", "COUNT", "ENDING"}


# This is the current hand-written group classifier expressed as stable group
# and bit tokens.  Reusing it here is intentional: an exact ISA_SET which is
# already represented must retain its original selector.  Existing groups not
# listed here are scalar/core and continue to require no optional-family bit.
GROUP_TO_BIT_TOKEN: dict[str, str] = {}


def _map(bit: str, *groups: str) -> None:
    for group in groups:
        GROUP_TO_BIT_TOKEN[group] = bit


_map("FPU", "X87", "FCMOV", "FCOMI")
_map("MMX", "MMX")
_map("3DNOW", "3DNOW", "3DNOW_EXT")
_map("SSE", "SSE")
_map("SSE2", "SSE2")
_map("SSE3", "SSE3")
_map("SSSE3", "SSSE3")
_map("SSE41", "SSE41")
_map("SSE42", "SSE42")
_map("SSE4A", "SSE4A")
_map("AVX", "AVX")
_map("AVX2", "AVX2")
_map("AVX_VNNI", "AVX_VNNI")
_map("AVX_VNNI_INT8", "AVX_VNNI_INT8")
_map("AVX_VNNI_INT16", "AVX_VNNI_INT16")
_map("F16C", "F16C")
_map("FMA3", "FMA3")
_map("XOP", "XOP")
_map("FMA4", "FMA4")
_map("AES", "AESNI")
_map("VAES", "VAES")
_map("PCLMUL", "PCLMULQDQ")
_map("VPCLMULQDQ", "VPCLMULQDQ")
_map("SHA", "SHA")
_map("SHA512", "SHA512")
_map("SM3", "SM3")
_map("SM4", "SM4")
_map("GFNI", "GFNI")
_map("BITMANIP", "LZCNT", "POPCNT", "TBM", "ADX")
_map("BMI1", "BMI1")
_map("BMI2", "BMI2")
_map(
    "AVX512",
    "AVX512F",
    "AVX512ER",
    "AVX512PF",
    "AVX512VL",
    "AVX512_4VNNIW",
    "AVX512_4FMAPS",
    "AVX512VP2INTERSECT",
    "AVX512BF16",
    "AVX512FP16",
)
_map("AVX512_CD", "AVX512CD")
_map("AVX512_DQ", "AVX512DQ")
_map("AVX512_BW", "AVX512BW")
_map("AVX512_IFMA", "AVX512IFMA")
_map("AVX512_VBMI", "AVX512VBMI")
_map("AVX512_VNNI", "AVX512VNNI")
_map("AVX512_VBMI2", "AVX512VBMI2")
_map("AVX512_VPOPCNTDQ", "AVX512VPOPCNTDQ")
_map("AVX512_BITALG", "AVX512BITALG")
_map("AVX10", "AVX10_1", "AVX10_2")
_map("AMX_TILE", "AMX_TILE")
_map("AMX_INT8", "AMX_INT8")
_map("AMX_BF16", "AMX_BF16")
_map("AMX_FP16", "AMX_FP16")
_map("AMX_COMPLEX", "AMX_COMPLEX")
_map("AMX_FP8", "AMX_FP8")
_map("AMX_MOVRS", "AMX_MOVRS")
_map("AMX_AVX512", "AMX_AVX512")
_map("APX", "APX_F")
_map("VMX", "VMX")
_map("SVM", "SVM")
_map("SMX", "SMX")
_map(
    "SYSTEM",
    "CPUID",
    "SEP",
    "MONITOR_MWAIT",
    "WAITPKG",
    "LWP",
    "FSGSBASE",
    "INVPCID",
    "RDPID",
    "SERIALIZE",
    "MOVDIRI",
    "MOVDIR64B",
    "WBNOINVD",
    "RDTSCP",
    "UINTR",
    "ENQCMD",
)
_map("CET", "CET_IBT", "CET_SS")
_map("STATE", "FXSR", "XSAVE", "XSAVEOPT", "XSAVEC", "XSAVES")
_map("TRANSACTIONAL", "HLE", "RTM", "TSX_LDTRK")
_map("SECURITY", "RDRAND", "RDSEED", "SGX", "MPX", "PKU")
_map(
    "MEMORY_HINTS",
    "PREFETCHW",
    "CLFLUSH",
    "PAUSE",
    "CLFLUSHOPT",
    "CLWB",
)


class GenerationError(RuntimeError):
    pass


@dataclass(frozen=True)
class PriorAllocation:
    isa_set: str
    macro_token: str
    group_id: int
    decode_bit_token: str
    decode_bit_id: int
    bit_allocation: str


@dataclass(frozen=True)
class IsaSetEntry:
    xed_index: int
    isa_set: str
    macro_token: str
    group_token: str
    group_id: int
    group_allocation: str
    decode_bit_token: str
    decode_bit_id: int
    bit_allocation: str
    record_count: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def normalize_token(value: str) -> str:
    token = re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_")
    if not token:
        token = "XED_ISA_SET"
    # This is a suffix of CDISASM_X86_GROUP_/DECODE_BIT_, not a standalone C
    # identifier, so a leading decimal digit is valid and preserves 3DNOW.
    return token


def read_xed_sets(path: Path) -> tuple[list[tuple[str, int]], int]:
    with path.open("r", encoding="utf-8") as stream:
        document: Any = json.load(stream)
    records = document.get("Instructions") if isinstance(document, dict) else None
    if not isinstance(records, list):
        raise GenerationError("XED JSON has no Instructions array")
    if document.get("Version") != EXPECTED_XED_VERSION:
        raise GenerationError(
            f"expected XED {EXPECTED_XED_VERSION}, got {document.get('Version')!r}"
        )
    if len(records) != EXPECTED_RECORD_COUNT:
        raise GenerationError(
            f"expected {EXPECTED_RECORD_COUNT} XED records, got {len(records)}"
        )
    counts: dict[str, int] = {}
    for record in records:
        if not isinstance(record, dict):
            raise GenerationError("XED Instructions contains a non-object")
        isa_set = str(record.get("isa_set", ""))
        if not isa_set or not isa_set.isascii() or any(
            character in "\r\n\t\0" for character in isa_set
        ):
            raise GenerationError(f"unsupported XED ISA_SET: {isa_set!r}")
        counts[isa_set] = counts.get(isa_set, 0) + 1
    if len(counts) != EXPECTED_ISA_SET_COUNT:
        raise GenerationError(
            f"expected {EXPECTED_ISA_SET_COUNT} XED ISA_SET values, got {len(counts)}"
        )
    return sorted(counts.items()), len(records)


def parse_manual_groups(path: Path) -> tuple[dict[str, int], dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    numeric = {
        token: int(value)
        for token, value in GROUP_RE.findall(text)
        if token not in METADATA_TOKENS
    }
    aliases = {
        token: target
        for token, target in GROUP_ALIAS_RE.findall(text)
        if token not in METADATA_TOKENS
    }
    numeric.pop("NONE", None)
    if sorted(numeric.values()) != list(range(1, max(numeric.values()) + 1)):
        raise GenerationError("manual x86 group IDs are not contiguous")
    for alias, target in aliases.items():
        if target not in numeric:
            raise GenerationError(f"group alias {alias} targets unknown {target}")
    return numeric, aliases


def parse_manual_bits(path: Path) -> dict[str, int]:
    text = path.read_text(encoding="utf-8")
    bits = {
        token: int(value)
        for token, value in BIT_RE.findall(text)
        if token not in METADATA_TOKENS
    }
    if sorted(bits.values()) != list(range(max(bits.values()) + 1)):
        raise GenerationError("manual x86 decode-bit IDs are not contiguous")
    return bits


def read_prior(path: Path) -> dict[str, PriorAllocation]:
    if not path.is_file():
        return {}
    result: dict[str, PriorAllocation] = {}
    with path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, dialect="excel-tab"):
            if row.get("group_allocation") != "appended":
                continue
            entry = PriorAllocation(
                isa_set=row["isa_set"],
                macro_token=row["macro_token"],
                group_id=int(row["group_id"]),
                decode_bit_token=row["decode_bit_token"],
                decode_bit_id=int(row["decode_bit_id"]),
                bit_allocation=row["bit_allocation"],
            )
            if entry.isa_set in result:
                raise GenerationError(f"duplicate prior ISA_SET {entry.isa_set}")
            result[entry.isa_set] = entry
    return result


def allocate(
    source: list[tuple[str, int]],
    groups: dict[str, int],
    aliases: dict[str, str],
    bits: dict[str, int],
    prior: dict[str, PriorAllocation],
) -> tuple[list[IsaSetEntry], list[PriorAllocation]]:
    occupied_group_ids = set(groups.values())
    occupied_bit_ids = set(bits.values())
    occupied_tokens = set(groups) | set(aliases) | METADATA_TOKENS
    occupied_bit_tokens = set(bits) | METADATA_TOKENS
    retained: dict[str, PriorAllocation] = {}
    for item in sorted(prior.values(), key=lambda value: value.group_id):
        if item.group_id in occupied_group_ids:
            raise GenerationError(f"prior allocation collides for {item.isa_set}")
        if (item.bit_allocation == "appended"
                and item.decode_bit_id in occupied_bit_ids):
            raise GenerationError(f"prior bit allocation collides for {item.isa_set}")
        if item.macro_token in occupied_tokens:
            raise GenerationError(f"prior token collides: {item.macro_token}")
        occupied_group_ids.add(item.group_id)
        if item.bit_allocation == "appended":
            occupied_bit_ids.add(item.decode_bit_id)
            if item.decode_bit_token in occupied_bit_tokens:
                raise GenerationError(
                    f"prior bit token collides: {item.decode_bit_token}"
                )
            occupied_bit_tokens.add(item.decode_bit_token)
        occupied_tokens.add(item.macro_token)
        retained[item.isa_set] = item

    next_group = max(occupied_group_ids) + 1
    next_bit = max(occupied_bit_ids) + 1
    # Version-1 catalogs briefly reused same-spelled legacy umbrella bits for
    # newly appended exact CET and SSE4 groups. Promote such rows at the end
    # without renumbering any already appended assignment: an SSE4a-only CPU
    # must not thereby admit Intel SSE4.1, and CET subsets remain independent.
    for isa_set, item in sorted(
        retained.items(), key=lambda pair: pair[1].group_id
    ):
        if item.bit_allocation == "appended":
            continue
        preferred = item.macro_token
        bit_token = preferred
        if bit_token in occupied_bit_tokens:
            bit_token += "_ISA_SET"
        if bit_token in occupied_bit_tokens:
            raise GenerationError(f"cannot allocate exact bit token for {isa_set}")
        retained[isa_set] = PriorAllocation(
            item.isa_set,
            item.macro_token,
            item.group_id,
            bit_token,
            next_bit,
            "appended",
        )
        occupied_bit_tokens.add(bit_token)
        occupied_bit_ids.add(next_bit)
        next_bit += 1
    entries: list[IsaSetEntry] = []
    for xed_index, (isa_set, record_count) in enumerate(source):
        token = normalize_token(isa_set)
        canonical_group = token
        if token in groups:
            group_id = groups[token]
            group_allocation = "existing"
        elif token in aliases:
            canonical_group = aliases[token]
            group_id = groups[canonical_group]
            group_allocation = "existing_alias"
        elif isa_set in retained:
            allocation = retained[isa_set]
            token = allocation.macro_token
            canonical_group = token
            group_id = allocation.group_id
            group_allocation = "appended"
        else:
            if token in occupied_tokens:
                digest = hashlib.sha256(isa_set.encode("ascii")).hexdigest()[:8].upper()
                token = f"{token}_ISA_SET_{digest}"
            allocated_bit_token = token
            if allocated_bit_token in occupied_bit_tokens:
                allocated_bit_token += "_ISA_SET"
            if allocated_bit_token in occupied_bit_tokens:
                raise GenerationError(
                    f"cannot allocate exact bit token for {isa_set}"
                )
            allocated_bit_id = next_bit
            allocated_bit_kind = "appended"
            occupied_bit_tokens.add(allocated_bit_token)
            occupied_bit_ids.add(next_bit)
            next_bit += 1
            allocation = PriorAllocation(
                isa_set,
                token,
                next_group,
                allocated_bit_token,
                allocated_bit_id,
                allocated_bit_kind,
            )
            retained[isa_set] = allocation
            occupied_tokens.add(token)
            occupied_group_ids.add(next_group)
            canonical_group = token
            group_id = next_group
            group_allocation = "appended"
            next_group += 1

        if group_allocation == "appended":
            bit_id = retained[isa_set].decode_bit_id
            bit_token = retained[isa_set].decode_bit_token
            bit_allocation = retained[isa_set].bit_allocation
        else:
            bit_token = GROUP_TO_BIT_TOKEN.get(canonical_group, "NONE")
            if bit_token == "NONE":
                bit_id = NO_BIT
                bit_allocation = "base"
            else:
                if bit_token not in bits:
                    raise GenerationError(
                        f"group {canonical_group} maps to unknown bit {bit_token}"
                    )
                bit_id = bits[bit_token]
                bit_allocation = "existing"
        entries.append(
            IsaSetEntry(
                xed_index=xed_index,
                isa_set=isa_set,
                macro_token=token,
                group_token=canonical_group,
                group_id=group_id,
                group_allocation=group_allocation,
                decode_bit_token=bit_token,
                decode_bit_id=bit_id,
                bit_allocation=bit_allocation,
                record_count=record_count,
            )
        )

    if next_bit > BIT_CAPACITY:
        raise GenerationError(
            f"x86 decode-bit catalog needs {next_bit} bits, capacity is {BIT_CAPACITY}"
        )
    if len(entries) != EXPECTED_ISA_SET_COUNT:
        raise GenerationError("ISA_SET mapping is not exhaustive")
    if len({entry.isa_set for entry in entries}) != len(entries):
        raise GenerationError("ISA_SET mapping contains duplicates")
    if len({entry.group_id for entry in entries}) != len(entries):
        raise GenerationError("exact ISA_SET group IDs are not one-to-one")
    return entries, sorted(retained.values(), key=lambda value: value.group_id)


def render_group_include(allocations: list[PriorAllocation]) -> str:
    if not allocations:
        raise GenerationError("no appended x86 ISA_SET group IDs")
    lines = [
        "/* Generated by tools/isa_codegen/generate_x86_isa_set_catalog.py.",
        " * Exact pinned-XED ISA_SET identities not already public. */",
    ]
    for item in allocations:
        lines.append(
            f"#define CDISASM_X86_GROUP_{item.macro_token} "
            f"UINT16_C({item.group_id})"
        )
    final = allocations[-1]
    lines.extend(
        [
            f"#define CDISASM_X86_GROUP_LAST CDISASM_X86_GROUP_{final.macro_token}",
            f"#define CDISASM_X86_GROUP_COUNT UINT16_C({final.group_id + 1})",
            "",
        ]
    )
    return "\n".join(lines)


def render_bit_include(allocations: list[PriorAllocation]) -> str:
    bit_allocations = [
        item for item in allocations if item.bit_allocation == "appended"
    ]
    if not bit_allocations:
        raise GenerationError("no appended x86 ISA_SET decode bits")
    lines = [
        "/* Generated by tools/isa_codegen/generate_x86_isa_set_catalog.py.",
        " * Logical IDs address cdisasm_decode_flags.bitmap[bit / 64]. */",
    ]
    for item in sorted(bit_allocations, key=lambda value: value.decode_bit_id):
        lines.append(
            f"#define CDISASM_X86_DECODE_BIT_{item.decode_bit_token} "
            f"UINT32_C({item.decode_bit_id})"
        )
    final = max(bit_allocations, key=lambda value: value.decode_bit_id)
    bit_count = final.decode_bit_id + 1
    lines.extend(
        [
            f"#define CDISASM_X86_DECODE_BIT_LAST "
            f"CDISASM_X86_DECODE_BIT_{final.decode_bit_token}",
            f"#define CDISASM_X86_DECODE_BIT_COUNT UINT32_C({bit_count})",
            "",
        ]
    )
    for bitmap_index in range(1, 8):
        first = bitmap_index * 64
        used = max(0, min(64, bit_count - first))
        mask = 0 if used == 0 else (1 << used) - 1
        lines.append(
            f"#define CDISASM_X86_DECODE_FLAG_KNOWN_MASK_{bitmap_index} "
            f"UINT64_C(0x{mask:016x})"
        )
    lines.append("")
    return "\n".join(lines)


def render_catalog_tsv(entries: list[IsaSetEntry]) -> str:
    output = io.StringIO(newline="")
    fields = [
        "xed_index",
        "isa_set",
        "macro_token",
        "group_token",
        "group_id",
        "group_allocation",
        "decode_bit_token",
        "decode_bit_id",
        "decode_bitmap_index",
        "decode_bitmap_mask",
        "bit_allocation",
        "record_count",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, dialect="excel-tab")
    writer.writeheader()
    for entry in entries:
        has_bit = entry.decode_bit_id != NO_BIT
        writer.writerow(
            {
                "xed_index": entry.xed_index,
                "isa_set": entry.isa_set,
                "macro_token": entry.macro_token,
                "group_token": entry.group_token,
                "group_id": entry.group_id,
                "group_allocation": entry.group_allocation,
                "decode_bit_token": entry.decode_bit_token,
                "decode_bit_id": entry.decode_bit_id if has_bit else "none",
                "decode_bitmap_index": entry.decode_bit_id // 64 if has_bit else "none",
                "decode_bitmap_mask": (
                    f"0x{1 << (entry.decode_bit_id % 64):016x}" if has_bit else "0x0000000000000000"
                ),
                "bit_allocation": entry.bit_allocation,
                "record_count": entry.record_count,
            }
        )
    return output.getvalue()


def read_iclass_ids(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    with path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, dialect="excel-tab"):
            result[row["iclass"]] = int(row["name_id"])
    return result


def render_descriptor_outputs(
    descriptor_path: Path,
    entries: list[IsaSetEntry],
    iclass_path: Path,
) -> tuple[str, str, int]:
    by_set = {entry.isa_set: entry for entry in entries}
    iclass_ids = read_iclass_ids(iclass_path)
    output = io.StringIO(newline="")
    fields = [
        "descriptor_index",
        "iform_id",
        "name_id",
        "group_id",
        "decode_bit_id",
        "decode_bitmap_index",
        "decode_bitmap_mask",
        "iclass",
        "isa_set",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, dialect="excel-tab")
    writer.writeheader()
    include_lines = [
        "/* Generated numeric descriptor metadata. The includer defines",
        " * CDISASM_X86_DESCRIPTOR_FAMILY(index, name_id, group_id, bit_id). */",
    ]
    seen: set[int] = set()
    count = 0
    with descriptor_path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, dialect="excel-tab"):
            index = int(row["descriptor_index"])
            if index in seen:
                raise GenerationError(f"duplicate descriptor index {index}")
            seen.add(index)
            isa_set = row["isa_set"]
            iclass = row["iclass"]
            if isa_set not in by_set:
                raise GenerationError(f"descriptor has unknown ISA_SET {isa_set}")
            if iclass not in iclass_ids:
                raise GenerationError(f"descriptor has unknown ICLASS {iclass}")
            name_id = iclass_ids[iclass]
            if "iclass_id" in row and row["iclass_id"] and int(row["iclass_id"]) != name_id:
                raise GenerationError(f"descriptor {index} has stale ICLASS ID")
            entry = by_set[isa_set]
            has_bit = entry.decode_bit_id != NO_BIT
            writer.writerow(
                {
                    "descriptor_index": index,
                    "iform_id": row["iform_id"],
                    "name_id": name_id,
                    "group_id": entry.group_id,
                    "decode_bit_id": entry.decode_bit_id if has_bit else "none",
                    "decode_bitmap_index": entry.decode_bit_id // 64 if has_bit else "none",
                    "decode_bitmap_mask": (
                        f"0x{1 << (entry.decode_bit_id % 64):016x}"
                        if has_bit
                        else "0x0000000000000000"
                    ),
                    "iclass": iclass,
                    "isa_set": isa_set,
                }
            )
            bit_expression = (
                f"UINT32_C({entry.decode_bit_id})"
                if has_bit
                else "CDISASM_X86_DECODE_BIT_NONE"
            )
            include_lines.append(
                "CDISASM_X86_DESCRIPTOR_FAMILY("
                f"{index}, {name_id}, {entry.group_id}, {bit_expression})"
            )
            count += 1
    if seen != set(range(count)):
        raise GenerationError("descriptor indices are not contiguous from zero")
    include_lines.append("")
    return output.getvalue(), "\n".join(include_lines), count


def write_or_check(path: Path, content: str, check: bool) -> None:
    encoded = content.encode("utf-8")
    if check:
        if not path.is_file() or path.read_bytes() != encoded:
            raise GenerationError(f"generated artifact is stale: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)


def main(argv: list[str]) -> int:
    repo = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--xed-db", required=True, type=Path)
    parser.add_argument(
        "--ids-header", type=Path, default=repo / "include/cdisasm/cdisasm_x86_ids.h"
    )
    parser.add_argument(
        "--x86-header", type=Path, default=repo / "include/cdisasm/cdisasm_x86.h"
    )
    parser.add_argument(
        "--iclass-catalog",
        type=Path,
        default=repo / "tools/isa_codegen/generated/x86_iclass_catalog.tsv",
    )
    parser.add_argument(
        "--descriptors",
        type=Path,
        default=repo / "tools/isa_codegen/generated/x86_descriptors.tsv",
    )
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    actual_xed_hash = sha256_file(args.xed_db)
    if actual_xed_hash != EXPECTED_XED_SHA256:
        raise GenerationError(
            f"XED JSON hash mismatch: expected {EXPECTED_XED_SHA256}, "
            f"got {actual_xed_hash}"
        )

    catalog_path = repo / "tools/isa_codegen/generated/x86_isa_sets.tsv"
    prior = read_prior(catalog_path)
    source, record_count = read_xed_sets(args.xed_db)
    groups, aliases = parse_manual_groups(args.ids_header)
    bits = parse_manual_bits(args.x86_header)
    entries, allocations = allocate(source, groups, aliases, bits, prior)
    descriptor_tsv, descriptor_inc, descriptor_count = render_descriptor_outputs(
        args.descriptors, entries, args.iclass_catalog
    )
    appended_bits = sorted(
        item.decode_bit_id
        for item in allocations
        if item.bit_allocation == "appended"
    )
    if appended_bits != list(range(max(bits.values()) + 1, max(appended_bits) + 1)):
        raise GenerationError("appended x86 decode-bit IDs are not contiguous")

    outputs = {
        repo / "include/cdisasm/cdisasm_x86_isa_set_ids.inc": render_group_include(allocations),
        repo / "include/cdisasm/cdisasm_x86_isa_set_bits.inc": render_bit_include(allocations),
        catalog_path: render_catalog_tsv(entries),
        repo / "tools/isa_codegen/generated/x86_descriptor_families.tsv": descriptor_tsv,
        repo / "src/x86/generated/cdisasm_x86_descriptor_families.inc": descriptor_inc,
    }
    manifest = {
        "generator": "tools/isa_codegen/generate_x86_isa_set_catalog.py",
        "generator_version": GENERATOR_VERSION,
        "xed_db_sha256": actual_xed_hash,
        "xed_version": EXPECTED_XED_VERSION,
        "xed_record_count": record_count,
        "isa_set_count": len(entries),
        "normalization_change_count": sum(
            entry.isa_set != entry.macro_token for entry in entries
        ),
        "macro_collision_count": sum("_ISA_SET_" in item.macro_token for item in allocations),
        "existing_direct_group_count": sum(
            entry.group_allocation == "existing" for entry in entries
        ),
        "existing_alias_group_count": sum(
            entry.group_allocation == "existing_alias" for entry in entries
        ),
        "existing_group_count": sum(
            entry.group_allocation != "appended" for entry in entries
        ),
        "appended_group_count": sum(
            entry.group_allocation == "appended" for entry in entries
        ),
        "group_count": max(item.group_id for item in allocations) + 1,
        "existing_or_base_bit_set_count": sum(
            entry.bit_allocation != "appended" for entry in entries
        ),
        "existing_bit_set_count": sum(
            entry.bit_allocation == "existing" for entry in entries
        ),
        "base_no_bit_set_count": sum(
            entry.bit_allocation == "base" for entry in entries
        ),
        "appended_bit_count": len(appended_bits),
        "decode_bit_count": max(appended_bits) + 1,
        "decode_bit_capacity": BIT_CAPACITY,
        "descriptor_count": descriptor_count,
        "no_bit_sentinel": NO_BIT,
    }
    outputs[
        repo / "tools/isa_codegen/generated/x86_isa_set_catalog.json"
    ] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    for path, content in outputs.items():
        write_or_check(path, content, args.check)
    print(
        f"x86 ISA_SET catalog: {len(entries)} sets, "
        f"{manifest['existing_group_count']} existing groups, "
        f"{manifest['appended_group_count']} appended groups, "
        f"{manifest['decode_bit_count']} logical bits, "
        f"{descriptor_count} descriptors"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
