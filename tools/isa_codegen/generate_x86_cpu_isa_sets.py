#!/usr/bin/env python3
"""Generate conservative named-CPU masks for exact x86 ISA_SET bits.

The official pinned XED chip-model file supplies reviewed Intel model sets.
Profiles without an exact XED model use small, explicit set expressions below;
notably AMD and low-end Intel profiles never inherit a marketing ancestor's
AVX/AVX-512 features accidentally.  Bitmap zero remains owned by the existing
hand-written cdisasm CPU capability code.  This generator emits words 1..7.
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


EXPECTED_CHIP_MODELS_SHA256 = (
    "220139cb83757a61dfe81a29ea850ff4db0bb41db83de269dd9418554bba0f4c"
)
CPU_COUNT = 53
MODES = (16, 32, 64)
BITMAP_WORDS = 8


class GenerationError(RuntimeError):
    pass


@dataclass(frozen=True)
class IsaSet:
    name: str
    group_id: int
    bit_id: int | None
    bit_allocation: str


@dataclass(frozen=True)
class ChipExpression:
    parents: tuple[str, ...]
    additions: tuple[str, ...]
    removals: tuple[str, ...]


CPU_NAMES = (
    "X86",
    "8086",
    "80186",
    "80286",
    "80386",
    "80486",
    "80486_CPUID",
    "PENTIUM",
    "PENTIUM_PRO",
    "PENTIUM_MMX",
    "PENTIUM_II",
    "AMD_K6_2",
    "PENTIUM_III",
    "PENTIUM_4",
    "ATHLON_64",
    "PRESCOTT",
    "INTEL_VT_X",
    "AMD_V",
    "CORE_2",
    "PENRYN",
    "AMD_BARCELONA",
    "NEHALEM",
    "WESTMERE",
    "SANDY_BRIDGE",
    "AMD_BULLDOZER",
    "IVY_BRIDGE",
    "HASWELL",
    "BROADWELL",
    "SKYLAKE",
    "GOLDMONT",
    "AMD_ZEN",
    "SKYLAKE_SP",
    "ICE_LAKE",
    "TIGER_LAKE",
    "ALDER_LAKE",
    "AMD_ZEN_4",
    "SAPPHIRE_RAPIDS",
    "AVX10",
    "APX",
    "CELERON_G1840",
    "CELERON_G3900",
    "CELERON_N3350",
    "CELERON_N4020",
    "CELERON_G5900",
    "PENTIUM_SILVER_N6000",
    "8086_8087",
    "80186_80187",
    "80286_80287",
    "80386_80387",
    "GRANITE_RAPIDS",
    "ARROW_LAKE",
    "DIAMOND_RAPIDS",
    "KNIGHTS_MILL",
)


DIRECT_MODELS = {
    1: "I86",
    2: "I186",
    3: "I286",
    4: "I386",
    6: "I486",
    7: "PENTIUM",
    8: "PENTIUMPRO",
    9: "PENTIUMMMX",
    10: "PENTIUM2",
    12: "PENTIUM3",
    13: "PENTIUM4",
    15: "P4PRESCOTT",
    16: "P4PRESCOTT_VTX",
    18: "MEROM",
    19: "PENRYN",
    21: "NEHALEM",
    22: "WESTMERE",
    23: "SANDYBRIDGE",
    25: "IVYBRIDGE",
    26: "HASWELL",
    27: "BROADWELL",
    28: "SKYLAKE",
    29: "GOLDMONT",
    31: "SKYLAKE_SERVER",
    32: "ICE_LAKE",
    33: "TIGER_LAKE",
    34: "ALDER_LAKE",
    36: "SAPPHIRE_RAPIDS",
    45: "I86FP",
    46: "I186FP",
    47: "I2186FP",
    48: "I386FP",
    49: "GRANITE_RAPIDS",
    50: "ARROW_LAKE",
    51: "DIAMOND_RAPIDS",
    52: "KNM",
}


def cpu_modes(ordinal: int) -> set[int]:
    if ordinal == 0 or 14 <= ordinal <= 44 or 49 <= ordinal <= 52:
        return {16, 32, 64}
    if ordinal in {1, 2, 3, 45, 46, 47}:
        return {16}
    return {16, 32}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def read_isa_sets(path: Path) -> dict[str, IsaSet]:
    result: dict[str, IsaSet] = {}
    with path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, dialect="excel-tab"):
            bit_text = row["decode_bit_id"]
            item = IsaSet(
                name=row["isa_set"],
                group_id=int(row["group_id"]),
                bit_id=None if bit_text == "none" else int(bit_text),
                bit_allocation=row["bit_allocation"],
            )
            if item.name in result:
                raise GenerationError(f"duplicate ISA_SET {item.name}")
            result[item.name] = item
    if len(result) != 285:
        raise GenerationError(f"expected 285 ISA_SET rows, got {len(result)}")
    return result


def read_mode_sets(path: Path) -> dict[str, set[int]]:
    result: dict[str, set[int]] = {}
    with path.open("r", encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, dialect="excel-tab"):
            result.setdefault(row["isa_set"], set()).update(
                int(value) for value in row["mode"].split(",") if value
            )
    return result


def parse_chip_expressions(path: Path) -> dict[str, ChipExpression]:
    expressions: dict[str, ChipExpression] = {}
    logical = ""
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        code = raw_line.split("#", 1)[0].strip()
        if not code:
            continue
        logical = (logical + " " + code).strip() if logical else code
        if logical.endswith("\\"):
            logical = logical[:-1].rstrip()
            continue
        if ":" not in logical:
            logical = ""
            continue
        name, body = (part.strip() for part in logical.split(":", 1))
        logical = ""
        if not re.fullmatch(r"[A-Z0-9_]+", name):
            raise GenerationError(f"invalid XED chip name {name!r}")
        parents = tuple(re.findall(r"ALL_OF\(([A-Z0-9_]+)\)", body))
        removals = tuple(re.findall(r"NOT\(([A-Za-z0-9_]+)\)", body))
        remainder = re.sub(r"(?:ALL_OF|NOT)\([A-Za-z0-9_]+\)", " ", body)
        additions = tuple(re.findall(r"[A-Za-z0-9_]+", remainder))
        if name in expressions:
            raise GenerationError(f"duplicate XED chip model {name}")
        expressions[name] = ChipExpression(parents, additions, removals)
    if logical:
        raise GenerationError("unterminated XED chip-model continuation")
    return expressions


def resolve_chips(
    expressions: dict[str, ChipExpression], known_sets: set[str]
) -> dict[str, set[str]]:
    resolved: dict[str, set[str]] = {}
    active: set[str] = set()

    def resolve(name: str) -> set[str]:
        if name in resolved:
            return resolved[name]
        if name in active:
            raise GenerationError(f"cyclic XED chip inheritance at {name}")
        if name not in expressions:
            raise GenerationError(f"unknown inherited XED chip {name}")
        active.add(name)
        expression = expressions[name]
        values: set[str] = set()
        for parent in expression.parents:
            values.update(resolve(parent))
        values.update(value for value in expression.additions if value in known_sets)
        values.difference_update(expression.removals)
        active.remove(name)
        resolved[name] = values
        return values

    for chip_name in expressions:
        resolve(chip_name)
    return resolved


def cpu_header_ordinals(path: Path) -> dict[str, int]:
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(
        r"#define CDISASM_CPU_([A-Z0-9_]+)\s+\\\s*"
        r"\(CDISASM_CPU_GROUP_X86 \| UINT32_C\(0x([0-9a-fA-F]+)\)\)"
    )
    values = {name: int(ordinal, 16) for name, ordinal in pattern.findall(text)}
    for ordinal, name in enumerate(CPU_NAMES):
        if values.get(name) != ordinal:
            raise GenerationError(
                f"CPU profile ABI mismatch for {name}: expected {ordinal}, "
                f"got {values.get(name)}"
            )
    return values


def without(values: set[str], *names: str) -> set[str]:
    result = set(values)
    result.difference_update(names)
    return result


def no_avx(values: set[str]) -> set[str]:
    prefixes = ("AVX", "FMA", "F16C", "XOP", "VAES", "VPCLMUL", "AMX", "APX")
    return {
        value
        for value in values
        if not value.startswith(prefixes) and value != "GFNI"
    }


def build_profiles(chips: dict[str, set[str]], all_sets: set[str]) -> tuple[list[set[str]], list[str]]:
    profiles: list[set[str]] = [set() for _ in range(CPU_COUNT)]
    provenance = ["" for _ in range(CPU_COUNT)]
    profiles[0] = set(all_sets)
    provenance[0] = "unrestricted:pinned-xed-all"
    for ordinal, model in DIRECT_MODELS.items():
        if model not in chips:
            raise GenerationError(f"required XED chip model is missing: {model}")
        profiles[ordinal] = set(chips[model])
        provenance[ordinal] = f"xed-chip:{model}"

    # The generic 80486 profile intentionally predates late-486 CPUID. XED's
    # I486 model combines those encodings, so omit that exact bucket here.
    profiles[5] = without(chips["I486"], "I486REAL")
    provenance[5] = "synthetic:I486-minus-late-486-real"

    profiles[11] = set(chips["PENTIUMMMX"]) | {"3DNOW"}
    provenance[11] = "synthetic:K6-2-conservative"

    athlon64 = set(chips["PENTIUM4"]) | {
        "3DNOW", "LONGMODE", "CMPXCHG16B", "FXSAVE64", "RDTSCP", "PREFETCH_NOP"
    }
    profiles[14] = athlon64
    provenance[14] = "synthetic:Athlon64-conservative"
    profiles[17] = athlon64 | {"SVM", "SSE3", "SSE3X87"}
    provenance[17] = "synthetic:AMD-V-conservative"
    profiles[20] = profiles[17] | {"AMD", "SSE4a", "LZCNT", "POPCNT"}
    provenance[20] = "synthetic:Barcelona-conservative"

    bulldozer = profiles[20] | {
        "SSSE3", "SSSE3MMX", "SSE4", "SSE42", "AVX", "AVXAES", "F16C",
        "FMA4", "LWP", "XOP", "XSAVE", "XSAVEOPT", "RDWRFSGS"
    }
    profiles[24] = bulldozer
    provenance[24] = "synthetic:Bulldozer-conservative"

    zen = without(bulldozer, "FMA4", "LWP", "XOP") | {
        "FMA", "AVX2", "AVX2GATHER", "BMI1", "BMI2", "MOVBE", "ADOX_ADCX",
        "SHA", "RDRAND", "RDSEED", "SMAP", "XSAVEC", "XSAVES",
        "CLFLUSHOPT", "CLZERO"
    }
    profiles[30] = zen
    provenance[30] = "synthetic:Zen-conservative"

    zen4_vector = {
        value
        for value in chips["ICE_LAKE"]
        if value.startswith("AVX512")
        or value in {"AVX_GFNI", "GFNI", "VAES", "VPCLMULQDQ"}
    }
    profiles[35] = zen | zen4_vector | {"CET", "CLWB", "RDPID", "WBNOINVD"}
    provenance[35] = "synthetic:Zen4-reviewed-AVX512-subset"

    avx10_vector = {
        value
        for value in chips["DIAMOND_RAPIDS"]
        if value.startswith("AVX512")
        or value.startswith("AVX10_")
        or value in {"AVX_IFMA", "AVX_NE_CONVERT", "AVX_VNNI_INT8", "AVX_VNNI_INT16"}
    }
    profiles[37] = set(chips["ALDER_LAKE"]) | avx10_vector
    provenance[37] = "synthetic:AVX10.2-no-APX-AMX"
    profiles[38] = profiles[37] | {
        value
        for value in chips["DIAMOND_RAPIDS"]
        if (value.startswith("APX_F") and "AMX" not in value)
        or value == "CMPCCXADD"
    }
    provenance[38] = "synthetic:AVX10.2-plus-APX-no-AMX"

    g1840 = no_avx(chips["HASWELL"])
    profiles[39] = without(
        g1840, "AES", "PCLMULQDQ", "RTM", "BMI1", "BMI2", "LZCNT", "VMFUNC"
    )
    provenance[39] = "synthetic:G1840-no-AVX-product-mask"
    skylake_low = no_avx(chips["SKYLAKE"])
    skylake_low = without(
        skylake_low, "RTM", "BMI1", "BMI2", "LZCNT", "SGX", "MPX", "SHA"
    )
    profiles[40] = skylake_low
    provenance[40] = "synthetic:G3900-no-AVX-product-mask"
    profiles[41] = without(chips["GOLDMONT"], "MPX")
    provenance[41] = "synthetic:N3350-Goldmont-product-mask"
    profiles[42] = without(chips["GOLDMONT_PLUS"], "MPX", "SGX")
    provenance[42] = "synthetic:N4020-GoldmontPlus-product-mask"
    profiles[43] = without(skylake_low | {"PKU"}, "PKU")
    provenance[43] = "synthetic:G5900-no-AVX-product-mask"
    profiles[44] = without(chips["TREMONT"] | {"WAITPKG"}, "GFNI")
    provenance[44] = "synthetic:N6000-Tremont-product-mask"

    if any(not provenance[index] for index in range(CPU_COUNT)):
        missing = [index for index in range(CPU_COUNT) if not provenance[index]]
        raise GenerationError(f"CPU profile set is missing for ordinals {missing}")
    for values in profiles:
        values.intersection_update(all_sets)
    return profiles, provenance


def build_masks(
    profiles: list[set[str]],
    isa_sets: dict[str, IsaSet],
    mode_sets: dict[str, set[int]],
) -> list[list[list[int]]]:
    result: list[list[list[int]]] = []
    for ordinal, profile in enumerate(profiles):
        mode_rows: list[list[int]] = []
        for mode in MODES:
            words = [0] * (BITMAP_WORDS - 1)
            if mode in cpu_modes(ordinal):
                for name in profile:
                    item = isa_sets[name]
                    if item.bit_id is None or item.bit_id < 64 or mode not in mode_sets[name]:
                        continue
                    words[item.bit_id // 64 - 1] |= 1 << (item.bit_id % 64)
            mode_rows.append(words)
        result.append(mode_rows)
    return result


def render_include(masks: list[list[list[int]]], provenance: list[str]) -> str:
    lines = [
        "/* Generated by tools/isa_codegen/generate_x86_cpu_isa_sets.py.",
        " * Words 1..7 only; bitmap 0 remains hand-written CPU metadata. */",
        "static const uint64_t x86_cpu_isa_set_flag_masks",
        "    [CDISASM_CPU_ORDINAL_OF(CDISASM_CPU_LAST) + 1u]",
        "    [3][CDISASM_DECODE_FLAGS_BITMAP_COUNT - 1u] = {",
    ]
    for ordinal, mode_rows in enumerate(masks):
        lines.append(f"    {{ /* {ordinal}: CDISASM_CPU_{CPU_NAMES[ordinal]} ({provenance[ordinal]}) */")
        for mode, words in zip(MODES, mode_rows):
            literals = ", ".join(f"UINT64_C(0x{word:016x})" for word in words)
            lines.append(f"        {{{literals}}}, /* mode {mode} */")
        lines.append("    },")
    lines.extend(["};", ""])
    return "\n".join(lines)


def render_audit_tsv(
    profiles: list[set[str]],
    provenance: list[str],
    isa_sets: dict[str, IsaSet],
    mode_sets: dict[str, set[int]],
) -> str:
    output = io.StringIO(newline="")
    fields = [
        "cpu_ordinal", "cpu_token", "mode", "isa_set", "group_id",
        "decode_bit_id", "supported", "profile_source",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, dialect="excel-tab")
    writer.writeheader()
    appended = sorted(
        (item for item in isa_sets.values() if item.bit_id is not None and item.bit_id >= 64),
        key=lambda item: item.bit_id,
    )
    for ordinal, profile in enumerate(profiles):
        for mode in MODES:
            for item in appended:
                writer.writerow(
                    {
                        "cpu_ordinal": ordinal,
                        "cpu_token": CPU_NAMES[ordinal],
                        "mode": mode,
                        "isa_set": item.name,
                        "group_id": item.group_id,
                        "decode_bit_id": item.bit_id,
                        "supported": int(
                            mode in cpu_modes(ordinal)
                            and item.name in profile
                            and mode in mode_sets[item.name]
                        ),
                        "profile_source": provenance[ordinal],
                    }
                )
    return output.getvalue()


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
    parser.add_argument("--xed-chip-models", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    actual_hash = sha256_file(args.xed_chip_models)
    if actual_hash != EXPECTED_CHIP_MODELS_SHA256:
        raise GenerationError(
            f"XED chip-model hash mismatch: expected {EXPECTED_CHIP_MODELS_SHA256}, got {actual_hash}"
        )
    isa_path = repo / "tools/isa_codegen/generated/x86_isa_sets.tsv"
    descriptor_path = repo / "tools/isa_codegen/generated/x86_descriptors.tsv"
    isa_sets = read_isa_sets(isa_path)
    mode_sets = read_mode_sets(descriptor_path)
    if set(mode_sets) != set(isa_sets):
        raise GenerationError("descriptor mode coverage does not match ISA_SET catalog")
    cpu_header_ordinals(repo / "include/cdisasm/cdisasm_x86.h")
    expressions = parse_chip_expressions(args.xed_chip_models)
    chips = resolve_chips(expressions, set(isa_sets))
    profiles, provenance = build_profiles(chips, set(isa_sets))
    masks = build_masks(profiles, isa_sets, mode_sets)
    include_text = render_include(masks, provenance)
    audit_text = render_audit_tsv(profiles, provenance, isa_sets, mode_sets)
    outputs = {
        repo / "src/x86/generated/cdisasm_x86_cpu_isa_set_masks.inc": include_text,
        repo / "tools/isa_codegen/generated/x86_cpu_isa_set_profiles.tsv": audit_text,
    }
    manifest = {
        "generator": "tools/isa_codegen/generate_x86_cpu_isa_sets.py",
        "generator_version": 1,
        "xed_chip_models_sha256": actual_hash,
        "cpu_profile_count": CPU_COUNT,
        "mode_count": len(MODES),
        "appended_decode_bit_count": sum(
            item.bit_id is not None and item.bit_id >= 64 for item in isa_sets.values()
        ),
        "matrix_row_count": CPU_COUNT * len(MODES) * sum(
            item.bit_id is not None and item.bit_id >= 64 for item in isa_sets.values()
        ),
        "profile_sources": {
            CPU_NAMES[index]: provenance[index] for index in range(CPU_COUNT)
        },
        "supported_appended_bits_by_cpu_mode": {
            f"{CPU_NAMES[cpu]}:{mode}": sum(word.bit_count() for word in masks[cpu][mode_index])
            for cpu in range(CPU_COUNT)
            for mode_index, mode in enumerate(MODES)
        },
    }
    outputs[
        repo / "tools/isa_codegen/generated/x86_cpu_isa_set_profiles.json"
    ] = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    for path, content in outputs.items():
        write_or_check(path, content, args.check)
    print(
        f"x86 CPU ISA_SET masks: {CPU_COUNT} profiles x {len(MODES)} modes, "
        f"{manifest['appended_decode_bit_count']} appended bits"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
