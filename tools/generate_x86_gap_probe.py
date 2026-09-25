#!/usr/bin/env python3
"""Generate conservative catalog-gap probes for XED forms without witnesses.

This is a development helper. It chooses one legal mode and a register or
simple [rax] encoding per descriptor, then leaves text columns as ``@``
(wildcard). The corpus runner can therefore validate decode ownership without
hand-writing thousands of formatter strings.  An optional pinned-XED pass
proves exact IFORM/length ownership and can emit a conservative explicit
operand/access sidecar for the companion contract test.
"""
from __future__ import annotations

import csv
import concurrent.futures
import re
import subprocess
import sys
import argparse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DESC = ROOT / "tools" / "isa_codegen" / "generated" / "x86_descriptors.tsv"
FORMS = ROOT / "tools" / "coverage" / "generated" / "x86_forms.tsv"

IMM = {
    "IMM8()": 1, "SIMM8()": 1, "SE_IMM8()": 1, "UIMM8()": 1,
    "UIMM8_1()": 1, "UIMM16()": 2, "UIMM32()": 4,
    "BRDISP8()": 1, "BRDISP32()": 4, "BRDISPz()": 4,
}

def first_int(pattern: str, key: str, default: int | None = None) -> int | None:
    m = re.search(rf"\b{re.escape(key)}=(\d+)", pattern)
    return int(m.group(1)) if m else default

def list_int(row: dict[str, str], key: str, default: int) -> int:
    text = row.get(key, "")
    if not text:
        return default
    return int(text.split(",")[0])

def pattern_int(pattern: str, field: str, default: int) -> int:
    match = re.search(rf"\b{field}\[0b([01]+)\]", pattern)
    return int(match.group(1), 2) if match else default

def modes(row: dict[str, str]) -> set[int]:
    return {int(x) for x in row.get("mode", "").split(",") if x}

def choose_mode(row: dict[str, str]) -> int | None:
    available = modes(row)
    if not available:
        return None
    pattern = row.get("pattern", "")
    if "MODE=2" in pattern:
        return 64 if 64 in available else None
    if "MODE!=2" in pattern:
        return 32 if 32 in available else min(available)
    if "EASZ=1" in pattern and 16 in available:
        return 16
    return 64 if 64 in available else max(available)

def immediate_size(token: str, pp: int) -> int | None:
    """Return the encoded size for a recipe in the selected EVEX form.

    XED's SIMMz is operand-size dependent.  For EVEX/APX rows a semantic
    66 prefix selects a 16-bit immediate; the unprefixed and W forms use a
    sign-extended 32-bit immediate.  Treating SIMMz as unconditionally four
    bytes silently adds padding to every 66-prefixed APX-F SCC witness.
    """
    if token == "SIMMz()":
        return 2 if pp == 1 else 4
    return IMM.get(token)

def _legacy_map_prefix(map_id: int) -> list[int] | None:
    return {0: [], 1: [0x0f], 2: [0x0f, 0x38], 3: [0x0f, 0x3a]}.get(map_id)

def _modrm_bytes(row: dict[str, str], pattern: str) -> list[int] | None:
    if row.get("has_modrm", "") != "True":
        return []
    mod_text = row.get("mod_required", "")
    if mod_text == "3" or "MOD=3" in pattern:
        mod = 3
    elif mod_text:
        mod = int(mod_text.split(",")[0])
    else:
        mod = 0
    default_reg = 1 if "GATHER" in row.get("iform", "").upper() else 0
    reg = list_int(row, "reg_required", pattern_int(pattern, "REG", default_reg))
    rm = list_int(row, "rm_required", pattern_int(pattern, "RM", 0))
    if mod == 0 and rm in (4, 5) and not row.get("rm_required", ""):
        rm = 0
    result = [(mod << 6) | (reg << 3) | rm]
    if mod != 3 and rm == 4:
        # Gather/scatter memory operands use a vector-index SIB (VSIB), not
        # the ordinary integer SIB index. Keep the destination and index
        # distinct so upstream validators do not reject the witness as a
        # destructive register overlap.
        sib_index = 2 if "GATHER" in row.get("iform", "").upper() else 0
        result.append(sib_index << 3)
    return result

def _recipe_immediates(pattern: str, mode: int, pp: int) -> list[int]:
    result: list[int] = []
    for token in re.findall(r"\b[A-Za-z][A-Za-z0-9_]*\(\)", pattern):
        size = immediate_size(token, pp)
        if token == "BRDISPz()":
            size = 2 if mode == 16 else 4
        if size is not None:
            result.extend(b"\0" * size)
    return result

def _candidate_evex(row: dict[str, str]) -> bytes | None:
    if row.get("encoding_space") != "evex" or choose_mode(row) != 64:
        return None
    pattern = row.get("pattern", "")
    map_id = int(row.get("map", "0"))
    opcode = int(row.get("opcode_hex", "0"), 16)
    pp = int(row.get("evex_pp", "0") or 0)
    pp_encoded = {0: 0, 1: 1, 2: 3, 3: 2}[pp]
    w = int(row.get("rexw", "0") or 0)
    u = int(row.get("u_bit", "") or first_int(pattern, "UBIT", 1) or 1)
    # XED's FP16 complex/scalar families use the raw EVEX U bit as an
    # addressing discriminator: memory forms encode U=0 (the decoder
    # canonicalizes this to UBIT=1), while register forms keep U=1.  The
    # descriptor table intentionally stores the canonical predicate, so the
    # witness recipe must recover the raw encoding here.
    iform_upper = row.get("iform", "").upper()
    # Complex FP16 forms carry a NO_SRC_DEST_MATCH constraint that is not
    # represented by a fixed ModRM field.  Keep this predicate narrow to the
    # CPH/CSH families; ordinary FP16 round/classify instructions use the
    # generic EVEX recipe below.
    fp16 = "CPH" in iform_upper or "CSH" in iform_upper
    if fp16 and "MOD!=3" in pattern:
        u = 0
    vl = int(row.get("vl", "") or first_int(pattern, "VL", 0) or 0)
    ll = {0: 0, 128: 0, 256: 1, 512: 2}.get(vl, 0)
    p0 = 0xF0 | map_id
    p1 = (w << 7) | (0x78) | (u << 2) | pp_encoded
    p2 = (ll << 5) | 0x08  # VEXDEST4=0, V'=1
    if fp16:
        # FP16 forms select the high source-register bank with V'=0.  Leaving
        # the generic V'=1 default in place produces XED BAD_REG_MATCH even
        # though the opcode and ModRM fields are otherwise correct.
        p2 &= ~0x08
    if "POP2P" in iform_upper or "PUSH2P" in iform_upper:
        # APX push/pop pair forms reserve EVEX.V' (P2[3]); setting the generic
        # V'=1 value makes XED reject the otherwise valid NDD witness.
        p2 &= ~0x08
    bcrc = first_int(pattern, "BCRC", 0)
    if bcrc:
        p2 |= 0x10
    # Native APX NDD encodings reuse P2[4] as the ND selector (the same bit
    # is BCRC for ordinary EVEX rows).  Without this bit POP2/PUSH2 and the
    # three-operand APX rows are structurally indistinguishable from their
    # two-operand spellings.
    nd = first_int(pattern, "ND", 0)
    if nd:
        p2 |= 0x10
    zeroing = first_int(pattern, "ZEROING", 0)
    if zeroing:
        p2 |= 0x80
    nf = first_int(pattern, "NF", 0)
    if nf:
        p2 |= 0x04
    # APX SCC and MASK share the low p2 bits in the XED patterns.
    scc = first_int(pattern, "SCC", None)
    mask = first_int(pattern, "MASK", None)
    if scc is not None:
        p2 = (p2 & ~0x0F) | scc
    elif mask is not None:
        p2 = (p2 & ~0x07) | mask
    elif "MASK" in row.get("iform", ""):
        p2 = (p2 & ~0x07) | 1
    v4 = first_int(pattern, "VEXDEST4", 0)
    if v4:
        p2 &= ~0x08
    has_modrm = row.get("has_modrm", "") == "True"
    out = bytearray((0x62, p0, p1, p2, opcode))
    if has_modrm:
        mod_text = row.get("mod_required", "")
        if mod_text == "3":
            mod = 3
        elif mod_text:
            mod = int(mod_text.split(",")[0])
        elif "MOD=3" in pattern:
            mod = 3
        else:
            mod = 0
        default_reg = 1 if "GATHER" in row.get("iform", "").upper() else 0
        reg = list_int(row, "reg_required", pattern_int(pattern, "REG", default_reg))
        rm = list_int(row, "rm_required", pattern_int(pattern, "RM", 0))
        if fp16 and mod == 3 and not row.get("rm_required", ""):
            # Register-register complex forms reject destructive source /
            # destination overlap.  ModRM.rm=1 gives XMM/YMM/ZMM1 while the
            # destination remains register 0.
            rm = 1
        # Avoid the no-base/SIB encodings for a simple memory witness.
        if mod == 0 and rm in (4, 5) and not row.get("rm_required", ""):
            rm = 0
        out.append((mod << 6) | (reg << 3) | rm)
        if mod != 3 and rm == 4:
            # SIB base/index 0; VSIB gathers use the vector index selected by
            # the EVEX.vvvv field and still require the SIB byte structurally.
            sib_index = 2 if "GATHER" in row.get("iform", "").upper() else 0
            out.append(sib_index << 3)
    out.extend(_recipe_immediates(pattern, 64, pp))
    return bytes(out)

def _candidate_vex(row: dict[str, str]) -> bytes | None:
    if row.get("encoding_space") != "vex" or choose_mode(row) != 64:
        return None
    pattern = row.get("pattern", "")
    map_id = int(row.get("map", "0"))
    opcode = int(row.get("opcode_hex", "0"), 16)
    if _legacy_map_prefix(map_id) is None:
        return None
    pp = int(row.get("evex_pp", "0") or 0)
    pp_encoded = {0: 0, 1: 1, 2: 3, 3: 2}[pp]
    w = int(row.get("rexw", "0") or 0)
    vl = int(row.get("vl", "0") or 0)
    l_bit = 1 if vl == 256 else 0
    out = bytearray((0xc4, 0xe0 | map_id,
                     (w << 7) | 0x78 | (l_bit << 2) | pp_encoded,
                     opcode))
    modrm = _modrm_bytes(row, pattern)
    if modrm is None:
        return None
    out.extend(modrm)
    out.extend(_recipe_immediates(pattern, 64, pp))
    return bytes(out)

def _candidate_legacy(row: dict[str, str]) -> bytes | None:
    if row.get("encoding_space") != "legacy":
        return None
    mode = choose_mode(row)
    if mode is None:
        return None
    pattern = row.get("pattern", "")
    map_id = int(row.get("map", "0"))
    prefix = _legacy_map_prefix(map_id)
    if prefix is None:
        return None
    out = bytearray()
    rep = first_int(pattern, "REP", 0) or 0
    if rep in (2, 3):
        out.append(0xf2 if rep == 2 else 0xf3)
    if "OSZ=1" in pattern or "REFINING66()" in pattern:
        out.append(0x66)
    if "EASZ=1" in pattern and mode != 16:
        out.append(0x67)
    if first_int(pattern, "REX2", 0) or 0:
        payload = 0x08 if (first_int(pattern, "REXW", 0) or 0) else 0
        out.extend((0xd5, payload))
    elif mode == 64 and (first_int(pattern, "REXW", 0) or 0):
        out.append(0x48)
    out.extend(prefix)
    out.append(int(row.get("opcode_hex", "0"), 16))
    modrm = _modrm_bytes(row, pattern)
    if modrm is None:
        return None
    out.extend(modrm)
    out.extend(_recipe_immediates(pattern, mode, 0))
    return bytes(out)

def candidate(row: dict[str, str]) -> bytes | None:
    encoding = row.get("encoding_space")
    if encoding == "evex":
        return _candidate_evex(row)
    if encoding == "vex":
        return _candidate_vex(row)
    if encoding == "legacy":
        return _candidate_legacy(row)
    return None

def generate_rows() -> tuple[list[str], int, list[tuple[str, int, bytes]]]:
    forms = {}
    with FORMS.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            if row["coverage_status"] == "catalog_only":
                forms[row["iform"]] = row
    rows = []
    witnesses: list[tuple[str, int, bytes]] = []
    with DESC.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            if row["iform"] not in forms:
                continue
            if row["encoding_space"] not in {"legacy", "vex", "evex"}:
                continue
            data = candidate(row)
            if data is None or len(data) > 15:
                continue
            form = forms[row["iform"]]
            selected_mode = choose_mode(row)
            if selected_mode is None:
                continue
            rows.append((row["iform"], form["extension"], selected_mode,
                         data.hex(" ")))
            witnesses.append((row["iform"], selected_mode, data))
            # one descriptor per unique form is enough for the first probe
            forms.pop(row["iform"], None)
    lines = [
        f"gap_probe_{extension.lower()}_{index:05d}\t0x00010000\t{selected_mode}\t0x1000\tEXTRA_OK\t{len(bytes.fromhex(hex_bytes))}\t@\t@\t{hex_bytes}"
        for index, (iform, extension, selected_mode, hex_bytes)
        in enumerate(rows)
    ]
    return lines, len(forms), witnesses


def _decode_with_xed(
    xed_dec: Path,
    mode: int,
    encoded: bytes,
    xed_format: Path | None = None,
) -> dict[str, object]:
    """Decode one witness with the pinned XED command-line oracle."""
    command = [str(xed_dec)]
    if mode in (16, 64):
        command.append(f"-{mode}")
    elif mode != 32:
        return {
            "decoded": False,
            "diagnostic": f"unsupported mode {mode}",
        }
    command.append(encoded.hex())
    try:
        process = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return {"decoded": False, "diagnostic": "xed-dec timeout"}
    except OSError as error:
        return {"decoded": False, "diagnostic": str(error)}
    output = process.stdout
    iform_match = re.search(r"(?m)^iform-enum-name\s+(\S+)", output)
    length_match = re.search(r"(?m)^instruction-length\s+(\d+)", output)
    result: dict[str, object] = {
        "decoded": iform_match is not None and length_match is not None,
        "iform": iform_match.group(1) if iform_match else "",
        "length": int(length_match.group(1)) if length_match else -1,
        "return_code": process.returncode,
    }
    if result["decoded"]:
        result["operands"] = _parse_xed_explicit_operands(
            str(result["iform"]), output)
        if xed_format is not None:
            format_command = [str(xed_format)]
            if mode in (16, 64):
                format_command.append(f"-{mode}")
            format_command.extend(("-I", "-j", "-d", encoded.hex()))
            try:
                format_process = subprocess.run(
                    format_command,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=5,
                )
            except subprocess.TimeoutExpired:
                result["format_diagnostic"] = "xed formatter timeout"
            except OSError as error:
                result["format_diagnostic"] = str(error)
            else:
                short_match = re.search(
                    r"(?m)^SHORT:\s*(.+?)\s*$", format_process.stdout)
                if short_match is not None and format_process.returncode == 0:
                    result["short"] = _normalize_xed_short(
                        str(result["iform"]), short_match.group(1))
                else:
                    result["format_diagnostic"] = (
                        " ".join(format_process.stdout.strip().split())[:240])
    if not result["decoded"]:
        result["diagnostic"] = " ".join(output.strip().split())[:240]
    return result


def _parse_xed_explicit_operands(iform: str, output: str) -> str | None:
    """Return a compact explicit operand contract from xed-dec output.

    XED prints suppressed architectural state (for example STACKPOP and
    implicit flags) alongside user-visible operands.  The cdisasm public
    operand array intentionally exposes only explicit operands, so this
    sidecar records each explicit operand's broad kind and read/write access:
    ``R3`` (register, read/write), ``M1`` (memory, read) or ``I2`` (immediate,
    write).  The comparison is deliberately independent of register-number
    spelling while still catching operand loss, reordering and access errors.
    """
    # These families expose architectural state through dedicated cdisasm
    # metadata (VSIB index state, branch targets, or far pointers), rather
    # than ordinary opcode[] entries. Mask registers are handled below as
    # decorators and are intentionally omitted from the public opcode array.
    upper_iform = iform.upper()
    string_form = upper_iform.startswith(("REP_", "REPE_", "REPNE_"))
    in_operands = False
    result: list[str] = []
    for line in output.splitlines():
        if line.startswith("Operands"):
            in_operands = True
            continue
        if line.startswith("Memory Operands"):
            break
        if not in_operands:
            continue
        fields = line.split()
        if len(fields) < 4 or not fields[0].isdigit():
            continue
        visibility_index = next(
            (index for index, field in enumerate(fields)
             if field in ("EXPLICIT", "SUPPRESSED")), None)
        if visibility_index is None:
            continue
        visibility = fields[visibility_index]
        xed_type = fields[1].upper()
        if visibility != "EXPLICIT":
            if not string_form:
                continue
            # String instructions expose their architectural source/dest
            # memory operands as suppressed XED operands.  The public ABI
            # intentionally keeps those memory operands, and keeps only the
            # accumulator register (not the implicit count/index registers).
            if xed_type.startswith("REG"):
                details = " ".join(fields[2:visibility_index]).upper()
                if not re.search(r"REG\d+=([RE]AX|AX|AL)\b", details):
                    continue
            elif not xed_type.startswith("MEM"):
                continue
        if any(field.upper() == "MASK" for field in fields):
            continue
        if xed_type.startswith("REG"):
            kind = "R"
        elif xed_type.startswith(("MEM", "AGEN")):
            kind = "M"
        elif xed_type.startswith(("IMM", "RELBR", "ABSBR", "PTR")):
            kind = "I"
        else:
            raise RuntimeError(
                f"unsupported explicit XED operand type {fields[1]!r}")
        rw = fields[visibility_index + 1].upper()
        access = 0
        if "R" in rw and "W" not in rw:
            access |= 1
        if "W" in rw:
            access |= 2
        if access == 0:
            raise RuntimeError(
                f"XED explicit operand has no access mode: {line.strip()}")
        result.append(f"{kind}{access}")
    return ",".join(result)


def _formatter_comparable(iform: str) -> bool:
    """Whether the pinned Intel spelling is comparable without aliases.

    The public formatter has a canonical spelling contract for all currently
    generated x86 witnesses.  Family-specific alias normalization is applied
    by ``_normalize_xed_short`` before comparison.
    """
    return True


def _normalize_xed_short(iform: str, short: str) -> str:
    """Normalize XED's REP alias spelling to cdisasm's canonical mnemonic."""
    upper_iform = iform.upper()
    branch_aliases = {
        "JNB_RELBRD": "jae",
        "JZ_RELBRD": "je",
        "JNZ_RELBRD": "jne",
        "JNBE_RELBRD": "ja",
        "JNL_RELBRD": "jge",
        "JNLE_RELBRD": "jg",
    }
    alias = branch_aliases.get(upper_iform)
    if alias is not None:
        separator = short.find(" ")
        return alias + (short[separator:] if separator >= 0 else "")
    # The native x87 table intentionally retains the architectural FN* IDs
    # for these undocumented 8087/287 encodings.  XED exposes the more
    # descriptive catalog-only IFORM names; compare their text using the
    # library's canonical spellings rather than treating the alias as a gap.
    legacy_aliases = {
        "FDISI8087_NOP": "fndisi",
        "FENI8087_NOP": "fneni",
        "FSETPM287_NOP": "fnsetpm",
    }
    alias = legacy_aliases.get(upper_iform)
    if alias is not None:
        separator = short.find(" ")
        return alias + (short[separator:] if separator >= 0 else "")
    if upper_iform == "IBHF":
        return "ibhf"
    if upper_iform.startswith("REPE_") and short.startswith("rep "):
        return "repe " + short[4:]
    if upper_iform.startswith("REPNE_") and short.startswith("rep "):
        return "repne " + short[4:]
    if "GATHER" in upper_iform or "SCATTER" in upper_iform:
        # XED exposes the EVEX mask as a separate operand.  cdisasm models it
        # as the destination/memory decorator, which is the public x86 ABI
        # spelling used by the checked-in corpus.
        first_comma = short.find(", ")
        if first_comma >= 0:
            head = short[:first_comma]
            remainder = short[first_comma + 2:]
            mask_comma = remainder.find(", ")
            if (mask_comma >= 0 and remainder.startswith("k")
                    and remainder[1:2].isdigit()):
                mask = remainder[:mask_comma]
                tail = remainder[mask_comma + 2:]
                return f"{head}{{{mask}}}, {tail}"
            if ("PF" in upper_iform and remainder.startswith("k")):
                return f"{head}{{{remainder}}}"
    return short


def verify_xed(
    xed_dec: Path,
    witnesses: list[tuple[str, int, bytes]],
    jobs: int,
    operand_output: Path | None = None,
    xed_format: Path | None = None,
    format_output: Path | None = None,
) -> dict[tuple[str, int, bytes], dict[str, object]]:
    """Require every generated witness to decode to its intended IFORM."""
    if not xed_dec.is_file():
        raise RuntimeError(f"XED decoder does not exist: {xed_dec}")
    if xed_format is not None and not xed_format.is_file():
        raise RuntimeError(f"XED formatter does not exist: {xed_format}")
    failures: list[str] = []
    verified: dict[tuple[str, int, bytes], dict[str, object]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as executor:
        futures = {
            executor.submit(
                _decode_with_xed, xed_dec, mode, encoded, xed_format):
            (iform, mode, encoded)
            for iform, mode, encoded in witnesses
        }
        for future in concurrent.futures.as_completed(futures):
            iform, mode, encoded = futures[future]
            result = future.result()
            if result.get("decoded"):
                verified[(iform, mode, encoded)] = result
            if not result.get("decoded"):
                failures.append(
                    f"{iform} mode={mode} bytes={encoded.hex()}: "
                    f"XED rejected ({result.get('diagnostic', '')})")
                continue
            if result.get("iform") != iform:
                failures.append(
                    f"{iform} mode={mode} bytes={encoded.hex()}: "
                    f"XED selected {result.get('iform')}")
                continue
            if result.get("length") != len(encoded):
                failures.append(
                    f"{iform} mode={mode} bytes={encoded.hex()}: "
                    f"XED length {result.get('length')} != {len(encoded)}")
    if failures:
        preview = "\n".join(failures[:20])
        more = len(failures) - min(20, len(failures))
        if more:
            preview += f"\n... and {more} more failure(s)"
        raise RuntimeError(preview)
    if operand_output is not None:
        operand_output.parent.mkdir(parents=True, exist_ok=True)
        lines = ["# iform\tmode\thex_bytes\texplicit_operands"]
        deferred = 0
        for witness in witnesses:
            result = verified[witness]
            operands = result.get("operands")
            if operands is None:
                operands = "-"
                deferred += 1
            lines.append(
                f"{witness[0]}\t{witness[1]}\t{witness[2].hex()}\t"
                f"{operands}")
        operand_output.write_text(
            "\n".join(lines) + "\n", encoding="ascii", newline="\n")
        print(
            f"operand contract sidecar: {len(witnesses) - deferred} checked, "
            f"{deferred} deferred", file=sys.stderr)
    if format_output is not None:
        format_output.parent.mkdir(parents=True, exist_ok=True)
        lines = ["# iform\tmode\thex_bytes\tintel"]
        deferred = 0
        for witness in witnesses:
            result = verified[witness]
            # Keep the formatter oracle aligned with the operand contract:
            # masks, VSIB, REP strings, branch targets, EVEX embedded
            # rounding/SAE attachment, and other shapes need family-specific
            # canonicalization before a byte-for-byte text comparison is
            # meaningful.
            short = result.get("short")
            if (short is None
                    or result.get("operands") is None
                    or not _formatter_comparable(witness[0])):
                short = "-"
                deferred += 1
            lines.append(
                f"{witness[0]}\t{witness[1]}\t{witness[2].hex()}\t{short}")
        format_output.write_text(
            "\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        print(
            f"formatter sidecar: {len(witnesses) - deferred} checked, "
            f"{deferred} deferred", file=sys.stderr)
    print(f"xed verified {len(witnesses)} exact IFORM witnesses", file=sys.stderr)
    return verified


def write_evidence_ledger(
    output: Path,
    witnesses: list[tuple[str, int, bytes]],
    verified: dict[tuple[str, int, bytes], dict[str, object]],
    decoder_contract: str,
) -> None:
    """Write a deterministic per-IFORM evidence ledger.

    The ledger keeps evidence axes independent.  A successful XED decode and
    cdisasm corpus check prove byte/decoder ownership for the selected witness;
    they do not silently promote operand semantics or CPU legality.  The
    latter columns therefore remain explicit, machine-readable blockers until
    their dedicated contracts have been checked.
    """
    form_metadata: dict[str, dict[str, str]] = {}
    with FORMS.open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            if row.get("coverage_status") == "catalog_only":
                form_metadata[row["iform"]] = row

    fields = [
        "iform",
        "iclass",
        "category",
        "extension",
        "isa_set",
        "mode",
        "bytes",
        "xed_iform",
        "xed_length",
        "decoder_contract",
        "operand_contract",
        "legality_contract",
        "formatter_contract",
        "evidence_state",
        "blocker",
    ]
    rows: list[dict[str, str]] = []
    for iform, mode, encoded in sorted(witnesses, key=lambda item: item[0]):
        key = (iform, mode, encoded)
        result = verified[key]
        metadata = form_metadata.get(iform, {})
        operand_contract = (
            "exact" if result.get("operands") is not None else "deferred"
        )
        formatter_contract = (
            "exact" if result.get("short") is not None else "deferred"
        )
        rows.append(
            {
                "iform": iform,
                "iclass": metadata.get("iclass", ""),
                "category": metadata.get("category", ""),
                "extension": metadata.get("extension", ""),
                "isa_set": metadata.get("isa_set", ""),
                "mode": str(mode),
                "bytes": encoded.hex(" "),
                "xed_iform": str(result.get("iform", "")),
                "xed_length": str(result.get("length", "")),
                "decoder_contract": decoder_contract,
                "operand_contract": operand_contract,
                # No generated probe exercises malformed-neighbor, feature,
                # privilege, vendor, or CPU-profile legality. Keep that gap
                # visible instead of calling structural acceptance exact.
                "legality_contract": "structural_only",
                "formatter_contract": formatter_contract,
                "evidence_state": "decode_exact",
                "blocker": "cpu_legality_and_semantics_pending",
            }
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=fields,
            dialect="excel-tab",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate and optionally execute data-driven x86 catalog-gap probes")
    parser.add_argument(
        "--output", type=Path,
        help="write the probe corpus to this path instead of stdout")
    parser.add_argument(
        "--check", type=Path,
        help="run the opcode-corpus test executable against the generated corpus")
    parser.add_argument(
        "--xed-dec", type=Path,
        help="independently verify each generated witness with pinned xed-dec")
    parser.add_argument(
        "--xed-format", type=Path,
        help="pinned xed executable used for the optional Intel text oracle")
    parser.add_argument(
        "--jobs", type=int, default=8,
        help="parallel XED workers (default: 8)")
    parser.add_argument(
        "--operand-output", type=Path,
        help="write the XED explicit-operand/access sidecar to this path")
    parser.add_argument(
        "--operand-check", type=Path,
        help="run this executable against --operand-output after XED verification")
    parser.add_argument(
        "--format-output", type=Path,
        help="write the XED Intel formatter sidecar to this path")
    parser.add_argument(
        "--format-check", type=Path,
        help="run this executable against --format-output after XED verification")
    parser.add_argument(
        "--evidence-output", type=Path,
        help="write a deterministic per-IFORM evidence ledger after XED verification")
    args = parser.parse_args()

    lines, unresolved, witnesses = generate_rows()
    text = "\n".join(lines) + ("\n" if lines else "")
    if args.output is None:
        sys.stdout.write(text)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="ascii", newline="\n")
    print(
        f"# generated={len(lines)} unresolved={unresolved}",
        file=sys.stderr)
    check_ran = False
    if unresolved:
        print(
            f"gap probe generation left {unresolved} catalog IFORM(s) without a witness",
            file=sys.stderr)
        return 2
    if args.xed_dec is not None:
        try:
            verified = verify_xed(
                args.xed_dec.resolve(), witnesses, args.jobs,
                args.operand_output.resolve() if args.operand_output else None,
                args.xed_format.resolve() if args.xed_format else None,
                args.format_output.resolve() if args.format_output else None)
        except (OSError, RuntimeError) as error:
            print(f"XED witness verification failed: {error}", file=sys.stderr)
            return 3
        if args.operand_check is not None:
            if args.operand_output is None:
                parser.error("--operand-check requires --operand-output")
            result = subprocess.run(
                [str(args.operand_check), str(args.operand_output)],
                check=False)
            if result.returncode != 0:
                return result.returncode
        if args.format_check is not None:
            if args.format_output is None:
                parser.error("--format-check requires --format-output")
            result = subprocess.run(
                [str(args.format_check), str(args.format_output)],
                check=False)
            if result.returncode != 0:
                return result.returncode
        decoder_contract = "not_checked"
        if args.check is not None:
            if args.output is None:
                parser.error("--check requires --output")
            corpus_result = subprocess.run(
                [str(args.check), str(args.output)], check=False)
            check_ran = True
            if corpus_result.returncode != 0:
                return corpus_result.returncode
            decoder_contract = "exact"
        if args.evidence_output is not None:
            write_evidence_ledger(
                args.evidence_output.resolve(), witnesses, verified,
                decoder_contract)
    elif (args.operand_output is not None or args.operand_check is not None
          or args.xed_format is not None or args.format_output is not None
          or args.format_check is not None or args.evidence_output is not None):
        parser.error("XED sidecars require --xed-dec")
    if args.check is None:
        return 0
    if args.output is None:
        parser.error("--check requires --output")
    if check_ran:
        return 0
    result = subprocess.run([str(args.check), str(args.output)], check=False)
    return result.returncode

if __name__ == "__main__":
    raise SystemExit(main())
