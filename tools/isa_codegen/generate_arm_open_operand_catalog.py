#!/usr/bin/env python3
"""Generate independently checked A64 flat-register operand descriptors.

The open AARCHMRS catalogue identifies canonical instruction leaves and maps
assembly placeholders to encoded fields, but it intentionally does not carry
operand read/write metadata.  This generator joins that grammar with the
operand detail reported by a pinned, BSD-licensed Capstone checkout.  Capstone
is a generation-time oracle only: the emitted decoder table is numeric, small,
and has no Capstone runtime dependency.

Only a deliberately closed grammar subset is accepted here: one to four flat
A32/T32 general-purpose registers or A64 general-purpose/scalar FP registers. Two independent
register assignments must decode to the same AARCHMRS form and must agree with
the grammar and with Capstone's register/access detail.  Register-31 choices
are checked with a third assignment.  Anything outside that proof envelope is
left opaque.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
sys.path.insert(0, str(SCRIPT_DIR))
import generate_arm_tree as arm_tree  # noqa: E402
import generate_arm_assembly_catalog as arm_assembly  # noqa: E402


SCHEMA_VERSION = 1
PINNED_ARM_COMMIT = "47b5446cf08ef6a46c86147c7deb0d56caf99d93"
PINNED_ARM_SHA256 = (
    "0496ca9d55f66fd096c2a7120fafe951763dbd00fa2f006652cbd0547e430602"
)
PINNED_CAPSTONE_COMMIT = "6ef3f4856689e340db794cceec23b155eefb541b"

ORACLE_FIELDS = [
    "form_id",
    "source_form_id",
    "mnemonic",
    "isa",
    "width",
    "witness_a",
    "witness_b",
    "witness_31",
    "operand_access",
    "capstone_real_name",
    "capstone_groups",
]

ACCESS = {"READ": 1, "WRITE": 2, "READ_WRITE": 3}

# Numeric internal register classes.  These values are emitted into the
# decoder-only include; their spelling is intentionally tooling-local.
REG_CLASS = {
    "R": 1,
    "W": 2,
    "X": 3,
    "H": 4,
    "S": 5,
    "D": 6,
}
REG_SIZE = {"R": 4, "W": 4, "X": 8, "H": 2, "S": 4, "D": 8}
SPECIAL31 = {"": 0, "PC": 1, "WZR": 2, "WSP": 3, "XZR": 4, "SP": 5}


class OperandCatalogError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def git_head(path: Path) -> str:
    process = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if process.returncode != 0:
        raise OperandCatalogError(
            process.stderr.strip() or f"cannot inspect Git checkout {path}"
        )
    return process.stdout.strip()


def load_arm_source(path: Path) -> dict[str, Any]:
    if git_head(path) != PINNED_ARM_COMMIT:
        raise OperandCatalogError(
            f"Arm source must be pinned at {PINNED_ARM_COMMIT}"
        )
    source = path / "Instructions.json"
    if not source.is_file() or sha256_file(source) != PINNED_ARM_SHA256:
        raise OperandCatalogError("pinned Arm Instructions.json digest mismatch")
    with source.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def symbols(assembly: dict[str, Any] | None) -> list[dict[str, Any]]:
    return list((assembly or {}).get("symbols", []) or [])


def is_true_ast(value: Any) -> bool:
    return value == {"_type": "AST.Bool", "value": True}


def identifier_expression(value: Any) -> str | None:
    if isinstance(value, dict) and value.get("_type") == "AST.Identifier":
        return str(value.get("value", ""))
    return None


class GrammarAnalyzer:
    """Recognize a closed, lossless subset of the Arm assembly grammar."""

    def __init__(
        self,
        rules: dict[str, Any],
        register_classes: set[str] | frozenset[str] | None = None,
    ):
        self.rules = rules
        self.register_classes = frozenset(
            REG_CLASS if register_classes is None else register_classes
        )

    def assembly_shape(
        self,
        assembly: dict[str, Any] | None,
        encoded: dict[str, list[Any]],
        inherited: Any = None,
        stack: tuple[str, ...] = (),
    ) -> list[tuple[Any, ...]] | None:
        result: list[tuple[Any, ...]] = []
        for symbol in symbols(assembly):
            kind = symbol.get("_type")
            if kind == "Instruction.Symbols.Literal":
                result.append(("literal", str(symbol.get("value", ""))))
            elif kind == "Instruction.Symbols.RuleReference":
                nested = self.rule_shape(
                    str(symbol.get("rule_id", "")), encoded, inherited, stack
                )
                if nested is None:
                    return None
                result.extend(nested)
            else:
                return None
        return result

    def rule_shape(
        self,
        rule_id: str,
        encoded: dict[str, list[Any]],
        inherited: Any,
        stack: tuple[str, ...],
    ) -> list[tuple[Any, ...]] | None:
        if rule_id in stack or rule_id not in self.rules:
            return None
        rule = self.rules[rule_id]
        display = rule.get("display")
        values = encoded.get(display) if display in encoded else [inherited]
        if values is None or len(values) != 1:
            return None
        value = values[0]
        kind = rule.get("_type")
        nested_stack = stack + (rule_id,)

        if kind == "Instruction.Rules.Token":
            if rule_id == "SPACE":
                return [("separator", " ")]
            if rule_id == "COMMA":
                return [("separator", ",")]
            if rule_id in {"UInteger", "SInteger"} and value is not None:
                return [("number", rule_id, value)]
            default = rule.get("default")
            if default is not None:
                return [("literal", str(default))]
            return None

        if kind == "Instruction.Rules.Rule":
            # T32's fixed AL option and A32's condition suffix are mnemonic
            # decorators rather than operands.  This catalogue admits A64
            # only, but recognizing them makes the grammar boundary explicit.
            if rule_id.startswith("AL_option"):
                return [("decorator", rule_id)]
            if not is_true_ast(rule.get("condition")):
                return None
            return self.assembly_shape(
                rule.get("symbols"), encoded, value, nested_stack
            )

        if kind != "Instruction.Rules.Choice":
            return None
        if rule_id.startswith("cond_choice"):
            return [("decorator", rule_id)]
        if rule_id in {"hash", "opt_hash"}:
            return [("literal", "#")]

        choices: list[list[tuple[Any, ...]]] = []
        for choice in rule.get("choices", []) or []:
            shape = self.assembly_shape(choice, encoded, value, nested_stack)
            if shape is None:
                return None
            choices.append(shape)
        if choices and all(choice == choices[0] for choice in choices):
            return choices[0]

        parsed = [self._register_choice(choice) for choice in choices]
        if len(parsed) == 2 and all(parsed):
            normal = next((item for item in parsed if item[0] == "normal"), None)
            special = next((item for item in parsed if item[0] == "special"), None)
            if normal is not None and special is not None:
                expression = identifier_expression(normal[2])
                spelling = special[1].upper()
                if normal[1] in self.register_classes and spelling in SPECIAL31:
                    return [("register", normal[1], expression, spelling)]
        return None

    def _register_choice(
        self,
        choice: list[tuple[Any, ...]],
    ) -> tuple[str, Any, Any] | None:
        if (
            len(choice) == 1
            and choice[0][0] == "literal"
            and str(choice[0][1]).upper() in {"PC", "WZR", "WSP", "XZR", "SP"}
        ):
            return ("special", str(choice[0][1]), None)
        if (
            len(choice) == 2
            and choice[0][0] == "literal"
            and choice[0][1] in self.register_classes
            and choice[1][0] == "number"
        ):
            return ("normal", choice[0][1], choice[1][2])
        return None

    def flat_operands(
        self, source: dict[str, Any]
    ) -> list[dict[str, Any]] | None:
        encoded = ((source.get("_meta") or {}).get("encoded_in") or {})
        top_symbols = symbols(source.get("assembly"))
        if not top_symbols or top_symbols[0].get("_type") \
            != "Instruction.Symbols.Literal":
            return None
        # Everything between the leading mnemonic literal and the first SPACE
        # is a mnemonic decorator (condition, flag-setting, width qualifier,
        # and similar choices).  It cannot change operand structure, so it is
        # intentionally outside this operand-only proof.
        space_index = next(
            (
                index
                for index, symbol in enumerate(top_symbols[1:], 1)
                if symbol.get("_type") == "Instruction.Symbols.RuleReference"
                and symbol.get("rule_id") == "SPACE"
            ),
            None,
        )
        if space_index is None:
            return None
        operand_assembly = {"symbols": top_symbols[space_index + 1 :]}
        shape = self.assembly_shape(operand_assembly, encoded)
        if not shape:
            return None
        tail = [
            item
            for item in shape
            if item[0] != "decorator"
            and not (item[0] == "separator" and item[1] == " ")
        ]
        groups: list[list[tuple[Any, ...]]] = [[]]
        for item in tail:
            if item == ("separator", ","):
                groups.append([])
            else:
                groups[-1].append(item)
        if not 1 <= len(groups) <= 4:
            return None

        operands: list[dict[str, Any]] = []
        for group in groups:
            register_class: str
            expression: str | None
            special = ""
            if len(group) == 1 and group[0][0] == "register":
                register_class = str(group[0][1])
                expression = group[0][2]
                special = str(group[0][3])
            elif (
                len(group) == 2
                and group[0][0] == "literal"
                and group[0][1] in self.register_classes
                and group[1][0] == "number"
            ):
                register_class = str(group[0][1])
                expression = identifier_expression(group[1][2])
            elif len(group) == 1 and group[0][0] == "number":
                operands.append(
                    {
                        "kind": "immediate",
                        "signed": group[0][1] == "SInteger",
                        "expression": group[0][2],
                    }
                )
                continue
            elif (
                len(group) == 2
                and group[0] == ("literal", "#")
                and group[1][0] == "number"
            ):
                operands.append(
                    {
                        "kind": "immediate",
                        "signed": group[1][1] == "SInteger",
                        "expression": group[1][2],
                    }
                )
                continue
            else:
                return None
            if not expression:
                return None
            operands.append(
                {
                    "kind": "register",
                    "class": register_class,
                    "field": expression,
                    "special31": special,
                }
            )
        return operands

    def flat_register_operands(
        self, source: dict[str, Any]
    ) -> list[dict[str, Any]] | None:
        operands = self.flat_operands(source)
        return (
            operands
            if operands is not None
            and all(operand["kind"] == "register" for operand in operands)
            else None
        )


def choose_field_value(
    desired: int,
    start: int,
    width: int,
    resolved_mask: int,
    resolved_value: int,
) -> int:
    local_mask = (resolved_mask >> start) & ((1 << width) - 1)
    local_value = (resolved_value >> start) & ((1 << width) - 1)
    return (desired & ~local_mask) | local_value


def make_witness(
    node: dict[str, Any], operands: list[dict[str, Any]], seed: int
) -> int:
    word = int(node["resolved_value_int"])
    width_mask = (1 << int(node["width"])) - 1
    assignments: dict[str, int] = {}
    next_value = seed
    for operand in operands:
        field = operand["field"]
        if field not in assignments:
            start, width = node["bindings"][field]
            # Keep ordinary witnesses away from register 31 and make different
            # encoded fields visibly distinct.
            desired = next_value % min(31, 1 << width)
            assignments[field] = choose_field_value(
                desired,
                start,
                width,
                int(node["resolved_mask_int"]),
                int(node["resolved_value_int"]),
            )
            next_value += 5
    for field, value in assignments.items():
        start, width = node["bindings"][field]
        mask = ((1 << width) - 1) << start
        word = (word & ~mask) | ((value << start) & mask)
    return word & width_mask


def make_register31_witness(
    node: dict[str, Any], operands: list[dict[str, Any]]
) -> int | None:
    special_fields = {
        operand["field"]
        for operand in operands
        if operand["special31"]
    }
    if not special_fields:
        return None
    word = make_witness(node, operands, 7)
    for field in special_fields:
        start, width = node["bindings"][field]
        maximum = (1 << width) - 1
        value = choose_field_value(
            maximum,
            start,
            width,
            int(node["resolved_mask_int"]),
            int(node["resolved_value_int"]),
        )
        if value != maximum:
            return None
        mask = ((1 << width) - 1) << start
        word = (word & ~mask) | value << start
    return word & UINT32_MASK


UINT32_MASK = (1 << 32) - 1


class CdisasmFormOracle:
    """Optional generation guard; never linked into the produced library."""

    class Flags(ctypes.Structure):
        _fields_ = [("bitmap", ctypes.c_uint64 * 8)]

    class Operand(ctypes.Structure):
        _fields_ = [
            ("address", ctypes.c_uint64),
            ("imm", ctypes.c_uint64),
            ("reg", ctypes.c_uint16),
            ("base_reg", ctypes.c_uint16),
            ("index_reg", ctypes.c_uint16),
            ("register_list", ctypes.c_uint16),
            ("type", ctypes.c_uint8),
            ("size", ctypes.c_uint8),
            ("access", ctypes.c_uint8),
            ("flags", ctypes.c_uint8),
            ("shift_type", ctypes.c_uint8),
            ("shift_amount", ctypes.c_uint8),
            ("extend_type", ctypes.c_uint8),
            ("scale", ctypes.c_uint8),
        ]

    class Instruction(ctypes.Structure):
        pass

    Instruction._fields_ = [
        ("address", ctypes.c_uint64),
        ("branch_target", ctypes.c_uint64),
        ("opcode_size", ctypes.c_uint32),
        ("opcode_groups", ctypes.c_uint32),
        ("raw_instruction", ctypes.c_uint32),
        ("instruction_flags", ctypes.c_uint32),
        ("name_id", ctypes.c_uint16),
        ("last_error_id", ctypes.c_uint8),
        ("operand_count", ctypes.c_uint8),
        ("condition", ctypes.c_uint8),
        ("isa_id", ctypes.c_uint8),
        ("form_id", ctypes.c_uint16),
        ("operand", Operand * 4),
    ]

    def __init__(self, library: Path):
        if ctypes.sizeof(self.Operand) != 32 or ctypes.sizeof(self.Instruction) != 168:
            raise OperandCatalogError("local ctypes ABI model is stale")
        self.library = ctypes.CDLL(str(library.resolve()))
        function = self.library.cdisasm_arm_decode
        function.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.c_uint64,
            ctypes.POINTER(self.Flags),
            ctypes.POINTER(self.Instruction),
        ]
        function.restype = ctypes.c_uint32
        self.decode = function

    def form(self, word: int, isa: str, width: int) -> int:
        encoded = instruction_bytes(word, isa, width)
        code = (ctypes.c_uint8 * len(encoded))(*encoded)
        flags = self.Flags()
        instruction = self.Instruction()
        mode = {"A32": 1, "T32": 2, "A64": 3}[isa]
        size = self.decode(
            0x00020000,
            mode,
            code,
            len(encoded),
            0,
            ctypes.byref(flags),
            ctypes.byref(instruction),
        )
        return (
            int(instruction.form_id)
            if size == len(encoded) and instruction.last_error_id == 0
            else 0
        )


def instruction_bytes(word: int, isa: str, width: int) -> bytes:
    if isa in {"A32", "A64"} and width == 32:
        return word.to_bytes(4, "little")
    if isa == "T32" and width == 16:
        return word.to_bytes(2, "little")
    if isa == "T32" and width == 32:
        return (word >> 16).to_bytes(2, "little") + (word & 0xFFFF).to_bytes(2, "little")
    raise OperandCatalogError(f"unsupported instruction state {isa}/{width}")


class CapstoneCstoolOracle:
    def __init__(self, root: Path, cstool: Path | None = None):
        if git_head(root) != PINNED_CAPSTONE_COMMIT:
            raise OperandCatalogError(
                f"Capstone source must be pinned at {PINNED_CAPSTONE_COMMIT}"
            )
        self.root = root
        self.cstool = cstool or root / "build-arm-audit" / "cstool.exe"
        if not self.cstool.is_file():
            raise OperandCatalogError(f"missing Capstone cstool: {self.cstool}")

    def decode(self, word: int, isa: str, width: int) -> dict[str, Any] | None:
        encoded = instruction_bytes(word, isa, width)
        byte_text = ",".join(f"{value:02x}" for value in encoded)
        architecture = {
            "A32": "arm",
            "T32": "arm+thumb+v8",
            "A64": "aarch64",
        }[isa]
        process = subprocess.run(
            [str(self.cstool), "-dr", architecture, byte_text],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        output = process.stdout.replace("\r\n", "\n")
        if process.returncode != 0 or "\tID:" not in output:
            return None
        id_match = re.search(r"^[ \t]*ID: [0-9]+ \(([^)]+)\)", output, re.MULTILINE)
        count_match = re.search(r"^[ \t]*op_count: ([0-9]+)", output, re.MULTILINE)
        if id_match is None or count_match is None:
            return None
        count = int(count_match.group(1))
        operands: list[dict[str, Any]] = []
        for index in range(count):
            type_match = re.search(
                rf"^[ \t]*operands\[{index}\]\.type: ([A-Z_]+)(?: = ([^\n]+))?",
                output,
                re.MULTILINE,
            )
            access_match = re.search(
                rf"^[ \t]*operands\[{index}\]\.access: ([A-Z_| ]+)",
                output,
                re.MULTILINE,
            )
            if type_match is None or access_match is None:
                return None
            access_text = access_match.group(1).strip().replace(" ", "")
            read = "READ" in access_text
            write = "WRITE" in access_text
            access = "READ_WRITE" if read and write else "READ" if read else "WRITE" if write else ""
            operands.append(
                {
                    "type": type_match.group(1),
                    "value": (type_match.group(2) or "").strip(),
                    "access": access,
                }
            )
            if type_match.group(1) == "PREDICATE":
                predicate_match = re.search(
                    rf"^[ \t]*operands\[{index}\]\.pred\.reg: ([^\n]+)",
                    output,
                    re.MULTILINE,
                )
                if predicate_match is None:
                    return None
                operands[-1]["value"] = predicate_match.group(1).strip()
            if type_match.group(1) == "MEM":
                base_match = re.search(
                    rf"^[ \t]*operands\[{index}\]\.mem\.base: REG = ([^\n]+)",
                    output,
                    re.MULTILINE,
                )
                index_match = re.search(
                    rf"^[ \t]*operands\[{index}\]\.mem\.index: REG = ([^\n]+)",
                    output,
                    re.MULTILINE,
                )
                displacement_match = re.search(
                    rf"^[ \t]*operands\[{index}\]\.mem\.disp: ([^\n]+)",
                    output,
                    re.MULTILINE,
                )
                post_indexed_match = re.search(
                    r"^[ \t]*post-indexed: (true|false)",
                    output,
                    re.MULTILINE | re.IGNORECASE,
                )
                operands[-1].update(
                    {
                        "base": (base_match.group(1).strip().lower()
                                 if base_match else ""),
                        "index": (index_match.group(1).strip().lower()
                                  if index_match else ""),
                        "displacement": (displacement_match.group(1).strip()
                                         if displacement_match else "0"),
                        "post_indexed": (
                            post_indexed_match is not None
                            and post_indexed_match.group(1).lower() == "true"
                        ),
                    }
                )
        groups_match = re.search(r"^[ \t]*Groups: ([^\n]+)", output, re.MULTILINE)
        return {
            "real_name": id_match.group(1).strip().lower(),
            "operands": operands,
            "groups": sorted((groups_match.group(1).split() if groups_match else [])),
        }


def expected_register_name(
    operand: dict[str, Any], node: dict[str, Any], word: int
) -> str:
    start, width = node["bindings"][operand["field"]]
    value = (word >> start) & ((1 << width) - 1)
    if value == (1 << width) - 1 and operand["special31"]:
        return str(operand["special31"]).lower()
    if operand["class"] == "R" and value == 13:
        return "sp"
    if operand["class"] == "R" and value == 14:
        return "lr"
    if operand["class"] == "R" and value == 15:
        return "pc"
    return f"{str(operand['class']).lower()}{value}"


def validate_observation(
    observation: dict[str, Any] | None,
    operands: list[dict[str, Any]],
    node: dict[str, Any],
    word: int,
) -> tuple[int, ...] | None:
    if observation is None or len(observation["operands"]) != len(operands):
        return None
    access: list[int] = []
    for expected, actual in zip(operands, observation["operands"]):
        if actual["type"] != "REG":
            return None
        actual_name = actual["value"].split()[0].strip().lower()
        if actual_name != expected_register_name(expected, node, word):
            return None
        numeric_access = ACCESS.get(actual["access"])
        if numeric_access is None:
            return None
        access.append(numeric_access)
    return tuple(access)


def is_scalar_floating_point(candidate: dict[str, Any]) -> bool:
    """Return true only inside the architecture's FP-labelled taxonomy."""
    if not any(
        operand["class"] in {"H", "S", "D"}
        for operand in candidate["operands"]
    ):
        return False
    path = candidate["source_form_id"].lower()
    return "float" in path or "fp16" in path


def collect_candidates(
    document: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    nodes, leaves, _aliases, _roots = arm_tree.make_tree(document)
    leaf_sources, _alias_sources = arm_assembly.collect_sources(document)
    analyzer = GrammarAnalyzer(document["assembly_rules"])
    candidates: list[dict[str, Any]] = []
    for leaf, source in zip(leaves, leaf_sources):
        node = nodes[leaf["node_index"]]
        operands = analyzer.flat_register_operands(source)
        if operands is None:
            continue
        isa = node["instruction_set_name"]
        allowed_classes = {"W", "X", "H", "S", "D"} if isa == "A64" else {"R"}
        if any(operand["class"] not in allowed_classes for operand in operands):
            continue
        if any(operand["field"] not in node["bindings"] for operand in operands):
            continue
        if any(
            not (
                (operand["class"] == "R" and 1 <= node["bindings"][operand["field"]][1] <= 4)
                or (operand["class"] != "R" and node["bindings"][operand["field"]][1] == 5)
            )
            for operand in operands
        ):
            continue
        # Scalar B registers are real architecture operands but the current
        # public ARM validator has no scalar-B schema.  Vector/scalable classes
        # need arrangement or predicate metadata and are outside this flat
        # catalogue by construction.
        candidates.append(
            {
                "form_id": leaf["form_id"],
                "source_form_id": leaf["source_form_id"],
                "mnemonic": leaf["mnemonic"].lower(),
                "isa": isa,
                "width": int(node["width"]),
                "node": node,
                "operands": operands,
            }
        )
    return nodes, leaves, candidates


def observe_candidate(
    candidate: dict[str, Any],
    capstone: CapstoneCstoolOracle,
    cdisasm: CdisasmFormOracle | None,
) -> dict[str, str] | None:
    node = candidate["node"]
    operands = candidate["operands"]
    words = [make_witness(node, operands, 1), make_witness(node, operands, 2)]
    if words[0] == words[1]:
        words[1] = make_witness(node, operands, 11)
    special_word = make_register31_witness(node, operands)
    check_words = words + ([special_word] if special_word is not None else [])
    if cdisasm is not None and any(
        cdisasm.form(word, candidate["isa"], candidate["width"])
            != candidate["form_id"]
        for word in check_words
    ):
        return None

    observations = [
        capstone.decode(word, candidate["isa"], candidate["width"])
        for word in check_words
    ]
    accesses = [
        validate_observation(observation, operands, node, word)
        for observation, word in zip(observations, check_words)
    ]
    if any(access is None for access in accesses):
        return None
    if any(access != accesses[0] for access in accesses[1:]):
        return None
    assert observations[0] is not None
    # The public scalar H/S/D register schema is intentionally reserved for
    # floating-point operations.  Crypto/AdvSIMD instructions sometimes use
    # the same architectural register spellings but need vector arrangement
    # metadata that this flat catalogue does not claim to provide.
    if any(operand["class"] in {"H", "S", "D"} for operand in operands) \
        and not is_scalar_floating_point(candidate):
        return None
    return {
        "form_id": str(candidate["form_id"]),
        "source_form_id": candidate["source_form_id"],
        "mnemonic": candidate["mnemonic"],
        "isa": candidate["isa"],
        "width": str(candidate["width"]),
        "witness_a": f"0x{words[0]:0{candidate['width'] // 4}x}",
        "witness_b": f"0x{words[1]:0{candidate['width'] // 4}x}",
        "witness_31": "" if special_word is None else f"0x{special_word:0{candidate['width'] // 4}x}",
        "operand_access": ",".join(str(value) for value in accesses[0] or ()),
        "capstone_real_name": observations[0]["real_name"],
        "capstone_groups": ",".join(observations[0]["groups"]),
    }


def write_tsv(path: Path, rows: Iterable[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, dialect="excel-tab")
        writer.writeheader()
        writer.writerows(rows)


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, dialect="excel-tab")
        if reader.fieldnames != ORACLE_FIELDS:
            raise OperandCatalogError(f"stale oracle schema in {path}")
        return list(reader)


def validate_oracle_rows(
    rows: list[dict[str, str]], candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_id = {candidate["form_id"]: candidate for candidate in candidates}
    records: list[dict[str, Any]] = []
    previous = 0
    for row in rows:
        form_id = int(row["form_id"])
        if form_id <= previous or form_id not in by_id:
            raise OperandCatalogError("oracle form IDs must be unique, sorted candidates")
        previous = form_id
        candidate = by_id[form_id]
        if (
            row["source_form_id"] != candidate["source_form_id"]
            or row["mnemonic"] != candidate["mnemonic"]
            or row["isa"] != candidate["isa"]
            or int(row["width"]) != candidate["width"]
        ):
            raise OperandCatalogError(f"oracle identity drift for form {form_id}")
        access = tuple(int(value) for value in row["operand_access"].split(","))
        if len(access) != len(candidate["operands"]) or any(
            value not in ACCESS.values() for value in access
        ):
            raise OperandCatalogError(f"invalid oracle access for form {form_id}")
        for key in ("witness_a", "witness_b"):
            word = int(row[key], 16)
            node = candidate["node"]
            if word & int(node["resolved_mask_int"]) != int(node["resolved_value_int"]):
                raise OperandCatalogError(
                    f"oracle {key} violates fixed encoding for form {form_id}"
                )
        records.append({**candidate, "access": access, "oracle": row})
    return records


def c_u8(value: int) -> str:
    return f"UINT8_C({value})"


def c_u16(value: int) -> str:
    return f"UINT16_C({value})"


def emit_include(path: Path, records: list[dict[str, Any]]) -> None:
    operand_rows: list[str] = []
    form_rows: list[str] = []
    first = 0
    for record in records:
        flags = 0
        if is_scalar_floating_point(record):
            flags |= 1
        for operand, access in zip(record["operands"], record["access"]):
            start, width = record["node"]["bindings"][operand["field"]]
            operand_rows.append(
                "{ %s, %s, %s, %s, %s, %s }"
                % (
                    c_u8(start),
                    c_u8(width),
                    c_u8(REG_CLASS[operand["class"]]),
                    c_u8(access),
                    c_u8(REG_SIZE[operand["class"]]),
                    c_u8(SPECIAL31[operand["special31"]]),
                )
            )
        form_rows.append(
            "{ %s, %s, %s, %s }"
            % (
                c_u16(record["form_id"]),
                c_u16(first),
                c_u8(len(record["operands"])),
                c_u8(flags),
            )
        )
        first += len(record["operands"])

    lines = [
        "/* Generated numeric ARM operand semantics; do not edit. */",
        "/* AARCHMRS fields joined to pinned Capstone operand detail offline. */",
        "#define CDISASM_ARM_OPEN_OPERAND_SCHEMA_VERSION UINT32_C(1)",
        f"#define CDISASM_ARM_OPEN_OPERAND_FORM_COUNT UINT32_C({len(records)})",
        f"#define CDISASM_ARM_OPEN_OPERAND_COUNT UINT32_C({len(operand_rows)})",
        "#define CDISASM_ARM_OPEN_OPERAND_FLAG_FLOATING_POINT UINT8_C(1)",
        "",
        "typedef struct cdisasm_arm_open_operand_desc {",
        "    uint8_t bit_start, bit_width, reg_class, access, size, special31;",
        "} cdisasm_arm_open_operand_desc;",
        "typedef struct cdisasm_arm_open_form_desc {",
        "    uint16_t form_id, first_operand;",
        "    uint8_t operand_count, flags;",
        "} cdisasm_arm_open_form_desc;",
        "",
        "static const cdisasm_arm_open_operand_desc cdisasm_arm_open_operands[] = {",
        *(f"    {row}," for row in operand_rows),
        "};",
        "",
        "static const cdisasm_arm_open_form_desc cdisasm_arm_open_forms[] = {",
        *(f"    {row}," for row in form_rows),
        "};",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def emit_manifest(
    path: Path,
    source: Path,
    candidates: list[dict[str, Any]],
    records: list[dict[str, Any]],
    oracle_path: Path,
    include_path: Path,
) -> None:
    by_class: dict[str, int] = {}
    by_isa: dict[str, int] = {}
    for record in records:
        by_isa[record["isa"]] = by_isa.get(record["isa"], 0) + 1
        for operand in record["operands"]:
            key = operand["class"]
            by_class[key] = by_class.get(key, 0) + 1
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "source": {
            "arm_commit": PINNED_ARM_COMMIT,
            "arm_instructions_sha256": sha256_file(source),
            "capstone_commit": PINNED_CAPSTONE_COMMIT,
            "generator_sha256": sha256_file(Path(__file__).resolve()),
        },
        "policy": {
            "scope": (
                "A32/T32 flat GPR and A64 flat GPR/scalar-FP register operands"
            ),
            "runtime_dependency": False,
            "strings_in_decoder_table": False,
            "validation": (
                "two ordinary register assignments plus register-31 assignment "
                "when present; exact Capstone register/type/access agreement"
            ),
            "unlisted_forms": "remain operands-opaque",
        },
        "counts": {
            "structural_candidates": len(candidates),
            "oracle_verified_forms": len(records),
            "oracle_rejected_or_unavailable": len(candidates) - len(records),
            "lowered_operands": sum(len(record["operands"]) for record in records),
            "operand_classes": dict(sorted(by_class.items())),
            "forms_by_isa": dict(sorted(by_isa.items())),
            "scalar_fp_forms": sum(
                is_scalar_floating_point(record)
                for record in records
            ),
        },
        "artifacts": {
            str(oracle_path.relative_to(REPO_ROOT)).replace("\\", "/"): {
                "sha256": sha256_file(oracle_path),
                "bytes": oracle_path.stat().st_size,
            },
            str(include_path.relative_to(REPO_ROOT)).replace("\\", "/"): {
                "sha256": sha256_file(include_path),
                "bytes": include_path.stat().st_size,
            },
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, ensure_ascii=True, indent=2, sort_keys=True)
        stream.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm-root", type=Path, required=True)
    parser.add_argument("--capstone-root", type=Path)
    parser.add_argument("--capstone-cstool", type=Path)
    parser.add_argument("--cdisasm-dll", type=Path)
    parser.add_argument("--refresh-oracle", action="store_true")
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument(
        "--oracle",
        type=Path,
        default=SCRIPT_DIR / "generated" / "arm_open_operand_oracle.tsv",
    )
    parser.add_argument(
        "--decode-include",
        type=Path,
        default=REPO_ROOT / "src" / "arm" / "generated" / "cdisasm_arm_open_operands.inc",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=SCRIPT_DIR / "generated" / "arm_open_operand_manifest.json",
    )
    arguments = parser.parse_args()
    document = load_arm_source(arguments.arm_root.resolve())
    _nodes, _leaves, candidates = collect_candidates(document)
    candidates.sort(key=lambda record: record["form_id"])

    if arguments.refresh_oracle:
        if arguments.capstone_root is None:
            raise OperandCatalogError("--refresh-oracle requires --capstone-root")
        capstone_root = arguments.capstone_root.resolve()
        capstone = CapstoneCstoolOracle(capstone_root, arguments.capstone_cstool)
        cdisasm = (
            CdisasmFormOracle(arguments.cdisasm_dll)
            if arguments.cdisasm_dll is not None
            else None
        )
        rows: list[dict[str, str]] = []
        with ThreadPoolExecutor(max_workers=max(1, arguments.jobs)) as pool:
            futures = {
                pool.submit(observe_candidate, candidate, capstone, cdisasm): candidate
                for candidate in candidates
            }
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    rows.append(result)
        rows.sort(key=lambda row: int(row["form_id"]))
        write_tsv(arguments.oracle, rows, ORACLE_FIELDS)
    else:
        capstone_root = None
        if not arguments.oracle.is_file():
            raise OperandCatalogError(
                f"missing checked-in oracle {arguments.oracle}; use --refresh-oracle"
            )
        rows = read_tsv(arguments.oracle)

    records = validate_oracle_rows(rows, candidates)
    emit_include(arguments.decode_include, records)
    emit_manifest(
        arguments.manifest,
        arguments.arm_root / "Instructions.json",
        candidates,
        records,
        arguments.oracle,
        arguments.decode_include,
    )
    print(
        f"Arm open operand catalogue: {len(records)}/{len(candidates)} verified "
        f"forms, {sum(len(record['operands']) for record in records)} operands"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except OperandCatalogError as error:
        print(f"Arm open operand generation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
