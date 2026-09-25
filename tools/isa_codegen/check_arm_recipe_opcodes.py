#!/usr/bin/env python3
"""Check the generated ARM recipe-opcode enum without upstream ISA data.

The assembly-catalog generator declares recipe opcodes in its literal
``RECIPE_OPCODE`` mapping. The generated decoder include repeats that mapping
as ``enum cdisasm_arm_asmgen_recipe_opcode``. This script parses both files
statically; it does not import the generator or require an AARCHMRS checkout.
"""

from __future__ import annotations

import argparse
import ast
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
import re
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
DEFAULT_GENERATOR = SCRIPT_DIR / "generate_arm_assembly_catalog.py"
DEFAULT_DECODE_INCLUDE = (
    REPO_ROOT / "src/arm/generated/cdisasm_arm_assembly_decode.inc"
)

PYTHON_MAPPING_NAME = "RECIPE_OPCODE"
C_ENUM_TAG = "cdisasm_arm_asmgen_recipe_opcode"
C_ENUM_PREFIX = "CDISASM_ARM_ASMGEN_"
OPCODE_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
C_ENUM_RE = re.compile(
    rf"\benum\s+{re.escape(C_ENUM_TAG)}\s*\{{(?P<body>.*?)\}}\s*;",
    re.DOTALL,
)
C_ENUM_ENTRY_RE = re.compile(
    rf"^{re.escape(C_ENUM_PREFIX)}(?P<name>[A-Z][A-Z0-9_]*)\s*=\s*"
    r"(?P<number>(?:0[xX][0-9A-Fa-f]+|[0-9]+))[uUlL]*$"
)
C_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\r\n]*", re.DOTALL)


class FreshnessError(Exception):
    """An input is unreadable, malformed, or violates an opcode invariant."""


@dataclass(frozen=True)
class OpcodeDrift:
    missing: tuple[str, ...]
    unexpected: tuple[str, ...]
    mismatched: tuple[str, ...]

    @property
    def synchronized(self) -> bool:
        return not (self.missing or self.unexpected or self.mismatched)


def _location(source_name: str, line: int | None) -> str:
    return source_name if line is None else f"{source_name}:{line}"


def _add_opcode(
    result: dict[str, int],
    value_owners: dict[int, str],
    raw_name: object,
    raw_value: object,
    source_name: str,
    line: int | None = None,
) -> None:
    location = _location(source_name, line)
    if not isinstance(raw_name, str) or not OPCODE_NAME_RE.fullmatch(raw_name):
        raise FreshnessError(
            f"{location}: invalid recipe opcode name {raw_name!r}"
        )
    if isinstance(raw_value, bool) or not isinstance(raw_value, int):
        raise FreshnessError(
            f"{location}: opcode {raw_name} must have a literal integer value"
        )
    if not 1 <= raw_value <= 255:
        raise FreshnessError(
            f"{location}: opcode {raw_name} value {raw_value} does not fit "
            "the nonzero uint8_t opcode field"
        )
    if raw_name in result:
        raise FreshnessError(
            f"{location}: duplicate recipe opcode name {raw_name}"
        )
    if raw_value in value_owners:
        raise FreshnessError(
            f"{location}: opcode value {raw_value} is shared by "
            f"{value_owners[raw_value]} and {raw_name}"
        )
    result[raw_name] = raw_value
    value_owners[raw_value] = raw_name


def parse_generator_opcodes(source: str, source_name: str) -> dict[str, int]:
    """Extract the module-level literal RECIPE_OPCODE mapping."""

    try:
        module = ast.parse(source, filename=source_name)
    except SyntaxError as error:
        raise FreshnessError(
            f"{source_name}:{error.lineno or 0}: "
            f"{error.msg or 'invalid Python syntax'}"
        ) from error

    definitions: list[tuple[ast.expr, int]] = []
    for statement in module.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name)
            and target.id == PYTHON_MAPPING_NAME
            for target in statement.targets
        ):
            definitions.append((statement.value, statement.lineno))
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == PYTHON_MAPPING_NAME
            and statement.value is not None
        ):
            definitions.append((statement.value, statement.lineno))

    if len(definitions) != 1:
        raise FreshnessError(
            f"{source_name}: expected exactly one module-level "
            f"{PYTHON_MAPPING_NAME} definition, found {len(definitions)}"
        )
    mapping, definition_line = definitions[0]
    if not isinstance(mapping, ast.Dict):
        raise FreshnessError(
            f"{source_name}:{definition_line}: {PYTHON_MAPPING_NAME} must be "
            "a literal dictionary"
        )

    result: dict[str, int] = {}
    value_owners: dict[int, str] = {}
    for key_node, value_node in zip(mapping.keys, mapping.values):
        if key_node is None:
            raise FreshnessError(
                f"{source_name}:{definition_line}: dictionary unpacking is "
                f"not allowed in {PYTHON_MAPPING_NAME}"
            )
        line = getattr(key_node, "lineno", definition_line)
        try:
            key = ast.literal_eval(key_node)
            value = ast.literal_eval(value_node)
        except (TypeError, ValueError) as error:
            raise FreshnessError(
                f"{source_name}:{line}: {PYTHON_MAPPING_NAME} keys and "
                "values must be literals"
            ) from error
        _add_opcode(result, value_owners, key, value, source_name, line)

    if not result:
        raise FreshnessError(
            f"{source_name}:{definition_line}: {PYTHON_MAPPING_NAME} is empty"
        )
    return result


def _parse_c_integer(token: str, source_name: str) -> int:
    base = 16 if token.lower().startswith("0x") else 10
    if len(token) > 1 and token.startswith("0") and base == 10:
        base = 8
    try:
        return int(token, base)
    except ValueError as error:
        raise FreshnessError(
            f"{source_name}: invalid C integer literal {token!r}"
        ) from error


def parse_generated_opcodes(source: str, source_name: str) -> dict[str, int]:
    """Extract explicit values from the generated recipe-opcode C enum."""

    matches = list(C_ENUM_RE.finditer(C_COMMENT_RE.sub("", source)))
    if len(matches) != 1:
        raise FreshnessError(
            f"{source_name}: expected exactly one enum {C_ENUM_TAG}, "
            f"found {len(matches)}"
        )

    entries = matches[0].group("body").split(",")
    result: dict[str, int] = {}
    value_owners: dict[int, str] = {}
    for index, raw_entry in enumerate(entries):
        entry = " ".join(raw_entry.split())
        if not entry:
            if index == len(entries) - 1:
                continue
            raise FreshnessError(
                f"{source_name}: empty enumerator in enum {C_ENUM_TAG}"
            )
        match = C_ENUM_ENTRY_RE.fullmatch(entry)
        if match is None:
            raise FreshnessError(
                f"{source_name}: unsupported enumerator syntax {entry!r}; "
                "every value must be explicit"
            )
        _add_opcode(
            result,
            value_owners,
            match.group("name"),
            _parse_c_integer(match.group("number"), source_name),
            source_name,
        )

    if not result:
        raise FreshnessError(f"{source_name}: enum {C_ENUM_TAG} is empty")
    return result


def compare_opcodes(
    generator: dict[str, int], generated: dict[str, int]
) -> OpcodeDrift:
    generator_names = set(generator)
    generated_names = set(generated)
    return OpcodeDrift(
        missing=tuple(sorted(generator_names - generated_names)),
        unexpected=tuple(sorted(generated_names - generator_names)),
        mismatched=tuple(
            sorted(
                name
                for name in generator_names & generated_names
                if generator[name] != generated[name]
            )
        ),
    )


def format_drift(
    drift: OpcodeDrift,
    generator: dict[str, int],
    generated: dict[str, int],
) -> str:
    lines = ["ARM recipe opcode freshness check failed:"]
    if drift.missing:
        lines.append("  missing from generated enum:")
        lines.extend(
            f"    {C_ENUM_PREFIX}{name} = {generator[name]}"
            for name in drift.missing
        )
    if drift.unexpected:
        lines.append("  unexpected in generated enum:")
        lines.extend(
            f"    {C_ENUM_PREFIX}{name} = {generated[name]}"
            for name in drift.unexpected
        )
    if drift.mismatched:
        lines.append("  numeric value mismatches:")
        lines.extend(
            f"    {C_ENUM_PREFIX}{name}: generator={generator[name]}, "
            f"generated={generated[name]}"
            for name in drift.mismatched
        )
    lines.append(
        "Regenerate the ARM assembly catalog from the pinned AARCHMRS checkout."
    )
    return "\n".join(lines)


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise FreshnessError(f"cannot read {path}: {error}") from error


def run_self_test(quiet: bool) -> int:
    generator_fixture = 'RECIPE_OPCODE = {"MNEMONIC": 1, "TEXT": 2}\n'
    generated_fixture = (
        "enum cdisasm_arm_asmgen_recipe_opcode { "
        "CDISASM_ARM_ASMGEN_MNEMONIC = 1, "
        "CDISASM_ARM_ASMGEN_TEXT = 2 };\n"
    )
    generator = parse_generator_opcodes(generator_fixture, "generator.py")
    drift_cases = (
        ("matching", generated_fixture, OpcodeDrift((), (), ())),
        (
            "missing",
            "enum cdisasm_arm_asmgen_recipe_opcode { "
            "CDISASM_ARM_ASMGEN_MNEMONIC = 1 };",
            OpcodeDrift(("TEXT",), (), ()),
        ),
        (
            "unexpected",
            generated_fixture.replace(
                " };", ", CDISASM_ARM_ASMGEN_EXTRA = 3 };"
            ),
            OpcodeDrift((), ("EXTRA",), ()),
        ),
        (
            "renumbered",
            generated_fixture.replace("TEXT = 2", "TEXT = 3"),
            OpcodeDrift((), (), ("TEXT",)),
        ),
    )
    failures: list[str] = []
    for name, source, expected in drift_cases:
        try:
            actual = compare_opcodes(
                generator, parse_generated_opcodes(source, "generated.inc")
            )
            if actual != expected:
                failures.append(f"{name}: expected {expected}, got {actual}")
        except FreshnessError as error:
            failures.append(f"{name}: unexpected error: {error}")

    error_cases = (
        (
            "duplicate generator name",
            parse_generator_opcodes,
            'RECIPE_OPCODE = {"TEXT": 1, "TEXT": 2}',
            "duplicate recipe opcode name TEXT",
        ),
        (
            "duplicate generated value",
            parse_generated_opcodes,
            generated_fixture.replace("TEXT = 2", "TEXT = 1"),
            "opcode value 1 is shared",
        ),
        (
            "dynamic generator mapping",
            parse_generator_opcodes,
            "RECIPE_OPCODE = dict(MNEMONIC=1)",
            "must be a literal dictionary",
        ),
        (
            "implicit generated value",
            parse_generated_opcodes,
            generated_fixture.replace("TEXT = 2", "TEXT"),
            "every value must be explicit",
        ),
        (
            "out-of-range opcode",
            parse_generated_opcodes,
            generated_fixture.replace("TEXT = 2", "TEXT = 256"),
            "does not fit the nonzero uint8_t opcode field",
        ),
    )
    for name, parser, source, expected_text in error_cases:
        try:
            parser(source, "fixture")
        except FreshnessError as error:
            if expected_text not in str(error):
                failures.append(
                    f"{name}: expected {expected_text!r}, got {str(error)!r}"
                )
        else:
            failures.append(f"{name}: malformed fixture was accepted")

    if failures:
        print("ARM recipe opcode checker self-test failed:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    if not quiet:
        print(
            "ARM recipe opcode checker self-test passed: "
            f"{len(drift_cases) + len(error_cases)} cases"
        )
    return 0


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n\n", maxsplit=1)[0],
        epilog=(
            "Exit status: 0 synchronized, 1 drift, 2 invalid/unreadable input. "
            "Use --self-test to validate the checker without repository files."
        ),
    )
    parser.add_argument(
        "--generator",
        type=Path,
        metavar="PATH",
        help=(
            "generator source (default: "
            "tools/isa_codegen/generate_arm_assembly_catalog.py)"
        ),
    )
    parser.add_argument(
        "--decode-include",
        type=Path,
        metavar="PATH",
        help=(
            "generated decode include (default: "
            "src/arm/generated/cdisasm_arm_assembly_decode.inc)"
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run self-contained parser and drift-detection checks",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress successful check output",
    )
    parsed = parser.parse_args(arguments)
    if parsed.self_test and (
        parsed.generator is not None or parsed.decode_include is not None
    ):
        parser.error("--self-test cannot be combined with input paths")
    return parsed


def main(arguments: Sequence[str] | None = None) -> int:
    parsed = parse_arguments(arguments)
    if parsed.self_test:
        return run_self_test(parsed.quiet)

    generator_path = parsed.generator or DEFAULT_GENERATOR
    decode_path = parsed.decode_include or DEFAULT_DECODE_INCLUDE
    try:
        generator = parse_generator_opcodes(
            _read_text(generator_path), str(generator_path)
        )
        generated = parse_generated_opcodes(
            _read_text(decode_path), str(decode_path)
        )
    except FreshnessError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    drift = compare_opcodes(generator, generated)
    if not drift.synchronized:
        print(format_drift(drift, generator, generated), file=sys.stderr)
        return 1
    if not parsed.quiet:
        print(
            "ARM recipe opcode freshness check passed: "
            f"{len(generator)} opcodes synchronized"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
