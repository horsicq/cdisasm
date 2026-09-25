#!/usr/bin/env python3
"""Generate the pinned AARCHMRS decode topology and evaluator bytecode.

This emits C-neutral audit tables and one unconnected internal C include. It
does not modify or route the cdisasm ARM decoder.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Iterable


SCHEMA_VERSION = 1
GENERATOR_VERSION = 1
NONE = 0xFFFFFFFF

NODE_KIND = {
    "Instruction.InstructionSet": 0,
    "Instruction.InstructionGroup": 1,
    "Instruction.Instruction": 2,
}
INSTRUCTION_SET = {"A32": 0, "T32": 1, "A64": 2}

BC_OPCODE = {
    "PUSH_BOOL": 1,
    "PUSH_FIELD": 2,
    "PUSH_FEATURE": 3,
    "PUSH_SYMBOL": 4,
    "PUSH_VALUE": 5,
    "PUSH_INTEGER": 6,
    "MAKE_SET": 7,
    "MAKE_SLICE": 8,
    "SQUARE": 9,
    "UNARY_LOGICAL_NOT": 16,
    "UNARY_BIT_NOT": 17,
    "BINARY_AND": 32,
    "BINARY_OR": 33,
    "BINARY_EQ": 34,
    "BINARY_NE": 35,
    "BINARY_LT": 36,
    "BINARY_GT": 37,
    "BINARY_GE": 38,
    "BINARY_IN": 39,
    "BINARY_CONCAT": 40,
    "BINARY_XOR": 41,
    "BINARY_MOD": 42,
    "BINARY_ADD": 43,
    "CALL": 48,
}
UNARY_OPCODE = {
    "!": BC_OPCODE["UNARY_LOGICAL_NOT"],
    "NOT": BC_OPCODE["UNARY_BIT_NOT"],
}
BINARY_OPCODE = {
    "&&": BC_OPCODE["BINARY_AND"],
    "||": BC_OPCODE["BINARY_OR"],
    "==": BC_OPCODE["BINARY_EQ"],
    "!=": BC_OPCODE["BINARY_NE"],
    "<": BC_OPCODE["BINARY_LT"],
    ">": BC_OPCODE["BINARY_GT"],
    ">=": BC_OPCODE["BINARY_GE"],
    "IN": BC_OPCODE["BINARY_IN"],
    "::": BC_OPCODE["BINARY_CONCAT"],
    "XOR": BC_OPCODE["BINARY_XOR"],
    "MOD": BC_OPCODE["BINARY_MOD"],
    "+": BC_OPCODE["BINARY_ADD"],
}

EXPECTED_AST_TYPES = {
    "AST.Bool",
    "AST.Identifier",
    "Values.Value",
    "AST.Integer",
    "AST.Set",
    "AST.SquareOp",
    "AST.Slice",
    "AST.BinaryOp",
    "AST.UnaryOp",
    "AST.Function",
}
CLOSED_EVALUATOR_UNARY = {"!"}
CLOSED_EVALUATOR_BINARY = {
    "&&",
    "||",
    "==",
    "!=",
    "<",
    ">",
    ">=",
    "IN",
    "::",
    "XOR",
    "MOD",
    "+",
}
CLOSED_EVALUATOR_FUNCTIONS = {
    "IsFeatureImplemented",
    "UInt",
    "SInt",
    "InITBlock",
    "T32ExpandImm",
    "BitCount",
    "SysOp",
    "SysLOp",
    "SysOp128",
    "EncodingExists",
    "IsZero",
    "IsOnes",
    "BFXPreferred",
    "MoveWidePreferred",
    "SVEMoveMaskPreferred",
}


class TreeError(RuntimeError):
    pass


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def value_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def git_head(repository: Path) -> str | None:
    process = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return process.stdout.strip() if process.returncode == 0 else None


def parse_local_encoding(
    encoding: dict[str, Any] | None,
) -> tuple[int, int, int | None, dict[str, tuple[int, int]]]:
    if not encoding:
        return 0, 0, None, {}
    raw_width = encoding.get("width")
    width = int(raw_width) if raw_width is not None else None
    mask = 0
    value = 0
    bindings: dict[str, tuple[int, int]] = {}
    for field in encoding.get("values", []):
        bit_range = field.get("range") or {}
        start = int(bit_range.get("start", 0))
        field_width = int(bit_range.get("width", 0))
        raw = str((field.get("value") or {}).get("value", "")).strip("'")
        if len(raw) != field_width or any(bit not in "01x" for bit in raw):
            raise TreeError(
                f"unsupported encoding bit pattern {raw!r} at {start}:{field_width}"
            )
        if "name" in field:
            name = str(field["name"])
            if name in bindings:
                raise TreeError(f"duplicate local field binding {name!r}")
            bindings[name] = (start, field_width)
        field_mask = ((1 << field_width) - 1) << start
        for offset, bit in enumerate(reversed(raw)):
            position = start + offset
            if bit != "x":
                mask |= 1 << position
                if bit == "1":
                    value |= 1 << position
        if width is not None and field_mask & ~((1 << width) - 1):
            raise TreeError(f"encoding field extends beyond width {width}")
    return mask, value, width, bindings


def merge_encoding(
    parent_mask: int,
    parent_value: int,
    parent_width: int | None,
    parent_bindings: dict[str, tuple[int, int]],
    local_mask: int,
    local_value: int,
    local_width: int | None,
    local_bindings: dict[str, tuple[int, int]],
    encoding: dict[str, Any] | None,
) -> tuple[int, int, int | None, dict[str, tuple[int, int]]]:
    width = local_width if local_width is not None else parent_width
    if parent_width is not None and width is not None and width != parent_width:
        mask = 0
        value = 0
        bindings: dict[str, tuple[int, int]] = {}
    else:
        mask = parent_mask
        value = parent_value
        bindings = dict(parent_bindings)
    for field in (encoding or {}).get("values", []):
        bit_range = field.get("range") or {}
        start = int(bit_range.get("start", 0))
        field_width = int(bit_range.get("width", 0))
        field_mask = ((1 << field_width) - 1) << start
        mask &= ~field_mask
        value &= ~field_mask
    mask |= local_mask
    value |= local_value
    bindings.update(local_bindings)
    if width is not None:
        width_mask = (1 << width) - 1
        mask &= width_mask
        value &= width_mask
        bindings = {
            name: binding
            for name, binding in bindings.items()
            if binding[0] + binding[1] <= width
        }
    return mask, value, width, bindings


def first_literal(node: dict[str, Any]) -> str:
    for symbol in (node.get("assembly") or {}).get("symbols", []):
        if symbol.get("_type") == "Instruction.Symbols.Literal":
            return str(symbol.get("value", ""))
    return ""


def assembly_template(node: dict[str, Any]) -> str:
    result: list[str] = []
    for symbol in (node.get("assembly") or {}).get("symbols", []):
        kind = symbol.get("_type")
        if kind == "Instruction.Symbols.Literal":
            result.append(str(symbol.get("value", "")))
        elif kind == "Instruction.Symbols.RuleReference":
            result.append(f"<rule:{symbol.get('rule_id', '')}>")
        else:
            result.append(f"<unsupported:{kind or 'unknown'}>")
    return "".join(result)


def ast_walk(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from ast_walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from ast_walk(child)


def make_tree(document: dict[str, Any]) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[int],
]:
    nodes: list[dict[str, Any]] = []
    leaves: list[dict[str, Any]] = []
    aliases: list[dict[str, Any]] = []

    def visit(
        source: dict[str, Any],
        instruction_set_name: str,
        parent_index: int,
        path: tuple[str, ...],
        parent_mask: int,
        parent_value: int,
        parent_width: int | None,
        parent_bindings: dict[str, tuple[int, int]],
    ) -> int:
        node_type = str(source.get("_type", ""))
        if node_type not in NODE_KIND:
            raise TreeError(f"unexpected tree node type {node_type!r}")
        name = str(source.get("name", ""))
        node_path = path + (name,)
        local_mask, local_value, local_width, local_bindings = parse_local_encoding(
            source.get("encoding")
        )
        resolved_mask, resolved_value, width, bindings = merge_encoding(
            parent_mask,
            parent_value,
            parent_width,
            parent_bindings,
            local_mask,
            local_value,
            local_width,
            local_bindings,
            source.get("encoding"),
        )
        if width not in (16, 32):
            raise TreeError(f"unexpected node width {width!r} at {'/'.join(node_path)}")
        node_index = len(nodes)
        node = {
            "node_index": node_index,
            "parent": parent_index,
            "first_child": NONE,
            "next_sibling": NONE,
            "child_count": 0,
            "kind": NODE_KIND[node_type],
            "kind_name": node_type.rsplit(".", 1)[-1],
            "instruction_set": INSTRUCTION_SET[instruction_set_name],
            "instruction_set_name": instruction_set_name,
            "width": width,
            "local_mask_int": local_mask,
            "local_value_int": local_value,
            "resolved_mask_int": resolved_mask,
            "resolved_value_int": resolved_value,
            "name": name,
            "path": "/".join(node_path),
            "bindings": bindings,
            "condition_ast": source.get("condition"),
            "assertions_ast": source.get("assertions"),
            "condition_digest": value_digest(source.get("condition")),
            "assertions_digest": value_digest(source.get("assertions")),
            "leaf_index": NONE,
        }
        nodes.append(node)

        if node_type == "Instruction.Instruction":
            leaf_index = len(leaves)
            node["leaf_index"] = leaf_index
            leaf_aliases = [
                child
                for child in source.get("children", [])
                if child.get("_type") == "Instruction.InstructionAlias"
            ]
            alias_start = len(aliases)
            leaf = {
                "leaf_index": leaf_index,
                "form_id": leaf_index + 1,
                "node_index": node_index,
                "internal_name": name,
                "mnemonic": first_literal(source),
                "assembly_template": assembly_template(source),
                "operation_id": str(source.get("operation_id", "")),
                "alias_start": alias_start,
                "alias_count": len(leaf_aliases),
                "source_form_id": "/".join(node_path),
            }
            leaves.append(leaf)
            for alias_source in leaf_aliases:
                aliases.append(
                    {
                        "alias_index": len(aliases),
                        "leaf_index": leaf_index,
                        "internal_name": str(alias_source.get("name", "")),
                        "mnemonic": first_literal(alias_source),
                        "assembly_template": assembly_template(alias_source),
                        "operation_id": str(alias_source.get("operation_id", "")),
                        "condition_ast": alias_source.get("condition"),
                        "preferred_ast": alias_source.get("preferred"),
                        "condition_digest": value_digest(alias_source.get("condition")),
                        "preferred_digest": value_digest(alias_source.get("preferred")),
                        "bindings": bindings,
                        "form_id": leaf["form_id"],
                        "source_form_id": leaf["source_form_id"],
                    }
                )

        children = [
            child
            for child in source.get("children", [])
            if child.get("_type") != "Instruction.InstructionAlias"
        ]
        child_indices: list[int] = []
        for child in children:
            child_indices.append(
                visit(
                    child,
                    instruction_set_name,
                    node_index,
                    node_path,
                    resolved_mask,
                    resolved_value,
                    width,
                    bindings,
                )
            )
        node["child_count"] = len(child_indices)
        if child_indices:
            node["first_child"] = child_indices[0]
            for left, right in zip(child_indices, child_indices[1:]):
                nodes[left]["next_sibling"] = right
        return node_index

    root_indices: list[int] = []
    for root in document.get("instructions", []):
        instruction_set_name = str(root.get("name", ""))
        if instruction_set_name not in INSTRUCTION_SET:
            raise TreeError(f"unexpected root {instruction_set_name!r}")
        root_indices.append(
            visit(root, instruction_set_name, NONE, (), 0, 0, None, {})
        )
    for left, right in zip(root_indices, root_indices[1:]):
        nodes[left]["next_sibling"] = right
    return nodes, leaves, aliases, root_indices


def ast_inventory(
    nodes: list[dict[str, Any]], aliases: list[dict[str, Any]]
) -> dict[str, Any]:
    type_counts: dict[str, int] = {}
    unary_counts: dict[str, int] = {}
    binary_counts: dict[str, int] = {}
    function_counts: dict[str, int] = {}
    symbol_counts: dict[str, int] = {}
    feature_counts: dict[str, int] = {}
    value_counts: dict[str, int] = {}

    jobs: list[tuple[Any, dict[str, tuple[int, int]]]] = []
    for node in nodes:
        jobs.append((node["condition_ast"], node["bindings"]))
        jobs.append((node["assertions_ast"], node["bindings"]))
    for alias in aliases:
        jobs.append((alias["condition_ast"], alias["bindings"]))
        jobs.append((alias["preferred_ast"], alias["bindings"]))
    for ast, bindings in jobs:
        for item in ast_walk(ast):
            item_type = str(item.get("_type", ""))
            if item_type:
                type_counts[item_type] = type_counts.get(item_type, 0) + 1
            if item_type == "AST.UnaryOp":
                op = str(item.get("op", ""))
                unary_counts[op] = unary_counts.get(op, 0) + 1
            elif item_type == "AST.BinaryOp":
                op = str(item.get("op", ""))
                binary_counts[op] = binary_counts.get(op, 0) + 1
            elif item_type == "AST.Function":
                name = str(item.get("name", ""))
                function_counts[name] = function_counts.get(name, 0) + 1
            elif item_type == "AST.Identifier":
                name = str(item.get("value", ""))
                if name in bindings:
                    continue
                target = feature_counts if name.startswith("FEAT_") else symbol_counts
                target[name] = target.get(name, 0) + 1
            elif item_type == "Values.Value":
                value = str(item.get("value", ""))
                value_counts[value] = value_counts.get(value, 0) + 1
    return {
        "type_counts": dict(sorted(type_counts.items())),
        "unary_operator_counts": dict(sorted(unary_counts.items())),
        "binary_operator_counts": dict(sorted(binary_counts.items())),
        "function_counts": dict(sorted(function_counts.items())),
        "symbol_counts": dict(sorted(symbol_counts.items())),
        "feature_counts": dict(sorted(feature_counts.items())),
        "value_counts": dict(sorted(value_counts.items())),
        "outside_closed_evaluator": {
            "ast_types": sorted(set(type_counts) - EXPECTED_AST_TYPES),
            "unary_operators": sorted(set(unary_counts) - CLOSED_EVALUATOR_UNARY),
            "binary_operators": sorted(set(binary_counts) - CLOSED_EVALUATOR_BINARY),
            "functions": sorted(set(function_counts) - CLOSED_EVALUATOR_FUNCTIONS),
        },
    }


def compile_ast(
    value: Any,
    bindings: dict[str, tuple[int, int]],
    features: dict[str, int],
    symbols: dict[str, int],
    values: dict[str, int],
    functions: dict[str, int],
) -> tuple[tuple[int, int, int], ...] | None:
    if value is None or value == []:
        return None
    if isinstance(value, list):
        programs = [
            compile_ast(item, bindings, features, symbols, values, functions)
            for item in value
        ]
        programs = [program for program in programs if program is not None]
        if not programs:
            return None
        result = list(programs[0])
        for program in programs[1:]:
            result.extend(program)
            result.append((BC_OPCODE["BINARY_AND"], 0, 0))
        return tuple(result)
    if not isinstance(value, dict):
        raise TreeError(f"AST value is not a node: {value!r}")
    node_type = value.get("_type")
    result: list[tuple[int, int, int]] = []
    if node_type == "AST.Bool":
        result.append((BC_OPCODE["PUSH_BOOL"], int(bool(value.get("value"))), 0))
    elif node_type == "AST.Identifier":
        name = str(value.get("value", ""))
        if name in bindings:
            start, width = bindings[name]
            result.append((BC_OPCODE["PUSH_FIELD"], start, width))
        elif name.startswith("FEAT_"):
            result.append((BC_OPCODE["PUSH_FEATURE"], features[name], 0))
        else:
            result.append((BC_OPCODE["PUSH_SYMBOL"], symbols[name], 0))
    elif node_type == "Values.Value":
        result.append((BC_OPCODE["PUSH_VALUE"], values[str(value.get("value", ""))], 0))
    elif node_type == "AST.Integer":
        result.append((BC_OPCODE["PUSH_INTEGER"], int(value.get("value", 0)), 0))
    elif node_type == "AST.Set":
        children = value.get("values", [])
        for child in children:
            child_program = compile_ast(
                child, bindings, features, symbols, values, functions
            )
            if child_program is None:
                raise TreeError("empty AST child in Set")
            result.extend(child_program)
        result.append((BC_OPCODE["MAKE_SET"], len(children), 0))
    elif node_type == "AST.Slice":
        for key in ("left", "right"):
            child_program = compile_ast(
                value.get(key), bindings, features, symbols, values, functions
            )
            if child_program is None:
                raise TreeError("empty AST child in Slice")
            result.extend(child_program)
        result.append((BC_OPCODE["MAKE_SLICE"], 0, 0))
    elif node_type == "AST.SquareOp":
        var_program = compile_ast(
            value.get("var"), bindings, features, symbols, values, functions
        )
        if var_program is None:
            raise TreeError("empty SquareOp variable")
        result.extend(var_program)
        arguments = value.get("arguments", [])
        for argument in arguments:
            argument_program = compile_ast(
                argument, bindings, features, symbols, values, functions
            )
            if argument_program is None:
                raise TreeError("empty SquareOp argument")
            result.extend(argument_program)
        result.append((BC_OPCODE["SQUARE"], len(arguments), 0))
    elif node_type == "AST.UnaryOp":
        op = str(value.get("op", ""))
        if op not in UNARY_OPCODE:
            raise TreeError(f"unsupported unary operator {op!r}")
        child_program = compile_ast(
            value.get("expr"), bindings, features, symbols, values, functions
        )
        if child_program is None:
            raise TreeError("empty unary expression")
        result.extend(child_program)
        result.append((UNARY_OPCODE[op], 0, 0))
    elif node_type == "AST.BinaryOp":
        op = str(value.get("op", ""))
        if op not in BINARY_OPCODE:
            raise TreeError(f"unsupported binary operator {op!r}")
        for key in ("left", "right"):
            child_program = compile_ast(
                value.get(key), bindings, features, symbols, values, functions
            )
            if child_program is None:
                raise TreeError("empty binary expression")
            result.extend(child_program)
        result.append((BINARY_OPCODE[op], 0, 0))
    elif node_type == "AST.Function":
        name = str(value.get("name", ""))
        parameters = value.get("parameters", [])
        arguments = value.get("arguments", [])
        for child in [*parameters, *arguments]:
            child_program = compile_ast(
                child, bindings, features, symbols, values, functions
            )
            if child_program is None:
                raise TreeError("empty function operand")
            result.extend(child_program)
        packed_counts = (len(parameters) << 16) | len(arguments)
        result.append((BC_OPCODE["CALL"], functions[name], packed_counts))
    else:
        raise TreeError(f"unsupported AST node type {node_type!r}")
    return tuple(result)


def attach_compiled_metadata(
    nodes: list[dict[str, Any]], aliases: list[dict[str, Any]], inventory: dict[str, Any]
) -> tuple[
    list[dict[str, Any]],
    list[tuple[int, int, int]],
    dict[str, list[str]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    pool_names = {
        "features": sorted(inventory["feature_counts"]),
        "symbols": sorted(inventory["symbol_counts"]),
        "values": sorted(inventory["value_counts"]),
        "functions": sorted(inventory["function_counts"]),
    }
    pool_ids = {
        category: {name: index for index, name in enumerate(names)}
        for category, names in pool_names.items()
    }

    raw_programs: list[tuple[tuple[int, int, int], ...]] = []
    for node in nodes:
        condition = compile_ast(
            node["condition_ast"], node["bindings"], **pool_ids
        )
        assertions = compile_ast(
            node["assertions_ast"], node["bindings"], **pool_ids
        )
        node["condition_program_raw"] = condition
        node["assertion_program_raw"] = assertions
        if condition is not None:
            raw_programs.append(condition)
        if assertions is not None:
            raw_programs.append(assertions)
    for alias in aliases:
        condition = compile_ast(
            alias["condition_ast"], alias["bindings"], **pool_ids
        )
        preferred = compile_ast(
            alias["preferred_ast"], alias["bindings"], **pool_ids
        )
        alias["condition_program_raw"] = condition
        alias["preferred_program_raw"] = preferred
        if condition is not None:
            raw_programs.append(condition)
        if preferred is not None:
            raw_programs.append(preferred)

    unique_programs = sorted(set(raw_programs))
    program_ids = {program: index for index, program in enumerate(unique_programs)}
    bytecode: list[tuple[int, int, int]] = []
    programs: list[dict[str, Any]] = []
    for program_id, program in enumerate(unique_programs):
        first = len(bytecode)
        bytecode.extend(program)
        programs.append(
            {
                "program_id": program_id,
                "first_instruction": first,
                "instruction_count": len(program),
                "digest": value_digest(program),
            }
        )
    for node in nodes:
        raw = node.pop("condition_program_raw")
        node["condition_program_id"] = NONE if raw is None else program_ids[raw]
        raw = node.pop("assertion_program_raw")
        node["assertion_program_id"] = NONE if raw is None else program_ids[raw]
    for alias in aliases:
        raw = alias.pop("condition_program_raw")
        alias["condition_program_id"] = NONE if raw is None else program_ids[raw]
        raw = alias.pop("preferred_program_raw")
        alias["preferred_program_id"] = NONE if raw is None else program_ids[raw]

    binding_keys = {
        canonical_json(
            [
                {"name": name, "start": start, "width": width}
                for name, (start, width) in sorted(record["bindings"].items())
            ]
        )
        for record in nodes
    }
    sorted_binding_keys = sorted(binding_keys)
    binding_set_ids = {key: index for index, key in enumerate(sorted_binding_keys)}
    binding_entries: list[dict[str, Any]] = []
    binding_sets: list[dict[str, Any]] = []
    for binding_set_id, key in enumerate(sorted_binding_keys):
        entries = json.loads(key)
        first = len(binding_entries)
        for entry in entries:
            binding_entries.append({"binding_set_id": binding_set_id, **entry})
        binding_sets.append(
            {
                "binding_set_id": binding_set_id,
                "first_binding": first,
                "binding_count": len(entries),
                "digest": value_digest(entries),
            }
        )
    for node in nodes:
        key = canonical_json(
            [
                {"name": name, "start": start, "width": width}
                for name, (start, width) in sorted(node.pop("bindings").items())
            ]
        )
        node["binding_set_id"] = binding_set_ids[key]
    for alias in aliases:
        alias.pop("bindings")
    return programs, bytecode, pool_names, binding_sets, binding_entries


def validate_tree(
    nodes: list[dict[str, Any]],
    leaves: list[dict[str, Any]],
    aliases: list[dict[str, Any]],
    roots: list[int],
    programs: list[dict[str, Any]],
    bytecode: list[tuple[int, int, int]],
    binding_sets: list[dict[str, Any]],
    binding_entries: list[dict[str, Any]],
    pools: dict[str, list[str]],
) -> dict[str, Any]:
    expected = {"nodes": 7592, "leaves": 6569, "aliases": 611, "roots": 3}
    actual = {
        "nodes": len(nodes),
        "leaves": len(leaves),
        "aliases": len(aliases),
        "roots": len(roots),
    }
    if actual != expected:
        raise TreeError(f"pinned topology count mismatch: expected {expected}, got {actual}")
    group_count = sum(1 for node in nodes if node["kind"] == 1)
    if group_count != 1020:
        raise TreeError(f"expected 1020 groups, got {group_count}")

    visited: set[int] = set()

    def visit_siblings(index: int, expected_parent: int) -> None:
        sibling_seen: set[int] = set()
        while index != NONE:
            if index >= len(nodes) or index in sibling_seen or index in visited:
                raise TreeError(f"invalid/cyclic topology at node {index}")
            sibling_seen.add(index)
            visited.add(index)
            node = nodes[index]
            if node["parent"] != expected_parent:
                raise TreeError(f"parent mismatch at node {index}")
            if node["first_child"] != NONE:
                visit_siblings(node["first_child"], index)
            index = node["next_sibling"]

    # Roots are linked as siblings; entering at the first traverses all three.
    visit_siblings(roots[0], NONE)
    if len(visited) != len(nodes):
        raise TreeError(f"topology reached {len(visited)} of {len(nodes)} nodes")
    if roots != [node["node_index"] for node in nodes if node["parent"] == NONE]:
        raise TreeError("root index list does not match topology")

    for index, leaf in enumerate(leaves):
        if leaf["leaf_index"] != index:
            raise TreeError("non-contiguous leaf indexes")
        if leaf["form_id"] != index + 1:
            raise TreeError("Arm form IDs must be contiguous and 1-based")
        node = nodes[leaf["node_index"]]
        if node["kind"] != 2 or node["leaf_index"] != index:
            raise TreeError(f"leaf/node back-reference mismatch at leaf {index}")
        if leaf["alias_start"] + leaf["alias_count"] > len(aliases):
            raise TreeError(f"alias span out of range at leaf {index}")
    for index, alias in enumerate(aliases):
        if alias["alias_index"] != index or alias["leaf_index"] >= len(leaves):
            raise TreeError(f"alias reference mismatch at alias {index}")

    for node in nodes:
        width_mask = (1 << node["width"]) - 1
        for key in ("local_mask_int", "local_value_int", "resolved_mask_int", "resolved_value_int"):
            if node[key] & ~width_mask:
                raise TreeError(f"{key} exceeds width at node {node['node_index']}")
        if node["local_value_int"] & ~node["local_mask_int"]:
            raise TreeError(f"local value outside mask at node {node['node_index']}")
        if node["resolved_value_int"] & ~node["resolved_mask_int"]:
            raise TreeError(f"resolved value outside mask at node {node['node_index']}")
        if node["binding_set_id"] >= len(binding_sets):
            raise TreeError(f"binding set out of range at node {node['node_index']}")
        for key in ("condition_program_id", "assertion_program_id"):
            if node[key] != NONE and node[key] >= len(programs):
                raise TreeError(f"program out of range at node {node['node_index']}")
    for alias in aliases:
        for key in ("condition_program_id", "preferred_program_id"):
            if alias[key] != NONE and alias[key] >= len(programs):
                raise TreeError(f"program out of range at alias {alias['alias_index']}")
    for binding_set in binding_sets:
        if binding_set["first_binding"] + binding_set["binding_count"] > len(binding_entries):
            raise TreeError("binding span out of range")
    for program in programs:
        if program["first_instruction"] + program["instruction_count"] > len(bytecode):
            raise TreeError("bytecode span out of range")
    for opcode, a, _b in bytecode:
        if opcode == BC_OPCODE["PUSH_FEATURE"] and a >= len(pools["features"]):
            raise TreeError("feature pool reference out of range")
        if opcode == BC_OPCODE["PUSH_SYMBOL"] and a >= len(pools["symbols"]):
            raise TreeError("symbol pool reference out of range")
        if opcode == BC_OPCODE["PUSH_VALUE"] and a >= len(pools["values"]):
            raise TreeError("value pool reference out of range")
        if opcode == BC_OPCODE["CALL"] and a >= len(pools["functions"]):
            raise TreeError("function pool reference out of range")

    known_word = int.from_bytes(bytes.fromhex("20284393"), "little")
    known = next(
        node
        for node in nodes
        if node["path"].endswith("/SBFM_64M_bitfield")
    )
    if known_word & known["resolved_mask_int"] != known["resolved_value_int"]:
        raise TreeError("known SBFM word does not satisfy its resolved encoding")
    return {
        "expected_counts": expected,
        "actual_counts": actual,
        "group_count": group_count,
        "topology_nodes_visited": len(visited),
        "known_probe": {
            "bytes_little_endian": "20284393",
            "form_id": known["path"],
            "resolved_mask_match": True,
        },
        "reference_bounds_checked": True,
    }


def write_tsv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=fields,
            dialect="excel-tab",
            extrasaction="ignore",
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)


class StringPool:
    def __init__(self, strings: Iterable[str]):
        ordered = [""] + sorted(set(strings) - {""})
        self.offsets: dict[str, int] = {}
        data = bytearray()
        for value in ordered:
            self.offsets[value] = len(data)
            data.extend(value.encode("utf-8"))
            data.append(0)
        self.data = bytes(data)

    def offset(self, value: str) -> int:
        return self.offsets[value]


def c_u32(value: int) -> str:
    return f"UINT32_C({value})"


def emit_rows(
    output: list[str], declaration: str, rows: Iterable[str]
) -> None:
    output.append(declaration + " = {")
    output.extend(f"    {row}," for row in rows)
    output.append("};")
    output.append("")


def c_identifier(value: str) -> str:
    result = "".join(character if character.isalnum() else "_" for character in value)
    if not result or result[0].isdigit():
        result = "_" + result
    return result.upper()


def numeric_value_record(raw: str) -> tuple[int, int, int]:
    bits = raw.strip("'")
    if not bits or any(bit not in "01x" for bit in bits):
        raise TreeError(f"unsupported Values.Value bit pattern {raw!r}")
    mask = 0
    value = 0
    for bit in bits:
        mask <<= 1
        value <<= 1
        if bit != "x":
            mask |= 1
            if bit == "1":
                value |= 1
    return mask, value, len(bits)


def emit_c_includes(
    decode_path: Path,
    text_path: Path,
    nodes: list[dict[str, Any]],
    leaves: list[dict[str, Any]],
    aliases: list[dict[str, Any]],
    roots: list[int],
    programs: list[dict[str, Any]],
    bytecode: list[tuple[int, int, int]],
    pools: dict[str, list[str]],
    binding_sets: list[dict[str, Any]],
    binding_entries: list[dict[str, Any]],
) -> None:
    source_names = sorted(
        {node["name"] for node in nodes}
        | {leaf["internal_name"] for leaf in leaves}
        | {alias["internal_name"] for alias in aliases}
    )
    source_name_ids = {name: index for index, name in enumerate(source_names)}
    field_names = sorted({entry["name"] for entry in binding_entries})
    field_name_ids = {name: index for index, name in enumerate(field_names)}
    mnemonics = sorted(
        {leaf["mnemonic"] for leaf in leaves}
        | {alias["mnemonic"] for alias in aliases}
    )
    mnemonic_ids = {name: index for index, name in enumerate(mnemonics)}

    decode = [
        "/* Generated numeric-only ARM decode inventory. Do not edit. */",
        "/* Contains no runtime strings and is not connected to the decoder. */",
        "#ifndef CDISASM_ARM_ISA_DECODE_GENERATED_INC",
        "#define CDISASM_ARM_ISA_DECODE_GENERATED_INC",
        "#include <stdint.h>",
        "#define CDISASM_ARM_GEN_NONE UINT32_C(4294967295)",
        f"#define CDISASM_ARM_GEN_FORM_ID_COUNT UINT16_C({len(leaves)})",
        f"#define CDISASM_ARM_GEN_NODE_COUNT UINT32_C({len(nodes)})",
        f"#define CDISASM_ARM_GEN_FEATURE_COUNT UINT32_C({len(pools['features'])})",
        f"#define CDISASM_ARM_GEN_SPECIAL_SYMBOL_COUNT UINT32_C({len(pools['symbols'])})",
        f"#define CDISASM_ARM_GEN_FUNCTION_COUNT UINT32_C({len(pools['functions'])})",
        f"#define CDISASM_ARM_GEN_VALUE_COUNT UINT32_C({len(pools['values'])})",
        f"#define CDISASM_ARM_GEN_SOURCE_NAME_COUNT UINT32_C({len(source_names)})",
        f"#define CDISASM_ARM_GEN_FIELD_SYMBOL_COUNT UINT32_C({len(field_names)})",
        f"#define CDISASM_ARM_GEN_MNEMONIC_COUNT UINT16_C({len(mnemonics)})",
        "enum cdisasm_arm_gen_node_kind { CDISASM_ARM_GEN_SET = 0, CDISASM_ARM_GEN_GROUP = 1, CDISASM_ARM_GEN_LEAF = 2 };",
        "enum cdisasm_arm_gen_instruction_set { CDISASM_ARM_GEN_A32 = 0, CDISASM_ARM_GEN_T32 = 1, CDISASM_ARM_GEN_A64 = 2 };",
        "enum cdisasm_arm_gen_bc_opcode {",
    ]
    for name, opcode in sorted(BC_OPCODE.items(), key=lambda item: item[1]):
        decode.append(f"    CDISASM_ARM_GEN_BC_{name} = {opcode},")
    decode.extend(["};", "enum cdisasm_arm_gen_feature_id {"])
    for index, name in enumerate(pools["features"]):
        decode.append(f"    CDISASM_ARM_GEN_FEATURE_{c_identifier(name)} = {index},")
    decode.extend(["};", "enum cdisasm_arm_gen_special_symbol_id {"])
    for index, name in enumerate(pools["symbols"]):
        decode.append(f"    CDISASM_ARM_GEN_SYMBOL_{c_identifier(name)} = {index},")
    decode.extend(["};", "enum cdisasm_arm_gen_function_id {"])
    for index, name in enumerate(pools["functions"]):
        decode.append(f"    CDISASM_ARM_GEN_FUNCTION_{c_identifier(name)} = {index},")
    decode.extend(
        [
            "};",
            "typedef struct cdisasm_arm_gen_node {",
            "    uint32_t source_name_id, parent, first_child, next_sibling, leaf_index;",
            "    uint32_t binding_set_id, condition_program_id, assertion_program_id;",
            "    uint32_t local_mask, local_value, resolved_mask, resolved_value;",
            "    uint16_t width, child_count; uint8_t kind, instruction_set;",
            "} cdisasm_arm_gen_node;",
            "typedef struct cdisasm_arm_gen_leaf {",
            "    uint32_t node_index, alias_start, alias_count; uint16_t form_id, mnemonic_pool_id;",
            "} cdisasm_arm_gen_leaf;",
            "typedef struct cdisasm_arm_gen_alias {",
            "    uint32_t leaf_index, source_name_id, condition_program_id, preferred_program_id; uint16_t mnemonic_pool_id;",
            "} cdisasm_arm_gen_alias;",
            "typedef struct cdisasm_arm_gen_program { uint32_t first_instruction, instruction_count; } cdisasm_arm_gen_program;",
            "typedef struct cdisasm_arm_gen_bc { uint8_t opcode; int32_t a, b; } cdisasm_arm_gen_bc;",
            "typedef struct cdisasm_arm_gen_binding_set { uint32_t first_binding, binding_count; } cdisasm_arm_gen_binding_set;",
            "typedef struct cdisasm_arm_gen_binding { uint16_t field_symbol_id; uint8_t start, width; } cdisasm_arm_gen_binding;",
            "typedef struct cdisasm_arm_gen_value { uint32_t value, mask; uint8_t width; } cdisasm_arm_gen_value;",
            "",
        ]
    )
    emit_rows(
        decode,
        "static const uint32_t cdisasm_arm_gen_roots[3]",
        (c_u32(root) for root in roots),
    )
    emit_rows(
        decode,
        f"static const cdisasm_arm_gen_node cdisasm_arm_gen_nodes[{len(nodes)}]",
        (
            "{" + ", ".join(
                [
                    c_u32(source_name_ids[node["name"]]),
                    c_u32(node["parent"]),
                    c_u32(node["first_child"]),
                    c_u32(node["next_sibling"]),
                    c_u32(node["leaf_index"]),
                    c_u32(node["binding_set_id"]),
                    c_u32(node["condition_program_id"]),
                    c_u32(node["assertion_program_id"]),
                    f"UINT32_C(0x{node['local_mask_int']:08x})",
                    f"UINT32_C(0x{node['local_value_int']:08x})",
                    f"UINT32_C(0x{node['resolved_mask_int']:08x})",
                    f"UINT32_C(0x{node['resolved_value_int']:08x})",
                    str(node["width"]),
                    str(node["child_count"]),
                    str(node["kind"]),
                    str(node["instruction_set"]),
                ]
            ) + "}"
            for node in nodes
        ),
    )
    emit_rows(
        decode,
        f"static const cdisasm_arm_gen_leaf cdisasm_arm_gen_leaves[{len(leaves)}]",
        (
            "{" + ", ".join(
                [
                    c_u32(leaf["node_index"]),
                    c_u32(leaf["alias_start"]),
                    c_u32(leaf["alias_count"]),
                    f"UINT16_C({leaf['form_id']})",
                    f"UINT16_C({mnemonic_ids[leaf['mnemonic']]})",
                ]
            ) + "}"
            for leaf in leaves
        ),
    )
    emit_rows(
        decode,
        f"static const uint32_t cdisasm_arm_gen_form_to_leaf[{len(leaves) + 1}]",
        [c_u32(NONE)] + [c_u32(index) for index in range(len(leaves))],
    )
    emit_rows(
        decode,
        f"static const uint16_t cdisasm_arm_gen_leaf_to_form[{len(leaves)}]",
        (f"UINT16_C({index + 1})" for index in range(len(leaves))),
    )
    emit_rows(
        decode,
        f"static const cdisasm_arm_gen_alias cdisasm_arm_gen_aliases[{len(aliases)}]",
        (
            "{" + ", ".join(
                [
                    c_u32(alias["leaf_index"]),
                    c_u32(source_name_ids[alias["internal_name"]]),
                    c_u32(alias["condition_program_id"]),
                    c_u32(alias["preferred_program_id"]),
                    f"UINT16_C({mnemonic_ids[alias['mnemonic']]})",
                ]
            ) + "}"
            for alias in aliases
        ),
    )
    emit_rows(
        decode,
        f"static const cdisasm_arm_gen_program cdisasm_arm_gen_programs[{len(programs)}]",
        (
            "{" + f"{c_u32(program['first_instruction'])}, {c_u32(program['instruction_count'])}" + "}"
            for program in programs
        ),
    )
    emit_rows(
        decode,
        f"static const cdisasm_arm_gen_bc cdisasm_arm_gen_bytecode[{len(bytecode)}]",
        ("{" + f"{opcode}, {a}, {b}" + "}" for opcode, a, b in bytecode),
    )
    emit_rows(
        decode,
        f"static const cdisasm_arm_gen_binding_set cdisasm_arm_gen_binding_sets[{len(binding_sets)}]",
        (
            "{" + f"{c_u32(record['first_binding'])}, {c_u32(record['binding_count'])}" + "}"
            for record in binding_sets
        ),
    )
    emit_rows(
        decode,
        f"static const cdisasm_arm_gen_binding cdisasm_arm_gen_bindings[{len(binding_entries)}]",
        (
            "{" + f"UINT16_C({field_name_ids[record['name']]}), {record['start']}, {record['width']}" + "}"
            for record in binding_entries
        ),
    )
    emit_rows(
        decode,
        f"static const cdisasm_arm_gen_value cdisasm_arm_gen_values[{len(pools['values'])}]",
        (
            "{" + f"UINT32_C(0x{value:x}), UINT32_C(0x{mask:x}), {width}" + "}"
            for mask, value, width in (numeric_value_record(raw) for raw in pools["values"])
        ),
    )
    decode.extend(["#endif", ""])
    decode_path.parent.mkdir(parents=True, exist_ok=True)
    decode_path.write_text("\n".join(decode), encoding="ascii", newline="\n")

    strings: list[str] = []
    for node in nodes:
        strings.append(node["name"])
    for leaf in leaves:
        strings.extend(
            [
                leaf["internal_name"],
                leaf["mnemonic"],
                leaf["assembly_template"],
                leaf["operation_id"],
                leaf["source_form_id"],
            ]
        )
    for alias in aliases:
        strings.extend(
            [
                alias["internal_name"],
                alias["mnemonic"],
                alias["assembly_template"],
                alias["operation_id"],
                alias["source_form_id"],
            ]
        )
    for names in pools.values():
        strings.extend(names)
    strings.extend(entry["name"] for entry in binding_entries)
    strings.extend(source_names)
    strings.extend(field_names)
    strings.extend(mnemonics)
    string_pool = StringPool(strings)
    out = [
        "/* Generated ARM formatter/tooling text inventory. Do not edit. */",
        "/* This file is separate from the numeric-only decode inventory. */",
        "#ifndef CDISASM_ARM_ISA_FORMAT_GENERATED_INC",
        "#define CDISASM_ARM_ISA_FORMAT_GENERATED_INC",
        "#include <stdint.h>",
        "typedef struct cdisasm_arm_gen_leaf_text { uint32_t name_offset, mnemonic_offset, assembly_offset, operation_offset, source_form_offset; } cdisasm_arm_gen_leaf_text;",
        "typedef struct cdisasm_arm_gen_alias_text { uint32_t name_offset, mnemonic_offset, assembly_offset, operation_offset, source_form_offset; } cdisasm_arm_gen_alias_text;",
        "",
    ]
    emit_rows(
        out,
        f"static const uint32_t cdisasm_arm_gen_source_names[{len(source_names)}]",
        (c_u32(string_pool.offset(name)) for name in source_names),
    )
    emit_rows(
        out,
        f"static const uint32_t cdisasm_arm_gen_field_names[{len(field_names)}]",
        (c_u32(string_pool.offset(name)) for name in field_names),
    )
    emit_rows(
        out,
        f"static const uint32_t cdisasm_arm_gen_mnemonics[{len(mnemonics)}]",
        (c_u32(string_pool.offset(name)) for name in mnemonics),
    )
    emit_rows(
        out,
        f"static const cdisasm_arm_gen_leaf_text cdisasm_arm_gen_leaf_texts[{len(leaves)}]",
        (
            "{" + ", ".join(
                c_u32(string_pool.offset(value))
                for value in (
                    leaf["internal_name"],
                    leaf["mnemonic"],
                    leaf["assembly_template"],
                    leaf["operation_id"],
                    leaf["source_form_id"],
                )
            ) + "}"
            for leaf in leaves
        ),
    )
    emit_rows(
        out,
        f"static const cdisasm_arm_gen_alias_text cdisasm_arm_gen_alias_texts[{len(aliases)}]",
        (
            "{" + ", ".join(
                c_u32(string_pool.offset(value))
                for value in (
                    alias["internal_name"],
                    alias["mnemonic"],
                    alias["assembly_template"],
                    alias["operation_id"],
                    alias["source_form_id"],
                )
            ) + "}"
            for alias in aliases
        ),
    )
    for category in ("features", "symbols", "values", "functions"):
        names = pools[category]
        emit_rows(
            out,
            f"static const uint32_t cdisasm_arm_gen_{category}_text_offsets[{len(names)}]",
            (c_u32(string_pool.offset(name)) for name in names),
        )
    out.append(
        f"static const unsigned char cdisasm_arm_gen_strings[{len(string_pool.data)}] = {{"
    )
    for start in range(0, len(string_pool.data), 16):
        chunk = string_pool.data[start : start + 16]
        out.append("    " + ", ".join(f"0x{byte:02x}" for byte in chunk) + ",")
    out.extend(["};", "#endif", ""])
    text_path.parent.mkdir(parents=True, exist_ok=True)
    text_path.write_text("\n".join(out), encoding="ascii", newline="\n")


def prepare_tsv_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for node in nodes:
        result.append(
            {
                **node,
                "local_mask": f"0x{node['local_mask_int']:08x}",
                "local_value": f"0x{node['local_value_int']:08x}",
                "resolved_mask": f"0x{node['resolved_mask_int']:08x}",
                "resolved_value": f"0x{node['resolved_value_int']:08x}",
            }
        )
    return result


def main() -> int:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arm-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=script_dir / "generated")
    parser.add_argument(
        "--decode-include",
        type=Path,
        default=repo_root / "src" / "arm" / "generated" / "cdisasm_arm_isa_decode.inc",
    )
    parser.add_argument(
        "--text-include",
        type=Path,
        default=repo_root / "src" / "arm" / "generated" / "cdisasm_arm_isa_format.inc",
    )
    parser.add_argument("--allow-source-drift", action="store_true")
    arguments = parser.parse_args()
    arm_root = arguments.arm_root.resolve()
    output_dir = arguments.output_dir.resolve()
    decode_include = arguments.decode_include.resolve()
    text_include = arguments.text_include.resolve()
    baseline_path = repo_root / "tools" / "coverage" / "baselines.json"
    baseline = load_json(baseline_path)["arm_aarchmrs"]
    actual_commit = git_head(arm_root)
    if actual_commit != baseline["commit"] and not arguments.allow_source_drift:
        raise TreeError(
            f"Arm commit mismatch: expected {baseline['commit']}, got "
            f"{actual_commit or 'not a Git checkout'}"
        )
    inventory_path = arm_root / baseline["inventory_file"]
    document = load_json(inventory_path)
    version = (document.get("_meta") or {}).get("version") or {}
    expected_version = {
        "architecture": baseline["architecture_revision"],
        "ref": baseline["data_ref"],
        "build": baseline["build"],
        "schema": baseline["schema"],
        "timestamp": baseline["data_timestamp"],
    }
    if any(str(version.get(key)) != str(value) for key, value in expected_version.items()):
        if not arguments.allow_source_drift:
            raise TreeError(
                f"Arm metadata mismatch: expected {expected_version}, got {version}"
            )

    nodes, leaves, aliases, roots = make_tree(document)
    inventory = ast_inventory(nodes, aliases)
    programs, bytecode, pools, binding_sets, binding_entries = attach_compiled_metadata(
        nodes, aliases, inventory
    )
    validation = validate_tree(
        nodes,
        leaves,
        aliases,
        roots,
        programs,
        bytecode,
        binding_sets,
        binding_entries,
        pools,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    node_path = output_dir / "arm_tree_nodes.tsv"
    leaf_path = output_dir / "arm_tree_leaves.tsv"
    alias_path = output_dir / "arm_tree_aliases.tsv"
    program_path = output_dir / "arm_tree_programs.tsv"
    bytecode_path = output_dir / "arm_tree_bytecode.tsv"
    binding_set_path = output_dir / "arm_tree_binding_sets.tsv"
    binding_path = output_dir / "arm_tree_bindings.tsv"
    pool_path = output_dir / "arm_tree_pools.json"
    manifest_path = output_dir / "arm_tree_manifest.json"

    write_tsv(
        node_path,
        prepare_tsv_nodes(nodes),
        [
            "node_index",
            "parent",
            "first_child",
            "next_sibling",
            "child_count",
            "kind",
            "kind_name",
            "instruction_set",
            "instruction_set_name",
            "width",
            "local_mask",
            "local_value",
            "resolved_mask",
            "resolved_value",
            "name",
            "path",
            "binding_set_id",
            "condition_program_id",
            "assertion_program_id",
            "condition_digest",
            "assertions_digest",
            "leaf_index",
        ],
    )
    write_tsv(
        leaf_path,
        leaves,
        [
            "leaf_index",
            "form_id",
            "node_index",
            "internal_name",
            "mnemonic",
            "assembly_template",
            "operation_id",
            "alias_start",
            "alias_count",
            "source_form_id",
        ],
    )
    write_tsv(
        alias_path,
        aliases,
        [
            "alias_index",
            "leaf_index",
            "form_id",
            "internal_name",
            "mnemonic",
            "assembly_template",
            "operation_id",
            "condition_program_id",
            "preferred_program_id",
            "condition_digest",
            "preferred_digest",
            "source_form_id",
        ],
    )
    write_tsv(
        program_path,
        programs,
        ["program_id", "first_instruction", "instruction_count", "digest"],
    )
    write_tsv(
        bytecode_path,
        [
            {"instruction_index": index, "opcode": opcode, "a": a, "b": b}
            for index, (opcode, a, b) in enumerate(bytecode)
        ],
        ["instruction_index", "opcode", "a", "b"],
    )
    write_tsv(
        binding_set_path,
        binding_sets,
        ["binding_set_id", "first_binding", "binding_count", "digest"],
    )
    write_tsv(
        binding_path,
        binding_entries,
        ["binding_set_id", "name", "start", "width"],
    )
    with pool_path.open("w", encoding="utf-8", newline="\n") as stream:
        source_names = sorted(
            {node["name"] for node in nodes}
            | {leaf["internal_name"] for leaf in leaves}
            | {alias["internal_name"] for alias in aliases}
        )
        field_symbols = sorted({entry["name"] for entry in binding_entries})
        mnemonics = sorted(
            {leaf["mnemonic"] for leaf in leaves}
            | {alias["mnemonic"] for alias in aliases}
        )
        json.dump(
            {
                "schema_version": SCHEMA_VERSION,
                "bytecode_opcodes": BC_OPCODE,
                "source_names": source_names,
                "field_symbols": field_symbols,
                "mnemonics": mnemonics,
                **pools,
            },
            stream,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        stream.write("\n")

    emit_c_includes(
        decode_include,
        text_include,
        nodes,
        leaves,
        aliases,
        roots,
        programs,
        bytecode,
        pools,
        binding_sets,
        binding_entries,
    )
    artifacts = [
        node_path,
        leaf_path,
        alias_path,
        program_path,
        bytecode_path,
        binding_set_path,
        binding_path,
        pool_path,
        decode_include,
        text_include,
    ]
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "generator_version": GENERATOR_VERSION,
        "source": {
            **baseline,
            "observed_commit": actual_commit,
            "instructions_sha256": file_digest(inventory_path),
            "generator_sha256": file_digest(Path(__file__).resolve()),
            "source_drift_allowed": arguments.allow_source_drift,
        },
        "counts": {
            "roots": len(roots),
            "nodes": len(nodes),
            "groups": sum(1 for node in nodes if node["kind"] == 1),
            "leaves": len(leaves),
            "aliases": len(aliases),
            "binding_sets": len(binding_sets),
            "binding_entries": len(binding_entries),
            "programs": len(programs),
            "bytecode_instructions": len(bytecode),
            "assertion_program_references": sum(
                node["assertion_program_id"] != NONE for node in nodes
            ),
            "leaf_assertion_field_null": sum(
                node["kind"] == 2 and node["assertions_ast"] is None
                for node in nodes
            ),
            "leaf_assertion_field_nonnull": sum(
                node["kind"] == 2 and node["assertions_ast"] is not None
                for node in nodes
            ),
        },
        "ast_inventory": inventory,
        "validation": validation,
        "bytecode": {
            "format": "postfix stack machine; each instruction is (opcode,a,b)",
            "call_b": "high 16 bits parameter count, low 16 bits argument count",
            "field_resolution": "PUSH_FIELD embeds inherited encoding-field start and width",
            "special_symbols": pools["symbols"],
            "outside_closed_evaluator_preserved": True,
            "assertion_boundary": "all 6,569 pinned canonical leaf assertion fields are explicitly null; any future non-null AST is compiled or generation fails",
        },
        "integration": {
            "wired_into_decoder": False,
            "alias_preference_separate": True,
            "contains_prose_or_pseudocode": False,
        },
        "artifacts": {
            path.name: {
                "path": str(path.relative_to(repo_root)).replace("\\", "/")
                if path.is_relative_to(repo_root)
                else str(path),
                "bytes": path.stat().st_size,
                "sha256": file_digest(path),
            }
            for path in artifacts
        },
    }
    with manifest_path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, ensure_ascii=True, indent=2, sort_keys=True)
        stream.write("\n")
    print(
        f"Arm tree: {len(roots)} roots, {len(nodes)} nodes, {len(leaves)} leaves, "
        f"{len(aliases)} aliases"
    )
    print(
        f"AST: {len(programs)} programs, {len(bytecode)} instructions, "
        f"{len(binding_sets)} binding sets"
    )
    print(f"wrote {manifest_path}, {decode_include}, and {text_include}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TreeError as error:
        print(f"Arm tree generation failed: {error}", file=sys.stderr)
        raise SystemExit(2)
