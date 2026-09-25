"""Executable boundary tests for reviewed ARM assembly split fields."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools/isa_codegen"))
import generate_arm_assembly_catalog as catalog  # noqa: E402


class SplitFieldTests(unittest.TestCase):
    def fixture(self, shape, display, size_pattern=None):
        source = {"_meta": {"encoded_in": {
            display: [{"_type": "AST.Identifier", "value": name}
                      for name, _start, _width in shape]
        }}, "encoding": {"values": []}}
        if size_pattern is not None:
            source["encoding"]["values"].append({
                "_type": "Instruction.Encodeset.Field",
                "name": "size",
                "value": {"value": size_pattern},
            })
        bindings = {name: (start, width) for name, start, width in shape}
        expressions = [
            ((catalog.tree.BC_OPCODE["PUSH_FIELD"], start, width),)
            for _name, start, width in shape
        ]
        return source, bindings, expressions

    def test_split_lane_indexes(self):
        for (rule_id, display), shape in catalog.REVIEWED_SPLIT_FIELDS.items():
            if rule_id in {"index", "index__3"}:
                continue
            with self.subTest(rule=rule_id):
                source, bindings, expressions = self.fixture(shape, display)
                result = catalog.reviewed_split_field_value(
                    rule_id, display, source, bindings, expressions
                )
                self.assertEqual(
                    result, catalog.concatenate_encoded_expressions(expressions)
                )
                self.assertIsNone(catalog.reviewed_split_field_value(
                    rule_id, display, source,
                    {**bindings, shape[0][0]: (shape[0][1] + 1, shape[0][2])},
                    expressions,
                ))

    def test_a64_lane_index_bit_selection(self):
        for rule_id, names, size_pattern, expected_width in (
            ("index", ("Q", "S", "size"), "'xx'", 4),
            ("index__2", ("Q", "S", "size"), "'x0'", 3),
            ("index__3", ("Q", "S"), "'00'", 2),
        ):
            shape = tuple((name, {"Q": 30, "S": 12, "size": 10}[name],
                           {"Q": 1, "S": 1, "size": 2}[name])
                          for name in names)
            source, bindings, expressions = self.fixture(
                shape, "<index>", size_pattern
            )
            result = catalog.reviewed_split_field_value(
                rule_id, "<index>", source, bindings, expressions
            )
            self.assertEqual(catalog.direct_program_width(result), expected_width)
            if rule_id == "index__2":
                self.assertIn(
                    (catalog.tree.BC_OPCODE["PUSH_FIELD"], 11, 1), result
                )
                self.assertNotIn(
                    (catalog.tree.BC_OPCODE["PUSH_FIELD"], 10, 2), result
                )
            source["encoding"]["values"][0]["value"]["value"] = "'xx'"
            if rule_id != "index":
                self.assertIsNone(catalog.reviewed_split_field_value(
                    rule_id, "<index>", source, bindings, expressions
                ))

    def test_unreviewed_and_reordered_fields_stay_opaque(self):
        shape = (("T", 4, 1), ("Zt", 0, 3))
        source, bindings, expressions = self.fixture(shape, "<Zt1>")
        self.assertIsNone(catalog.reviewed_split_field_value(
            "Zt1__3", "<Zt1>", source, bindings, expressions
        ))
        shape = (("K", 12, 1), ("Zk", 10, 2))
        source, bindings, expressions = self.fixture(shape, "<Zk>")
        self.assertIsNone(catalog.reviewed_split_field_value(
            "Zk__2", "<Zk>", source, bindings, expressions
        ))
        shape = catalog.REVIEWED_SPLIT_FIELDS[("index__20", "<index>")]
        source, bindings, expressions = self.fixture(shape, "<index>")
        source["_meta"]["encoded_in"]["<index>"].reverse()
        self.assertIsNone(catalog.reviewed_split_field_value(
            "index__20", "<index>", source, bindings, expressions
        ))

    def test_sme_grouped_registers(self):
        for rule_id, (stride, ordinal, display) in (
                catalog.GROUPED_ZREG_RULES.items()):
            with self.subTest(rule=rule_id):
                rule = {
                    "_type": "Instruction.Rules.Rule", "display": display,
                    "symbols": {"symbols": [
                        {"_type": "Instruction.Symbols.Literal", "value": "Z"},
                        {"_type": "Instruction.Symbols.RuleReference",
                         "rule_id": "UInteger"},
                    ]},
                }
                source = {
                    "name": "ld1b_mzx_p_br_2x8" if stride == 8
                            else "ld1b_mzx_p_br_4x4",
                    "_meta": {"encoded_in": {display: [
                        {"_type": "AST.Identifier", "value": "T"},
                        {"_type": "AST.Identifier", "value": "Zt"},
                    ]}},
                    "encoding": {"values": [
                        {"_type": "Instruction.Encodeset.Field",
                         "name": name, "value": {"value": value}}
                        for name, value in (
                            ("T", "'x'"),
                            ("Zt", "'xxx'" if stride == 8 else "'xx'"),
                            ("N", "'0'"),
                            *(([("op2", "'0'")] if stride == 4 else [])),
                        )
                    ]},
                }
                bindings = {"T": (4, 1), "Zt": (0, 3 if stride == 8 else 2),
                            "N": (3, 1)}
                self.assertEqual(catalog.reviewed_grouped_zreg(
                    rule_id, rule, source, bindings),
                    stride | (ordinal << 8))
                self.assertIsNone(catalog.reviewed_grouped_zreg(
                    rule_id, rule, source, {**bindings, "T": (3, 1)}))
                source["_meta"]["encoded_in"][display][0]["value"] = "N"
                self.assertIsNone(catalog.reviewed_grouped_zreg(
                    rule_id, rule, source, bindings))

    def test_sme_predicate_group_is_not_raw_pn_number(self):
        rule = {
            "_type": "Instruction.Rules.Rule", "display": "<PNg>",
            "symbols": {"symbols": [
                {"_type": "Instruction.Symbols.Literal", "value": "PN"},
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "UInteger"},
            ]},
        }
        source = {
            "_meta": {"encoded_in": {"<PNg>": [
                {"_type": "AST.Identifier", "value": "PNg"}]}},
            "assembly": {"symbols": [
                {"_type": "Instruction.Symbols.RuleReference",
                 "rule_id": "Zt1__3"}]},
            "encoding": {"values": [
                {"_type": "Instruction.Encodeset.Field", "name": "PNg",
                 "value": {"value": "'xxx'"}}]},
        }
        self.assertTrue(catalog.reviewed_pn_group(
            "PNg", rule, source, {"PNg": (10, 3)}))
        self.assertFalse(catalog.reviewed_pn_group(
            "PNg", rule, source, {"PNg": (9, 3)}))
        source["assembly"]["symbols"][0]["rule_id"] = "Xn"
        self.assertFalse(catalog.reviewed_pn_group(
            "PNg", rule, source, {"PNg": (10, 3)}))

    def test_indexed_simd_projection_boundaries(self):
        fixtures = (
            ("Vm__5", "<m>", "SQDMLAL_asisdelem_L",
             (("size", 22, 2, "'xx'"), ("M", 20, 1, "'x'"),
              ("Rm", 16, 4, "'xxxx'")),
             [{"_type": "Instruction.Symbols.RuleReference",
               "rule_id": "UInteger"}], "A64_INDEXED_VM"),
            ("index_option", "<index>", "SQDMLAL_asisdelem_L",
             (("size", 22, 2, "'xx'"), ("H", 11, 1, "'x'"),
              ("L", 21, 1, "'x'"), ("M", 20, 1, "'x'")),
             [{"_type": "Instruction.Symbols.RuleReference",
               "rule_id": "UInteger"}], "A64_INDEXED_LANE"),
            ("Dmx__4", "<Dm[x]>", "VQDMULL_A2",
             (("M", 5, 1, "'x'"), ("Vm", 0, 4, "'xxxx'"),
              ("size", 20, 2, "'xx'")),
             [{"_type": "Instruction.Symbols.Literal", "value": "D"},
              {"_type": "Instruction.Symbols.RuleReference",
               "rule_id": "UInteger"},
              {"_type": "Instruction.Symbols.RuleReference",
               "rule_id": "Ddx_index"}], "A32_DMX_LANE"),
        )
        for rule_id, display, name, shape, symbols, opcode in fixtures:
            with self.subTest(rule=rule_id):
                rule = {"_type": "Instruction.Rules.Rule",
                        "display": display, "symbols": {"symbols": symbols}}
                source = {
                    "name": name,
                    "_meta": {"encoded_in": {display: [
                        {"_type": "AST.Identifier", "value": field}
                        for field, _start, _width, _value in shape]}},
                    "encoding": {"values": [
                        {"_type": "Instruction.Encodeset.Field",
                         "name": field, "value": {"value": value}}
                        for field, _start, _width, value in shape]},
                }
                bindings = {field: (start, width)
                            for field, start, width, _value in shape}
                self.assertEqual(catalog.reviewed_indexed_operand(
                    rule_id, rule, source, bindings), opcode)
                first_field = shape[0][0]
                self.assertIsNone(catalog.reviewed_indexed_operand(
                    rule_id, rule, source,
                    {**bindings, first_field: (0, 1)}))
                source["_meta"]["encoded_in"][display].reverse()
                self.assertIsNone(catalog.reviewed_indexed_operand(
                    rule_id, rule, source, bindings))

    def test_modified_immediate_family_boundaries(self):
        for mnemonic, variant, isa, cmode, op, family in (
            ("VMVN", 1, "A", "'0xx0'", "'1'", 1),
            ("VORR", 1, "A", "'0xx1'", "'0'", 2),
            ("VBIC", 1, "A", "'0xx1'", "'1'", 3),
            ("VMVN", 2, "A", "'10x0'", "'1'", 4),
            ("VORR", 2, "A", "'10x1'", "'0'", 5),
            ("VBIC", 2, "A", "'10x1'", "'1'", 6),
            ("VMVN", 3, "A", "'110x'", "'1'", 7),
            ("VORR", 1, "T", "'0xx1'", "'0'", 0x102),
        ):
            with self.subTest(mnemonic=mnemonic, variant=variant, isa=isa):
                names = ("cmode", "i", "imm3", "imm4")
                shape = (("cmode", 8, 4, cmode),
                         ("i", 24 if isa == "A" else 28, 1, "'x'"),
                         ("imm3", 16, 3, "'xxx'"),
                         ("imm4", 0, 4, "'xxxx'"),
                         ("op", 5, 1, op))
                rule = {"_type": "Instruction.Rules.Rule",
                        "display": "<imm>", "symbols": {"symbols": [
                            {"_type": "Instruction.Symbols.RuleReference",
                             "rule_id": "UInteger"}]}}
                source = {
                    "name": f"{mnemonic}_i_{isa}{variant}_D",
                    "_meta": {"encoded_in": {"<imm>": [
                        {"_type": "AST.Identifier", "value": name}
                        for name in names]}},
                    "encoding": {"values": [
                        {"_type": "Instruction.Encodeset.Field",
                         "name": name, "value": {"value": value}}
                        for name, _start, _width, value in shape]},
                }
                bindings = {name: (start, width)
                            for name, start, width, _value in shape}
                self.assertEqual(catalog.reviewed_neon_modified_immediate(
                    "imm__114", rule, source, bindings), family)
                source["encoding"]["values"][0]["value"]["value"] = "'xxxx'"
                self.assertIsNone(catalog.reviewed_neon_modified_immediate(
                    "imm__114", rule, source, bindings))


if __name__ == "__main__":
    unittest.main()
