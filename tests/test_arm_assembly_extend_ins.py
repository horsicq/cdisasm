"""Exact source/rule gates for SVE extend types and AdvSIMD INS aliases."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools/isa_codegen"))
import generate_arm_assembly_catalog as catalog  # noqa: E402


def ref(name):
    return {"_type": "Instruction.Symbols.RuleReference", "rule_id": name}


def lit(value):
    return {"_type": "Instruction.Symbols.Literal", "value": value}


def ident(name):
    return {"_type": "AST.Identifier", "value": name}


def field(name, pattern):
    return {"_type": "Instruction.Encodeset.Field", "name": name,
            "value": {"value": pattern}}


def choices(*names):
    return {"_type": "Instruction.Rules.Choice",
            "choices": [{"symbols": [ref(name)]} for name in names]}


def leaf(value):
    return {"symbols": {"symbols": [lit(value)]}}


class ExtendInsTests(unittest.TestCase):
    def test_sve_extend_type_exact_rules(self):
        cases = (
            ("T_xt_SD", "sxth_z_p_z_m", 1,
             (("T_xt_S__2", "S"), ("T_xt_D__2", "D"))),
            ("T_xt_HSD", "sxtb_z_p_z_z", 2,
             (("T_xt_H", "H"), ("T_xt_S", "S"),
              ("T_xt_D", "D"))),
        )
        for rule_id, name, mode, leaves in cases:
            with self.subTest(rule=rule_id):
                rule = {**choices(*(key for key, _value in leaves)),
                        "display": "<T>"}
                rules = {key: leaf(value) for key, value in leaves}
                source = {"name": name, "_meta": {"encoded_in": {
                    "<T>": [ident("size")]}},
                    "encoding": {"values": [field("size", "'xx'")]}}
                self.assertEqual(catalog.reviewed_a64_sve_extend_t(
                    rule_id, rule, rules, source, {"size": (22, 2)}), mode)
                self.assertIsNone(catalog.reviewed_a64_sve_extend_t(
                    rule_id, rule, rules, source, {"size": (21, 2)}))
                source["_meta"]["encoded_in"]["<T>"] = [ident("Q")]
                self.assertIsNone(catalog.reviewed_a64_sve_extend_t(
                    rule_id, rule, rules, source, {"size": (22, 2)}))

    def test_ins_type_prefix_and_lanes(self):
        ts_leaves = (("Ts_xxxx1_B", "B"), ("Ts_xxx10_H", "H"),
                     ("Ts_xx100_S", "S"), ("Ts_x1000_D", "D"))
        ts_rules = {key: leaf(value) for key, value in ts_leaves}
        ts_rule = {**choices(*(key for key, _value in ts_leaves)),
                   "display": "<Ts>"}
        r_rules = {"imm5_R__2": leaf("W"),
                   "R_x1000_X__2": leaf("X"),
                   "R_xxxx1_W": leaf("W"),
                   "R_x1000_X__3": leaf("X"),
                   "n_ZR": leaf("ZR"),
                   "n": {"symbols": {"symbols": [ref("UInteger")]}}}
        canonical = {"name": "INS_asimdins_IR_r",
                     "operation_id": "INS_advsimd_gen",
                     "_meta": {"encoded_in": {
                         "<Ts>": [ident("imm5")],
                         "<R>": [ident("imm5")],
                         "<index>": [ident("imm5")],
                         "<n>": [ident("Rn")]}},
                     "encoding": {"values": [field("imm5", "'xxxxx'"),
                                             field("Rn", "'xxxxx'")]}}
        alias = {"name": "MOV", "operation_id": "MOV_INS_advsimd_gen",
                 "_meta": canonical["_meta"]}
        bindings = {"imm5": (16, 5), "Rn": (5, 5)}
        self.assertTrue(catalog.reviewed_a64_asimd_ins_ts(
            "Ts_option", ts_rule, ts_rules, canonical, bindings))
        self.assertTrue(catalog.reviewed_a64_asimd_ins_ts(
            "Ts_option", ts_rule, ts_rules, alias, bindings))
        self.assertTrue(catalog.reviewed_a64_asimd_ins_r(
            "R_option__4", {**choices("imm5_R__2", "R_x1000_X__2"),
                             "display": "<R>"},
            r_rules, canonical, bindings))
        self.assertTrue(catalog.reviewed_a64_asimd_ins_r(
            "R_option__5", {**choices("R_xxxx1_W", "R_x1000_X__3"),
                             "display": "<R>"},
            r_rules, alias, bindings))
        self.assertEqual(catalog.reviewed_a64_asimd_ins_lane(
            "imm5_index", {"_type": "Instruction.Rules.Rule",
                           "display": "<index>",
                           "symbols": {"symbols": [ref("UInteger")]}},
            canonical, bindings), 0)
        self.assertTrue(catalog.reviewed_a64_asimd_ins_rn(
            "Rn_option__2", {**choices("n_ZR", "n"),
                              "display": "<n>"},
            r_rules, canonical, bindings))
        self.assertFalse(catalog.reviewed_a64_asimd_ins_ts(
            "Ts_option", ts_rule, ts_rules, canonical,
            {**bindings, "imm5": (15, 5)}))

    def test_ins_vector_source_index_and_alias(self):
        source = {"name": "INS_asimdins_IV_v",
                  "operation_id": "INS_advsimd_elt",
                  "_meta": {"encoded_in": {
                      "<index1>": [ident("imm5")],
                      "<index2>": [ident("imm5"), ident("imm4")]}},
                  "encoding": {"values": [field("imm5", "'xxxxx'"),
                                          field("imm4", "'xxxx'")]}}
        alias = {"name": "MOV", "operation_id": "MOV_INS_advsimd_elt",
                 "_meta": source["_meta"]}
        bindings = {"imm5": (16, 5), "imm4": (11, 4)}
        for candidate in (source, alias):
            with self.subTest(name=candidate["name"]):
                self.assertEqual(catalog.reviewed_a64_asimd_ins_lane(
                    "imm5_index__5", {"_type": "Instruction.Rules.Rule",
                                     "display": "<index1>",
                                     "symbols": {"symbols": [ref(
                                         "UInteger")]}},
                    candidate, bindings), 0)
                self.assertEqual(catalog.reviewed_a64_asimd_ins_lane(
                    "imm5_index__6", {"_type": "Instruction.Rules.Rule",
                                     "display": "<index2>",
                                     "symbols": {"symbols": [ref(
                                         "UInteger")]}},
                    candidate, bindings), 1)
                self.assertIsNone(catalog.reviewed_a64_asimd_ins_lane(
                    "imm5_index__6", {"_type": "Instruction.Rules.Rule",
                                     "display": "<index2>",
                                     "symbols": {"symbols": [ref(
                                         "UInteger")]}},
                    candidate, {**bindings, "imm4": (10, 4)}))


if __name__ == "__main__":
    unittest.main()
