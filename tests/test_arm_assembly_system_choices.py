"""Exact shape gates for reviewed A32/T32 register and VSHLL choices."""

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


def choice(display, *names):
    return {"_type": "Instruction.Rules.Choice", "display": display,
            "choices": [{"symbols": [ref(name)]} for name in names]}


def leaves(*pairs):
    return {name: {"symbols": {"symbols": [lit(text)]}}
            for name, text in pairs}


class SystemChoiceTests(unittest.TestCase):
    def test_mrs_apsr_spsr(self):
        pairs = (("CPSR", "CPSR"), ("APSR", "APSR"),
                 ("spec_reg_1_SPSR", "SPSR"))
        rule = choice("<spec_reg>", *(name for name, _ in pairs))
        for name, shift in (("MRS_A1_AS", 22), ("MRS_T1_AS", 20)):
            with self.subTest(name=name):
                source = {"name": name, "operation_id": "MRS_a32",
                          "_meta": {"encoded_in": {
                              "<spec_reg>": [ident("R")]}},
                          "encoding": {"values": [field("R", "'x'")]}}
                self.assertEqual(catalog.reviewed_a32_mrs_spec_reg(
                    "spec_reg_option", rule, leaves(*pairs), source,
                    {"R": (shift, 1)}), shift)
                self.assertIsNone(catalog.reviewed_a32_mrs_spec_reg(
                    "spec_reg_option", rule, leaves(*pairs), source,
                    {"R": (shift - 1, 1)}))

    def test_vfp_register_set(self):
        pairs = (("spec_reg_0000_FPSID", "FPSID"),
                 ("spec_reg_0001_FPSCR", "FPSCR"),
                 ("spec_reg_001x_UNPREDICTABLE", "UNPREDICTABLE"),
                 ("spec_reg_1000_FPEXC", "FPEXC"))
        source = {"name": "VMSR_A1_AS", "operation_id": "VMSR",
                  "_meta": {"encoded_in": {
                      "<spec_reg>": [ident("reg")]}},
                  "encoding": {"values": [field("reg", "'xxxx'")]}}
        rule = choice("<spec_reg>", *(name for name, _ in pairs))
        self.assertEqual(catalog.reviewed_a32_vfp_spec_reg(
            "spec_reg_option__2", rule, leaves(*pairs), source,
            {"reg": (16, 4)}), 0)
        source["_meta"]["encoded_in"]["<spec_reg>"] = [ident("other")]
        self.assertIsNone(catalog.reviewed_a32_vfp_spec_reg(
            "spec_reg_option__2", rule, leaves(*pairs), source,
            {"reg": (16, 4)}))

    def test_vshll_imm6(self):
        source = {"name": "VSHLL_T1", "operation_id": "VSHLL",
                  "_meta": {"encoded_in": {}},
                  "encoding": {"values": [field("imm6", "'xxxxxx'")]}}
        rule = {"_type": "Instruction.Rules.Rule", "display": "<size>",
                "symbols": {"symbols": [ref("UInteger")]}}
        self.assertEqual(catalog.reviewed_a32_vshll_imm6(
            "size__5", rule, source, {"imm6": (16, 6)}), 0)
        self.assertIsNone(catalog.reviewed_a32_vshll_imm6(
            "size__5", rule, source, {"imm6": (15, 6)}))
        source["_meta"]["encoded_in"]["<size>"] = [ident("imm6")]
        self.assertIsNone(catalog.reviewed_a32_vshll_imm6(
            "size__5", rule, source, {"imm6": (16, 6)}))

    def test_barrier_named_option(self):
        names = ("SY", "ST", "LD", "ISH", "ISHST", "ISHLD",
                 "NSH", "NSHST", "NSHLD", "OSH", "OSHST", "OSHLD")
        inner = choice("<option>", *(f"CRm_{name}" for name in names))
        rules = {"CRm_option__4": inner}
        for name in names:
            rules[f"CRm_{name}"] = {
                "condition": {"_type": "AST.Bool", "value": True},
                "symbols": {"symbols": [lit(name)]}}
        outer = {"_type": "Instruction.Rules.Choice", "display": None,
                 "choices": [None, {"symbols": [ref("CRm_option__4")]}]}
        source = {"name": "DSB_A1", "operation_id": "DSB_a32",
                  "_meta": {"encoded_in": {
                      "<option>": [ident("option")]}},
                  "encoding": {"values": [field("option", "'xxxx'")]}}
        self.assertTrue(catalog.reviewed_a32_barrier_option(
            "crm_option_choice", outer, rules, source,
            {"option": (0, 4)}))
        self.assertFalse(catalog.reviewed_a32_barrier_option(
            "crm_option_choice", outer, rules, source,
            {"option": (1, 4)}))
        rules["CRm_ISH"]["condition"] = {
            "_type": "AST.Identifier", "value": "FEAT_OTHER"}
        self.assertFalse(catalog.reviewed_a32_barrier_option(
            "crm_option_choice", outer, rules, source,
            {"option": (0, 4)}))


if __name__ == "__main__":
    unittest.main()
