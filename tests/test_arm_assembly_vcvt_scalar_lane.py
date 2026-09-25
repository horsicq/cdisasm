"""Narrow source-shape gates for A32/T32 VCVT and SIMD scalar operands."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools/isa_codegen"))
import generate_arm_assembly_catalog as catalog  # noqa: E402


def identifier(name):
    return {"_type": "AST.Identifier", "value": name}


def field(name, pattern):
    return {"_type": "Instruction.Encodeset.Field", "name": name,
            "value": {"value": pattern}}


class VCVTScalarLaneTests(unittest.TestCase):
    def test_dmx2_exact_forms_and_fields(self):
        names = ("VMLA_s_A1_D", "VMLA_s_A1_Q", "VMLS_s_A1_D",
                 "VMLS_s_A1_Q", "VMLA_s_T1_D", "VMLA_s_T1_Q",
                 "VMLS_s_T1_D", "VMLS_s_T1_Q")
        rule = {"_type": "Instruction.Rules.Rule", "display": "<Dm[x]>",
                "symbols": {"symbols": [
                    {"_type": "Instruction.Symbols.Literal", "value": "D"},
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "UInteger"},
                    {"_type": "Instruction.Symbols.RuleReference",
                     "rule_id": "Ddx_index"},
                ]}}
        shape = {"M": (5, 1), "Vm": (0, 4), "size": (20, 2)}
        for name in names:
            with self.subTest(name=name):
                source = {"name": name,
                          "_meta": {"encoded_in": {"<Dm[x]>": [
                              identifier(key) for key in shape]}},
                          "encoding": {"values": [
                              field("M", "'x'"), field("Vm", "'xxxx'"),
                              field("size", "'xx'")]}}
                self.assertEqual(catalog.reviewed_indexed_operand(
                    "Dmx__2", rule, source, shape), "A32_DMX_LANE")
                self.assertIsNone(catalog.reviewed_indexed_operand(
                    "Dmx__2", rule, source, {**shape, "M": (6, 1)}))
                source["name"] = "VMLA_s_A2_D"
                self.assertIsNone(catalog.reviewed_indexed_operand(
                    "Dmx__2", rule, source, shape))

    def test_vcvt_sdm_and_fbits_exact_forms_and_fields(self):
        names = ("VCVT_toxv_A1_H", "VCVT_xv_A1_H",
                 "VCVT_toxv_A1_S", "VCVT_xv_A1_S",
                 "VCVT_toxv_T1_H", "VCVT_xv_T1_H",
                 "VCVT_toxv_T1_S", "VCVT_xv_T1_S")
        sdm_rule = {"_type": "Instruction.Rules.Rule", "display": "<Sdm>",
                    "symbols": {"symbols": [
                        {"_type": "Instruction.Symbols.Literal", "value": "S"},
                        {"_type": "Instruction.Symbols.RuleReference",
                         "rule_id": "UInteger"},
                    ]}}
        fbits_rule = {"_type": "Instruction.Rules.Rule",
                      "display": "<fbits>", "symbols": {"symbols": [
                          {"_type": "Instruction.Symbols.RuleReference",
                           "rule_id": "UInteger"},
                      ]}}
        bindings = {"Vd": (12, 4), "D": (22, 1),
                    "sx": (7, 1), "i": (5, 1), "imm4": (0, 4)}
        for name in names:
            with self.subTest(name=name):
                source = {"name": name, "_meta": {"encoded_in": {
                    "<Sdm>": [identifier("Vd"), identifier("D")]}},
                    "encoding": {"values": [
                        field("Vd", "'xxxx'"), field("D", "'x'"),
                        field("sx", "'x'"), field("i", "'x'"),
                        field("imm4", "'xxxx'")]}}
                self.assertTrue(catalog.reviewed_a32_vcvt_sdm(
                    "Vd_D__2", sdm_rule, source, bindings))
                self.assertTrue(catalog.reviewed_a32_vcvt_fbits(
                    "fbits__5", fbits_rule, source, bindings))
                self.assertFalse(catalog.reviewed_a32_vcvt_sdm(
                    "Vd_D__2", sdm_rule, source,
                    {**bindings, "D": (21, 1)}))
                self.assertFalse(catalog.reviewed_a32_vcvt_fbits(
                    "fbits__5", fbits_rule, source,
                    {**bindings, "i": (4, 1)}))
                source["_meta"]["encoded_in"]["<fbits>"] = [
                    identifier("imm4")]
                self.assertFalse(catalog.reviewed_a32_vcvt_fbits(
                    "fbits__5", fbits_rule, source, bindings))


if __name__ == "__main__":
    unittest.main()
