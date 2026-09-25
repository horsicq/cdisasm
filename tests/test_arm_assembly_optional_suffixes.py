"""Source-shape boundary tests for reviewed A64 optional suffix recipes."""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools/isa_codegen"))
import generate_arm_assembly_catalog as catalog  # noqa: E402


def reference(name):
    return {"_type": "Instruction.Symbols.RuleReference", "rule_id": name}


def literal(value):
    return {"_type": "Instruction.Symbols.Literal", "value": value}


def choice(*symbols):
    return {"symbols": list(symbols)}


def field(name, pattern):
    return {"_type": "Instruction.Encodeset.Field", "name": name,
            "value": {"value": pattern}}


class OptionalSuffixTests(unittest.TestCase):
    def test_asimd_lsl_rule_and_cmode_shape(self):
        for rule_id, suffix, amount_rule, leaf_names, pattern, expected in (
                ("optional_extend__18", "_L_sl", "amount_option__8",
                 ("amount_00_0", "amount_01_8", "amount_10_16",
                  "amount_11_24"), "0xx", 1),
                ("optional_extend__20", "_L_hl", "amount_option__10",
                 ("amount_0_0__2", "amount_1_8"), "10x", 2)):
            for stem, low in (("MOVI_asimdimm", 0),
                              ("ORR_asimdimm", 1),
                              ("MVNI_asimdimm", 0),
                              ("BIC_asimdimm", 1)):
                with self.subTest(rule=rule_id, stem=stem):
                    rules = {amount_rule: {"choices": [choice(reference(n))
                                                       for n in leaf_names]}}
                    rules.update({n: {"symbols": {"symbols": [
                        literal(str(i * 8))]}}
                                  for i, n in enumerate(leaf_names)})
                    rule = {"_type": "Instruction.Rules.Choice",
                            "choices": [
                                choice(reference("amount_default")),
                                choice(reference("COMMA"), literal("LSL"),
                                       reference("OPT_SPACE"),
                                       reference("hash"),
                                       reference(amount_rule))]}
                    source = {"name": stem + suffix,
                              "_meta": {"encoded_in": {"<amount>": [
                                  {"_type": "AST.Identifier",
                                   "value": "cmode"}]}},
                              "encoding": {"values": [field(
                                  "cmode", "'" + pattern + str(low) + "'")]}}
                    self.assertEqual(
                        catalog.reviewed_a64_asimd_optional_lsl(
                            rule_id, rule, rules, source,
                            {"cmode": (12, 4)}), expected + 2 * low)
                    self.assertIsNone(
                        catalog.reviewed_a64_asimd_optional_lsl(
                            rule_id, rule, rules, source,
                            {"cmode": (11, 4)}))
                    source["encoding"]["values"][0]["value"]["value"] = \
                        "'xxxx'"
                    self.assertIsNone(
                        catalog.reviewed_a64_asimd_optional_lsl(
                            rule_id, rule, rules, source,
                            {"cmode": (12, 4)}))

    def test_sve_signed_imm9_optional_mul_vl_shape(self):
        rule = {"_type": "Instruction.Rules.Choice", "choices": [
            choice(reference("default_imm")),
            choice(reference("COMMA"), reference("hash"),
                   reference("imm__77"), reference("COMMA"),
                   literal("MUL"), reference("OPT_SPACE"), literal("VL"))]}
        rules = {"imm__77": {"_type": "Instruction.Rules.Rule",
                            "display": "<imm>", "symbols": {"symbols": [
                                reference("SInteger")]}}}
        source = {"name": "ldr_p_bi_", "_meta": {"encoded_in": {
            "<imm>": [{"_type": "AST.Identifier", "value": "imm9h"},
                      {"_type": "AST.Identifier", "value": "imm9l"}]}},
                  "encoding": {"values": [field("imm9h", "'xxxxxx'"),
                                          field("imm9l", "'xxx'")]}}
        bindings = {"imm9h": (16, 6), "imm9l": (10, 3)}
        for name in ("ldr_p_bi_", "ldr_z_bi_", "str_p_bi_",
                     "str_z_bi_"):
            with self.subTest(name=name):
                source["name"] = name
                self.assertTrue(catalog.reviewed_a64_sve_optional_vl(
                    "optional_imm__25", rule, rules, source, bindings))
        self.assertFalse(catalog.reviewed_a64_sve_optional_vl(
            "optional_imm__25", rule, rules, source,
            {**bindings, "imm9l": (9, 3)}))
        source["_meta"]["encoded_in"]["<imm>"].reverse()
        self.assertFalse(catalog.reviewed_a64_sve_optional_vl(
            "optional_imm__25", rule, rules, source, bindings))


if __name__ == "__main__":
    unittest.main()
