"""Keep VORN-immediate pseudo-instructions out of byte-level coverage claims.

Arm Compiler armasm Reference Guide, section 4.28, says VORN immediate
disassembles as VORR with the complementary immediate:
https://documentation-service.arm.com/static/5f3fa899428f7a6b3328fd44
"""

from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools/isa_codegen"))
import generate_arm_assembly_catalog as catalog  # noqa: E402


REASON = "encoded_concat_transform_missing:imm__114:<imm>"


class VornAuditTests(unittest.TestCase):
    def source(self):
        return {
            "name": "VORN",
            "operation_id": "VORN_VORR_i",
            "condition": {"_type": "AST.Bool", "value": True},
            "preferred": {"_type": "AST.Bool", "value": False},
            "assembly": {"symbols": [{
                "_type": "Instruction.Symbols.Literal", "value": "VORN"}]},
            "_meta": {"encoded_in": {"<imm>": [{
                "_type": "AST.Identifier", "value": "cmode"}]}},
        }

    def test_all_eight_are_assembly_only_not_missing_opcodes(self):
        self.assertEqual(set(catalog.ASSEMBLY_ONLY_VORN_ALIASES),
                         {84, 85, 88, 89, 168, 169, 172, 173})
        for index, parent in catalog.ASSEMBLY_ONLY_VORN_ALIASES.items():
            with self.subTest(index=index):
                alias = {"source_form_id": parent}
                self.assertEqual(catalog.opaque_audit_class(
                    index, alias, self.source(), REASON),
                    "assembly_only_pseudoinstruction")

    def test_changed_preference_or_parent_invalidates_audit(self):
        index = 84
        parent = catalog.ASSEMBLY_ONLY_VORN_ALIASES[index]
        for change in ("preferred", "condition", "parent", "operation",
                       "reason"):
            with self.subTest(change=change):
                source = self.source()
                alias = {"source_form_id": parent}
                reason = REASON
                if change == "preferred":
                    source["preferred"]["value"] = True
                elif change == "condition":
                    source["condition"]["value"] = False
                elif change == "parent":
                    alias["source_form_id"] = parent.replace("VORR_i", "VBIC_i")
                elif change == "operation":
                    source["operation_id"] = "VORN_VBIC_i"
                else:
                    reason = "some_other_missing_recipe"
                with self.assertRaises(catalog.AssemblyError):
                    catalog.opaque_audit_class(index, alias, source, reason)


if __name__ == "__main__":
    unittest.main()
