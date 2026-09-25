"""Regression boundaries for non-invertible Arm assembly-only aliases."""

import csv
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/isa_codegen"))
import generate_arm_assembly_catalog as catalog  # noqa: E402


SHIFT_REASON = "choice_selection_missing:dt_option__8"
VORN_REASON = "encoded_concat_transform_missing:imm__114:<imm>"


class AssemblyAuditClassTests(unittest.TestCase):
    def test_checked_in_audit_classes(self):
        opaque_path = ROOT / "tools/isa_codegen/generated/arm_assembly_opaque.tsv"
        manifest_path = ROOT / "tools/isa_codegen/generated/arm_assembly_manifest.json"
        with opaque_path.open(encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream, dialect="excel-tab"))
        with manifest_path.open(encoding="utf-8") as stream:
            manifest = json.load(stream)

        aliases = {int(row["record_index"]): row for row in rows
                   if row["record_kind"] == "alias"}
        for index in catalog.NON_INVERTIBLE_SHIFT_ALIASES:
            with self.subTest(alias=index):
                self.assertEqual(aliases[index]["audit_class"],
                                 "non_invertible_assembly_alias")
                self.assertEqual(aliases[index]["reason"], SHIFT_REASON)
        for index in catalog.ASSEMBLY_ONLY_VORN_ALIASES:
            with self.subTest(alias=index):
                self.assertEqual(aliases[index]["audit_class"],
                                 "assembly_only_pseudoinstruction")
                self.assertEqual(aliases[index]["reason"], VORN_REASON)

        class_counts = {}
        for row in rows:
            class_counts[row["audit_class"]] = (
                class_counts.get(row["audit_class"], 0) + 1
            )
        self.assertEqual(manifest["schema_version"], 2)
        self.assertEqual(manifest["counts"]["opaque_records"], len(rows))
        self.assertEqual(manifest["counts"]["opaque_audit_class_counts"],
                         class_counts)
        self.assertEqual(manifest["counts"]["actionable_opaque_records"],
                         class_counts.get("unresolved_recipe", 0))
        self.assertEqual(class_counts["non_invertible_assembly_alias"], 8)
        self.assertEqual(class_counts["assembly_only_pseudoinstruction"], 8)

    def test_pinned_alias_shape_and_fail_closed_boundary(self):
        pinned = ROOT.parents[1] / "_arm_aarchmrs_pinned/Instructions.json"
        if not pinned.is_file():
            self.skipTest("optional pinned AARCHMRS checkout is unavailable")
        with pinned.open(encoding="utf-8") as stream:
            document = json.load(stream)
        import generate_arm_tree as tree
        sources = catalog.collect_sources(document)[1]
        aliases = tree.make_tree(document)[2]
        for index in catalog.NON_INVERTIBLE_SHIFT_ALIASES:
            with self.subTest(alias=index):
                self.assertEqual(catalog.opaque_audit_class(
                    index, aliases[index], sources[index], SHIFT_REASON),
                    "non_invertible_assembly_alias")
        for index in catalog.ASSEMBLY_ONLY_VORN_ALIASES:
            with self.subTest(alias=index):
                self.assertEqual(catalog.opaque_audit_class(
                    index, aliases[index], sources[index], VORN_REASON),
                    "assembly_only_pseudoinstruction")
        for index, reason in ((60, SHIFT_REASON), (84, VORN_REASON)):
            with self.subTest(changed_alias=index):
                changed = {**sources[index],
                           "preferred": {"_type": "AST.Bool", "value": True}}
                with self.assertRaises(catalog.AssemblyError):
                    catalog.opaque_audit_class(index, aliases[index],
                                               changed, reason)


if __name__ == "__main__":
    unittest.main()
