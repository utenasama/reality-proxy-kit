import importlib.util
import json
from pathlib import Path
import unittest


class BuildProvenance(unittest.TestCase):
    def test_module_metadata_keeps_checksums_without_builder_paths(self):
        spec = importlib.util.spec_from_file_location("build_core", Path(__file__).resolve().parents[1] / "scripts/build_core.py")
        builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
        modules = [{"Path": "example.org/core", "Main": True, "Dir": "/private/builder/core", "GoMod": "/private/builder/core/go.mod"},
                   {"Path": "example.org/tls", "Version": "v1.0.0", "Sum": "h1:fixture", "GoModSum": "h1:metadata",
                    "Replace": {"Path": "../reality", "Dir": "/private/builder/reality", "GoMod": "/private/builder/reality/go.mod"}}]
        result = builder.public_modules("\n".join(json.dumps(m) for m in modules))
        self.assertNotIn("/private/builder", result)
        public = json.loads(result)
        self.assertEqual(public[1]["Sum"], "h1:fixture")
        self.assertEqual(public[1]["GoModSum"], "h1:metadata")
        self.assertEqual(public[1]["Replace"], {"Path": "../reality"})
