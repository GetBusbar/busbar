"""The shipped SBOM must include the assembled plugins, and reject a core-only graph."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("crosscheck", Path(__file__).with_name("crosscheck.py"))
crosscheck = importlib.util.module_from_spec(spec)
spec.loader.exec_module(crosscheck)


def metadata():
    root = "/fixture/dist/default"
    packages = [
        {"id": name, "name": name, "version": "1.6.0", "source": None,
         "manifest_path": root + "/Cargo.toml" if name == "busbar-default" else "/fixture/" + name + "/Cargo.toml",
         "targets": [{"name": "busbar", "kind": ["bin"]}] if name == "busbar-default" else []}
        for name in ("busbar-default", "busbar-kernel", "busbar-plane-llm", "build-helper", "dev-only")]
    def edge(name, kind=None):
        return {"pkg": name, "dep_kinds": [{"kind": kind}]}
    return {"workspace_root": root, "workspace_members": ["busbar-default"], "packages": packages,
            "resolve": {"nodes": [
                {"id": "busbar-default", "deps": [edge("busbar-kernel"), edge("busbar-plane-llm"),
                                                   edge("build-helper", "build"), edge("dev-only", "dev")]},
                *({"id": name, "deps": []} for name in ("busbar-kernel", "busbar-plane-llm", "build-helper", "dev-only"))]}}


class ShippedClosure(unittest.TestCase):
    def test_assembled_binary_includes_plugins_and_build_edges_without_dev_only(self):
        self.assertEqual(crosscheck.closure(metadata()),
                         {(name, "1.6.0") for name in ("busbar-kernel", "busbar-plane-llm", "build-helper")})

    def test_core_only_workspace_is_refused_even_if_its_binary_is_named_busbar(self):
        meta = metadata()
        meta["workspace_root"] = "/fixture"
        with self.assertRaisesRegex(SystemExit, "not the assembled"):
            crosscheck.closure(meta)

    def test_a_dependency_binary_cannot_be_mistaken_for_the_workspace_owner(self):
        meta = metadata()
        meta["workspace_members"] = []
        with self.assertRaisesRegex(SystemExit, "found 0"):
            crosscheck.closure(meta)

    def test_plugin_omission_is_red_and_complete_sbom_is_green(self):
        meta = metadata()
        sbom = {"components": [{"name": name, "version": version}
                               for name, version in sorted(crosscheck.closure(meta))]}
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            meta_path, sbom_path = directory / "metadata.json", directory / "sbom.json"
            meta_path.write_text(json.dumps(meta))
            sbom_path.write_text(json.dumps(sbom))
            self.assertEqual(crosscheck.check(sbom_path, meta_path), 0)
            sbom["components"] = [c for c in sbom["components"] if c["name"] != "busbar-plane-llm"]
            sbom_path.write_text(json.dumps(sbom))
            self.assertEqual(crosscheck.check(sbom_path, meta_path), 1)


if __name__ == "__main__":
    unittest.main()
