"""Tests of the API reference's build (SITE-12): every example on the pages fits the
schema it illustrates, the validator catches one that does not, every operation is on
exactly one page, and every SDK call shown names a method the SDK has.

    python3 -m unittest tools/test_build_api_docs.py      # needs PyYAML, as the build does

The build itself refuses an example that does not fit (tools/build-api-docs.py), so
pages.yml's build fails on one; this test names each.
"""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
import api_examples as ax  # noqa: E402

_spec = importlib.util.spec_from_file_location("build_api_docs", TOOLS / "build-api-docs.py")
bad = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bad)

SPEC = bad.load_spec()
OPS = bad.operations(SPEC)
BY_ID = {o.id: o for o in OPS}


class ExamplesFitTheContract(unittest.TestCase):
    def test_every_request_example_fits_its_schema(self):
        checked = 0
        for op in OPS:
            if not op.body_schema or "json" not in op.body_type:
                continue
            value = ax.REQUEST_OVERRIDES.get(op.id)
            if value is None:
                value = ax.example(SPEC, op.body_schema, full=False)
            with self.subTest(op=op.id):
                self.assertEqual(ax.validate(SPEC, op.body_schema, value), [])
            checked += 1
        self.assertGreater(checked, 60)

    def test_every_response_example_fits_its_schema(self):
        checked = 0
        for op in OPS:
            code, r = op.success()
            for ctype, c in ((r or {}).get("content") or {}).items():
                if "json" not in ctype:
                    continue
                value = ax.example(SPEC, c.get("schema"))
                with self.subTest(op=op.id, status=code):
                    self.assertEqual(ax.validate(SPEC, c.get("schema"), value), [])
                checked += 1
        self.assertGreater(checked, 120)

    def test_hand_written_examples_name_real_operations_and_fit(self):
        for op_id, value in ax.REQUEST_OVERRIDES.items():
            with self.subTest(op=op_id):
                self.assertIn(op_id, BY_ID)
                self.assertEqual(ax.validate(SPEC, BY_ID[op_id].body_schema, value), [])

    def test_the_build_refuses_an_example_that_does_not_fit(self):
        op = BY_ID["createWebhook"]
        saved = ax.REQUEST_OVERRIDES["createWebhook"]
        try:
            ax.REQUEST_OVERRIDES["createWebhook"] = {**saved, "url": 42}
            with self.assertRaises(SystemExit) as cm:
                op.request_example()
            self.assertIn("createWebhook", str(cm.exception))
            self.assertIn("/url", str(cm.exception))
        finally:
            ax.REQUEST_OVERRIDES["createWebhook"] = saved


class TheValidatorCatchesDrift(unittest.TestCase):
    def schema(self, name):
        return {"$ref": f"#/components/schemas/{name}"}

    def test_a_value_outside_an_enum(self):
        errs = ax.validate(SPEC, self.schema("EnvelopeCreate"), {"status": "maybe"})
        self.assertTrue(any(e.startswith("/status:") for e in errs), errs)

    def test_a_missing_required_member(self):
        errs = ax.validate(SPEC, self.schema("ApiClientCreate"), {"name": "CRM sync", "kind": "api_key"})
        self.assertTrue(any("missing required 'scopes'" in e for e in errs), errs)

    def test_a_member_the_schema_does_not_allow(self):
        errs = ax.validate(SPEC, self.schema("EnvelopeCreate"), {"subject": "x", "colour": "red"})
        self.assertTrue(any("'colour' is not allowed" in e for e in errs), errs)

    def test_a_wrong_type_deep_in_an_array(self):
        value = {"documents": [{"name": 7, "content_base64": "JVBERi0="}]}
        errs = ax.validate(SPEC, self.schema("EnvelopeCreate"), value)
        self.assertTrue(any(e.startswith("/documents/0/name:") for e in errs), errs)

    def test_a_string_over_its_limit_and_a_bad_time(self):
        self.assertTrue(ax.validate(SPEC, {"type": "string", "maxLength": 3}, "four"))
        self.assertTrue(ax.validate(SPEC, {"type": "string", "format": "date-time"}, "yesterday"))
        self.assertFalse(ax.validate(SPEC, {"type": ["string", "null"], "format": "date-time"}, None))

    def test_an_unknown_keyword_is_reported_not_ignored(self):
        errs = ax.validate(SPEC, {"type": "string", "x-new": True}, "a")
        self.assertTrue(errs and "not understood" in errs[0], errs)


class Pages(unittest.TestCase):
    def test_every_operation_is_on_exactly_one_page(self):
        pages = bad.render_all()
        seen: dict[str, int] = {}
        for rel, text in pages.items():
            if not rel.startswith("docs/api-") or rel == "docs/api-objects.html":
                continue
            for oid in re.findall(r'<h2 class="api-op__title" id="op-([a-z0-9]+)"', text):
                seen[oid] = seen.get(oid, 0) + 1
        self.assertEqual(sorted(seen), sorted(o.id.lower() for o in OPS))
        self.assertEqual({n for n in seen.values()}, {1})

    def test_the_ceremony_is_marked_not_public(self):
        text = bad.render_all()["docs/api-ceremony.html"]
        self.assertIn("Not public API", text)
        self.assertNotIn("@openseal/sdk", text)  # no SDK samples: the SDKs leave it out

    def test_every_sdk_call_shown_is_a_method_of_the_sdks(self):
        ts = set(re.findall(r'^  "(\w+)": \{', (TOOLS.parent / "sdk/typescript/operations.js").read_text(), re.M))
        py = set(re.findall(r'^    "(\w+)": \{', (TOOLS.parent / "sdk/python/openseal/_operations.py").read_text(), re.M))
        self.assertTrue(ts and py)
        for op in OPS:
            if op.ceremony or op.id == "token":
                continue
            with self.subTest(op=op.id):
                self.assertIn(f"os.{op.id}(", op.typescript())
                self.assertIn(op.id, ts)
                self.assertIn(op.id, py)
                self.assertIn(f"client.{bad.sitelib_snake(op.id)}(", op.python())


if __name__ == "__main__":
    unittest.main()
