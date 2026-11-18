"""Tests for pin_release.py (`REL-01`). Run: python3 -I -m unittest discover -s tools/release -p 'test_*.py'."""

from __future__ import annotations

import io
import json
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pin_release as pr  # noqa: E402

D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64
PREFIX = "ghcr.io/casualoffice/openseal"


def images(**over: str) -> dict[str, str]:
    base = {
        "server": f"{PREFIX}-server:0.0.2@{D1}",
        "worker": f"{PREFIX}-worker:0.0.2@{D2}",
        "keyd": f"{PREFIX}-keyd@{D3}",
    }
    base.update(over)
    return {k: v for k, v in base.items() if v}


class Build(unittest.TestCase):
    def test_pins_every_production_service_to_its_digest(self) -> None:
        files = pr.render(pr.build_release("0.0.2", images()))
        compose = files["compose.release.yml"]
        for svc, digest in (("server", D1), ("migrate", D1), ("worker", D2), ("keyd", D3)):
            self.assertIn(f"  {svc}:\n    image: ", compose)
        self.assertIn(f"  migrate:\n    image: {PREFIX}-server:0.0.2@{D1}\n", compose)
        self.assertIn(f"  keyd:\n    image: {PREFIX}-keyd:0.0.2@{D3}\n", compose)
        self.assertIn(f"OPENSEAL_IMAGE_PREFIX={PREFIX}\nOPENSEAL_VERSION=0.0.2\n", files["openseal-release.env"])

    def test_every_openseal_service_of_the_profile_is_pinned(self) -> None:
        # HRD-11: the profile runs a second server replica; every service that runs an
        # OpenSeal image must take the signed digest, not only the first of each kind.
        profile = (Path(__file__).resolve().parent.parent.parent / "deploy" / "compose.production.yml").read_text()
        body = profile.split("\nservices:\n", 1)[1].split("\nnetworks:\n", 1)[0]
        names = re.findall(r"^  ([a-z0-9-]+):\n", body, re.M)
        third_party = {"postgres", "s3", "proxy"}  # pinned by digest in the profile itself
        self.assertIn("server-2", names)
        compose = pr.render(pr.build_release("0.0.2", images()))["compose.release.yml"]
        for svc in sorted(set(names) - third_party):
            self.assertIn(f"  {svc}:\n    image: ", compose, svc)

    def test_same_input_same_bytes_and_round_trips_through_images_json(self) -> None:
        a = pr.render(pr.build_release("0.0.2", images()))
        b = pr.render(pr.build_release("0.0.2", dict(reversed(list(images().items())))))
        self.assertEqual(a, b)
        again = pr.render(pr.load_release(a["images.json"]))
        self.assertEqual(a, again)

    def test_refuses_a_tag_without_a_digest(self) -> None:
        with self.assertRaisesRegex(pr.PinError, "server: not an image reference pinned by sha256"):
            pr.build_release("0.0.2", images(server=f"{PREFIX}-server:0.0.2"))

    def test_refuses_a_short_or_uppercase_digest(self) -> None:
        for bad in ("sha256:" + "a" * 63, "sha256:" + "A" * 64, "sha512:" + "a" * 64):
            with self.subTest(bad=bad), self.assertRaisesRegex(pr.PinError, "worker: not an image reference"):
                pr.build_release("0.0.2", images(worker=f"{PREFIX}-worker@{bad}"))

    def test_refuses_a_missing_or_unknown_service(self) -> None:
        with self.assertRaisesRegex(pr.PinError, "missing image for: keyd"):
            pr.build_release("0.0.2", images(keyd=""))
        with self.assertRaisesRegex(pr.PinError, "unknown service: modeld"):
            pr.build_release("0.0.2", images(modeld=f"{PREFIX}-modeld@{D1}"))

    def test_refuses_an_image_of_another_service_or_prefix(self) -> None:
        with self.assertRaisesRegex(pr.PinError, "does not end in '-worker'"):
            pr.build_release("0.0.2", images(worker=f"{PREFIX}-server@{D2}"))
        with self.assertRaisesRegex(pr.PinError, "more than one prefix"):
            pr.build_release("0.0.2", images(keyd=f"ghcr.io/someone/openseal-keyd@{D3}"))

    def test_refuses_a_tag_that_is_not_the_version_and_a_bad_version(self) -> None:
        with self.assertRaisesRegex(pr.PinError, "tag '0.0.1' is not the version"):
            pr.build_release("0.0.2", images(server=f"{PREFIX}-server:0.0.1@{D1}"))
        with self.assertRaisesRegex(pr.PinError, "is not MAJOR.MINOR.PATCH"):
            pr.build_release("v0.0.2", images())

    def test_refuses_a_malformed_images_json(self) -> None:
        for text, msg in (
            ("{", "not JSON"),
            ("[]", "no 'images' object"),
            ('{"images": {}}', "no 'version' string"),
            ('{"version": "0.0.2", "images": {"server": "x"}}', "server: entry needs"),
        ):
            with self.subTest(text=text), self.assertRaisesRegex(pr.PinError, msg):
                pr.load_release(text)
        tampered = json.loads(pr.render(pr.build_release("0.0.2", images()))["images.json"])
        tampered["images"]["keyd"]["digest"] = "sha256:deadbeef"
        with self.assertRaisesRegex(pr.PinError, "keyd: not an image reference"):
            pr.load_release(json.dumps(tampered))


class Cli(unittest.TestCase):
    def run_main(self, argv: list[str]) -> tuple[int, str]:
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()):
            rc = pr.main(argv)
        return rc, err.getvalue()

    def test_writes_three_files_then_repins_identically_from_images_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out, again = Path(tmp, "a"), Path(tmp, "b")
            args = ["--version", "0.0.2", "--out", str(out)]
            for svc, ref in images().items():
                args += ["--image", f"{svc}={ref}"]
            self.assertEqual(self.run_main(args), (0, ""))
            names = sorted(p.name for p in out.iterdir())
            self.assertEqual(names, ["compose.release.yml", "images.json", "openseal-release.env"])
            self.assertEqual(self.run_main(["--from", str(out / "images.json"), "--out", str(again)]), (0, ""))
            for name in names:
                self.assertEqual((out / name).read_bytes(), (again / name).read_bytes())

    def test_fails_non_zero_naming_the_problem_and_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp, "out")
            rc, err = self.run_main(["--version", "0.0.2", "--out", str(out), "--image", f"server={PREFIX}-server:0.0.2"])
            self.assertEqual(rc, 1)
            self.assertIn("missing image for: keyd, worker", err)
            self.assertFalse(out.exists())
            rc, err = self.run_main(["--out", str(out), "--image", "server"])
            self.assertEqual(rc, 1)
            self.assertIn("--version is required", err)
            rc, err = self.run_main(
                ["--version", "0.0.2", "--out", str(out), "--image", f"server={PREFIX}-server@{D1}", "--image", f"server={PREFIX}-server@{D1}"]
            )
            self.assertEqual((rc, "server: given twice" in err), (1, True))


if __name__ == "__main__":
    unittest.main()
