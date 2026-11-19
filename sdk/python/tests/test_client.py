"""The Python SDK against the recorded contract (sdk/contract/recorded.json), with no
network: each call is checked as sent and answered as recorded.

    python3 -I -m unittest discover -s sdk/python/tests -t sdk/python
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import re
import unittest
import urllib.parse

from openseal import OPERATIONS, OpenSeal, OpenSealError, Response, verify_webhook

HERE = pathlib.Path(__file__).resolve().parent
REC = json.loads((HERE.parent.parent / "contract" / "recorded.json").read_text())
API = (HERE.parent.parent.parent / "api" / "openapi.yaml").read_text()


class Replay:
    def __init__(self, response: dict):
        self.response = response
        self.seen: list[tuple[str, str, dict, bytes | None]] = []

    def __call__(self, method, url, headers, body):
        self.seen.append((method, url, headers, body))
        r = self.response
        raw = b"" if r["body"] is None else json.dumps(r["body"]).encode()
        return Response(r["status"], r["headers"], raw)


def no_network(*_args):
    raise AssertionError("no network")


class Contract(unittest.TestCase):
    def test_every_public_operation_is_a_method(self):
        ids = re.findall(r"^ {6}operationId: (\S+)$", API, re.M)
        c = OpenSeal(REC["base_url"], transport=no_network)
        for op_id, op in OPERATIONS.items():
            self.assertIn(op_id, ids)
            self.assertFalse(op["path"].startswith("/s/"))
            if op_id != "token":
                self.assertTrue(callable(getattr(c, op_id)))
        self.assertGreaterEqual(len(OPERATIONS), 150)
        with self.assertRaises(AttributeError):
            c.no_such_operation  # noqa: B018

    def test_recorded_exchanges(self):
        for x in REC["exchanges"]:
            with self.subTest(x["name"]):
                t = Replay(x["response"])
                c = OpenSeal(REC["base_url"], api_key=x["credential"], transport=t)
                params = dict(x["params"])
                if "idempotencyKey" in params:
                    params["idempotency_key"] = params.pop("idempotencyKey")
                method = getattr(c, x["operation"])
                if "error" in x:
                    with self.assertRaises(OpenSealError) as e:
                        method(**params)
                    self.assertEqual((e.exception.code, e.exception.status, e.exception.request_id),
                                     (x["error"]["code"], x["error"]["status"], "req-1"))
                else:
                    self.assertEqual(method(**params), x["response"]["body"])
                (m, url, headers, body), = t.seen
                self.assertEqual(m, x["request"]["method"])
                self.assertEqual(url, x["request"]["url"])
                for k, v in x["request"]["headers"].items():
                    self.assertEqual(headers.get(k), v, k)
                if "body" in params:
                    self.assertEqual(json.loads(body), params["body"])

    def test_snake_case_names_work(self):
        t = Replay({"status": 200, "headers": {"content-type": "application/json"}, "body": {"items": []}})
        OpenSeal(REC["base_url"], api_key="k", transport=t).list_envelopes(limit=1)
        self.assertEqual(t.seen[0][1], f"{REC['base_url']}/api/v1/envelopes?limit=1")

    def test_a_missing_path_parameter_or_body_is_refused_before_any_request(self):
        c = OpenSeal(REC["base_url"], transport=no_network)
        with self.assertRaisesRegex(ValueError, "id is required"):
            c.get_envelope()
        with self.assertRaisesRegex(ValueError, "body is required"):
            c.create_envelope()


class OAuth(unittest.TestCase):
    def test_the_authorization_url_carries_an_s256_challenge_of_its_verifier(self):
        url, verifier, state = OpenSeal(REC["base_url"], transport=no_network).authorization_url(
            "c1", "https://app.example.test/callback", ["envelopes:read", "envelopes:write"])
        u = urllib.parse.urlsplit(url)
        q = dict(urllib.parse.parse_qsl(u.query))
        self.assertEqual(f"{u.scheme}://{u.netloc}{u.path}", f"{REC['base_url']}/api/v1/oauth/authorize")
        self.assertEqual(q["scope"], "envelopes:read envelopes:write")
        self.assertEqual(q["state"], state)
        want = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        self.assertEqual(q["code_challenge"], want)
        self.assertTrue(43 <= len(verifier) <= 128)

    def test_the_code_exchange_is_the_recorded_one_and_later_calls_carry_the_token(self):
        rec = REC["token"]
        t = Replay(rec["response"])
        c = OpenSeal(REC["base_url"], transport=t)
        tok = c.token(client_id=rec["client_id"], client_secret=rec["client_secret"], **rec["form"])
        self.assertEqual(tok["refresh_token"], "osr_refresh")
        method, url, headers, body = t.seen[0]
        self.assertEqual((method, url), (rec["request"]["method"], rec["request"]["url"]))
        for k, v in rec["request"]["headers"].items():
            self.assertEqual(headers[k], v, k)
        self.assertEqual(dict(urllib.parse.parse_qsl(body.decode())), rec["form"])
        later = Replay({"status": 200, "headers": {"content-type": "application/json"}, "body": {"items": []}})
        c.transport = later
        c.list_envelopes()
        self.assertEqual(later.seen[0][2]["authorization"], "Bearer eyJ.access.token")
        bad = OpenSeal(REC["base_url"], transport=Replay(rec["refused"]))
        with self.assertRaises(OpenSealError) as e:
            bad.token(client_id="c", client_secret="s", grant_type="refresh_token", refresh_token="osr_x")
        self.assertEqual((e.exception.oauth_error, e.exception.code), ("invalid_grant", "CS-AUTH-0014"))


class Webhooks(unittest.TestCase):
    def test_the_standard_webhooks_example_verifies_and_changes_do_not(self):
        w = REC["webhook"]
        now = w["now_ms"] / 1000
        self.assertEqual(verify_webhook(w["secret"], w["headers"], w["body"].encode(), now=now), {"test": 2432232314})
        for secret, headers, body, at in (
            (w["secret"], w["headers"], w["body"].replace("2432", "2433"), now),
            (w["secret"], w["headers"], w["body"], now + 301),
            ("whsec_c2Vjb25kLXNlY3JldC1mb3Itcm90YXRpb24=", w["headers"], w["body"], now),
            (w["secret"], {k: v for k, v in w["headers"].items() if k != "webhook-id"}, w["body"], now),
        ):
            with self.assertRaises(OpenSealError) as e:
                verify_webhook(secret, headers, body, now=at)
            self.assertEqual(e.exception.code, "webhook_signature")
        rotated = {**w["headers"], "Webhook-Signature": "v1,AAAA " + w["headers"]["webhook-signature"]}
        del rotated["webhook-signature"]
        self.assertEqual(verify_webhook(w["secret"], rotated, w["body"], now=now), {"test": 2432232314})


if __name__ == "__main__":
    unittest.main()
