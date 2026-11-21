// RSP-02 (ADR-047): an India eSign signer through the client and the mock, as the server
// takes it: the consent shown and required ticked, one hand-off per document, the
// return to the page. Run: cd webapp && npm test
import test from "node:test";
import assert from "node:assert/strict";

import { createClient } from "../api.js";
import { createMockFetch, MOCK } from "../mock.js";
import { rspReturn, RSP_KEY } from "../signfields.js";

function withProviders(on) {
  const store = new Map(on ? [["openseal.mock.rsp", "1"]] : []);
  globalThis.sessionStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) };
}

test("an eSign signer sees the consent, cannot start without ticking it, and signs through the hand-off", async () => {
  withProviders(true);
  try {
    const api = createClient({ fetch: createMockFetch() });
    const tok = MOCK.esignSignToken;
    const v = await api.ceremony.open(tok);
    assert.equal(v.recipient.signature.type, "remote");
    assert.equal(v.remote_provider_name, "Demo eSign provider");
    assert.equal(v.remote_esign.consent_version, "esign-consent-v1-en");
    assert.match(v.remote_esign.consent_text, /OpenSeal never receives them/);
    assert.deepEqual(v.remote_esign.auth_modes, ["otp", "face"]);
    const sig = v.fields.find((f) => f.type === "signature");
    await api.ceremony.consent(tok, v.consent_required.version);
    const a = await api.ceremony.adopt(tok, "signature", "type", btoa("\x89PNG\r\n\x1a\n" + "x".repeat(16)));
    await api.ceremony.fill(tok, sig.id, { signature: a.adoption_id });
    // No consent, an unticked consent, another version, a mode not offered: refused.
    await assert.rejects(api.ceremony.remoteStart(tok), (e) => e.status === 422);
    await assert.rejects(api.ceremony.remoteStart(tok, null, { consent: "esign-consent-v1-en", accepted: false }), (e) => e.status === 422);
    await assert.rejects(api.ceremony.remoteStart(tok, null, { consent: "v0", accepted: true }), (e) => e.status === 422);
    await assert.rejects(api.ceremony.remoteStart(tok, null, { consent: "esign-consent-v1-en", accepted: true, auth_mode: "iris" }), (e) => e.status === 422);
    let r = await api.ceremony.remoteStart(tok, null, { consent: "esign-consent-v1-en", accepted: true, auth_mode: "face" });
    assert.equal(r.remote_signing.status, "prepared");
    assert.equal(r.remote_authorization_url, undefined, "no provider login for eSign");
    r = await api.ceremony.remoteAuthorize(tok);
    assert.deepEqual(r.remote_signing.esign, { handoff: "/s/rsp?state=esign", document: 1, of: 1 });
    assert.equal(r.recipient.status, "completed");
  } finally {
    withProviders(false);
  }
});

test("the return from the ESP names the link this tab kept, with state esign", () => {
  const store = new Map([[RSP_KEY, "tok-2"]]);
  const storage = { getItem: (k) => store.get(k) ?? null, removeItem: (k) => store.delete(k) };
  assert.deepEqual(rspReturn({ pathname: "/s/rsp", search: "?state=esign" }, storage), { token: "tok-2", state: "esign", code: null, error: null });
  assert.equal(rspReturn({ pathname: "/s/rsp", search: "?state=esign" }, storage), null, "once");
});
