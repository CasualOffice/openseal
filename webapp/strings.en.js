// English messages (WEB-01). Every user-facing string in the app is here, by key;
// `tests/i18n.test.mjs` fails on a key used in code or HTML that is missing here.
// Wording follows docs/47 principle 1: DocuSign's generic words (envelope, recipient,
// routing order, void), plain sentences, no legal claims (docs/09, docs/04 rule 25).
//
// The messages live in strings/ by area (UX-02), so each part of the app owns its own
// file: common (shared), shell, prepare, sign, manage and admin. This file merges them
// into the one map the app and the tests read. A key is defined in exactly one part
// (tests/pure.test.mjs checks it).
import { COMMON } from "./strings/common.en.js";
import { SHELL } from "./strings/shell.en.js";
import { PREPARE } from "./strings/prepare.en.js";
import { SIGN } from "./strings/sign.en.js";
import { MANAGE } from "./strings/manage.en.js";
import { ADMIN } from "./strings/admin.en.js";

/// Every part, by name: for the test that a key is defined only once.
export const PARTS = { COMMON, SHELL, PREPARE, SIGN, MANAGE, ADMIN };

export const EN = { ...COMMON, ...SHELL, ...PREPARE, ...SIGN, ...MANAGE, ...ADMIN };
