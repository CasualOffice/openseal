// Password strength indication (ASVS 2.1.8, ASVS-03): an estimate of how many guesses a
// password would take, shown as a meter with advice on every screen that sets a staff
// password (accept-invite, the profile's new password, an administrator setting a
// member's password). Pure: no DOM, so Node tests it (tests/pwstrength.test.mjs).
//
// Advisory only. What the server refuses is its own policy (12 to 256 characters, not on
// the breached-password list, ASVS-02); the meter never blocks a password the server
// would take, and never claims a password is safe, only how it scores.
//
// The estimate follows zxcvbn's idea (Wheeler, USENIX Security 2016), written here, not
// copied: the password is cut, left to right, into the cheapest-to-guess pieces it holds
// (a common password or word, a run of one character, a sequence such as "abcd" or
// "4321", a keyboard row such as "qwerty", a year, the person's own name or email), and
// any other character costs what a guess over its character classes costs. The bits add
// up; the score is the bits in five bands.

/// The most common passwords and the words they are made of, lower case, commonest first
/// (a word's rank is its cost). A small list on purpose: the server's breached list is the
/// control; this only stops the meter praising the obvious.
const COMMON = [
  "password", "123456", "qwerty", "letmein", "welcome", "admin", "login", "master", "hello",
  "monkey", "dragon", "football", "baseball", "soccer", "hockey", "iloveyou", "love", "princess",
  "sunshine", "shadow", "superman", "batman", "trustno1", "secret", "freedom", "whatever",
  "starwars", "pokemon", "michael", "jennifer", "jordan", "hunter", "ranger", "buster", "tigger",
  "charlie", "summer", "winter", "spring", "autumn", "flower", "cheese", "computer", "internet",
  "access", "default", "changeme", "passw0rd", "abc123", "test", "guest", "user", "root",
  "company", "office", "openseal", "sign", "signature", "document", "contract", "money", "please",
  "orange", "banana", "apple", "purple", "silver", "golden", "diamond", "matrix", "mustang",
  "harley", "thunder", "killer", "pepper", "ginger", "cookie", "chocolate", "butterfly", "angel",
  "jesus", "christ", "family", "friend", "friends", "forever", "happy", "lucky", "magic",
  "correct", "horse", "battery", "staple", "january", "february", "march", "april", "june",
  "july", "august", "september", "october", "november", "december", "monday", "friday",
  "sunday", "london", "paris", "berlin", "india", "america", "canada", "qwertz", "azerty",
];

const RANK = new Map();
COMMON.forEach((w, i) => { if (!RANK.has(w)) RANK.set(w, i + 1); });

/// Keyboard rows people walk along, and the digit row.
const ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "qwertzuiop", "azertyuiop", "yxcvbnm"];

/// Character swaps people make for letters ("p@ssw0rd").
const LEET = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s", "!": "i", "|": "l" };

/// How many characters a password needs, below which the advice says "longer".
const LONG_ENOUGH = 16;

const log2 = (n) => Math.log2(Math.max(1, n));

/// The cost, in bits, of one character guessed blind: the size of the character classes
/// the whole password uses.
function charBits(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^A-Za-z0-9]/.test(pw)) pool += /[^\x20-\x7e]/.test(pw) ? 100 : 33;
  return log2(pool || 26);
}

/// The person's own words worth guessing: from their name and email, lower case, three
/// characters or more.
function personalWords(inputs) {
  const out = new Set();
  for (const v of inputs || []) {
    for (const w of String(v || "").toLowerCase().split(/[^a-z0-9]+/)) if (w.length >= 3) out.add(w);
  }
  return [...out];
}

/// The cheapest piece that starts at `i`, or null: `{ len, bits, kind }`.
function pieceAt(pw, lower, i, mine) {
  const best = [];
  // One character repeated: "aaaa", "1111".
  let j = i + 1;
  while (j < pw.length && pw[j] === pw[i]) j += 1;
  if (j - i >= 3) best.push({ len: j - i, bits: charBits(pw[i]) + log2(j - i), kind: "repeat" });
  // A sequence of code points, up or down by one: "abcd", "6543".
  for (const step of [1, -1]) {
    let k = i + 1;
    while (k < pw.length && lower.charCodeAt(k) - lower.charCodeAt(k - 1) === step && /[a-z0-9]/.test(lower[k])) k += 1;
    if (k - i >= 3) best.push({ len: k - i, bits: log2(26) + 1 + log2(k - i), kind: "sequence" });
  }
  // A walk along a keyboard row, either way: "qwerty", "lkjh".
  for (const row of ROWS) {
    for (const r of [row, [...row].reverse().join("")]) {
      let n = 0;
      while (i + n < pw.length && r.includes(lower.slice(i, i + n + 1))) n += 1;
      if (n >= 4) best.push({ len: n, bits: log2(ROWS.length * 2 * 10) + log2(n), kind: "sequence" });
    }
  }
  // A year people use: 1900 to 2039.
  const year = /^(19[0-9]{2}|20[0-3][0-9])/.exec(lower.slice(i));
  if (year) best.push({ len: 4, bits: log2(140), kind: "year" });
  // A common word or password, as typed or with letters swapped ("p@ssw0rd"), and the
  // person's own name or email.
  const plain = [...lower.slice(i)].map((c) => LEET[c] || c).join("");
  for (let len = Math.min(pw.length - i, 16); len >= 3; len -= 1) {
    const typed = lower.slice(i, i + len);
    const swapped = plain.slice(0, len);
    for (const [word, leet] of [[typed, false], [swapped, swapped !== typed]]) {
      const caps = pw.slice(i, i + len) !== typed ? 1 : 0;
      const rank = RANK.get(word);
      if (rank && len >= 4) best.push({ len, bits: log2(rank) + caps + (leet ? 1 : 0) + 1, kind: "common" });
      if (mine.includes(word)) best.push({ len, bits: 1 + caps + (leet ? 1 : 0), kind: "personal" });
    }
  }
  if (!best.length) return null;
  // The piece that saves the most over guessing its characters blind.
  const blind = charBits(pw);
  best.sort((a, b) => (b.len * blind - b.bits) - (a.len * blind - a.bits));
  return best[0];
}

/// The advice keys, in the order they are worth reading.
const ADVICE = {
  common: "pwstrength.hint-common",
  personal: "pwstrength.hint-personal",
  repeat: "pwstrength.hint-repeat",
  sequence: "pwstrength.hint-sequence",
  year: "pwstrength.hint-year",
};

/// How strong `password` looks, for the person whose name and email are `inputs`:
/// `{ score, bits, label, hints }`. `score` 0 (very weak) to 4 (strong); `label` the
/// message key of the score (`pwstrength.0` … `pwstrength.4`); `hints` up to two message
/// keys of advice. An empty password scores null: nothing to show yet.
export function passwordStrength(password = "", inputs = []) {
  const pw = String(password);
  if (!pw) return { score: null, bits: 0, label: null, hints: [] };
  const lower = pw.toLowerCase();
  const mine = personalWords(inputs);
  const blind = charBits(pw);
  let bits = 0;
  const kinds = new Set();
  for (let i = 0; i < pw.length;) {
    const p = pieceAt(pw, lower, i, mine);
    if (p && p.bits < p.len * blind) {
      bits += p.bits;
      kinds.add(p.kind);
      i += p.len;
    } else {
      bits += blind;
      i += 1;
    }
  }
  const score = bits < 24 ? 0 : bits < 36 ? 1 : bits < 48 ? 2 : bits < 60 ? 3 : 4;
  const hints = Object.keys(ADVICE).filter((k) => kinds.has(k)).map((k) => ADVICE[k]);
  if (score < 4 && [...pw].length < LONG_ENOUGH) hints.push("pwstrength.hint-longer");
  if (score < 3 && !/[^a-z]/.test(pw)) hints.push("pwstrength.hint-mix");
  return { score, bits: Math.round(bits), label: `pwstrength.${score}`, hints: score === 4 ? [] : hints.slice(0, 2) };
}
