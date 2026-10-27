# sipkit

[![CI](https://github.com/BenPaoBaMingWangXing/sipkit/actions/workflows/ci.yml/badge.svg)](https://github.com/BenPaoBaMingWangXing/sipkit/actions/workflows/ci.yml)

**Sans-IO SIP message parsing, canonical re-emission and conformance diagnostics for MoonBit.**

SIP is the signalling protocol behind every VoIP call, SBC and IMS core. A SIP parser is
also one of the few parsers in a network stack that is routinely fed *hostile* input:
header folding, duplicate `Content-Length`, escaped characters that must not be unescaped,
and user parts containing the very characters that separate parameters.

`sipkit` parses SIP messages (RFC 3261) at the octet level, re-emits them byte-for-byte,
and reports structural defects with byte offsets. Correctness is not claimed — it is
measured against the IETF's own test corpus.

```
RFC 4475 torture corpus   49 messages extracted mechanically from the RFC text
                          45 verdicts asserted, 4 role-dependent (not asserted)
                          all 45 asserted verdicts match
                          every accepted message round-trips byte-for-byte *
Robustness                >4,000 generated inputs (random, truncated, mutated,
                          spliced) with zero panics
Coverage                  50 uncovered lines in the library (about 97% of 1,698
                          executable lines), measured with `moon coverage analyze`
Tests                     79, green on wasm · wasm-gc · js · native
Dependencies              none
Panics in the library     none — no `unwrap`, `panic` or `abort` outside tests
API documentation         112 of 112 public functions carry a doc comment
```

\* `mpart01` is a framing vector, not a round-trip vector — see Known limitations.

---

## Why this exists

MoonBit already has WebRTC media (`moonbit-community/rtc`) and SDP (`coke089/moon-sdp`),
but no signalling layer. A search of all 3,243 modules published on mooncakes.io and 1,805
MoonBit repositories created in 2026 returns **zero** packages for SIP itself, for RFC 3261,
or for the torture corpus. The layer that decides *which* session to set up is missing while
the layer that describes the session already exists.

The practical consequence: you cannot receive a SIP `INVITE` in MoonBit today. `sipkit` is
that missing first step, and only that step.

## What it does

| Capability | Detail |
|---|---|
| Parse | `Request-Line`, `Status-Line`, header block with folding, body framing by `Content-Length` |
| URI | `sip:` / `sips:` per RFC 3261 §19.1: userinfo, IPv4/IPv6 host, port, parameters, URI headers, single-pass `%` unescaping |
| Addresses | `name-addr` / `addr-spec` / `absoluteURI`, quoted and token display names, header parameters, comma-separated lists |
| Lexical | `token`, `quoted-string` with `quoted-pair`, nested `comment` with a depth cap, LWS including CRLF folding |
| Re-emit | `to_bytes` returns the input octets unchanged for any CRLF-framed message |
| Diagnose | 18 defect codes carrying byte offsets, each citing the torture case it implements |
| Compact names | RFC 3261 Table 2 single-letter forms (`i`, `l`, `v`, `t`, `f`, `m`, `c`, `s`, `k`, `e`) |

## What it deliberately does not do

This is a **message layer** library. It is sans-IO: it never opens a socket, never resolves
a name, and never owns a timer. Consequently:

- **No transaction or dialog layer.** No `INVITE` retransmission, no `ACK` matching, no
  `Route` set computation. RFC 4475 §3.2.1 is therefore checked as a *diagnostic* (branch
  identifier present), not as transaction behaviour.
- **No SDP.** `Content-Type: application/sdp` bodies are returned as opaque octets.
  `coke089/moon-sdp` is the natural companion.
- **No authentication.** `Authorization` / `WWW-Authenticate` are parsed as text; no Digest
  computation, no credential storage.
- **No TLS/DTLS transport.** `moonbitstack/moontls` owns that layer.
- **No extension support.** `Require` and `Proxy-Require` with any value are reported as
  unsupported, because the library implements none.
- **Role-dependent verdicts are not asserted.** Where RFC 4475 says "a proxy forwards but an
  endpoint replies 415", the library refuses to guess the caller's role.

## Conformance evidence

The evidence is generated from the RFC text, not hand-written:

```bash
python3 tools/extract_rfc4475.py --rfc rfc4475.txt --out-dir .
python3 tools/gen_tests.py
moon test
```

`extract_rfc4475.py` implements the three notations RFC 4475 §2 uses to print messages
(`<allOneLine>`, `<hex>`, `<repeat>`), keeps messages whole across page breaks, and emits the
exact octets. `rfc4475_expectations.json` holds the verdict for each message, read off the
prose of its section and reviewed by hand — the extractor never decides validity.

That separation is the point. A test suite that derives its expectations from its own
implementation proves nothing. Here the octets come from the IETF and the verdicts come from
the RFC's prose; the implementation is the only thing under test.

Two cases are worth calling out because they are commonly implemented backwards:

- **`lwsdisp` (§3.1.1.6)** — `From: caller<sip:caller@example.com>` has no LWS before `<`.
  The grammar forbids it, but the RFC identifies this as a *specification bug* and requires
  acceptance. `sipkit` accepts it.
- **`esc02` (§3.1.1.5)** — `%` is not an escape everywhere. `C%6Fntact` is **not** `Contact`,
  and `branch=z9hG4bK209%fzsnel234` is well formed. `sipkit` compares header names literally
  and accepts a stray `%`.

## Robustness

A SIP parser's worst failure is not rejecting a valid message — it is panicking on an
invalid one, because the panic takes the call path down with it. RFC 4475 proves the
grammar on 49 curated messages; it says nothing about the other infinity of inputs.

`fuzz_test.mbt` closes that gap with two deterministic generators, so any failure can be
replayed on the machine that found it:

| Generator | Inputs | What it reaches |
|---|---|---|
| Pseudo-random octets | 1,200 | Early grammar exits; the error paths |
| Structural octets (CR, LF, delimiters, high bits) | 1,500 | Adversarial whitespace and delimiter runs |
| Truncations of every corpus message | ~294 | Partial messages, unterminated constructs |
| Single-octet mutations of every corpus message | 1,176 | Deep grammar and diagnostics |
| Insertions and deletions (including an injected CRLF) | ~98 | Framing boundaries |

Result: **zero panics**, and the invariants hold — every syntax error carries an offset
inside the input, and anything that parses can be re-emitted.

Coverage is measured rather than assumed. `moon coverage analyze` reports 58 uncovered
lines, 50 of them in the library (`cmd/main` accounts for the rest). Against 1,698
executable lines — counted as non-blank, non-comment lines, the stated denominator so the
number can be checked — that is about 97%. The uncovered lines are defensive branches in
the lexer that the corpus cannot reach.

Removing unreachable code is part of this. A `Content-Length` that is negative or
non-numeric is rejected by the grammar layer, so the diagnostics layer used to carry a
`negative-content-length` branch that could never fire; it is gone rather than left as
decoration.

## Quick start

```bash
moon add BenPaoBaMingWangXing/sipkit
```

```moonbit
let input : Bytes =
  b"INVITE sip:bob@example.com SIP/2.0\r\nTo: <sip:bob@example.com>\r\nFrom: <sip:alice@example.com>;tag=1\r\nCall-ID: a1\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP host;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"

let a = analyze(input)
println(a.verdict())            // well-formed
let msg = a.message().unwrap()
println(ascii_of(msg.verb().unwrap().view()))   // INVITE
assert_eq(to_bytes(msg).length(), input.length())
```

`analyze` never raises. A syntax failure is data:

```moonbit
match analyze(b"garbage").syntax() {
  Some(pair) => println("rejected: \{pair.0} at byte \{pair.1}")
  None => ()
}
```

### Diagnostics

Each diagnostic carries a code, a severity and a byte offset:

```moonbit
for d in analyze(input).diagnostics() {
  println("\{d}")   // error:content-length-mismatch@214 declared 152 but body is 0
}
```

Severity is not decoration: `Verdict` follows it directly. `well-formed` means parsed with
no error-severity diagnostic, `syntax-rejected` means the grammar refused the octets, and
`semantic-rejected` means it parsed but a semantic rule fired.

Warnings (a missing `Max-Forwards`, an RFC 2543 style Via without `branch`, trailing octets)
do **not** change the verdict, because RFC 4475 accepts those messages.

## Examples

Three runnable programs, no dependencies, no setup:

```bash
moon run examples/parse_dump    # parse an INVITE, print every recovered field
moon run examples/diagnose      # the three verdicts, side by side
moon run examples/uri           # URI decomposition, including the awkward cases
```

`parse_dump` prints what actually came out of the octets, not a pretty-printed
restatement:

```
start line
  method     INVITE
  uri.scheme sip
  uri.user   bob
  uri.host   example.com
  uri.port   5060
  uri.params 1
    ;transport=tcp
headers (9), in wire order
  line 2  Via: SIP/2.0/UDP alice-pc.example.com:5060;branch=z9hG4bK776asdhds
  ...
round-trip identical: true
```

`diagnose` is the one worth reading, because it shows why the two layers are
separate — the third case parses cleanly and still fails:

```
--- semantic-rejected
    verdict: semantic-rejected
    [error] content-length-mismatch at byte 236
             declared 42 but body is 5
    [error] cseq-method-mismatch at byte 120
             CSeq method INVITE != start line OPTIONS

--- well-formed, with a warning
    verdict: well-formed
    [warning] missing-required-header at byte 0
             request has no Max-Forwards header
```

A proxy forwards that last message. An implementation that folds warnings into
errors drops a call it should have routed.

`uri` covers the cases that separate a real parser from a regex:

```
--- sip:al%41ice@example.com
    user     al%41ice
    user*    alAice   (decoded once)

--- sip:al%2541ice@example.com
    user*    al%41ice   (decoded once)      <- not `alAice`: decoding is single-pass

--- sip:user;par=u%40example.net@example.com
    user     user;par=u%40example.net
    user*    user;par=u@example.net         <- the ; belongs to the user part
```

## Design decisions

**Octets, never `String`.** SIP is an octet protocol; header values may carry octets that are
not valid UTF-8. The parser works on `Bytes` throughout and never materialises a `String`, so
parsing cannot fail or silently rewrite bytes for reasons the wire format does not sanction.
(In this toolchain `String` is UTF-16 — `"sip".to_bytes()` is six octets, not three — a detail
that silently corrupts byte protocols.)

**Two layers, two questions.** The grammar layer decides whether octets form a message; the
diagnostics layer decides whether a message is *acceptable*. RFC 4475 splits its corpus along
exactly this line (§3.1.2 syntax versus §3.2/§3.3 semantics), and conflating the two is what
makes SIP stacks reject messages they should forward.

**`trailing` is kept, not dropped.** Octets after the declared body belong to whatever
followed in the datagram. Dropping them hides a real attack surface (request smuggling);
`parse_message` exposes them and `to_bytes` does not re-emit them.

**Bounded recursion.** `comment` nests in the ABNF, a classic stack-exhaustion vector. The
implementation uses an explicit depth counter capped at 16 rather than recursion.

## Ecosystem position

Checked against 3,243 mooncakes.io modules and 1,805 MoonBit repositories created in 2026.
Neighbouring work, and why `sipkit` does not overlap:

| Project | Scope | Relationship |
|---|---|---|
| `moonbit-community/rtc` | WebRTC media stack | Media plane; `sipkit` is the signalling plane |
| `coke089/moon-sdp` | SDP (RFC 8866) offer/answer | Session *description*; `sipkit` keeps bodies opaque |
| `moonbitstack/moonurl` | RFC 3986 URI | Generic URI; SIP URI has its own grammar (§19.1) |
| `moonbitstack/moonhttp` | HTTP / WebSocket | Different protocol family |

## Data sources and licensing

- Source code: **Apache-2.0** (see `LICENSE`).
- RFC 3261 / RFC 4475 octets reproduced in generated fixtures are used under the
  **IETF Trust Legal Provisions** (see `NOTICE`). No RFC text is bundled: `rfc4475.txt` is
  fetched by the reproduction steps and is deliberately absent from the repository.
- Generated files (`rfc4475_test.mbt`, `rfc4475_vectors.json`) contain only message octets
  and section numbers; provenance is recorded in `NOTICE`.

## Reproduce

Requires MoonBit `0.1.20260904` or newer and Python 3.9+.

```bash
python3 tools/extract_rfc4475.py --rfc rfc4475.txt --out-dir .   # needs rfc4475.txt
python3 tools/gen_tests.py
moon check
moon fmt --check
moon test --target wasm
moon test --target wasm-gc
moon test --target js
moon coverage analyze        # line-level coverage; ~50 uncovered lines in the library
```

`rfc4475.txt` is available from <https://www.rfc-editor.org/rfc/rfc4475.txt>.

To reproduce the robustness numbers, just run the tests: the fuzz generators are
deterministic and part of the default suite, so `moon test` either passes or names the
seed that fails.

## Known limitations

Scope statement first: the final scope of this project is the **RFC 3261 message
layer** (§7 message format, §19.1 SIP-URI, §20 header fields, §25.1 message-layer
ABNF). Everything in that scope is implemented except two tracked items with
dates (below); everything outside it — dialog layer, transactions, authentication,
TLS — is out of scope by design, not "not yet".

**In scope, tracked, dated:**

1. **Typed validation for the remaining §20 header fields.** `CSeq`,
   `Max-Forwards`, `Retry-After`, `Via`, `Contact`, `Content-Length`, `Date`,
   duplicate single-valued headers and required-header presence are validated
   today. The rest of the message-layer fields (`Expires`, `Min-Expires`,
   `Warning`, `In-Reply-To`, `Rack`/`RSeq`) are parsed but not yet
   semantically validated — **due 2026-10-30**.
2. **`TEXT-UTF8-TRIM` well-formedness.** `Reason-Phrase` and other TEXT fields
   preserve octets; UTF-8 sequence validation with a diagnostic on malformed
   input is **due 2026-10-31**.

**Completed after the first application review** (previously listed here as
limitations):

- ~~`Date` is structural only~~ → full §25.1 `SIP-date` since 2026-10-27: fixed
  29-octet shape, weekday/month whitelists, day-in-month with leap years,
  `HH≤23`/`MM≤59`/`SS≤60` (60 as leap second), and weekday/date agreement via
  Zeller's congruence — `Mon, 01 Jan 2010` is rejected on the weekday although
  every token looks plausible.

**Specification-level conflicts, recorded not pending** — these have no correct
answer in the documents; the implementation takes a defensible side and says so:

1. **`:` in the user part.** RFC 4475 §3.1.1.2's message puts `:` inside the
   user part; RFC 3261 §25.1's `user-unreserved` does not include it (`:` is the
   user/password separator). The ABNF wins: the user ends at the first colon,
   the rest is the password.
2. **Parameter namespace on a bare addr-spec.** `Contact: sip:a@b;unknownparam`
   without angle brackets makes `;`-parameters both URI parameters and contact
   parameters, and the grammar cannot separate them. RFC 3261 §20.10 admits this
   and recommends always using `<>`. The parameter stays reachable and
   user/host are unaffected.
3. **`mpart01` sample data.** The RFC prints `Content-Length: 553` for a hex
   body that is 14 octets longer. Framing by `Content-Length` (the correct
   behaviour) leaves those 14 octets as trailing.

**Environment, not code:** the native backend is verified in CI only — this
development machine has no C compiler (`cl`/`cc`/`gcc`/`clang` all absent). The
three JS/Wasm backends pass locally.
