# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — unreleased

First release. Scope is deliberately one layer: SIP messages, not SIP sessions.

### Added

- **Octet-level parser** for RFC 3261 messages: `Request-Line`, `Status-Line`, header
  block with CRLF folding, body framing driven by `Content-Length`.
- **Lexical layer**: `token`, `quoted-string` with `quoted-pair` unescaping, nested
  `comment` with an explicit depth cap, and the two-argument whitespace rules
  (`LWS`, `SWS`) including fold detection.
- **URI layer** (RFC 3261 §19.1): userinfo, password, IPv4 and bracketed IPv6 hosts,
  port, `;`-parameters, `?`-headers, single-pass `%` unescaping that never recurses.
- **Address layer**: `name-addr`, bare `addr-spec`, `absoluteURI`, quoted and token
  display names, header parameters, comma-separated lists that do not split inside
  quoted strings.
- **Compact header forms** (RFC 3261 Table 2): `i`, `l`, `v`, `t`, `f`, `m`, `c`, `s`,
  `k`, `e` resolve to their long names in both directions.
- **Re-emission** (`to_bytes`) that returns the input octets unchanged for any
  CRLF-framed message, excluding octets that followed the declared body.
- **Diagnostics**: 18 codes with byte offsets and two severities, each citing the
  RFC 4475 case it implements.
- **`analyze`**, a single entry point that never raises and reports one of
  `well-formed` / `syntax-rejected` / `semantic-rejected`.

### Robustness

- `fuzz_test.mbt`: deterministic generators over pseudo-random octets, structural
  octets, truncations, single-octet mutations and spliced input. Over 4,000 inputs,
  zero panics; every syntax error carries an offset inside the input.
- Removed the unreachable `negative-content-length` diagnostic. The grammar layer
  already rejects a negative or non-numeric `Content-Length`, so the branch could
  never fire.
- Coverage measured with `moon coverage analyze`: 50 uncovered lines in the library
  against 1,698 executable lines (about 97%).

### Conformance

- 49 messages extracted mechanically from RFC 4475 by `tools/extract_rfc4475.py`,
  which implements the RFC's own `<allOneLine>`, `<hex>` and `<repeat>` notations and
  keeps messages whole across page breaks.
- 45 of the 49 carry an asserted verdict in `rfc4475_expectations.json`; all 45 match.
- 4 vectors are marked `policy` and deliberately not asserted, because the RFC's
  expected behaviour depends on whether the element is a proxy or an endpoint.
- Every accepted message round-trips byte-for-byte, except `mpart01`, where the RFC's
  own `Content-Length` is 14 octets short of the body it prints. That vector is kept as
  a framing test and the discrepancy is documented rather than hidden.

### Known gaps

- Native backend is not verified on the development machine (no C compiler available).
- No transaction layer, dialog layer, SDP, authentication or TLS — see README.
- `reason-phrase` UTF-8 well-formedness is not validated.
