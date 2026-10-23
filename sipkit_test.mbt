// sipkit_test.mbt — blackbox tests over the public API.
//
// These exercise behaviour a caller can observe: the parse verdict, the semantic
// diagnostics, and byte-exact round-trip. The RFC 4475 conformance suite lives in
// `rfc4475_test.mbt` and is generated from the RFC text itself.

///|
let good_invite : Bytes = b"INVITE sip:user@example.com SIP/2.0\r\nTo: sip:j.user@example.com\r\nFrom: sip:caller@example.net;tag=134161461246\r\nMax-Forwards: 7\r\nCall-ID: smoke01.0ha0isndaksdjasdf3234nas\r\nCSeq: 8 INVITE\r\nVia: SIP/2.0/UDP 192.0.2.15;branch=z9hG4bKkdjuw\r\nContact: <sip:caller@host.example.com>\r\nContent-Length: 0\r\n\r\n"

///|
let good_response : Bytes = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.0.2.15;branch=z9hG4bKkdjuw\r\nFrom: sip:caller@example.net;tag=134161461246\r\nTo: sip:j.user@example.com;tag=abc\r\nCall-ID: smoke02.aaaa\r\nCSeq: 8 INVITE\r\nContent-Length: 0\r\n\r\n"

///|
test "a well-formed INVITE parses, diagnoses clean, and round-trips" {
  let a = analyze(good_invite)
  assert_eq(a.verdict().to_string(), "well-formed")
  let msg = a.message().unwrap()
  assert_eq(ascii_of(msg.verb().unwrap().view()), "INVITE")
  // Byte-exact round-trip: the property the conformance suite relies on.
  assert_eq(ascii_of(to_bytes(msg).view()), ascii_of(good_invite.view()))
}

///|
test "a well-formed response parses with its status code" {
  let a = analyze(good_response)
  assert_eq(a.verdict().to_string(), "well-formed")
  let msg = a.message().unwrap()
  assert_eq(msg.status_code().unwrap(), 200)
}

///|
test "header field names are matched case-insensitively but never unescaped" {
  // RFC 4475 3.1.1.5: `C%6Fntact` is a different field from `Contact`.
  let raw : Bytes = b"INVITE sip:user@example.com SIP/2.0\r\nTo: sip:a@b\r\nFrom: sip:c@d;tag=1\r\nMax-Forwards: 70\r\nCall-ID: esc.1\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nContact: <sip:x@y>\r\nC%6Fntact: <sip:z@w>\r\nContent-Length: 0\r\n\r\n"
  let msg = analyze(raw).message().unwrap()
  assert_eq(msg.all_headers("Contact").length(), 1)
  assert_eq(msg.all_headers("C%6Fntact").length(), 1)
}

///|
test "Content-Length larger than the datagram is reported, not thrown" {
  let raw : Bytes = b"INVITE sip:user@example.com SIP/2.0\r\nTo: sip:a@b\r\nFrom: sip:c@d;tag=1\r\nMax-Forwards: 70\r\nCall-ID: cl.1\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nContent-Length: 999\r\n\r\n"
  let a = analyze(raw)
  assert_eq(a.verdict().to_string(), "semantic-rejected")
  assert_true(a.has_code(DiagCode::ContentLengthMismatch))
}

///|
test "a negative Content-Length is rejected by the grammar" {
  // `Content-Length = 1*DIGIT`, so a sign is a syntax error, not a range error.
  // RFC 4475 §3.1.2.3 ("ncl") requires the receiver not to break; returning a
  // located syntax error is how we satisfy that.
  let raw : Bytes = b"INVITE sip:user@example.com SIP/2.0\r\nTo: sip:a@b\r\nFrom: sip:c@d;tag=1\r\nMax-Forwards: 70\r\nCall-ID: neg.1\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nContent-Length: -1\r\n\r\n"
  let a = analyze(raw)
  assert_eq(a.verdict().to_string(), "syntax-rejected")
  match a.syntax() {
    Some(pair) => assert_eq(pair.0.to_string(), "malformed Content-Length")
    None => fail("expected a syntax error")
  }
}

///|
test "a second message in the same datagram is surfaced, not swallowed" {
  // RFC 4475 §3.1.1.8 (dblreq): the first message ends at Content-Length: 0 and
  // the rest of the datagram must be visible to the caller.
  let raw : Bytes = b"REGISTER sip:example.com SIP/2.0\r\nTo: sip:a@b\r\nFrom: sip:c@d;tag=1\r\nMax-Forwards: 8\r\nCall-ID: db.1\r\nCSeq: 8 REGISTER\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nContent-Length: 0\r\n\r\n" +
    b"INVITE sip:x@y SIP/2.0\r\n\r\n"
  let a = analyze(raw)
  let msg = a.message().unwrap()
  assert_eq(msg.trailing().length(), 26)
  assert_true(a.has_code(DiagCode::TrailingOctets))
}

///|
test "compact header forms are understood" {
  // RFC 3261 Table 2: `i` is Call-ID, `l` is Content-Length, `v` is Via.
  let raw : Bytes = b"OPTIONS sip:user@example.com SIP/2.0\r\nv: SIP/2.0/UDP h;branch=z9hG4bK1\r\nt: sip:a@b\r\nf: sip:c@d;tag=1\r\nl: 0\r\ni: compact.1\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\n\r\n"
  let a = analyze(raw)
  assert_eq(a.verdict().to_string(), "well-formed")
  let msg = a.message().unwrap()
  assert_eq(msg.all_headers("Call-ID").length(), 1)
  assert_eq(msg.all_headers("Content-Length").length(), 1)
}

///|
test "a Via without a branch is tolerated but reported" {
  // RFC 4475 §3.4.1 (inv2543) is well formed; §3.2.1 (badbranch) is not.
  let legacy : Bytes = b"OPTIONS sip:user@example.com SIP/2.0\r\nTo: sip:a@b\r\nFrom: sip:c@d;tag=1\r\nMax-Forwards: 70\r\nCall-ID: b1.1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h\r\nContent-Length: 0\r\n\r\n"
  let a = analyze(legacy)
  assert_eq(a.verdict().to_string(), "well-formed")
  assert_true(a.has_code(DiagCode::MissingViaBranch))

  let empty_id : Bytes = b"OPTIONS sip:user@example.com SIP/2.0\r\nTo: sip:a@b\r\nFrom: sip:c@d;tag=1\r\nMax-Forwards: 70\r\nCall-ID: b2.1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK\r\nContent-Length: 0\r\n\r\n"
  let b = analyze(empty_id)
  assert_eq(b.verdict().to_string(), "semantic-rejected")
  assert_true(b.has_code(DiagCode::MissingViaBranch))
}

///|
test "empty input is rejected with a located syntax error" {
  let a = analyze(b"")
  assert_eq(a.verdict().to_string(), "syntax-rejected")
  match a.syntax() {
    Some(pair) => {
      let (kind, at) = pair
      assert_eq(kind.to_string(), "empty input")
      assert_eq(at, 0)
    }
    None => fail("expected a syntax error")
  }
}

///|
test "SIP URIs parse into their components" {
  let c = Cursor::from_bytes(
    b"sip:alice:secret@example.com:5060;transport=tcp;lr?subject=hi",
  )
  let u = parse_sip_uri(c)
  assert_eq(ascii_of(u.user().unwrap().view()), "alice")
  assert_eq(ascii_of(u.password().unwrap().view()), "secret")
  assert_eq(u.host().to_string(), "example.com")
  assert_eq(u.port().unwrap(), 5060)
  assert_true(u.param("lr") is Some(_))
  assert_eq(u.headers().length(), 1)
  assert_eq(ascii_of(u.headers()[0].name().view()), "subject")
}

///|
test "percent escapes decode exactly once and never recursively" {
  // RFC 4475 3.1.1.3: value%41 is valueA, and unescaping is not recursive.
  assert_eq(ascii_of(unescape_once(b"value%41".view()).view()), "valueA")
  assert_eq(ascii_of(unescape_once(b"value%2541".view()).view()), "value%41")
  // A `%` that is not an escape survives literally (RFC 4475 3.1.1.5).
  assert_eq(
    ascii_of(unescape_once(b"z9hG4bK209%fz".view()).view()),
    "z9hG4bK209%fz",
  )
}

///|
test "a display name may sit directly against < without LWS" {
  // RFC 4475 3.1.1.6 (lwsdisp) must be accepted.
  let c = Cursor::from_bytes(b"caller<sip:caller@example.com>;tag=323")
  let a = parse_name_addr(c)
  assert_eq(ascii_of(a.display().unwrap().view()), "caller")
  assert_eq(ascii_of(a.tag().unwrap().view()), "323")
}

///|
test "a quoted display name keeps its semantic value and its quoting flag" {
  let c = Cursor::from_bytes(b"\"Bell, Alexander\" <sip:a.g.bell@example.com>")
  let a = parse_name_addr(c)
  assert_eq(ascii_of(a.display().unwrap().view()), "Bell, Alexander")
  assert_true(a.display_quoted())
}

///|
test "an unquoted display name containing a comma is rejected" {
  // RFC 4475 3.1.2.15 (baddn) is malformed.
  let raw : Bytes = b"OPTIONS sip:t.watson@example.org SIP/2.0\r\nFrom: Bell, Alexander <sip:a.g.bell@example.com>;tag=43\r\nTo: sip:t.watson@example.org\r\nMax-Forwards: 70\r\nCall-ID: baddn.1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP c;branch=z9hG4bK1\r\nContent-Length: 0\r\n\r\n"
  assert_eq(analyze(raw).verdict().to_string(), "syntax-rejected")
}

///|
test "whitespace inside the angle brackets is rejected" {
  // RFC 4475 3.1.2.14 (badaspec) is malformed.
  let c = Cursor::from_bytes(b"\"Watson, Thomas\" < sip:t.watson@example.org >")
  let r : Result[NameAddr, SipError] = Ok(parse_name_addr(c)) catch {
    e => Err(e)
  }
  assert_true(r is Err(_))
}
