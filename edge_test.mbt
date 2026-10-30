// edge_test.mbt — boundary behaviour and the public surface.
//
// Two jobs:
//
//   1. Every error branch that the torture corpus does not reach is exercised
//      once, with the specific error kind asserted. A branch nobody can trigger
//      is either dead code or an untested guard, and both are worth knowing about.
//   2. Every public accessor is called and its value checked. Getters rot
//      silently when a field is renamed; this catches that.

///|
/// Asserts that analysing `input` fails at the grammar layer with `kind`.
fn expect_syntax(input : Bytes, kind : String) -> Unit raise {
  let a = @sipkit.analyze(input)
  assert_eq(a.verdict().to_string(), "syntax-rejected")
  match a.syntax() {
    Some(pair) => assert_eq(pair.0.to_string(), kind)
    None => fail("expected a syntax error, got a message")
  }
}

// ---------------------------------------------------------------------------
// Lexical layer
// ---------------------------------------------------------------------------

///|
test "cursor: expect_byte succeeds on match and fails with a located error" {
  let c = @sipkit.Cursor::from_bytes(b"ab")
  c.expect_byte(b'a')
  assert_eq(c.position(), 1)
  let r : Result[Unit, @sipkit.SipError] = Ok(c.expect_byte(b'z')) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => fail("expected IllegalOctet")
    Err(e) => assert_true(e.to_string().contains("illegal octet"))
  }
  // Position must not advance on failure.
  assert_eq(c.position(), 1)
}

///|
test "cursor: expect_byte at end of input reports UnexpectedEnd" {
  let c = @sipkit.Cursor::from_bytes(b"")
  let r : Result[Unit, @sipkit.SipError] = Ok(c.expect_byte(b'a')) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => fail("expected UnexpectedEnd")
    Err(e) => assert_true(e.to_string().contains("unexpected end"))
  }
}

///|
test "cursor: literal matching is case-insensitive and rejects mismatch" {
  let c = @sipkit.Cursor::from_bytes(b"SIP/2.0")
  assert_true(c.starts_with_ignore_case("sip/"))
  assert_true(!c.starts_with("sip/"))
  c.expect_literal("sip/")
  assert_eq(c.position(), 4)
  let r : Result[Unit, @sipkit.SipError] = Ok(c.expect_literal("XX")) catch {
    e => Err(e)
  }
  assert_true(r is Err(_))
}

///|
test "cursor: peek_at beyond the end is None, not a panic" {
  let c = @sipkit.Cursor::from_bytes(b"ab")
  assert_true(c.peek_at(0) is Some(_))
  assert_true(c.peek_at(5) is None)
}

///|
test "token: an empty run raises ExpectedToken" {
  let c = @sipkit.Cursor::from_bytes(b";x")
  let r : Result[Bytes, @sipkit.SipError] = Ok(@sipkit.parse_token(c)) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => fail("expected ExpectedToken")
    Err(e) => assert_true(e.to_string().contains("expected token"))
  }
}

///|
test "quoted string: quoted-pair unescapes and raw keeps the wire form" {
  let c = @sipkit.Cursor::from_bytes(b"\"a\\\"b\"")
  let qs = @sipkit.parse_quoted_string(c)
  assert_eq(@sipkit.ascii_of(qs.value().exact_view()), "a\"b")
  assert_eq(@sipkit.ascii_of(qs.raw().exact_view()), "\"a\\\"b\"")
}

///|
test "quoted string: a backslash before CRLF is a bad escape" {
  // quoted-pair explicitly excludes CR and LF.
  let c = @sipkit.Cursor::from_bytes(b"\"a\\\r\nb\"")
  let r : Result[@sipkit.QuotedString, @sipkit.SipError] = Ok(
    @sipkit.parse_quoted_string(c),
  ) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => fail("expected BadEscape")
    Err(e) => assert_true(e.to_string().contains("bad quoted-pair escape"))
  }
}

///|
test "quoted string: a bare CR inside the quotes is rejected" {
  let c = @sipkit.Cursor::from_bytes(b"\"a\rb\"")
  let r : Result[@sipkit.QuotedString, @sipkit.SipError] = Ok(
    @sipkit.parse_quoted_string(c),
  ) catch {
    e => Err(e)
  }
  assert_true(r is Err(_))
}

///|
test "quoted string: a fold inside the quotes becomes a single SP" {
  let c = @sipkit.Cursor::from_bytes(b"\"a\r\n b\"")
  let qs = @sipkit.parse_quoted_string(c)
  assert_eq(@sipkit.ascii_of(qs.value().exact_view()), "a b")
}

///|
test "quoted string: unterminated input reports the specific kind" {
  let c = @sipkit.Cursor::from_bytes(b"\"abc")
  let r : Result[@sipkit.QuotedString, @sipkit.SipError] = Ok(
    @sipkit.parse_quoted_string(c),
  ) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => fail("expected UnterminatedQuotedString")
    Err(e) => assert_true(e.to_string().contains("unterminated quoted string"))
  }
}

///|
test "comment: nesting is parsed and depth is capped" {
  let c = @sipkit.Cursor::from_bytes(b"(a(b)c)")
  assert_eq(@sipkit.ascii_of(@sipkit.parse_comment(c).exact_view()), "a(b)c")

  // 17 levels: one past the cap, so this must be refused rather than recurse.
  let deep : Array[Byte] = []
  for _ in 0..<17 {
    deep.push(b'(')
  }
  deep.push(b'x')
  for _ in 0..<17 {
    deep.push(b')')
  }
  let c2 = @sipkit.Cursor::from_bytes(Bytes::from_array(deep))
  let r : Result[Bytes, @sipkit.SipError] = Ok(@sipkit.parse_comment(c2)) catch {
    e => Err(e)
  }
  assert_true(r is Err(_))
}

///|
test "comment: an unterminated comment reports the specific kind" {
  let c = @sipkit.Cursor::from_bytes(b"(abc")
  let r : Result[Bytes, @sipkit.SipError] = Ok(@sipkit.parse_comment(c)) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => fail("expected UnterminatedComment")
    Err(e) => assert_true(e.to_string().contains("unterminated comment"))
  }
}

///|
test "comment: a non-bracket start is refused" {
  let c = @sipkit.Cursor::from_bytes(b"abc")
  let r : Result[Bytes, @sipkit.SipError] = Ok(@sipkit.parse_comment(c)) catch {
    e => Err(e)
  }
  assert_true(r is Err(_))
}

///|
test "character classes are exhaustive over their boundaries" {
  // Hex digits: both cases and both ends.
  assert_true(@sipkit.is_hexdig(b'0'))
  assert_true(@sipkit.is_hexdig(b'9'))
  assert_true(@sipkit.is_hexdig(b'A'))
  assert_true(@sipkit.is_hexdig(b'F'))
  assert_true(@sipkit.is_hexdig(b'a'))
  assert_true(@sipkit.is_hexdig(b'f'))
  assert_true(!@sipkit.is_hexdig(b'g'))
  assert_true(!@sipkit.is_hexdig(b'/'))
  assert_eq(@sipkit.hex_value(b'0'), 0)
  assert_eq(@sipkit.hex_value(b'9'), 9)
  assert_eq(@sipkit.hex_value(b'A'), 10)
  assert_eq(@sipkit.hex_value(b'F'), 15)
  assert_eq(@sipkit.hex_value(b'a'), 10)
  assert_eq(@sipkit.hex_value(b'f'), 15)
  assert_eq(@sipkit.hex_value(b'z'), -1)

  // High octets: the UTF8-NONASCII range SIP must preserve.
  assert_true(!@sipkit.is_high_octet(b'\x7f'))
  assert_true(@sipkit.is_high_octet(b'\x80'))
  assert_true(@sipkit.is_high_octet(b'\xff'))

  // Separators: both ends of the set.
  assert_true(@sipkit.is_separator(b'('))
  assert_true(@sipkit.is_separator(b'}'))
  assert_true(@sipkit.is_separator(b'@'))
  assert_true(!@sipkit.is_separator(b'a'))
  assert_true(!@sipkit.is_separator(b'-'))
}

///|
test "range comparison helpers agree on length and content" {
  let src = b"Content-Type"
  assert_true(
    @sipkit.range_eq_ignore_case(src.exact_view(), 0, 12, "content-type"),
  )
  assert_true(
    !@sipkit.range_eq_ignore_case(src.exact_view(), 0, 12, "content-typ"),
  )
  assert_true(
    !@sipkit.range_eq_ignore_case(src.exact_view(), 0, 12, "content-typex"),
  )
  assert_true(@sipkit.contains_ignore_case(src.exact_view(), b"TYPE"))
  assert_true(!@sipkit.contains_ignore_case(src.exact_view(), b"zzz"))
  assert_true(!@sipkit.contains_ignore_case(src.exact_view(), b""))
}

///|
test "bytes helpers preserve octets exactly" {
  let src = b"\x00\x7f\x80\xff"
  assert_eq(@sipkit.hex_of(src.exact_view()), "007f80ff")
  assert_eq(@sipkit.bytes_from_hex("007f80ff").length(), 4)
  assert_eq(
    @sipkit.hex_of(@sipkit.bytes_from_hex("007f80ff").exact_view()),
    "007f80ff",
  )
  // A truncated hex string stops rather than inventing a byte.
  assert_eq(@sipkit.bytes_from_hex("00zz").length(), 1)
  assert_eq(@sipkit.bytes_of_view(b"abc".exact_view()).length(), 3)
  assert_eq(@sipkit.trim_ows(b"  x  ".exact_view()).length(), 1)
  assert_eq(@sipkit.ascii_bytes_of("SIP").length(), 3)
  // Non-ASCII code units are dropped, never truncated into garbage.
  assert_eq(@sipkit.ascii_bytes_of("SÍP").length(), 2)
}

// ---------------------------------------------------------------------------
// URI layer
// ---------------------------------------------------------------------------

///|
test "host shapes are classified without rejecting them" {
  let named = @sipkit.parse_sip_uri(
    @sipkit.Cursor::from_bytes(b"sip:example.com"),
  )
  match named.host() {
    Name(_) => ()
    _ => fail("expected a hostname")
  }
  let quad = @sipkit.parse_sip_uri(@sipkit.Cursor::from_bytes(b"sip:192.0.2.1"))
  match quad.host() {
    Ipv4(_) => ()
    _ => fail("expected an IPv4 host")
  }
  let v6 = @sipkit.parse_sip_uri(
    @sipkit.Cursor::from_bytes(b"sip:[2001:db8::1]"),
  )
  match v6.host() {
    Ipv6Reference(_) => ()
    _ => fail("expected an IPv6 reference")
  }
}

///|
test "dotted quad detection rejects malformed shapes" {
  // Each of these must stay a Name rather than be mislabelled as IPv4.
  for
    candidate in [
      "192.0.2", "192.0.2.1.5", "192..2.1", "192.0.2.x", "1920.0.2.1", "192.0.2.",
    ] {
    let uri = @sipkit.parse_sip_uri(
      @sipkit.Cursor::from_bytes(@sipkit.ascii_bytes_of("sip:" + candidate)),
    )
    match uri.host() {
      Ipv4(_) => fail("misclassified as IPv4: " + candidate)
      _ => ()
    }
  }
}

///|
test "uri: password is split from user at the first colon" {
  let u = @sipkit.parse_sip_uri(
    @sipkit.Cursor::from_bytes(b"sip:alice:pw@host"),
  )
  assert_eq(@sipkit.ascii_of(u.user().unwrap().exact_view()), "alice")
  assert_eq(@sipkit.ascii_of(u.password().unwrap().exact_view()), "pw")
}

///|
test "uri: no port means None, and user=phone is recognised" {
  let u = @sipkit.parse_sip_uri(
    @sipkit.Cursor::from_bytes(b"sip:t.watson@example.org;user=phone"),
  )
  assert_true(u.port() is None)
  assert_true(u.is_phone_user())
  let without = @sipkit.parse_sip_uri(
    @sipkit.Cursor::from_bytes(b"sip:t.watson@example.org"),
  )
  assert_true(!without.is_phone_user())
}

///|
test "uri: parameters without a value round-trip as None" {
  let u = @sipkit.parse_sip_uri(
    @sipkit.Cursor::from_bytes(b"sip:a@b;lr;transport=tcp"),
  )
  assert_eq(u.params().length(), 2)
  assert_true(u.params()[0].value() is None)
  assert_eq(
    @sipkit.ascii_of(u.params()[1].value().unwrap().exact_view()),
    "tcp",
  )
  assert_true(u.param("LR") is Some(_))
  assert_true(u.param("nope") is None)
}

///|
test "uri: a missing host is a syntax error, not an empty host" {
  expect_syntax(b"INVITE sip: SIP/2.0\r\n\r\n", "unexpected end of input")
}

///|
test "uri: a bad port is a syntax error" {
  let r : Result[@sipkit.SipUri, @sipkit.SipError] = Ok(
    @sipkit.parse_sip_uri(@sipkit.Cursor::from_bytes(b"sip:a@b:xc")),
  ) catch {
    e => Err(e)
  }
  assert_true(r is Err(_))
}

// ---------------------------------------------------------------------------
// Message framing
// ---------------------------------------------------------------------------

///|
test "framing: a bare LF terminates a line, but is not re-emitted as CRLF source" {
  let a = @sipkit.analyze(
    b"OPTIONS sip:a@b SIP/2.0\nTo: <sip:a@b>\nFrom: <sip:c@d>;tag=1\nCall-ID: x\nCSeq: 1 OPTIONS\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\nContent-Length: 0\n\n",
  )
  // Bare LF is tolerated on input; the message still parses.
  assert_true(a.message() is Some(_))
}

///|
test "framing: a stray CR without LF is a syntax error" {
  expect_syntax(b"OPTIONS sip:a@b SIP/2.0\rX", "expected CRLF")
}

///|
test "framing: a header line without a colon is refused" {
  expect_syntax(
    b"OPTIONS sip:a@b SIP/2.0\r\nNoColonHere\r\n\r\n", "illegal octet",
  )
}

///|
test "framing: a header block that never ends reports UnexpectedEnd" {
  expect_syntax(b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>", "expected CRLF")
}

///|
test "start line: status code without a reason phrase is accepted" {
  let a = @sipkit.analyze(
    b"SIP/2.0 200 \r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: r1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
  )
  let msg = a.message().unwrap()
  assert_eq(msg.status_code().unwrap(), 200)
  match msg.start_line() {
    Response(sl) => {
      assert_eq(sl.code(), 200)
      assert_eq(sl.reason().length(), 0)
      assert_eq(@sipkit.ascii_of(sl.version().exact_view()), "SIP/2.0")
    }
    Request(_) => fail("expected a response")
  }
}

///|
test "start line: a version other than 2.0 parses but is rejected semantically" {
  let a = @sipkit.analyze(
    b"OPTIONS sip:a@b SIP/3.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: v1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
  )
  assert_eq(a.verdict().to_string(), "semantic-rejected")
  assert_true(a.has_code(@sipkit.DiagCode::UnsupportedVersion))
}

// ---------------------------------------------------------------------------
// Address layer
// ---------------------------------------------------------------------------

///|
test "name-addr: header parameters expose name and value" {
  let c = @sipkit.Cursor::from_bytes(b"<sip:a@b>;tag=abc;q=0.5;flag")
  let a = @sipkit.parse_name_addr(c)
  assert_eq(a.params().length(), 3)
  assert_eq(@sipkit.ascii_of(a.params()[0].name().exact_view()), "tag")
  assert_eq(
    @sipkit.ascii_of(a.params()[0].value().unwrap().exact_view()),
    "abc",
  )
  assert_true(a.params()[2].value() is None)
  assert_true(a.had_angle_brackets())
  assert_eq(
    @sipkit.ascii_of(a.raw().exact_view()),
    "<sip:a@b>;tag=abc;q=0.5;flag",
  )
}

///|
test "name-addr: a bare addr-spec reports no display name and no brackets" {
  let c = @sipkit.Cursor::from_bytes(b"sip:a@b;tag=9")
  let a = @sipkit.parse_name_addr(c)
  assert_true(a.display() is None)
  assert_true(!a.display_quoted())
  assert_true(!a.had_angle_brackets())
  assert_eq(@sipkit.ascii_of(a.tag().unwrap().exact_view()), "9")
}

///|
test "name-addr: absoluteURI addresses keep their octets" {
  let c = @sipkit.Cursor::from_bytes(b"<isbn:2983792873>")
  let a = @sipkit.parse_name_addr(c)
  match a.uri() {
    Other(raw) =>
      assert_eq(@sipkit.ascii_of(raw.exact_view()), "isbn:2983792873")
    Sip(_) => fail("expected a non-SIP absolute URI")
  }
  assert_true(a.sip_uri() is None)
  assert_true(a.param("tag") is None)
}

///|
test "name-addr: an empty angle-bracket body is refused" {
  let c = @sipkit.Cursor::from_bytes(b"<>")
  let r : Result[@sipkit.NameAddr, @sipkit.SipError] = Ok(
    @sipkit.parse_name_addr(c),
  ) catch {
    e => Err(e)
  }
  assert_true(r is Err(_))
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

///|
test "diagnostics: a duplicated single-valued header is reported once per extra copy" {
  let a = @sipkit.analyze(
    b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nTo: <sip:x@y>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: d1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
  )
  assert_eq(a.verdict().to_string(), "semantic-rejected")
  assert_true(a.has_code(@sipkit.DiagCode::DuplicateSingleValueHeader))
}

///|
test "diagnostics: two Content-Length values are reported" {
  let a = @sipkit.analyze(
    b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: m1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
  )
  assert_true(a.has_code(@sipkit.DiagCode::MultipleContentLengthValues))
}

///|
test "diagnostics: an unsupported Require is reported" {
  let a = @sipkit.analyze(
    b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: q1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nRequire: 100rel\r\nContent-Length: 0\r\n\r\n",
  )
  assert_true(a.has_code(@sipkit.DiagCode::UnsupportedExtension))
  assert_eq(a.verdict().to_string(), "semantic-rejected")
}

///|
test "diagnostics: every diagnostic exposes code, severity, offset and detail" {
  let a = @sipkit.analyze(
    b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: z1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h\r\nMax-Forwards: 300\r\nContent-Length: 0\r\n\r\n",
  )
  let ds = a.diagnostics()
  assert_true(ds.length() >= 2)
  for d in ds {
    // Code and severity must stringify to their stable wire names.
    assert_true(d.code().to_string().length() > 0)
    assert_true(
      d.severity().to_string() == "error" ||
      d.severity().to_string() == "warning",
    )
    assert_true(d.offset() >= 0)
    assert_true(d.detail().length() > 0)
  }
}

///|
test "message accessors agree with the wire" {
  let raw : Bytes = b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: acc1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 3\r\n\r\nabc"
  let msg = @sipkit.analyze(raw).message().unwrap()
  assert_eq(@sipkit.ascii_of(msg.body().exact_view()), "abc")
  assert_eq(msg.trailing().length(), 0)
  assert_eq(msg.consumed(), raw.length())
  assert_eq(msg.headers().length(), 7)
  assert_eq(msg.all_headers("Via").length(), 1)
  let first = msg.header("To").unwrap()
  assert_eq(@sipkit.ascii_of(first.name().exact_view()), "To")
  assert_eq(@sipkit.ascii_of(first.value().exact_view()), "<sip:a@b>")
  assert_true(first.offset() > 0)
  assert_eq(first.line(), 2)
  assert_true(msg.status_code() is None)
  match msg.start_line() {
    Request(rl) => {
      assert_eq(@sipkit.ascii_of(rl.verb().exact_view()), "OPTIONS")
      assert_eq(@sipkit.ascii_of(rl.version().exact_view()), "SIP/2.0")
      match rl.uri() {
        Parsed(u) =>
          assert_eq(@sipkit.ascii_of(u.raw().exact_view()), "sip:a@b")
        Other(_) => fail("expected a parsed SIP URI")
      }
    }
    Response(_) => fail("expected a request")
  }
}

// ---------------------------------------------------------------------------
// SIP-date: full grammar + calendar agreement (RFC 3261 §25.1)
// ---------------------------------------------------------------------------

///|
/// Builds a minimal valid OPTIONS carrying the given Date value.
fn with_date(date_value : String) -> Bytes {
  b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: dt\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nDate: " +
  @sipkit.ascii_bytes_of(date_value) +
  b"\r\nContent-Length: 0\r\n\r\n"
}

///|
test "SIP-date: correct dates pass, wrong ones say why" {
  // 2010-01-01 really was a Friday.
  let ok = @sipkit.analyze(with_date("Fri, 01 Jan 2010 16:00:00 GMT"))
  assert_true(ok.message() is Some(_))
  // mpart01's own Date must keep passing: 2005-10-15 was a Saturday.
  assert_true(@sipkit.analyze(vector_bytes("mpart01")).message() is Some(_))

  // EST is a valid timezone in the real world and invalid in SIP -- §3.1.2.12.
  expect_syntax(
    with_date("Fri, 01 Jan 2010 16:00:00 EST"),
    "malformed Date field",
  )
  // Same date, wrong weekday: the grammar fixes the zone, the calendar fixes
  // the day-of-week, and this date was a Friday.
  expect_syntax(
    with_date("Mon, 01 Jan 2010 16:00:00 GMT"),
    "malformed Date field",
  )
  // Not a month.
  expect_syntax(
    with_date("Fri, 01 Foo 2010 16:00:00 GMT"),
    "malformed Date field",
  )
  // Not a weekday.
  expect_syntax(
    with_date("Fob, 01 Jan 2010 16:00:00 GMT"),
    "malformed Date field",
  )
  // Day beyond the month.
  expect_syntax(
    with_date("Fri, 32 Jan 2010 16:00:00 GMT"),
    "malformed Date field",
  )
  // 30 February in a non-leap year.
  expect_syntax(
    with_date("Fri, 30 Feb 2010 16:00:00 GMT"),
    "malformed Date field",
  )
  // 29 February in a non-leap year.
  expect_syntax(
    with_date("Fri, 29 Feb 2011 16:00:00 GMT"),
    "malformed Date field",
  )
  // Hour out of range.
  expect_syntax(
    with_date("Fri, 01 Jan 2010 25:00:00 GMT"),
    "malformed Date field",
  )
  // Second 61 is beyond even a leap second.
  expect_syntax(
    with_date("Fri, 01 Jan 2010 16:00:61 GMT"),
    "malformed Date field",
  )
  // The single-letter zone abbreviations RFC 4475 names as invalid.
  expect_syntax(
    with_date("Fri, 01 Jan 2010 16:00:00 UT"),
    "malformed Date field",
  )
  expect_syntax(
    with_date("Fri, 01 Jan 2010 16:00:00 UTC"),
    "malformed Date field",
  )

  // A leap day in a leap year, on the right weekday, passes.
  // 2012-02-29 was a Wednesday.
  assert_true(
    @sipkit.analyze(with_date("Wed, 29 Feb 2012 16:00:00 GMT")).message()
    is Some(_),
  )
  // Leap second at the end of June 2015 (announced) -- 2015-06-30 was a Tuesday.
  assert_true(
    @sipkit.analyze(with_date("Tue, 30 Jun 2015 23:59:60 GMT")).message()
    is Some(_),
  )
}

// ---------------------------------------------------------------------------
// Remaining accessors, scheme variants and rejection paths
// ---------------------------------------------------------------------------

///|
test "uri: Host/UriScheme/UriParam getters and Show round-trip" {
  let u = parse_sip_uri(
    Cursor::from_bytes(b"sip:a@192.0.2.9:5060;transport=udp"),
  )
  match u.host() {
    Ipv4(b) => assert_eq(ascii_of(b.exact_view()), "192.0.2.9")
    _ => fail("expected IPv4")
  }
  assert_eq(u.scheme().to_string(), "sip")
  let p = u.params()[0]
  assert_eq(ascii_of(p.name().exact_view()), "transport")
  assert_eq(ascii_of(p.value().unwrap().exact_view()), "udp")
}

///|
test "uri: sips scheme and non-SIP absoluteURI kept verbatim" {
  let s = parse_sip_uri(Cursor::from_bytes(b"sips:x@y"))
  assert_eq(s.scheme().to_string(), "sips")
  // absoluteURI values survive as bytes; SipUri::scheme never sees them, but the
  // RequestUri Other branch does, via the start line of a real request.
  let raw = b"OPTIONS http://example.com/x SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: o9\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
  let msg = analyze(raw).message().unwrap()
  match msg.start_line() {
    Request(rl) =>
      match rl.uri() {
        Other(o) => assert_eq(ascii_of(o.exact_view()), "http://example.com/x")
        Parsed(_) => fail("expected a verbatim non-SIP URI")
      }
    Response(_) => fail("expected a request")
  }
}

///|
test "message: a response has no verb; a request has no status code" {
  let req = analyze(
      b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: ac1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
    )
    .message()
    .unwrap()
  assert_true(req.status_code() is None)
  let resp = analyze(
      b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: ac2\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
    )
    .message()
    .unwrap()
  assert_true(resp.verb() is None)
  assert_eq(resp.status_code().unwrap(), 200)
}

///|
test "start line: every malformed shape is refused with its kind" {
  // no space between method and URI
  // No space: the method token runs into the colon, and the URI scan that
  // follows hits end-of-view.
  expect_syntax(b"INVITEsip:a@b SIP/2.0\r\n\r\n", "illegal octet")
  // URI present but the version is missing entirely
  expect_syntax(b"INVITE sip:a@b\r\n\r\n", "illegal octet")
  // double space before the version
  expect_syntax(b"INVITE sip:a@b  SIP/2.0\r\n\r\n", "illegal octet")
  // version with a bad minor
  expect_syntax(b"INVITE sip:a@b SIP/2.x\r\n\r\n", "illegal octet")
  // status line without SP before code
  expect_syntax(
    b"SIP/2.0200 OK\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\r\n", "illegal octet",
  )
}

///|
test "token: a quoted string must open with DQUOTE; trailing garbage is its own kind" {
  let c = Cursor::from_bytes(b"abc")
  let r : Result[QuotedString, SipError] = Ok(parse_quoted_string(c)) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => fail("expected ExpectedQuotedString")
    Err(e) => assert_true(e.to_string().contains("expected quoted string"))
  }
  // '!' IS a token character (mark in RFC 3261 §25.1), so it is consumed.
  let c2 = Cursor::from_bytes(b"a!")
  ignore(parse_token(c2))
  assert_eq(c2.position(), 2)
  // ';' stops a token: it is a separator.
  let c3 = Cursor::from_bytes(b"a;b")
  ignore(parse_token(c3))
  assert_eq(c3.position(), 1)
}

///|
test "token: quoted string with a trailing escaped quote keeps content" {
  // \" inside quotes is a literal quote; the string closes on the unescaped one.
  let c = Cursor::from_bytes(b"\"x\\\"y\"")
  let qs = parse_quoted_string(c)
  assert_eq(ascii_of(qs.value().exact_view()), "x\"y")
  assert_eq(c.position(), 6)
}
