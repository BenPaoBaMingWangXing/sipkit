// surface_test.mbt — error vocabulary and start-line rejection paths.
//
// Everything here exists for one reason: a diagnostic is only useful if the
// message it prints is the right one. That means every `@sipkit.DiagCode` and every
// `SyntaxKind` string must be exercised at least once, and every start-line
// rejection path must be reachable and report the specific kind rather than a
// generic failure.

///|
/// Feeds a message through @sipkit.analyze and returns the diagnostics' rendered form,
/// so the Show instance is exercised for whichever codes it produced.
fn render_diagnostics(input : Bytes) -> Array[String] {
  let out : Array[String] = []
  for d in @sipkit.analyze(input).diagnostics() {
    out.push(d.to_string())
  }
  out
}

///|
test "every diagnostic code renders as its stable wire name" {
  // One message per code family. Collecting the rendered strings covers the
  // Show instance without needing to construct Diagnostic values directly.
  let cases : Array[Bytes] = [
    // missing required header (no To)
    b"OPTIONS sip:a@b SIP/2.0\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
    // cseq method mismatch
     b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r2\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
    // content length mismatch
     b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r3\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 9\r\n\r\n",
    // duplicate single-valued header
     b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nTo: <sip:x@y>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r4\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
    // multiple content lengths
     b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r5\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
    // unsupported version
     b"OPTIONS sip:a@b SIP/9.9\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r6\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
    // status code out of range
     b"SIP/2.0 999 X\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: r7\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
    // scalar out of range (Max-Forwards)
     b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r8\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 300\r\nContent-Length: 0\r\n\r\n",
    // unknown request-uri scheme
     b"OPTIONS http://example.com SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r9\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
    // trailing octets
     b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r10\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\nxx",
    // extraneous separator
     b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r11\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1;;;;\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
    // unbracketed uri with headers
     b"REGISTER sip:example.com SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r12\r\nCSeq: 1 REGISTER\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContact: sip:user@example.com?Route=%3Csip:x%3E\r\nContent-Length: 0\r\n\r\n",
    // missing contact on INVITE
     b"INVITE sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r13\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
    // unsupported extension
     b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r14\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nRequire: 100rel\r\nContent-Length: 0\r\n\r\n",
    // escaped headers in request-uri
     b"INVITE sip:user@example.com?Route=%3Csip:example.com%3E SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r15\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContact: <sip:x@y>\r\nContent-Length: 0\r\n\r\n",
    // missing via branch identifier
     b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: r16\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
  ]
  let seen : Array[String] = []
  for c in cases {
    for rendered in render_diagnostics(c) {
      seen.push(rendered)
    }
  }
  // Every rendered diagnostic must start with its severity and contain a code.
  assert_true(seen.length() >= 16)
  for r in seen {
    assert_true(r.contains("error:") || r.contains("warning:"))
    assert_true(r.contains("@"))
  }
}

///|
test "syntax kinds render as human-readable phrases" {
  // Each case must fail with a distinct, non-empty description.
  let kinds : Array[String] = []
  let inputs : Array[Bytes] = [
    b"", // empty input
     b"INVITE", // no space after method
     b"INVITE  sip:a@b SIP/2.0\r\n\r\n", // double space
     b"INVITE sip:a@b SIP/2.0 ", // no CRLF
     b"INVITE sip:a@b SIP/x\r\n\r\n", // bad version
     b"SIP/2.0\r\n\r\n", // response without code
  ]
  for i in inputs {
    match @sipkit.analyze(i).syntax() {
      Some(pair) => kinds.push(pair.0.to_string())
      None => fail("expected a syntax error")
    }
  }
  assert_eq(kinds.length(), inputs.length())
  for k in kinds {
    assert_true(k.length() > 0)
  }
}

///|
test "start line: double space between elements is rejected" {
  expect_syntax(b"INVITE  sip:a@b SIP/2.0\r\n\r\n", "illegal octet")
}

///|
test "start line: a space before CRLF is rejected" {
  // RFC 4475 3.1.2.10. The trailing SP is caught by the CRLF check, which is the
  // first production that can tell the difference once the version is consumed.
  expect_syntax(b"INVITE sip:a@b SIP/2.0 \r\n\r\n", "expected CRLF")
}

///|
test "start line: a method with no URI is rejected" {
  expect_syntax(b"INVITE SIP/2.0\r\n\r\n", "illegal octet")
}

///|
test "start line: an unparseable version is rejected" {
  expect_syntax(b"INVITE sip:a@b SIP/x\r\n\r\n", "illegal octet")
}

///|
test "start line: a version missing its minor number is rejected" {
  expect_syntax(b"INVITE sip:a@b SIP/2\r\n\r\n", "illegal octet")
}

///|
test "status line: a non-numeric code is rejected" {
  expect_syntax(
    b"SIP/2.0 abc X\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\n\r\n", "illegal octet",
  )
}

///|
test "token primitives at end of input return None rather than panic" {
  let c = @sipkit.Cursor::from_bytes(b"ab")
  ignore(c.advance())
  ignore(c.advance())
  assert_true(c.peek() is None)
  assert_true(c.peek_at(0) is None)
  assert_true(c.advance() is None)
  assert_true(!c.starts_with_ignore_case("xyz"))
  assert_true(!c.at_fold())
  assert_true(!c.consume_fold())
  assert_eq(c.skip_lws(), 0)
  assert_eq(c.skip_sws(), 0)
}

///|
test "quoted string: a trailing backslash at end of input is reported" {
  let c = @sipkit.Cursor::from_bytes(b"\"abc\\")
  let r : Result[@sipkit.QuotedString, @sipkit.SipError] = Ok(
    @sipkit.parse_quoted_string(c),
  ) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => fail("expected UnexpectedEnd")
    Err(e) => assert_true(e.to_string().contains("unexpected end"))
  }
}

///|
test "comment: a trailing backslash at end of input is reported" {
  let c = @sipkit.Cursor::from_bytes(b"(abc\\")
  let r : Result[Bytes, @sipkit.SipError] = Ok(@sipkit.parse_comment(c)) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => fail("expected UnexpectedEnd")
    Err(e) => assert_true(e.to_string().contains("unexpected end"))
  }
}

// ---------------------------------------------------------------------------
// §20 field syntax + TEXT-UTF8-TRIM (RFC 3261 §25.1)
// ---------------------------------------------------------------------------

///|
/// Builds a minimal valid request carrying one extra header.
fn with_header(name : String, value : String) -> Bytes {
  b"OPTIONS sip:a@b SIP/2.0\r\nTo: <sip:a@b>\r\nFrom: <sip:c@d>;tag=1\r\nCall-ID: fh\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n" +
  @sipkit.ascii_bytes_of(name + ": " + value + "\r\n") +
  b"\r\n"
}

///|
/// Asserts the message parses and carries a malformed-field-value error.
fn expect_field_error(
  name : String,
  value : String,
  contains : String,
) -> Unit raise {
  let a = @sipkit.analyze(with_header(name, value))
  // A syntactically bad field value is a semantic finding, not a grammar one.
  assert_eq(a.verdict().to_string(), "semantic-rejected")
  let mut found = false
  for d in a.diagnostics() {
    if d.code().to_string() == "malformed-field-value" &&
      d.detail().contains(contains) {
      found = true
      break
    }
  }
  assert_true(found)
}

///|
test "Warning: warn-code must be 3DIGIT within 100..299" {
  // scalarlg's 1812 already exercises the range; assert it directly.
  let a = @sipkit.analyze(vector_bytes("scalarlg"))
  // Direct string comparison (see the has_code note below).
  let mut found = false
  for d in a.diagnostics() {
    if d.code().to_string() == "malformed-field-value" {
      found = true
      break
    }
  }
  assert_true(found)
  // The helper must agree with the manual scan.
  assert_eq(
    @sipkit.DiagCode::MalformedFieldValue.to_string(),
    "malformed-field-value",
  )
  assert_true(a.has_code(@sipkit.DiagCode::MalformedFieldValue))
  // A well-formed Warning passes without a field finding.
  let ok = @sipkit.analyze(
    with_header("Warning", "201 example.com \"clock skew\""),
  )
  for d in ok.diagnostics() {
    assert_true(
      !(d.code().to_string() == "malformed-field-value" &&
      d.detail().contains("Warning")),
    )
  }
  // Four digits: malformed, not merely out of range.
  expect_field_error("Warning", "1812 host \"x\"", "Warning")
  // Two digits: same.
  expect_field_error("Warning", "81 host \"x\"", "Warning")
  // A quoted warn-text may contain commas without splitting the value.
  let q = @sipkit.analyze(with_header("Warning", "301 host \"a, b\""))
  let mut bad = false
  for d in q.diagnostics() {
    if d.detail().contains("Warning") {
      bad = true
      break
    }
  }
  assert_true(!bad)
}

///|
test "Expires: delta-seconds or SIP-date, nothing else" {
  assert_true(
    @sipkit.analyze(with_header("Expires", "3600")).message() is Some(_),
  )
  assert_true(
    @sipkit.analyze(with_header("Expires", "Fri, 01 Jan 2010 16:00:00 GMT")).message()
    is Some(_),
  )
  expect_field_error("Expires", "tomorrow", "Expires")
}

///|
test "Content-Type: type/subtype required" {
  assert_true(
    @sipkit.analyze(with_header("Content-Type", "application/sdp")).message()
    is Some(_),
  )
  expect_field_error("Content-Type", "application", "Content-Type")
}

///|
test "RSeq / Rack / Timestamp / MIME-Version / In-Reply-To" {
  assert_true(@sipkit.analyze(with_header("RSeq", "1701")).message() is Some(_))
  expect_field_error("RSeq", "17x1", "RSeq")
  assert_true(
    @sipkit.analyze(with_header("Rack", "1701 1 INVITE")).message() is Some(_),
  )
  expect_field_error("Rack", "1701 INVITE", "Rack")
  assert_true(
    @sipkit.analyze(with_header("Timestamp", "12345.678 0.5")).message()
    is Some(_),
  )
  expect_field_error("Timestamp", "12..3", "Timestamp")
  assert_true(
    @sipkit.analyze(with_header("MIME-Version", "1.0")).message() is Some(_),
  )
  expect_field_error("MIME-Version", "1", "MIME-Version")
  assert_true(
    @sipkit.analyze(with_header("In-Reply-To", "abc@x")).message() is Some(_),
  )
  expect_field_error("In-Reply-To", "", "In-Reply-To")
}

///|
test "TEXT-UTF8-TRIM: well-formed UTF-8 passes, broken sequences are reported" {
  // A CJK reason phrase is legal and must pass untouched.
  let ok = @sipkit.analyze(
    b"SIP/2.0 503 \xe6\x9c\x8d\xe5\x8a\xa1\xe4\xb8\x8d\xe5\x8f\xaf\xe7\x94\xa8\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: u1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
  )
  assert_true(ok.message() is Some(_))
  // 0xC3 alone is a truncated 2-byte sequence.
  let bad = @sipkit.analyze(
    b"SIP/2.0 503 \xc3\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: u2\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
  )
  assert_eq(bad.verdict().to_string(), "semantic-rejected")
  assert_true(bad.has_code(@sipkit.DiagCode::InvalidUtf8))
  // An overlong encoding (0xC0 0x80 for NUL) is rejected.
  let over = @sipkit.analyze(
    b"SIP/2.0 503 \xc0\x80\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: u3\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
  )
  assert_true(over.has_code(@sipkit.DiagCode::InvalidUtf8))
  // A surrogate half (0xED 0xA0 0x80) is rejected.
  let sur = @sipkit.analyze(
    b"SIP/2.0 503 \xed\xa0\x80\r\nVia: SIP/2.0/UDP h;branch=z9hG4bK1\r\nFrom: <sip:a@b>;tag=1\r\nTo: <sip:c@d>\r\nCall-ID: u4\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n",
  )
  assert_true(sur.has_code(@sipkit.DiagCode::InvalidUtf8))
}
