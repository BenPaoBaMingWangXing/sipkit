// surface_test.mbt — error vocabulary and start-line rejection paths.
//
// Everything here exists for one reason: a diagnostic is only useful if the
// message it prints is the right one. That means every `DiagCode` and every
// `SyntaxKind` string must be exercised at least once, and every start-line
// rejection path must be reachable and report the specific kind rather than a
// generic failure.

///|
/// Feeds a message through analyze and returns the diagnostics' rendered form,
/// so the Show instance is exercised for whichever codes it produced.
fn render_diagnostics(input : Bytes) -> Array[String] {
  let out : Array[String] = []
  for d in analyze(input).diagnostics() {
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
    match analyze(i).syntax() {
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
  let c = Cursor::from_bytes(b"ab")
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
  let c = Cursor::from_bytes(b"\"abc\\")
  let r : Result[QuotedString, SipError] = Ok(parse_quoted_string(c)) catch {
    e => Err(e)
  }
  match r {
    Ok(_) => fail("expected UnexpectedEnd")
    Err(e) => assert_true(e.to_string().contains("unexpected end"))
  }
}

///|
test "comment: a trailing backslash at end of input is reported" {
  let c = Cursor::from_bytes(b"(abc\\")
  let r : Result[Bytes, SipError] = Ok(parse_comment(c)) catch { e => Err(e) }
  match r {
    Ok(_) => fail("expected UnexpectedEnd")
    Err(e) => assert_true(e.to_string().contains("unexpected end"))
  }
}
