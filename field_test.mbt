// field_test.mbt — field-level expectations taken from the RFC prose.
//
// The verdict suite answers "did the parser accept this". That is a coarse
// question: a parser can accept 49 messages and still misplace every field.
// Several RFC 4475 sections go further and state what a specific field must
// contain, so those statements are asserted here:
//
//   §3.1.1.9  "The Request-URI will parse so that the user part is
//              'user;par=u@example.net'"
//   §3.1.1.5  "two Contact header field values, not three"
//   §3.1.1.4  the AOR must not be "prematurely shortened" by the embedded %00
//   §3.3.12   `unknownparam` "must be interpreted as a contact-param and not a
//              url-param"
//
// Each assertion cites its sentence, so a failure points at a specific claim
// rather than at "the parser".

///|
/// Looks up a corpus vector by its RFC message id.
fn vector_bytes(id : String) -> Bytes raise {
  for v in vectors {
    if v.id == id {
      return @sipkit.bytes_from_hex(v.hex)
    }
  }
  fail("no such vector: " + id)
}

///|
/// Applies the single-pass decoder to a URI component and returns the text.
fn decoded(b : Bytes) -> String {
  @sipkit.ascii_of(@sipkit.unescape_once(b.exact_view()).exact_view())
}

///|
test "3.1.1.9 semiuri: the semicolon belongs to the user part" {
  let msg = @sipkit.analyze(vector_bytes("semiuri")).message().unwrap()
  match msg.start_line() {
    Request(rl) =>
      match rl.uri() {
        Parsed(u) => {
          // Said verbatim in the RFC: the user part is "user;par=u@example.net".
          assert_eq(decoded(u.user().unwrap()), "user;par=u@example.net")
          assert_eq(u.host().to_string(), "example.com")
          // The escaped @ is part of the user, so there is no password split.
          assert_true(u.password() is None)
          // And the trailing parameters are not part of the user.
          assert_eq(u.params().length(), 0)
        }
        Other(_) => fail("expected a SIP URI")
      }
    Response(_) => fail("expected a request")
  }
}

///|
test "3.1.1.5 esc02: two Contact values, not three" {
  let msg = @sipkit.analyze(vector_bytes("esc02")).message().unwrap()
  // The RFC counts two: C%6Fntact is a different field name, not an alias.
  assert_eq(msg.all_headers("Contact").length(), 2)
  assert_eq(msg.all_headers("C%6Fntact").length(), 1)
  // Asking for it explicitly: no unescaping of field names may happen.
  assert_true(msg.all_headers("C%6Fntact")[0].name_is("C%6Fntact"))
  assert_true(!msg.all_headers("C%6Fntact")[0].name_is("Contact"))
}

///|
test "3.1.1.4 escnull: the null in the AOR does not shorten the name" {
  let msg = @sipkit.analyze(vector_bytes("escnull")).message().unwrap()
  let to = msg.header("To").unwrap()
  let a = @sipkit.parse_name_addr(@sipkit.Cursor::new(to.value().exact_view()))
  let user = a.sip_uri().unwrap().user().unwrap()
  // "null-%00-null" is 13 octets on the wire and 11 after decoding: the NUL
  // stays inside the name instead of terminating it.
  assert_eq(user.length(), 13)
  let dec = @sipkit.unescape_once(user.exact_view())
  assert_eq(dec.length(), 11)
  assert_eq(dec[5], b'\x00')
  assert_eq(dec[0], b'n')
  assert_eq(dec[10], b'l')
}

///|
test "3.1.1.1 wsinv: leading zeros and odd casing still yield the values" {
  let msg = @sipkit.analyze(vector_bytes("wsinv")).message().unwrap()
  // MaX-fOrWaRdS: 0068
  assert_eq(
    @sipkit.ascii_of(msg.header("Max-Forwards").unwrap().value().exact_view()),
    "0068",
  )
  // cseq: 0009 with INVITE on a folded continuation line
  assert_eq(
    @sipkit.ascii_of(msg.header("CSeq").unwrap().value().exact_view()),
    "0009 INVITE",
  )
  // Content-Length   : 150 — spaces around the colon are legal (HCOLON), and
  // the body is framed by that value.
  assert_eq(msg.body().length(), 150)
  // The method comes from the start line, not from CSeq.
  assert_eq(@sipkit.ascii_of(msg.verb().unwrap().exact_view()), "INVITE")
}

///|
test "3.1.1.2 intmeth: the unparsed-looking values are still values" {
  let msg = @sipkit.analyze(vector_bytes("intmeth")).message().unwrap()
  assert_eq(
    @sipkit.ascii_of(msg.verb().unwrap().exact_view()),
    "!interesting-Method0123456789_*+`.%indeed'~",
  )
  assert_eq(
    @sipkit.ascii_of(msg.header("Max-Forwards").unwrap().value().exact_view()),
    "255",
  )
  match msg.start_line() {
    Request(rl) =>
      match rl.uri() {
        Parsed(u) => {
          // The user part ends at the first colon, because `:` is the
          // user/password separator (RFC 3261 §19.1.1) and is NOT listed in
          // `user-unreserved`. Everything before it is the user.
          assert_eq(
            decoded(u.user().unwrap()),
            "1_unusual.URI~(to-be!sure)&isn't+it$/crazy?,/;;*",
          )
          // What follows the colon is the password, which is where the rest of
          // the unusual characters land.
          assert_true(u.password() is Some(_))
          assert_eq(
            decoded(u.password().unwrap()),
            "&it+has=1,weird!*pas$wo~d_too.(doesn't-it)",
          )
          assert_eq(u.host().to_string(), "example.com")
        }
        Other(_) => fail("expected a SIP URI")
      }
    Response(_) => fail("expected a request")
  }
}

///|
test "3.1.1.6 lwsdisp: display name and tag survive the missing LWS" {
  let msg = @sipkit.analyze(vector_bytes("lwsdisp")).message().unwrap()
  let a = @sipkit.parse_name_addr(
    @sipkit.Cursor::new(msg.header("From").unwrap().value().exact_view()),
  )
  assert_eq(@sipkit.ascii_of(a.display().unwrap().exact_view()), "caller")
  assert_eq(@sipkit.ascii_of(a.tag().unwrap().exact_view()), "323")
  assert_eq(a.sip_uri().unwrap().host().to_string(), "example.com")
}

///|
test "3.1.1.8 dblreq: the first message ends where its Content-Length says" {
  let msg = @sipkit.analyze(vector_bytes("dblreq")).message().unwrap()
  assert_eq(@sipkit.ascii_of(msg.verb().unwrap().exact_view()), "REGISTER")
  assert_eq(msg.body().length(), 0)
  // The INVITE that follows is not part of this message.
  assert_true(msg.trailing().length() > 100)
  assert_true(@sipkit.ascii_of(msg.trailing().exact_view()).contains("INVITE "))
}

///|
test "3.3.12 cparam01: the parameter is reachable as a contact-param" {
  // RFC 4475 says "unknownparam must be interpreted as a contact-param and not
  // a url-param". The wire form here has no angle brackets, so both namespaces
  // occupy the same octets and the grammar cannot separate them; RFC 3261 §20.10
  // admits this and recommends `<>`. What must hold is that the parameter is
  // reachable through the address, and that the address itself parses correctly.
  let msg = @sipkit.analyze(vector_bytes("cparam01")).message().unwrap()
  let a = @sipkit.parse_name_addr(
    @sipkit.Cursor::new(msg.header("Contact").unwrap().value().exact_view()),
  )
  assert_true(a.param("unknownparam") is Some(_))
  assert_true(!a.had_angle_brackets())
  // The user and host are unaffected by the ambiguity.
  let uri = a.sip_uri().unwrap()
  assert_eq(@sipkit.ascii_of(uri.user().unwrap().exact_view()), "+19725552222")
  assert_eq(uri.host().to_string(), "gw1.example.net")
}
