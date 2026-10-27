// Example: SIP URIs, including the parts that are easy to get wrong.
//
// Run from the repository root:
//     moon run examples/uri

///|
fn show(text : String) -> Unit {
  let raw = @sipkit.ascii_bytes_of(text)
  let r : Result[@sipkit.SipUri, @sipkit.SipError] = Ok(
    @sipkit.parse_sip_uri(@sipkit.Cursor::from_bytes(raw)),
  ) catch {
    e => Err(e)
  }
  println("--- \{text}")
  match r {
    Err(e) => println("    rejected: \{e}")
    Ok(u) => {
      println("    scheme   \{u.scheme()}")
      match u.user() {
        Some(v) => {
          println("    user     \{@sipkit.ascii_of(v.exact_view())}")
          // Show the decoded form only when it differs, so `%41` -> `A` and
          // `%2541` -> `%41` are visible side by side: decoding is single-pass.
          let decoded = @sipkit.unescape_once(v.exact_view())
          if @sipkit.hex_of(decoded.exact_view()) !=
            @sipkit.hex_of(v.exact_view()) {
            println(
              "    user*    \{@sipkit.ascii_of(decoded.exact_view())}   (decoded once)",
            )
          }
        }
        None => println("    user     (none)")
      }
      match u.password() {
        Some(v) => println("    password \{@sipkit.ascii_of(v.exact_view())}")
        None => ()
      }
      println("    host     \{u.host()}")
      match u.port() {
        Some(p) => println("    port     \{p}")
        None => println("    port     (default)")
      }
      if u.params().length() > 0 {
        println("    params")
        for p in u.params() {
          match p.value() {
            Some(v) =>
              println(
                "      ;\{@sipkit.ascii_of(p.name().exact_view())}=\{@sipkit.ascii_of(v.exact_view())}",
              )
            None => println("      ;\{@sipkit.ascii_of(p.name().exact_view())}")
          }
        }
      }
      if u.headers().length() > 0 {
        println("    uri headers")
        for h in u.headers() {
          println(
            "      ?\{@sipkit.ascii_of(h.name().exact_view())}=\{@sipkit.ascii_of(h.value().exact_view())}",
          )
        }
      }
      if u.is_phone_user() {
        println(
          "    note     user=phone, so the user part compares as a telephone number",
        )
      }
    }
  }
  println("")
}

///|
fn main {
  show("sip:alice@example.com")
  show("sips:alice:secret@example.com:5061;transport=tls;lr")
  show("sip:192.0.2.1:5060")
  show("sip:alice@[2001:db8::1]:5060;transport=tcp")
  show("sip:+1-212-555-1212@gateway.example.com;user=phone")
  show("sip:alice@example.com?subject=hello&priority=urgent")

  // Escaping is decoded exactly once. `%41` is `A`; `%2541` is `%41`, not `A`.
  show("sip:al%41ice@example.com")
  show("sip:al%2541ice@example.com")

  // A `%` that is not an escape is legal and survives literally — RFC 4475 3.1.1.5.
  show("sip:alice@example.com;tag=z9hG4bK209%fzsnel234")

  // Semicolons and question marks are legal inside the user part, so they do not
  // end it. This is the case that breaks naive "split on ;" parsers.
  show("sip:user;par=u%40example.net@example.com")

  // And the failures, with the reason rather than a bare error.
  show("sip:")
  show("sip:alice@")
  println("--- (the last two are rejected on purpose: a URI needs a host)")
}
