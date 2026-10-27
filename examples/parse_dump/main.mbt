// Example: parse a real INVITE and dump what the parser recovered.
//
// Run from the repository root:
//     moon run examples/parse_dump
//
// The point of this example is that every value printed below came out of the
// octets — nothing is re-derived from the printed form.

///|
fn main {
  let raw : Bytes = b"INVITE sip:bob@example.com:5060;transport=tcp SIP/2.0\r\nVia: SIP/2.0/UDP alice-pc.example.com:5060;branch=z9hG4bK776asdhds\r\nMax-Forwards: 70\r\nTo: Bob <sip:bob@example.com>\r\nFrom: Alice <sip:alice@example.com>;tag=1928301774\r\nCall-ID: a84b4c76e66710@alice-pc.example.com\r\nCSeq: 314159 INVITE\r\nContact: <sip:alice@alice-pc.example.com>\r\nContent-Type: application/sdp\r\nContent-Length: 0\r\n\r\n"

  let analysis = @sipkit.analyze(raw)
  println("verdict: \{analysis.verdict()}")
  println("")

  let msg = analysis.message().unwrap()

  match msg.start_line() {
    Request(rl) => {
      println("start line")
      println("  method     \{@sipkit.ascii_of(rl.verb().exact_view())}")
      println("  version    \{@sipkit.ascii_of(rl.version().exact_view())}")
      match rl.uri() {
        Parsed(uri) => {
          println("  uri.scheme \{uri.scheme()}")
          match uri.user() {
            Some(u) =>
              println("  uri.user   \{@sipkit.ascii_of(u.exact_view())}")
            None => println("  uri.user   (none)")
          }
          println("  uri.host   \{uri.host()}")
          match uri.port() {
            Some(p) => println("  uri.port   \{p}")
            None => println("  uri.port   (default)")
          }
          println("  uri.params \{uri.params().length()}")
          for p in uri.params() {
            match p.value() {
              Some(v) =>
                println(
                  "    ;\{@sipkit.ascii_of(p.name().exact_view())}=\{@sipkit.ascii_of(v.exact_view())}",
                )
              None => println("    ;\{@sipkit.ascii_of(p.name().exact_view())}")
            }
          }
        }
        Other(o) =>
          println("  uri        (non-SIP) \{@sipkit.ascii_of(o.exact_view())}")
      }
    }
    Response(_) => println("(a response, not a request)")
  }

  println("")
  println("headers (\{msg.headers().length()}), in wire order")
  for h in msg.headers() {
    // Printed in full: `raw()` would give the same octets including the fold.
    println(
      "  line \{h.line()}  \{@sipkit.ascii_of(h.name().exact_view())}: \{@sipkit.ascii_of(h.value().exact_view())}",
    )
  }

  println("")
  println("body       \{msg.body().length()} octets")
  println("consumed   \{msg.consumed()} of \{raw.length()} octets")
  println("trailing   \{msg.trailing().length()} octets")

  // Re-emission is byte-exact, which is what makes the type useful for archival.
  let rebuilt = @sipkit.to_bytes(msg)
  println("")
  println(
    "round-trip identical: \{rebuilt.length() == raw.length() && @sipkit.hex_of(rebuilt.exact_view()) == @sipkit.hex_of(raw.exact_view())}",
  )
}
