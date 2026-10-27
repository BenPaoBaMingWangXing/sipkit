// Example: the three verdicts, and what a diagnostic actually tells you.
//
// Run from the repository root:
//     moon run examples/diagnose
//
// The interesting part is the third case: the message parses, so the grammar has
// nothing to say, but two independent semantic rules fire and both point at a
// byte offset you can jump to in a capture.

///|
/// Shows the octets around `at` so a reported offset is obviously actionable.
fn context_around(input : Bytes, at : Int32) -> String {
  let start = if at > 18 { at - 18 } else { 0 }
  let stop = if at + 18 < input.length() { at + 18 } else { input.length() }
  @sipkit.ascii_of(input.exact_view(start~, end=stop))
}

///|
fn report(label : String, raw : Bytes) -> Unit {
  println("--- \{label}")
  let a = @sipkit.analyze(raw)
  println("    verdict: \{a.verdict()}")
  match a.syntax() {
    Some(pair) => {
      let (kind, at) = pair
      println("    rejected at byte \{at}: \{kind}")
      println("    ...\{context_around(raw, at)}...")
    }
    None => {
      let ds = a.diagnostics()
      if ds.length() == 0 {
        println("    no findings")
      }
      for d in ds {
        println("    [\{d.severity()}] \{d.code()} at byte \{d.offset()}")
        println("             \{d.detail()}")
      }
    }
  }
  println("")
}

///|
fn main {
  // 1. A clean request.
  report(
    "well-formed", b"OPTIONS sip:user@example.com SIP/2.0\r\nTo: <sip:user@example.com>\r\nFrom: <sip:caller@example.net>;tag=1\r\nCall-ID: ok-1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP host.example.com;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n",
  )

  // 2. A grammar failure: the header block never terminates, so the parser runs
  //    out of octets while looking for the empty line.
  report(
    "syntax-rejected", b"OPTIONS sip:user@example.com SIP/2.0\r\nTo: <sip:user@example.com>\r\nFrom: <sip:caller@example.net>;tag=1\r\nCall-ID: broken-1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP host.example.com;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Length: 0",
  )

  // 3. Syntactically perfect, semantically wrong twice: the CSeq names a
  //    different method than the start line, and Content-Length disagrees with
  //    the body that was actually framed.
  report(
    "semantic-rejected", b"OPTIONS sip:user@example.com SIP/2.0\r\nTo: <sip:user@example.com>\r\nFrom: <sip:caller@example.net>;tag=1\r\nCall-ID: sem-1\r\nCSeq: 1 INVITE\r\nVia: SIP/2.0/UDP host.example.com;branch=z9hG4bK1\r\nMax-Forwards: 70\r\nContent-Type: application/sdp\r\nContent-Length: 42\r\n\r\nv=0\r\n",
  )

  // 4. A warning-severity finding does not change the verdict, which is the
  //    distinction that lets a proxy forward instead of rejecting.
  report(
    "well-formed, with a warning", b"OPTIONS sip:user@example.com SIP/2.0\r\nTo: <sip:user@example.com>\r\nFrom: <sip:caller@example.net>;tag=1\r\nCall-ID: warn-1\r\nCSeq: 1 OPTIONS\r\nVia: SIP/2.0/UDP host.example.com\r\nContent-Length: 0\r\n\r\n",
  )
}
