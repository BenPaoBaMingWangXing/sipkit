// Development driver: runs the analysis pipeline on a sample message.

///|
fn main {
  let sample : Bytes = b"INVITE sip:user@example.com SIP/2.0\r\nTo: sip:j.user@example.com\r\nFrom: sip:caller@example.net;tag=134161461246\r\nMax-Forwards: 7\r\nCall-ID: demo.1\r\nCSeq: 8 INVITE\r\nVia: SIP/2.0/UDP 192.0.2.15;branch=z9hG4bKkdjuw\r\nContact: <sip:caller@host.example.com>\r\nContent-Length: 0\r\n\r\n"
  let a = @sipkit.analyze(sample)
  println("verdict: \{a.verdict()}")
  match a.syntax() {
    Some(pair) => {
      let (kind, at) = pair
      println("syntax: \{kind} at byte \{at}")
    }
    None => println("syntax: ok")
  }
  println("diagnostics: \{a.diagnostics().length()}")
  for d in a.diagnostics() {
    println("  \{d}")
  }
  let c = @sipkit.Cursor::from_bytes(
    b"sip:alice:secret@example.com:5060;transport=tcp;lr",
  )
  let r : Result[@sipkit.SipUri, @sipkit.SipError] = Ok(
    @sipkit.parse_sip_uri(c),
  ) catch {
    e => Err(e)
  }
  match r {
    Ok(u) => println("uri: host=\{u.host()} port=\{u.port().unwrap()}")
    Err(e) => println("uri err: \{e}")
  }
}
