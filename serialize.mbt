// serialize.mbt — re-emission and the one-call analysis façade.
//
// Round-trip is a property, not a format: `to_bytes(parse_message(x))` returns `x`
// byte-for-byte for any message whose lines are CRLF-terminated. That property is
// what lets the conformance suite assert on *both* the parse verdict and the
// preserved octets, instead of trusting a pretty-printer.
//
// A message received with bare LF is normalised to CRLF on re-emission. That is
// intentional: bare LF is tolerated on input (every deployed stack tolerates it)
// but is not something we are willing to produce.

///|
/// Renders a parsed message back to octets without normalising anything that was
/// preserved verbatim (header case, fold positions, header order, body).
pub fn to_bytes(msg : SipMessage) -> Bytes {
  let out : Array[Byte] = []
  let start_raw = match msg.start {
    Request(r) => r.raw
    Response(r) => r.raw
  }
  for i in 0..<start_raw.length() {
    out.push(start_raw[i])
  }
  for h in msg.headers {
    for i in 0..<h.raw.length() {
      out.push(h.raw[i])
    }
    out.push(CR)
    out.push(LF)
  }
  out.push(CR)
  out.push(LF)
  for i in 0..<msg.body.length() {
    out.push(msg.body[i])
  }
  // `trailing` is deliberately excluded: those octets belong to whatever followed
  // this message in the same datagram, not to the message. `parse_message` keeps
  // them so a caller can notice them (RFC 4475 §3.1.1.8), and re-emission must not
  // silently glue them back on.
  Bytes::from_array(out)
}

///|
/// The outcome of analysing one octet string. `message` is `None` exactly when the
/// grammar rejected the input, in which case `syntax` carries the reason and byte
/// offset.
pub struct Analysis {
  message : SipMessage?
  syntax : (SyntaxKind, Int32)?
  diagnostics : Array[Diagnostic]
}

///|
/// The parsed message, or `None` when the grammar refused the input.
pub fn Analysis::message(self : Analysis) -> SipMessage? {
  self.message
}

///|
/// The syntax error kind and offset, when parsing failed.
pub fn Analysis::syntax(self : Analysis) -> (SyntaxKind, Int32)? {
  self.syntax
}

///|
/// Semantic findings. Empty when parsing failed.
pub fn Analysis::diagnostics(self : Analysis) -> Array[Diagnostic] {
  self.diagnostics
}

///|
/// Three-way verdict, mirroring the split RFC 4475 itself makes between the
/// grammar tests (§3.1.2) and the semantic tests (§3.2, §3.3).
pub enum Verdict {
  /// Parsed, and no error-severity diagnostic fired.
  WellFormed
  /// The grammar rejected it.
  SyntaxRejected
  /// Parsed, but a semantic rule fired.
  SemanticRejected
}

///|
pub extend Verdict with Show::{to_string, output}

///|
pub impl Show for Verdict with fn to_string(self : Verdict) -> String {
  match self {
    WellFormed => "well-formed"
    SyntaxRejected => "syntax-rejected"
    SemanticRejected => "semantic-rejected"
  }
}

///|
/// Three-way verdict, mirroring the split RFC 4475 makes.
pub fn Analysis::verdict(self : Analysis) -> Verdict {
  match self.message {
    None => SyntaxRejected
    Some(_) => {
      let mut rejected = false
      for d in self.diagnostics {
        match d.severity {
          Error => rejected = true
          Warning => ()
        }
      }
      if rejected {
        SemanticRejected
      } else {
        WellFormed
      }
    }
  }
}

///|
/// True when at least one diagnostic carries `code`. Comparison goes through the
/// stable string form so the enum needs no hand-written `Eq` instance.
pub fn Analysis::has_code(self : Analysis, code : DiagCode) -> Bool {
  for d in self.diagnostics() {
    if d.code() == code {
      return true
    }
  }
  false
}

///|
/// Parses and diagnoses in one step. Never raises: a syntax failure is data, not
/// an exception, because the whole point of the conformance suite is to report on
/// malformed input.
pub fn analyze(input : Bytes) -> Analysis {
  // One parse, one outcome: the failure reason and the message are produced by the
  // same call, so a malformed input is never parsed twice just to explain itself.
  let outcome : Result[SipMessage, (SyntaxKind, Int32)] = Ok(
    parse_message(input),
  ) catch {
    Syntax(kind, at) => Err((kind, at))
  }
  match outcome {
    Ok(msg) => { message: Some(msg), syntax: None, diagnostics: diagnose(msg), }
    Err(reason) => { message: None, syntax: Some(reason), diagnostics: [], }
  }
}
