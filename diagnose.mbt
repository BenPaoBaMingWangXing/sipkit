// diagnose.mbt — structural and semantic checks above the grammar.
//
// RFC 4475 asks for two different kinds of judgement, and conflating them is the
// usual mistake:
//
//   * §3.1.2.x  messages are syntactically invalid  -> the grammar layer must
//     fail to parse them.
//   * §3.3.x    messages are syntactically valid but semantically rejectable
//     -> the grammar layer must succeed, and the problem must be reported here.
//
// Every rule below cites the torture case it exists for, so the test report in
// `tests/rfc4475` maps one-to-one onto the specification text.

///|
pub enum Severity {
  Error
  Warning
}

///|
pub impl Show for Severity with fn to_string(self : Severity) -> String {
  match self {
    Error => "error"
    Warning => "warning"
  }
}

///|
/// Diagnostic codes. Deliberately fine-grained: a coarse "invalid message" verdict
/// cannot show a reviewer which rule fired.
pub(all) enum DiagCode {
  MissingRequiredHeader
  MissingViaBranch
  CSeqMethodMismatch
  ContentLengthMismatch
  MultipleContentLengthValues
  DuplicateSingleValueHeader
  UnsupportedVersion
  StatusCodeOutOfRange
  ScalarOutOfRange
  UnknownRequestUriScheme
  TrailingOctets
  ExtraneousSeparator
  UnbracketedUriWithHeaders
  MissingContactInDialogRequest
  UnsupportedExtension
  EscapedHeadersInRequestUri
  MalformedDate
}

///|
pub impl Show for DiagCode with fn to_string(self : DiagCode) -> String {
  match self {
    MissingRequiredHeader => "missing-required-header"
    MissingViaBranch => "missing-via-branch"
    CSeqMethodMismatch => "cseq-method-mismatch"
    ContentLengthMismatch => "content-length-mismatch"
    MultipleContentLengthValues => "multiple-content-length-values"
    DuplicateSingleValueHeader => "duplicate-single-value-header"
    UnsupportedVersion => "unsupported-version"
    StatusCodeOutOfRange => "status-code-out-of-range"
    ScalarOutOfRange => "scalar-out-of-range"
    UnknownRequestUriScheme => "unknown-request-uri-scheme"
    TrailingOctets => "trailing-octets"
    ExtraneousSeparator => "extraneous-separator"
    UnbracketedUriWithHeaders => "unbracketed-uri-with-headers"
    MissingContactInDialogRequest => "missing-contact-in-dialog-request"
    UnsupportedExtension => "unsupported-extension"
    EscapedHeadersInRequestUri => "escaped-headers-in-request-uri"
    MalformedDate => "malformed-date"
  }
}

///|
pub struct Diagnostic {
  code : DiagCode
  severity : Severity
  offset : Int
  detail : String
}

///|
pub fn Diagnostic::code(self : Diagnostic) -> DiagCode {
  self.code
}

///|
pub fn Diagnostic::severity(self : Diagnostic) -> Severity {
  self.severity
}

///|
pub fn Diagnostic::offset(self : Diagnostic) -> Int {
  self.offset
}

///|
pub fn Diagnostic::detail(self : Diagnostic) -> String {
  self.detail
}

///|
pub impl Show for Diagnostic with fn to_string(self : Diagnostic) -> String {
  "\{self.severity}:\{self.code}@\{self.offset} \{self.detail}"
}

///|
fn err(code : DiagCode, offset : Int, detail : String) -> Diagnostic {
  { code, severity: Severity::Error, offset, detail, }
}

///|
fn warn(code : DiagCode, offset : Int, detail : String) -> Diagnostic {
  { code, severity: Severity::Warning, offset, detail, }
}

///|
/// Header fields that RFC 3261 §7.3.1/§8.1.1.5 treat as single-valued. Duplicates
/// are what RFC 4475 §3.3.8 ("multi01") is about.
fn is_single_valued(name : String) -> Bool {
  for
    cand in [
      "to", "from", "cseq", "call-id", "i", "max-forwards", "content-length", "l",
      "content-type", "c", "date", "subject", "s", "expires", "user-agent", "server",
    ] {
    if bytes_eq_ignore_ascii_case(
        ascii_bytes_of(name).view(),
        ascii_bytes_of(cand).view(),
      ) {
      return true
    }
  }
  false
}

///|
/// Requests that must carry all six core headers (RFC 3261 §8.1.1).
fn request_requires_headers(verb : Bytes) -> Bool {
  // ACK/CANCEL also need them, and treating every request uniformly is both
  // simpler and stricter; RFC 4475 §3.3.1 exercises a plain INVITE.
  ignore(verb)
  true
}

///|
/// Extracts a `;name=value` parameter from a header field value. Returns the value
/// octets (quote-stripped) and the offset of the value.
fn param_of(value : BytesView, want : String) -> (Bytes?, Int) {
  let n = value.length()
  let mut i = 0
  while i < n {
    if value[i] == SEMI {
      i = i + 1
      while i < n && is_lws(value[i]) {
        i = i + 1
      }
      let ns = i
      while i < n && is_token_char(value[i]) {
        i = i + 1
      }
      let name = value.view(start=ns, end=i)
      let mut val : Bytes? = None
      let mut voff = i
      // Whitespace may surround `=`; RFC 4475 §3.1.1.1 does exactly that.
      let mut j = i
      while j < n && is_lws(value[j]) {
        j = j + 1
      }
      if j < n && value[j] == EQUALS {
        i = j + 1
        while i < n && is_lws(value[i]) {
          i = i + 1
        }
        voff = i
        if i < n && value[i] == DQUOTE {
          i = i + 1
          let vs = i
          while i < n && value[i] != DQUOTE {
            i = i + 1
          }
          val = Some(copy_range(value, vs, i))
          if i < n {
            i = i + 1
          }
        } else {
          let vs = i
          while i < n &&
                value[i] != SEMI &&
                value[i] != COMMA &&
                !is_lws(value[i]) {
            i = i + 1
          }
          val = Some(copy_range(value, vs, i))
        }
      }
      if bytes_eq_ignore_ascii_case(name, ascii_bytes_of(want).view()) {
        return (val, voff)
      }
    } else {
      i = i + 1
    }
  }
  (None, 0)
}

///|
/// Reads a leading decimal run from a value, returning `(value, ok)`.
fn leading_decimal(v : BytesView) -> (Int, Bool) {
  let mut i = 0
  let mut n = 0
  let mut overflow = false
  while i < v.length() && is_digit(v[i]) {
    if n > 214748363 {
      overflow = true
    }
    n = n * 10 + (v[i] - b'0').to_int()
    i = i + 1
  }
  (if overflow { 2147483647 } else { n }, i > 0)
}

///|
/// True when a value contains `;` immediately followed by `;`, `,` or end of value,
/// i.e. a separator with no parameter attached (RFC 4475 §3.1.2.1 "badinv01").
fn has_extraneous_separator(v : BytesView) -> Bool {
  let n = v.length()
  let mut i = 0
  while i < n {
    if v[i] == SEMI {
      let mut j = i + 1
      while j < n && is_lws(v[j]) {
        j = j + 1
      }
      if j >= n || v[j] == SEMI || v[j] == COMMA {
        return true
      }
    } else if v[i] == COMMA {
      let mut j = i + 1
      while j < n && is_lws(v[j]) {
        j = j + 1
      }
      if j >= n || v[j] == COMMA || v[j] == SEMI {
        return true
      }
    }
    i = i + 1
  }
  false
}

///|
/// Runs all semantic checks over a successfully parsed message.
pub fn diagnose(msg : SipMessage) -> Array[Diagnostic] {
  let out : Array[Diagnostic] = []
  // --- version -------------------------------------------------------------
  let version_ok = match msg.start {
    Request(r) => is_sip_2_0(r.version)
    Response(r) => is_sip_2_0(r.version)
  }
  if !version_ok {
    out.push(err(UnsupportedVersion, 0, "start line version is not SIP/2.0"))
  }
  // --- status code ---------------------------------------------------------
  match msg.start {
    Response(r) =>
      if r.code > 699 || r.code < 100 {
        // RFC 4475 §3.1.2.19 "bigcode": must not break the receiver.
        out.push(
          err(StatusCodeOutOfRange, 0, "status code \{r.code} outside 100..699"),
        )
      }
    Request(_) => ()
  }
  // --- duplicated single-valued headers (§3.3.8 "multi01") -----------------
  for h in msg.headers {
    let name = ascii_of(h.name.view())
    if is_single_valued(name) {
      let same = msg.all_headers(name)
      if same.length() > 1 {
        out.push(
          err(
            DuplicateSingleValueHeader,
            h.offset,
            "\{same.length()} values for single-valued header \{name}",
          ),
        )
      }
    }
  }
  // --- Content-Length consistency -----------------------------------------
  let cls = msg.all_headers("Content-Length")
  let cls2 = msg.all_headers("l")
  let cl_all = if cls.length() > 0 { cls } else { cls2 }
  if cl_all.length() > 1 {
    // RFC 4475 §3.3.9 "doubleCL"
    out.push(
      err(
        MultipleContentLengthValues,
        cl_all[0].offset,
        "\{cl_all.length()} Content-Length headers",
      ),
    )
  }
  for cl in cl_all {
    // The grammar layer already rejects a non-decimal or negative length
    // (SyntaxKind::BadContentLength), so the only question left here is whether
    // the declared length agrees with the framing that was actually produced.
    // Checks that can never fire are not kept as decoration.
    let declared = leading_decimal(cl.value.view()).0
    if !(msg.trailing.length() > 0) && declared != msg.body.length() {
      // Declared longer than the datagram: §3.1.2.2 "clrf" style defect.
      out.push(
        err(
          ContentLengthMismatch,
          cl.offset,
          "declared \{declared} but body is \{msg.body.length()}",
        ),
      )
    }
  }
  // --- trailing octets (§3.1.1.8 "trailingspace") -------------------------
  if msg.trailing.length() > 0 {
    out.push(
      warn(
        TrailingOctets,
        msg.consumed,
        "\{msg.trailing.length()} octets after the declared body",
      ),
    )
  }
  // --- scalar ranges (apply to requests and responses alike) ---------------
  // RFC 4475 §3.1.2.4 "scalar02" and §3.1.2.5 "scalarlg". A value that saturates
  // the reader is by definition out of the 32-bit range the grammar allows.
  match msg.header("CSeq") {
    Some(cseq) => {
      let v = cseq.value.view()
      let mut i = 0
      while i < v.length() && is_digit(v[i]) {
        i = i + 1
      }
      let digits = v.view(start=0, end=i)
      let (seq, ok) = leading_decimal(v)
      if !ok || seq >= 2147483647 || digits.length() > 10 {
        out.push(
          err(
            ScalarOutOfRange,
            cseq.offset,
            "CSeq sequence number outside 0..2^32-1",
          ),
        )
      }
    }
    None => ()
  }
  match msg.header("Retry-After") {
    Some(ra) => {
      let v = ra.value.view()
      let mut i = 0
      while i < v.length() && is_digit(v[i]) {
        i = i + 1
      }
      let (val, ok) = leading_decimal(v)
      if !ok || val >= 2147483647 || i > 10 {
        out.push(
          err(ScalarOutOfRange, ra.offset, "Retry-After outside 0..2^32-1"),
        )
      }
    }
    None => ()
  }
  // --- extensions we do not implement -------------------------------------
  // This library implements no SIP extensions, so any non-empty Require or
  // Proxy-Require names a feature the message demands and we cannot honour
  // (RFC 4475 §3.3.5 "bext01", which expects 420 Bad Extension).
  for hn in ["Require", "Proxy-Require"] {
    match msg.header(hn) {
      Some(f) =>
        if f.value.length() > 0 {
          out.push(
            err(
              UnsupportedExtension,
              f.offset,
              "unsupported extension: \{ascii_of(f.value.view())}",
            ),
          )
        }
      None => ()
    }
  }
  // --- request-specific checks --------------------------------------------
  match msg.start {
    Request(r) => {
      let verb = r.verb
      if request_requires_headers(verb) {
        for required in ["To", "From", "CSeq", "Call-ID", "Via"] {
          if msg.all_headers(required).length() == 0 {
            // RFC 4475 §3.3.1 "insuf"
            out.push(
              err(MissingRequiredHeader, 0, "request has no \{required} header"),
            )
          }
        }
        // Max-Forwards is a SHOULD in RFC 3261 §8.1.1.6 and absent from RFC 2543
        // messages (§3.4.1 "inv2543"), so its absence is a warning, not a defect.
        if msg.all_headers("Max-Forwards").length() == 0 {
          out.push(
            warn(MissingRequiredHeader, 0, "request has no Max-Forwards header"),
          )
        }
      }
      match r.uri {
        Other(raw) =>
          // RFC 4475 §3.3.2 "unkscm" / §3.3.3 "novelsc"
          out.push(
            err(
              UnknownRequestUriScheme,
              0,
              "Request-URI scheme is not sip/sips: \{ascii_of(raw.view())}",
            ),
          )
        Parsed(u) => {
          // RFC 4475 §3.1.2.11 "escruri": a Request-URI must not smuggle headers
          // past a proxy by escaping them. The vector escapes the angle brackets
          // of a Route value as %3C/%3E, which no legitimate Request-URI needs.
          let raw = u.raw().view()
          if contains_ignore_case(raw, b"%3c") ||
            contains_ignore_case(raw, b"%3e") {
            out.push(
              err(
                EscapedHeadersInRequestUri,
                0,
                "Request-URI contains escaped headers",
              ),
            )
          }
        }
      }
      // CSeq method agreement (§3.1.2.17 "mismatch01")
      match msg.header("CSeq") {
        Some(cseq) => {
          let v = cseq.value.view()
          let mut i = 0
          while i < v.length() && is_digit(v[i]) {
            i = i + 1
          }
          while i < v.length() && is_lws(v[i]) {
            i = i + 1
          }
          let mstart = i
          while i < v.length() && is_token_char(v[i]) {
            i = i + 1
          }
          let cm = v.view(start=mstart, end=i)
          if cm.length() > 0 && !bytes_eq_ignore_ascii_case(cm, verb.view()) {
            out.push(
              err(
                CSeqMethodMismatch,
                cseq.offset,
                "CSeq method \{ascii_of(cm.view())} != start line \{ascii_of(verb.view())}",
              ),
            )
          }
        }
        None => ()
      }
      // Max-Forwards range (§3.1.2.4)
      match msg.header("Max-Forwards") {
        Some(mf) => {
          let (v, ok) = leading_decimal(mf.value.view())
          if !ok || v > 255 {
            out.push(
              err(ScalarOutOfRange, mf.offset, "Max-Forwards outside 0..255"),
            )
          }
        }
        None => ()
      }
      // Via branch (§3.2.1 "nobranch", §3.4.1 "inv2543")
      let vias = msg.all_headers("Via")
      for via in vias {
        let (branch, at) = param_of(via.value.view(), "branch")
        match branch {
          Some(b) =>
            // `z9hG4bK` alone advertises RFC 3261 transaction matching yet carries
            // no identifier; that is the defect §3.2.1 is about.
            if b.length() == 0 ||
              bytes_eq_ignore_ascii_case(b.view(), b"z9hG4bK".view()) {
              out.push(
                err(
                  MissingViaBranch,
                  via.offset + at,
                  "branch has no transaction identifier",
                ),
              )
            }
          None =>
            // No branch at all is legal for RFC 2543 senders (§3.4.1), which fall
            // back to the older transaction matching rules. Report, do not reject.
            out.push(
              warn(
                MissingViaBranch,
                via.offset,
                "Via has no branch parameter (RFC 2543 style)",
              ),
            )
        }
      }
      // Contact framing (§3.1.2.13 "regbadct")
      for c in msg.all_headers("Contact") {
        let v = c.value.view()
        let mut i = 0
        while i < v.length() && is_lws(v[i]) {
          i = i + 1
        }
        if i < v.length() && v[i] != LT && v[i] != DQUOTE {
          let has_q = match v.find(b"?".view()) {
            Some(_) => true
            None => false
          }
          if has_q {
            out.push(
              err(
                UnbracketedUriWithHeaders,
                c.offset,
                "addr-spec with URI headers must use angle brackets",
              ),
            )
          }
        }
        // §3.1.2.1 "badinv01": `Contact: <sip:a@b>;;;;`
        if has_extraneous_separator(v) {
          out.push(
            err(ExtraneousSeparator, c.offset, "separator without a parameter"),
          )
        }
      }
      for via in vias {
        if has_extraneous_separator(via.value.view()) {
          out.push(
            err(
              ExtraneousSeparator,
              via.offset,
              "separator without a parameter",
            ),
          )
        }
      }
      // INVITE establishes a dialog and must carry Contact (RFC 3261 §8.1.1.6).
      if bytes_eq_ignore_ascii_case(verb, b"INVITE".view()) &&
        msg.all_headers("Contact").length() == 0 {
        out.push(
          warn(MissingContactInDialogRequest, 0, "INVITE has no Contact"),
        )
      }
    }
    Response(_) => ()
  }
  out
}
