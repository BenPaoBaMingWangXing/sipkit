// header.mbt — message header field parsing, RFC 3261 §7.3 and §25.1.
//
//   message-header = field-name ":" [ field-value ]
//   field-name     = token
//   HCOLON         = *( SP / HTAB ) ":" SWS
//   field-value    = *( field-content / LWS )
//
// Two properties matter more than speed here:
//
//   * Folding. A CRLF followed by SP/HTAB continues the same field value and is
//     semantically a single SP (RFC 3261 §7.3.1). A CRLF *not* followed by
//     whitespace terminates the field. Getting this backwards is how header
//     smuggling bugs start, so the distinction is explicit in `parse_field_value`.
//
//   * Names are compared literally, case-insensitively, and are NOT unescaped.
//     RFC 4475 §3.1.1.5 ("esc02") states that `C%6Fntact` is a *different* field
//     from `Contact` — there are two Contact values in that message, not three.

///|
/// One message header field.
///
/// `value` is the semantic value: folds collapsed to a single SP, leading and
/// trailing whitespace trimmed. `raw` keeps the exact octets of the field line
/// (without its terminating CRLF) so a caller can round-trip byte-for-byte.
pub struct HeaderField {
  name : Bytes
  value : Bytes
  raw : Bytes
  offset : Int
  line : Int
}

///|
pub fn HeaderField::name(self : HeaderField) -> Bytes {
  self.name
}

///|
pub fn HeaderField::value(self : HeaderField) -> Bytes {
  self.value
}

///|
pub fn HeaderField::raw(self : HeaderField) -> Bytes {
  self.raw
}

///|
pub fn HeaderField::offset(self : HeaderField) -> Int {
  self.offset
}

///|
pub fn HeaderField::line(self : HeaderField) -> Int {
  self.line
}

///|
/// RFC 3261 Table 2: the single-letter compact forms real networks still send.
/// Without this table an `I:` header is not recognised as `Call-ID`, which makes
/// otherwise valid messages look like they are missing a required field.
fn long_name_of(compact : Byte) -> String? {
  match compact {
    b'i' | b'I' => Some("Call-ID")
    b'm' | b'M' => Some("Contact")
    b'e' | b'E' => Some("Content-Encoding")
    b'l' | b'L' => Some("Content-Length")
    b'c' | b'C' => Some("Content-Type")
    b'f' | b'F' => Some("From")
    b's' | b'S' => Some("Subject")
    b'k' | b'K' => Some("Supported")
    b't' | b'T' => Some("To")
    b'v' | b'V' => Some("Via")
    _ => None
  }
}

///|
/// Case-insensitive name test, honouring the compact forms in both directions.
pub fn HeaderField::name_is(self : HeaderField, name : String) -> Bool {
  let want = ascii_bytes_of(name)
  if bytes_eq_ignore_ascii_case(self.name.view(), want.view()) {
    return true
  }
  if self.name.length() == 1 {
    match long_name_of(self.name[0]) {
      Some(long) =>
        return bytes_eq_ignore_ascii_case(
          want.view(),
          ascii_bytes_of(long).view(),
        )
      None => ()
    }
  }
  if want.length() == 1 {
    match long_name_of(want[0]) {
      Some(long) =>
        return bytes_eq_ignore_ascii_case(
          self.name.view(),
          ascii_bytes_of(long).view(),
        )
      None => ()
    }
  }
  false
}

///|
/// Parses a field value up to (but not including) the terminating CRLF.
///
/// A fold contributes exactly one SP and also records that folding happened, so
/// the caller can report suspicious folding without guessing.
fn parse_field_value(c : Cursor) -> Bytes {
  let out : Array[Byte] = []
  while c.pos < c.length() {
    let b = c.src[c.pos]
    if b == CR {
      if c.at_fold() {
        ignore(c.consume_fold())
        out.push(SP)
        continue
      }
      break
    }
    if b == LF {
      // Bare LF: tolerated as a line terminator by every deployed stack, and
      // reported by the diagnostics layer rather than rejected here.
      break
    }
    out.push(b)
    c.pos = c.pos + 1
  }
  let collected = Bytes::from_array(out)
  bytes_of_view(trim_ows(collected.view()))
}

///|
/// Trims leading and trailing SP/HTAB.
pub fn trim_ows(b : BytesView) -> BytesView {
  let mut s = 0
  let mut e = b.length()
  while s < e && is_lws(b[s]) {
    s = s + 1
  }
  while e > s && is_lws(b[e - 1]) {
    e = e - 1
  }
  b.view(start=s, end=e)
}

///|
/// Parses one header field. The cursor must be positioned at the first octet of
/// the field name.
pub fn parse_header_field(c : Cursor, line : Int) -> HeaderField raise SipError {
  let fstart = c.position()
  let nstart = c.position()
  while c.pos < c.length() {
    let b = c.src[c.pos]
    if is_token_char(b) {
      c.pos = c.pos + 1
    } else {
      break
    }
  }
  if c.pos == nstart {
    raise Syntax(ExpectedToken, nstart)
  }
  let name = copy_range(c.src, nstart, c.position())
  // HCOLON allows whitespace before the colon: `To :` is legal.
  ignore(c.skip_lws())
  if c.eof() || c.src[c.pos] != COLON {
    raise Syntax(IllegalOctet, c.position())
  }
  c.pos = c.pos + 1
  // SWS after the colon is part of the syntax, not the value.
  ignore(c.skip_sws())
  let value = parse_field_value(c)
  {
    name,
    value,
    raw: copy_range(c.src, fstart, c.position()),
    offset: fstart,
    line,
  }
}
