// message.mbt — start lines, header block, body framing and full-message parse.
//
// Framing rules implemented here (RFC 3261 §7 and §18.3):
//
//   * The start line and every header field end with CRLF; the header block ends
//     with an empty line.
//   * The body is `Content-Length` octets long. When the header is absent, the
//     remainder of the datagram is the body.
//   * Octets after the declared body are NOT silently discarded: they are kept in
//     `trailing`, because RFC 4475 §3.1.1.8 ("trailingspace") exists precisely to
//     test whether an implementation notices them.
//
// RFC 4475 §3.1.2.19 ("bigcode") returns a status code far outside 3DIGIT. Such a
// message must not crash a parser, so the code is read as a saturating integer and
// reported by the diagnostics layer instead of raising.

///|
/// Sentinel used when a decimal run exceeds `Int` range.
pub const SATURATED : Int32 = 2147483647

///|
/// A request start line.
pub struct RequestLine {
  verb : Bytes
  uri : RequestUri
  version : Bytes
  raw : Bytes
}

///|
/// The method token.
pub fn RequestLine::verb(self : RequestLine) -> Bytes {
  self.verb
}

///|
/// The request URI, parsed or kept verbatim for a non-SIP scheme.
pub fn RequestLine::uri(self : RequestLine) -> RequestUri {
  self.uri
}

///|
/// The protocol version octets, for example `SIP/2.0`.
pub fn RequestLine::version(self : RequestLine) -> Bytes {
  self.version
}

///|
/// A response start line.
pub struct StatusLine {
  version : Bytes
  code : Int32
  reason : Bytes
  raw : Bytes
}

///|
/// The protocol version octets.
pub fn StatusLine::version(self : StatusLine) -> Bytes {
  self.version
}

///|
/// The numeric status code, saturated when the digits overflow.
pub fn StatusLine::code(self : StatusLine) -> Int32 {
  self.code
}

///|
/// The reason phrase, which may be empty.
pub fn StatusLine::reason(self : StatusLine) -> Bytes {
  self.reason
}

///|
/// Request-URI as parsed. `Other` keeps a syntactically valid absolute URI whose
/// scheme is not sip/sips: RFC 3261 permits `absoluteURI` here, and RFC 4475
/// §3.3.2 expects such a message to parse and be rejected one layer up.
pub enum RequestUri {
  Parsed(SipUri)
  Other(Bytes)
}

///|
pub extend RequestUri with Show::{to_string, output}

///|
pub impl Show for RequestUri with fn to_string(self : RequestUri) -> String {
  match self {
    Parsed(u) => u.raw().to_string()
    Other(raw) => ascii_of(raw.exact_view())
  }
}

///|
pub enum StartLine {
  Request(RequestLine)
  Response(StatusLine)
}

///|
pub struct SipMessage {
  start : StartLine
  headers : Array[HeaderField]
  body : Bytes
  trailing : Bytes
  consumed : Int32
}

///|
/// The start line, request or response.
pub fn SipMessage::start_line(self : SipMessage) -> StartLine {
  self.start
}

///|
/// All header fields in wire order, duplicates included.
pub fn SipMessage::headers(self : SipMessage) -> Array[HeaderField] {
  self.headers
}

///|
/// The body, framed by `Content-Length`.
pub fn SipMessage::body(self : SipMessage) -> Bytes {
  self.body
}

///|
/// Octets that followed the declared body in the same datagram.
pub fn SipMessage::trailing(self : SipMessage) -> Bytes {
  self.trailing
}

///|
/// Number of octets belonging to this message.
pub fn SipMessage::consumed(self : SipMessage) -> Int32 {
  self.consumed
}

///|
/// The request method, or `None` for a response.
pub fn SipMessage::verb(self : SipMessage) -> Bytes? {
  match self.start {
    Request(r) => Some(r.verb)
    Response(_) => None
  }
}

///|
/// The status code, or `None` for a request.
pub fn SipMessage::status_code(self : SipMessage) -> Int32? {
  match self.start {
    Request(_) => None
    Response(r) => Some(r.code)
  }
}

///|
/// All header fields whose name matches, in wire order. Duplicates are preserved
/// because their presence is itself a diagnosable condition.
pub fn SipMessage::all_headers(
  self : SipMessage,
  name : String,
) -> Array[HeaderField] {
  let out : Array[HeaderField] = []
  for h in self.headers {
    if h.name_is(name) {
      out.push(h)
    }
  }
  out
}

///|
/// First header field with the given name.
pub fn SipMessage::header(self : SipMessage, name : String) -> HeaderField? {
  for h in self.headers {
    if h.name_is(name) {
      return Some(h)
    }
  }
  None
}

///|
/// Reads a decimal run, saturating instead of overflowing. Returns the value and
/// the octet count consumed.
fn read_decimal(c : Cursor) -> (Int32, Int32) {
  let start = c.position()
  let mut v = 0
  let mut overflow = false
  while c.pos < c.length() {
    let b = c.src[c.pos]
    if is_digit(b) {
      if v > 214748363 {
        overflow = true
      }
      v = v * 10 + (b - b'0').to_int()
      c.pos = c.pos + 1
    } else {
      break
    }
  }
  (if overflow { SATURATED } else { v }, c.position() - start)
}

///|
/// Parses `SIP/2.0` style version tokens. Returns the raw octets.
fn parse_version(c : Cursor) -> Bytes raise SipError {
  let start = c.position()
  if c.starts_with_ignore_case("SIP/") {
    c.pos = c.pos + 4
  } else {
    raise Syntax(IllegalOctet, c.position())
  }
  let (_, n1) = read_decimal(c)
  if n1 == 0 {
    raise Syntax(IllegalOctet, c.position())
  }
  if c.eof() || c.src[c.pos] != DOT {
    raise Syntax(IllegalOctet, c.position())
  }
  c.pos = c.pos + 1
  let (_, n2) = read_decimal(c)
  if n2 == 0 {
    raise Syntax(IllegalOctet, c.position())
  }
  copy_range(c.src, start, c.position())
}

///|
/// True when the version octets are exactly `SIP/2.0` ignoring case.
pub fn is_sip_2_0(v : Bytes) -> Bool {
  bytes_eq_ignore_ascii_case(v.exact_view(), b"SIP/2.0".exact_view())
}

///|
/// Consumes exactly one CRLF. A bare LF is accepted (every deployed stack does,
/// and RFC 4475 has messages that rely on leniency) but is reported downstream.
fn consume_crlf(c : Cursor) -> Unit raise SipError {
  if c.eof() {
    raise Syntax(ExpectedCrlf, c.position())
  }
  if c.src[c.pos] == CR {
    c.pos = c.pos + 1
    if c.pos < c.length() && c.src[c.pos] == LF {
      c.pos = c.pos + 1
      return
    }
    raise Syntax(ExpectedCrlf, c.position())
  }
  if c.src[c.pos] == LF {
    c.pos = c.pos + 1
    return
  }
  raise Syntax(ExpectedCrlf, c.position())
}

///|
/// Parses a Request-Line. Exactly one SP separates each element: RFC 4475
/// §3.1.2.9 and §3.1.2.10 mark multiple or trailing SPs as invalid.
fn parse_request_line(c : Cursor) -> RequestLine raise SipError {
  let start = c.position()
  let mstart = c.position()
  while c.pos < c.length() {
    let b = c.src[c.pos]
    if is_token_char(b) {
      c.pos = c.pos + 1
    } else {
      break
    }
  }
  if c.pos == mstart {
    raise Syntax(ExpectedToken, mstart)
  }
  let verb = copy_range(c.src, mstart, c.position())
  if c.eof() || c.src[c.pos] != SP {
    raise Syntax(IllegalOctet, c.position())
  }
  c.pos = c.pos + 1
  if c.pos < c.length() && c.src[c.pos] == SP {
    // RFC 4475 §3.1.2.9: multiple SP between Request-Line elements.
    raise Syntax(IllegalOctet, c.position())
  }
  let ustart = c.position()
  while c.pos < c.length() {
    let b = c.src[c.pos]
    if b == SP || b == CR || b == LF {
      break
    }
    c.pos = c.pos + 1
  }
  if c.pos == ustart {
    raise Syntax(IllegalOctet, ustart)
  }
  let uend = c.position()
  let uri = parse_request_uri(c.src.exact_view(start=ustart, end=uend))
  if c.eof() || c.src[c.pos] != SP {
    raise Syntax(IllegalOctet, c.position())
  }
  c.pos = c.pos + 1
  if c.pos < c.length() && c.src[c.pos] == SP {
    // RFC 4475 §3.1.2.10: SP at the end of the Request-Line.
    raise Syntax(IllegalOctet, c.position())
  }
  let version = parse_version(c)
  consume_crlf(c)
  { verb, uri, version, raw: copy_range(c.src, start, c.position()), }
}

///|
/// Parses a Request-URI from a bounded view. The view must be fully consumed:
/// leftover octets mean the URI grammar and the delimiter scan disagree, which is
/// a defect rather than something to paper over.
fn parse_request_uri(v : BytesView) -> RequestUri raise SipError {
  let sub = Cursor::new(v)
  let out = if looks_like_sip_uri(sub) {
    RequestUri::Parsed(parse_sip_uri(sub))
  } else {
    // Keep the raw octets; scheme-level rejection is an application-layer test
    // (RFC 4475 §3.3.2 / §3.3.3), not a parse failure.
    let mut i = 0
    while i < v.length() &&
          (
            is_alpha(v[i]) ||
            is_digit(v[i]) ||
            v[i] == b'+' ||
            v[i] == b'-' ||
            v[i] == b'.'
          ) {
      i = i + 1
    }
    if i == 0 || i >= v.length() || v[i] != COLON {
      raise Syntax(IllegalOctet, 0)
    }
    RequestUri::Other(copy_range(v, 0, v.length()))
  }
  if sub.position() != v.length() {
    match out {
      Parsed(_) => raise Syntax(TrailingGarbage, sub.position())
      Other(_) => ()
    }
  }
  out
}

///|
/// Parses a Status-Line.
fn parse_status_line(c : Cursor) -> StatusLine raise SipError {
  let start = c.position()
  let version = parse_version(c)
  if c.eof() || c.src[c.pos] != SP {
    raise Syntax(IllegalOctet, c.position())
  }
  c.pos = c.pos + 1
  let (code, digits) = read_decimal(c)
  if digits == 0 {
    raise Syntax(IllegalOctet, c.position())
  }
  let mut reason : Bytes = Bytes::new(0)
  if c.pos < c.length() && c.src[c.pos] == SP {
    c.pos = c.pos + 1
    let rstart = c.position()
    while c.pos < c.length() {
      let b = c.src[c.pos]
      if b == CR || b == LF {
        break
      }
      c.pos = c.pos + 1
    }
    reason = copy_range(c.src, rstart, c.position())
  }
  consume_crlf(c)
  { version, code, reason, raw: copy_range(c.src, start, c.position()), }
}

///|
/// Finds the `Content-Length` value, if any, using the first occurrence.
pub fn content_length_of(headers : Array[HeaderField]) -> Bytes? {
  for h in headers {
    if h.name_is("Content-Length") || h.name_is("l") {
      return Some(h.value)
    }
  }
  None
}

///|
/// Header fields whose value grammar is a name-addr list. Their values are parsed
/// structurally during message parse, not merely stored as octets: RFC 4475
/// §3.1.2.14 (spaces inside `< >`) and §3.1.2.15 (unquoted display name) are
/// grammar errors that only a structural parse can see.
fn is_address_header(name : Bytes) -> Bool {
  for
    cand in [
      b"From", b"To", b"Contact", b"Route", b"Record-Route", b"f", b"t", b"m",
    ] {
    if bytes_eq_ignore_ascii_case(name.exact_view(), cand.exact_view()) {
      return true
    }
  }
  false
}

///|
/// `SIP-date` per RFC 3261 §25.1: RFC 1123 date with the zone fixed to `GMT`.
/// Full grammar check (weekday names, month names, digit fields, ranges) plus
/// weekday/date agreement via Zeller's congruence, so `Mon, 01 Jan 2010` fails
/// on the weekday even though every token looks plausible. Other zone
/// designations that mean the same thing (`UT`, `UTC`, `UCT`) are explicitly
/// invalid -- that is exactly RFC 4475 §3.1.2.12 ("baddate").
fn is_sip_date(v : BytesView) -> Bool {
  // `Wkd, DD Mon YYYY HH:MM:SS GMT` is exactly 29 octets -- the grammar fixes
  // 2DIGIT day, 4DIGIT year and a 3-letter zone, so anything else is malformed.
  if v.length() != 29 {
    return false
  }
  if !bytes_eq_ignore_ascii_case(
      v.exact_view(start=26, end=29),
      b"GMT".exact_view(),
    ) {
    return false
  }
  if v[3] != COMMA || v[4] != SP || v[7] != SP || v[11] != SP || v[16] != SP {
    return false
  }
  if v[19] != COLON || v[22] != COLON {
    return false
  }
  let wnum = weekday_num(v.exact_view(start=0, end=3))
  if wnum < 0 {
    return false
  }
  let mon = month_num(v.exact_view(start=8, end=11))
  if mon < 0 {
    return false
  }
  for i in [5, 6, 12, 13, 14, 15, 17, 18, 20, 21, 23, 24] {
    if !is_digit(v[i]) {
      return false
    }
  }
  let day = digit2(v, 5)
  let year = digit2(v, 12) * 100 + digit2(v, 14)
  let hh = digit2(v, 17)
  let mm = digit2(v, 20)
  let ss = digit2(v, 23)
  if day < 1 || day > days_in_month(mon, year) {
    return false
  }
  // 60 seconds is legal exactly as a leap second.
  if hh > 23 || mm > 59 || ss > 60 {
    return false
  }
  // Weekday/date agreement: Zeller's congruence, h = 0 is Saturday.
  let zmon = if mon < 3 { mon + 12 } else { mon }
  let zyear = if mon < 3 { year - 1 } else { year }
  let k = zyear % 100
  let j = zyear / 100
  let h = (day + 13 * (zmon + 1) / 5 + k + k / 4 + j / 4 + 5 * j) % 7
  zeller_to_mon0(h) == wnum
}

///|
/// Two decimal digits starting at `at`, as an integer.
fn digit2(v : BytesView, at : Int32) -> Int32 {
  (v[at] - b'0').to_int() * 10 + (v[at + 1] - b'0').to_int()
}

///|
/// 0 = Mon .. 6 = Sun, or -1 when the name is not one of the seven.
fn weekday_num(w : BytesView) -> Int32 {
  let days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
  for i in 0..<days.length() {
    if bytes_eq_ignore_ascii_case(w, ascii_bytes_of(days[i]).exact_view()) {
      return i
    }
  }
  -1
}

///|
/// 1 = Jan .. 12 = Dec, or -1 when the name is not one of the twelve.
fn month_num(m : BytesView) -> Int32 {
  let months = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
    "Dec",
  ]
  for i in 0..<months.length() {
    if bytes_eq_ignore_ascii_case(m, ascii_bytes_of(months[i]).exact_view()) {
      return i + 1
    }
  }
  -1
}

///|
/// Days in a month, honouring the leap-year rule.
fn days_in_month(mon : Int32, year : Int32) -> Int32 {
  let dim = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
  let base = dim[mon - 1]
  if mon == 2 && year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
    return 29
  }
  base
}

///|
/// Maps Zeller's h (0 = Saturday) to the 0 = Mon numbering used above.
fn zeller_to_mon0(h : Int32) -> Int32 {
  match h {
    2 => 0
    3 => 1
    4 => 2
    5 => 3
    6 => 4
    0 => 5
    1 => 6
    _ => -1
  }
}

///|
/// Structurally validates an address-valued header. Raises with an offset already
/// translated into whole-message coordinates, so callers never see a view-relative
/// number.
fn validate_header_value(h : HeaderField) -> Unit raise SipError {
  if h.name_is("Date") && !is_sip_date(h.value.exact_view()) {
    raise Syntax(MalformedDate, h.offset)
  }
  if !is_address_header(h.name) {
    return
  }
  if h.value.length() == 0 {
    // An empty value is allowed by the grammar for optional fields; leave the
    // decision to the diagnostics layer.
    return
  }
  let sub = Cursor::new(h.value.exact_view())
  ignore(parse_name_addr_list(sub)) catch {
    Syntax(kind, at) => raise Syntax(kind, h.offset + at)
  }
  if sub.pos != sub.length() {
    raise Syntax(TrailingGarbage, h.offset + sub.pos)
  }
}

///|
/// Parses a whole message from a datagram or a buffered stream chunk.
pub fn parse_message(input : Bytes) -> SipMessage raise SipError {
  let c = Cursor::from_bytes(input)
  if input.length() == 0 {
    raise Syntax(EmptyInput, 0)
  }
  let start = if c.starts_with_ignore_case("SIP/") {
    StartLine::Response(parse_status_line(c))
  } else {
    StartLine::Request(parse_request_line(c))
  }
  let headers : Array[HeaderField] = []
  let mut line = 2
  while true {
    if c.eof() {
      raise Syntax(UnexpectedEnd, c.position())
    }
    // Empty line terminates the header block.
    if c.src[c.pos] == CR || c.src[c.pos] == LF {
      consume_crlf(c)
      break
    }
    let h = parse_header_field(c, line)
    validate_header_value(h)
    headers.push(h)
    consume_crlf(c)
    line = line + 1
  }
  let remaining = c.length() - c.position()
  let mut body : Bytes = Bytes::new(0)
  let mut trailing : Bytes = Bytes::new(0)
  match content_length_of(headers) {
    Some(raw) => {
      // Tolerate a leading `-` so a negative length becomes a diagnostic rather
      // than a parse failure (RFC 4475 §3.1.2.3).
      let sub = Cursor::new(raw.exact_view())
      let mut negative = false
      if sub.pos < sub.length() && sub.src[sub.pos] == MINUS {
        negative = true
        sub.pos = sub.pos + 1
      }
      // `Content-Length = 1*DIGIT` — a sign or trailing junk makes the field
      // ill-formed, not merely out of range (RFC 4475 §3.1.2.3 "ncl").
      let (declared, digits) = read_decimal(sub)
      if digits == 0 || sub.pos != sub.length() || negative {
        raise Syntax(BadContentLength, c.position())
      }
      let want = declared
      if want > remaining {
        // RFC 4475 §3.1.2.2: Content-Length larger than the message.
        body = copy_range(c.src, c.position(), c.length())
      } else {
        body = copy_range(c.src, c.position(), c.position() + want)
        trailing = copy_range(c.src, c.position() + want, c.length())
      }
    }
    None =>
      if remaining > 0 {
        body = copy_range(c.src, c.position(), c.length())
      }
  }
  { start, headers, body, trailing, consumed: c.position() + body.length(), }
}
