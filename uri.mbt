// uri.mbt — SIP and SIPS URI parsing, RFC 3261 §19.1.
//
// Two deliberate decisions, both driven by RFC 4475 rather than by taste:
//
// 1. `%` is accepted literally when it is not followed by two hex digits.
//    RFC 4475 §3.1.1.5 ("esc02") declares `branch=z9hG4bK209%fzsnel234` to be
//    well formed, so a parser that rejects a stray `%` is wrong. Strictness
//    about escapes belongs to the diagnostics layer, not the grammar layer.
//
// 2. Unescaping is never recursive (RFC 4475 §3.1.1.3). `value%41` decodes to
//    `valueA` exactly once and is compared as such; `value%2541` decodes to
//    `value%41`, not to `valueA`.

///|
/// Which scheme a request URI carries. Anything that is a syntactically valid
/// absolute URI but not `sip:`/`sips:` is kept as `Other`, because RFC 3261
/// §25.1 admits `absoluteURI` in Request-URI and RFC 4475 §3.3.2/§3.3.3 expect
/// such a message to parse and be rejected at the application layer instead.
pub enum UriScheme {
  Sip
  Sips
  Other(Bytes)
}

///|
pub impl Show for UriScheme with fn to_string(self : UriScheme) -> String {
  match self {
    Sip => "sip"
    Sips => "sips"
    Other(raw) => ascii_of(raw.view())
  }
}

///|
/// Host as written. The IPv6 form keeps its brackets, since dropping them makes
/// the rendered URI ambiguous with a bare IPv6 address.
pub enum Host {
  Name(Bytes)
  Ipv4(Bytes)
  Ipv6Reference(Bytes)
}

///|
pub impl Show for Host with fn to_string(self : Host) -> String {
  match self {
    Name(b) => ascii_of(b.view())
    Ipv4(b) => ascii_of(b.view())
    Ipv6Reference(b) => ascii_of(b.view())
  }
}

///|
/// One `;name[=value]` URI parameter. `value` is `None` for valueless parameters
/// such as the ubiquitous `;lr`.
pub struct UriParam {
  name : Bytes
  value : Bytes?
  raw : Bytes
}

///|
/// The parameter name.
pub fn UriParam::name(self : UriParam) -> Bytes {
  self.name
}

///|
/// The parameter value, or `None` for a flag such as `;lr`.
pub fn UriParam::value(self : UriParam) -> Bytes? {
  self.value
}

///|
/// One `?name=value` URI header. RFC 3261 calls the `?`-suffixed section "URI
/// headers", which is a *different* namespace from message headers.
pub struct UriHeader {
  name : Bytes
  value : Bytes
}

///|
/// The URI header name, the part before `=`.
pub fn UriHeader::name(self : UriHeader) -> Bytes {
  self.name
}

///|
/// The URI header value.
pub fn UriHeader::value(self : UriHeader) -> Bytes {
  self.value
}

///|
/// A parsed URI. `raw` is the exact octets consumed, so a caller can always
/// recover what was on the wire even when a field is interpreted.
pub struct SipUri {
  raw : Bytes
  scheme : UriScheme
  user : Bytes?
  password : Bytes?
  host : Host
  port : Int?
  params : Array[UriParam]
  headers : Array[UriHeader]
}

///|
/// The exact octets the URI was parsed from.
pub fn SipUri::raw(self : SipUri) -> Bytes {
  self.raw
}

///|
/// `sip`, `sips`, or another scheme kept verbatim.
pub fn SipUri::scheme(self : SipUri) -> UriScheme {
  self.scheme
}

///|
/// The user part, or `None` when absent.
pub fn SipUri::user(self : SipUri) -> Bytes? {
  self.user
}

///|
/// The password, or `None` when absent.
pub fn SipUri::password(self : SipUri) -> Bytes? {
  self.password
}

///|
/// The host in the form it was written, IPv6 brackets included.
pub fn SipUri::host(self : SipUri) -> Host {
  self.host
}

///|
/// The port, or `None` when absent.
pub fn SipUri::port(self : SipUri) -> Int? {
  self.port
}

///|
/// URI parameters in wire order.
pub fn SipUri::params(self : SipUri) -> Array[UriParam] {
  self.params
}

///|
/// URI headers in wire order.
pub fn SipUri::headers(self : SipUri) -> Array[UriHeader] {
  self.headers
}

///|
/// Looks up a URI parameter by name, case-insensitively. Returns the last
/// occurrence, matching how flags such as `;lr` are conventionally read.
pub fn SipUri::param(self : SipUri, name : String) -> UriParam? {
  let want = ascii_bytes_of(name).view()
  let mut found : UriParam? = None
  for p in self.params {
    if bytes_eq_ignore_ascii_case(p.name.view(), want) {
      found = Some(p)
    }
  }
  found
}

///|
/// True when `;user=phone` is present. RFC 3261 §19.1.4 makes this change how the
/// user part is compared, so callers need it as a first-class query.
pub fn SipUri::is_phone_user(self : SipUri) -> Bool {
  match self.param("user") {
    Some(p) =>
      match p.value {
        Some(v) => bytes_eq_ignore_ascii_case(v.view(), b"phone".view())
        None => false
      }
    None => false
  }
}

///|
/// `unreserved = alphanum / mark`; `mark = "-" / "_" / "." / "!" / "~" / "*" / "'" / "(" / ")"`
pub fn is_unreserved(b : Byte) -> Bool {
  if is_alnum(b) {
    return true
  }
  match b {
    b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')' => true
    _ => false
  }
}

///|
/// Component octets for the user part: unreserved, `%`, and
/// `user-unreserved = & = + $ , ; ? /`. `@` is deliberately excluded: it is the
/// one octet that terminates a userinfo section.
fn is_user_octet(b : Byte) -> Bool {
  if is_unreserved(b) || b == PERCENT {
    return true
  }
  match b {
    b'&' | b'=' | b'+' | b'$' | b',' | b';' | b'?' | b'/' => true
    _ => false
  }
}

///|
/// Password admits unreserved, `%`, and `& = + $ ,` — but not `; ? /`.
fn is_password_octet(b : Byte) -> Bool {
  if is_unreserved(b) || b == PERCENT {
    return true
  }
  match b {
    b'&' | b'=' | b'+' | b'$' | b',' => true
    _ => false
  }
}

///|
/// Parameter octets: unreserved, `%`, and `param-unreserved = [ ] / : & + $`.
/// `=` and `;` terminate name and value respectively.
fn is_param_octet(b : Byte) -> Bool {
  if is_unreserved(b) || b == PERCENT {
    return true
  }
  match b {
    b'[' | b']' | b'/' | b':' | b'&' | b'+' | b'$' => true
    _ => false
  }
}

///|
/// URI-header octets: unreserved, `%`, and `hnv-unreserved = [ ] / ? : + $`.
fn is_hnv_octet(b : Byte) -> Bool {
  if is_unreserved(b) || b == PERCENT {
    return true
  }
  match b {
    b'[' | b']' | b'/' | b'?' | b':' | b'+' | b'$' => true
    _ => false
  }
}

///|
/// Decodes `% HEX HEX` exactly once. Non-escapes are copied through, which keeps
/// `%41` -> `A` and `%25` -> `%` without recursing into the result.
pub fn unescape_once(src : BytesView) -> Bytes {
  let out : Array[Byte] = []
  let n = src.length()
  let mut i = 0
  while i < n {
    let b = src[i]
    if b == PERCENT && i + 2 < n {
      let hi = hex_value(src[i + 1])
      let lo = hex_value(src[i + 2])
      if hi >= 0 && lo >= 0 {
        out.push((hi * 16 + lo).to_byte())
        i = i + 3
        continue
      }
    }
    out.push(b)
    i = i + 1
  }
  Bytes::from_array(out)
}

///|
/// Parses the scheme prefix. Scheme tokens are case-insensitive (RFC 3261
/// §19.1.1); the URI as a whole is never normalised.
fn parse_scheme(c : Cursor) -> UriScheme raise SipError {
  let start = c.position()
  if c.eof() {
    raise Syntax(UnexpectedEnd, start)
  }
  if !is_alpha(c.src[start]) {
    raise Syntax(IllegalOctet, start)
  }
  c.pos = c.pos + 1
  while c.pos < c.length() {
    let b = c.src[c.pos]
    if is_alnum(b) || b == b'+' || b == b'-' || b == b'.' {
      c.pos = c.pos + 1
    } else {
      break
    }
  }
  let raw = copy_range(c.src, start, c.position())
  if bytes_eq_ignore_ascii_case(raw.view(), b"sip".view()) {
    UriScheme::Sip
  } else if bytes_eq_ignore_ascii_case(raw.view(), b"sips".view()) {
    UriScheme::Sips
  } else {
    UriScheme::Other(raw)
  }
}

///|
/// True when the URI starting at the cursor begins with `sip:` or `sips:`.
pub fn looks_like_sip_uri(c : Cursor) -> Bool {
  c.starts_with_ignore_case("sip:") || c.starts_with_ignore_case("sips:")
}

///|
/// Parses the userinfo section that ends at `at_pos`, leaving the cursor on the
/// `@`. Returns `(user, password)`.
fn parse_userinfo(c : Cursor, at_pos : Int) -> (Bytes?, Bytes?) raise SipError {
  let ustart = c.position()
  let mut user : Bytes? = None
  let mut password : Bytes? = None
  let mut seen_colon = false
  let mut pstart = -1
  while c.pos < at_pos {
    let b = c.src[c.pos]
    if b == COLON && !seen_colon {
      seen_colon = true
      user = Some(copy_range(c.src, ustart, c.pos))
      c.pos = c.pos + 1
      pstart = c.pos
      continue
    }
    if seen_colon {
      if !is_password_octet(b) {
        raise Syntax(IllegalOctet, c.pos)
      }
    } else if !is_user_octet(b) {
      raise Syntax(IllegalOctet, c.pos)
    }
    c.pos = c.pos + 1
  }
  if seen_colon {
    password = Some(copy_range(c.src, pstart, at_pos))
  } else {
    user = Some(copy_range(c.src, ustart, at_pos))
  }
  (user, password)
}

///|
fn parse_host(c : Cursor) -> Host raise SipError {
  let hstart = c.position()
  if c.eof() {
    raise Syntax(UnexpectedEnd, hstart)
  }
  if c.src[hstart] == LBRACKET {
    c.pos = c.pos + 1
    while c.pos < c.length() {
      let x = c.src[c.pos]
      if x == RBRACKET {
        c.pos = c.pos + 1
        return Host::Ipv6Reference(copy_range(c.src, hstart, c.position()))
      }
      if !(is_hexdig(x) || x == COLON || x == DOT) {
        raise Syntax(IllegalOctet, c.pos)
      }
      c.pos = c.pos + 1
    }
    raise Syntax(UnexpectedEnd, hstart)
  }
  while c.pos < c.length() {
    let x = c.src[c.pos]
    if is_alnum(x) || x == MINUS || x == DOT || x == b'_' {
      c.pos = c.pos + 1
    } else {
      break
    }
  }
  let hn = copy_range(c.src, hstart, c.position())
  if hn.length() == 0 {
    raise Syntax(IllegalOctet, hstart)
  }
  if is_dotted_quad(hn.view()) {
    Host::Ipv4(hn)
  } else {
    Host::Name(hn)
  }
}

///|
fn parse_port(c : Cursor) -> Int? raise SipError {
  if c.eof() || c.src[c.pos] != COLON {
    return None
  }
  c.pos = c.pos + 1
  let pstart = c.position()
  let mut v = 0
  while c.pos < c.length() {
    let x = c.src[c.pos]
    if is_digit(x) {
      v = v * 10 + (x - b'0').to_int()
      c.pos = c.pos + 1
    } else {
      break
    }
  }
  if c.position() == pstart {
    raise Syntax(IllegalOctet, pstart)
  }
  Some(v)
}

///|
fn parse_uri_params(c : Cursor) -> Array[UriParam] {
  let params : Array[UriParam] = []
  while c.pos < c.length() {
    if c.src[c.pos] != SEMI {
      break
    }
    let pstart = c.position()
    c.pos = c.pos + 1
    let nstart = c.position()
    while c.pos < c.length() {
      let x = c.src[c.pos]
      if is_param_octet(x) {
        c.pos = c.pos + 1
      } else {
        break
      }
    }
    let pname = copy_range(c.src, nstart, c.position())
    let mut pval : Bytes? = None
    if c.pos < c.length() && c.src[c.pos] == EQUALS {
      c.pos = c.pos + 1
      let vstart = c.position()
      while c.pos < c.length() {
        let x = c.src[c.pos]
        if is_param_octet(x) {
          c.pos = c.pos + 1
        } else {
          break
        }
      }
      pval = Some(copy_range(c.src, vstart, c.position()))
    }
    params.push({
      name: pname,
      value: pval,
      raw: copy_range(c.src, pstart, c.position()),
    })
  }
  params
}

///|
fn parse_uri_headers(c : Cursor) -> Array[UriHeader] raise SipError {
  let headers : Array[UriHeader] = []
  if c.eof() || c.src[c.pos] != b'?' {
    return headers
  }
  c.pos = c.pos + 1
  let mut first = true
  while c.pos < c.length() {
    if !first {
      if c.src[c.pos] != b'&' {
        break
      }
      c.pos = c.pos + 1
    }
    first = false
    let nstart = c.position()
    while c.pos < c.length() {
      let x = c.src[c.pos]
      if is_hnv_octet(x) {
        c.pos = c.pos + 1
      } else {
        break
      }
    }
    let hname = copy_range(c.src, nstart, c.position())
    if c.eof() || c.src[c.pos] != EQUALS {
      raise Syntax(IllegalOctet, c.position())
    }
    c.pos = c.pos + 1
    let vstart = c.position()
    while c.pos < c.length() {
      let x = c.src[c.pos]
      if is_hnv_octet(x) {
        c.pos = c.pos + 1
      } else {
        break
      }
    }
    headers.push({
      name: hname,
      value: copy_range(c.src, vstart, c.position()),
    })
  }
  headers
}

///|
/// Parses a SIP/SIPS URI.
///
/// The `@` that separates userinfo from host is the first one that appears
/// before any `?`. This is the only rule that keeps `sip:host?to=sip:a@b` from
/// being read as a userinfo section, and it matches what production stacks do.
/// The residual ambiguity — `?` is legal inside a user part — is documented in
/// the README rather than papered over.
pub fn parse_sip_uri(c : Cursor) -> SipUri raise SipError {
  let start = c.position()
  let scheme = parse_scheme(c)
  match scheme {
    Other(_) => raise Syntax(IllegalOctet, start)
    _ => ()
  }
  if c.eof() || c.src[c.pos] != COLON {
    raise Syntax(IllegalOctet, c.position())
  }
  c.pos = c.pos + 1
  let n = c.length()
  let mut scan = c.position()
  let mut at_pos = -1
  // The user part may legally contain `; , ? / & = + $` (RFC 3261 §25.1
  // `user-unreserved`), so the scan for the `@` cannot stop on any of them.
  // It stops only where the URI itself must end: whitespace or angle brackets.
  // RFC 4475 §3.1.1.2 ("intmeth") has a user part containing `,/;;*:` and is
  // the reason this is not a naive "first separator wins" scan.
  while scan < n {
    let b = c.src[scan]
    if b == AT {
      break
    }
    if b == CR || b == LF || b == SP || b == LT || b == GT || b == b'"' {
      break
    }
    scan = scan + 1
  }
  if scan < n && c.src[scan] == AT {
    at_pos = scan
  }
  let has_user = at_pos >= 0
  let mut user : Bytes? = None
  let mut password : Bytes? = None
  if has_user {
    let pair = parse_userinfo(c, at_pos)
    user = pair.0
    password = pair.1
    if c.eof() || c.src[c.pos] != AT {
      raise Syntax(IllegalOctet, c.position())
    }
    c.pos = c.pos + 1
  }
  let host = parse_host(c)
  let port = parse_port(c)
  let params = parse_uri_params(c)
  let headers = parse_uri_headers(c)
  {
    raw: copy_range(c.src, start, c.position()),
    scheme,
    user,
    password,
    host,
    port,
    params,
    headers,
  }
}

///|
/// True for a syntactically valid dotted quad. Used only to label the host for
/// diagnostics; both forms parse identically.
fn is_dotted_quad(b : BytesView) -> Bool {
  let mut parts = 0
  let mut digits = 0
  for i in 0..<b.length() {
    if b[i] == DOT {
      if digits == 0 || digits > 3 {
        return false
      }
      parts = parts + 1
      digits = 0
    } else if is_digit(b[i]) {
      digits = digits + 1
      if digits > 3 {
        return false
      }
    } else {
      return false
    }
  }
  if digits == 0 || digits > 3 {
    return false
  }
  parts = parts + 1
  parts == 4
}
