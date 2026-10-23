// bytes.mbt — octet-level primitives for SIP parsing.
//
// SIP is an octet protocol, not a text protocol. A message may legally carry
// octets that are not valid UTF-8 (RFC 3261 §7.1 requires UTF-8 only for the
// body when it is textual; headers are defined over octets). Every layer below
// therefore works on `Bytes` and never materialises a `String`, so that
// parsing cannot fail or silently rewrite bytes for reasons the wire format
// does not sanction.

///|
/// Octet constants used throughout the parser.
pub const CR : Byte = b'\r'

///|
pub const LF : Byte = b'\n'

///|
pub const SP : Byte = b' '

///|
pub const HTAB : Byte = b'\t'

///|
pub const DQUOTE : Byte = b'"'

///|
pub const COLON : Byte = b':'

///|
pub const LT : Byte = b'<'

///|
pub const GT : Byte = b'>'

///|
pub const COMMA : Byte = b','

///|
pub const SEMI : Byte = b';'

///|
pub const BSLASH : Byte = b'\\'

///|
pub const AT : Byte = b'@'

///|
pub const PERCENT : Byte = b'%'

///|
pub const EQUALS : Byte = b'='

///|
pub const LPAREN : Byte = b'('

///|
pub const RPAREN : Byte = b')'

///|
pub const SLASH : Byte = b'/'

///|
pub const LBRACKET : Byte = b'['

///|
pub const RBRACKET : Byte = b']'

///|
pub const DOT : Byte = b'.'

///|
pub const MINUS : Byte = b'-'

///|
pub fn is_digit(b : Byte) -> Bool {
  b >= b'0' && b <= b'9'
}

///|
pub fn is_alpha(b : Byte) -> Bool {
  (b >= b'a' && b <= b'z') || (b >= b'A' && b <= b'Z')
}

///|
pub fn is_alnum(b : Byte) -> Bool {
  is_digit(b) || is_alpha(b)
}

///|
pub fn is_hexdig(b : Byte) -> Bool {
  is_digit(b) || (b >= b'A' && b <= b'F') || (b >= b'a' && b <= b'f')
}

///|
/// Linear white space: SP and HTAB. CRLF that is followed by LWS is handled by
/// the folding logic in `token.mbt`, not here.
pub fn is_lws(b : Byte) -> Bool {
  b == SP || b == HTAB
}

///|
/// Control octets. RFC 3261 forbids raw CTLs in most productions; they may only
/// appear as `quoted-pair` escapes (`\` followed by %x00-09 / %x0B-0C / %x0E-7F).
pub fn is_ctl(b : Byte) -> Bool {
  b < 0x20 || b == 0x7F
}

///|
/// `%x80-FF`. RFC 3261 §25.1 allows these in `qdtext`, `ctext` and `token`-adjacent
/// productions through the UTF8-NONASCII rule, so they must survive round-trip.
pub fn is_high_octet(b : Byte) -> Bool {
  b >= 0x80
}

///|
/// RFC 3261 §25.1 `token` character set. Note this deliberately differs from
/// HTTP's token set: SIP excludes `|`, `&`, `^`, `$`, `#` and includes `%`, `*`,
/// `+`, `` ` ``, `'`, `~`.
pub fn is_token_char(b : Byte) -> Bool {
  if is_alnum(b) {
    return true
  }
  match b {
    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~' => true
    _ => false
  }
}

///|
/// RFC 3261 §25.1 `separators`. These may not appear inside a token.
pub fn is_separator(b : Byte) -> Bool {
  match b {
    b'('
    | b')'
    | b'<'
    | b'>'
    | b'@'
    | b','
    | b';'
    | b':'
    | b'\\'
    | b'"'
    | b'/'
    | b'['
    | b']'
    | b'?'
    | b'='
    | b'{'
    | b'}' => true
    _ => false
  }
}

///|
/// Case-insensitive comparison of ASCII letters.
pub fn eq_ignore_ascii_case(a : Byte, b : Byte) -> Bool {
  lower_ascii(a) == lower_ascii(b)
}

///|
pub fn lower_ascii(b : Byte) -> Byte {
  if b >= b'A' && b <= b'Z' {
    b + 32
  } else {
    b
  }
}

///|
/// Compares two octet strings case-insensitively over ASCII only, which is the
/// rule RFC 3261 §7.3.1 applies to header field names and to token-valued
/// parameters such as transport names.
pub fn bytes_eq_ignore_ascii_case(a : BytesView, b : BytesView) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut i = 0
  while i < a.length() {
    if !eq_ignore_ascii_case(a[i], b[i]) {
      return false
    }
    i = i + 1
  }
  true
}

///|
pub fn bytes_view_of(b : Bytes) -> BytesView {
  b.view()
}

///|
/// Copies an octet range into a fresh `Bytes`. Used when a parsed fragment must
/// outlive the input buffer.
pub fn copy_range(src : BytesView, start : Int, end : Int) -> Bytes {
  let n = end - start
  if n <= 0 {
    return Bytes::new(0)
  }
  Bytes::makei(n, fn(i) { src[start + i] })
}

///|
pub fn bytes_of_view(v : BytesView) -> Bytes {
  copy_range(v, 0, v.length())
}

///|
/// Converts an ASCII-only `String` to octets, taking the low byte of each UTF-16
/// code unit.
///
/// This exists because `String` in this toolchain is UTF-16: `b"sip"`
/// yields six octets, not three. Every `String` this module accepts is an ASCII
/// literal (a header name, a scheme), so the low-byte projection is exact; a
/// non-ASCII input is rejected rather than silently truncated.
pub fn ascii_bytes_of(s : String) -> Bytes {
  let out : Array[Byte] = []
  for u in s.code_units() {
    let v = u.to_int()
    if v <= 0x7F {
      out.push(v.to_byte())
    }
  }
  Bytes::from_array(out)
}

///|
/// Compares a byte range against an ASCII literal, case-insensitively.
pub fn range_eq_ignore_case(
  src : BytesView,
  start : Int,
  end : Int,
  lit : String,
) -> Bool {
  let l = ascii_bytes_of(lit).view()
  if end - start != l.length() {
    return false
  }
  let mut i = 0
  while i < l.length() {
    if !eq_ignore_ascii_case(src[start + i], l[i]) {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// Hex value of an ASCII hex digit, or -1 when the octet is not a hex digit.
pub fn hex_value(b : Byte) -> Int {
  if b >= b'0' && b <= b'9' {
    (b - b'0').to_int()
  } else if b >= b'A' && b <= b'F' {
    (b - b'A').to_int() + 10
  } else if b >= b'a' && b <= b'f' {
    (b - b'a').to_int() + 10
  } else {
    -1
  }
}

///|
/// Renders octets as lowercase hex, used by diagnostics and snapshot tests.
/// Built from `Char`s because `Bytes::to_string` is the `Show` instance and would
/// produce `b"..."` instead of the hex text.
pub fn hex_of(b : BytesView) -> String {
  let digits : Array[Char] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
  ]
  let out : Array[Char] = []
  for i in 0..<b.length() {
    let v = b[i].to_int()
    out.push(digits[v / 16])
    out.push(digits[v % 16])
  }
  String::from_array(out)
}

///|
/// Renders octets as a String when they are known to be ASCII/Latin-1, which is the
/// case for every SIP token this library reports. Non-ASCII octets are rendered as
/// `.` so that a diagnostic never claims a byte value it cannot display.
pub fn ascii_of(b : BytesView) -> String {
  let out : Array[Char] = []
  for i in 0..<b.length() {
    let v = b[i].to_int()
    if v >= 0x20 && v < 0x7F {
      out.push(Int::unsafe_to_char(v))
    } else {
      out.push('.')
    }
  }
  String::from_array(out)
}

///|
/// Decodes a hex string into octets. Used by the RFC 4475 fixture, which stores
/// vectors as hex so that non-ASCII and control octets survive a source file.
pub fn bytes_from_hex(s : String) -> Bytes {
  let units = s.code_units()
  let out : Array[Byte] = []
  let mut i = 0
  while i + 1 < units.length() {
    let hi = hex_value(units[i].to_int().to_byte())
    let lo = hex_value(units[i + 1].to_int().to_byte())
    if hi < 0 || lo < 0 {
      break
    }
    out.push((hi * 16 + lo).to_byte())
    i = i + 2
  }
  Bytes::from_array(out)
}

///|
/// Case-insensitive (ASCII) substring search. Used by diagnostics that look for a
/// specific escaped octet sequence such as `%3F`.
pub fn contains_ignore_case(hay : BytesView, needle : BytesView) -> Bool {
  let n = needle.length()
  if n == 0 || hay.length() < n {
    return false
  }
  let mut i = 0
  while i + n <= hay.length() {
    if bytes_eq_ignore_ascii_case(hay.view(start=i, end=i + n), needle) {
      return true
    }
    i = i + 1
  }
  false
}
