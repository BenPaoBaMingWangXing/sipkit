// token.mbt — cursor-based lexical layer for RFC 3261 §25.1 productions.
//
// The productions implemented here are the ones the message grammar actually
// uses: `token`, `quoted-string` (with `quoted-pair` unescaping), `comment`
// (nested, as the ABNF requires) and the LWS/SWS whitespace rules including
// CRLF folding.
//
// Design rule: the cursor never rewrites input. It records offsets so that every
// syntax error can point at the exact octet that caused it, which is what makes
// the diagnostics in `diagnose.mbt` useful on hostile traffic.

///|
/// Why a syntax error occurred. Kept structural (rather than a prebuilt string)
/// so tests can assert on the kind instead of on prose.
pub enum SyntaxKind {
  EmptyInput
  UnexpectedEnd
  IllegalOctet
  ExpectedCrlf
  ExpectedToken
  ExpectedQuotedString
  UnterminatedQuotedString
  UnterminatedComment
  TrailingGarbage
  BadEscape
  BadContentLength
  MalformedDate
}

///|
pub extend SyntaxKind with Show::{to_string, output}

///|
pub impl Show for SyntaxKind with fn to_string(self : SyntaxKind) -> String {
  match self {
    EmptyInput => "empty input"
    UnexpectedEnd => "unexpected end of input"
    IllegalOctet => "illegal octet"
    ExpectedCrlf => "expected CRLF"
    ExpectedToken => "expected token"
    ExpectedQuotedString => "expected quoted string"
    UnterminatedQuotedString => "unterminated quoted string"
    UnterminatedComment => "unterminated comment"
    TrailingGarbage => "trailing garbage"
    BadEscape => "bad quoted-pair escape"
    BadContentLength => "malformed Content-Length"
    MalformedDate => "malformed Date field"
  }
}

///|
/// The only error type the parser raises. `offset` is a byte offset into the
/// buffer handed to `parse_message`.
pub suberror SipError {
  Syntax(SyntaxKind, Int32)
}

///|
pub extend SipError with Show::{to_string, output}

///|
pub impl Show for SipError with fn to_string(self : SipError) -> String {
  match self {
    Syntax(kind, at) => "\{kind} at byte \{at}"
  }
}

///|
/// A read cursor over a byte view. Parsing functions take it by reference
/// semantics (MoonBit structs are references at runtime), so advancing moves the
/// caller's position.
pub struct Cursor {
  src : BytesView
  mut pos : Int32
}

///|
/// Creates a cursor over a byte view.
pub fn Cursor::new(src : BytesView) -> Cursor {
  { src, pos: 0, }
}

///|
/// Creates a cursor over owned octets.
pub fn Cursor::from_bytes(src : Bytes) -> Cursor {
  { src: src.exact_view(), pos: 0, }
}

///|
/// Current byte offset.
pub fn Cursor::position(self : Cursor) -> Int32 {
  self.pos
}

///|
/// Total octets in the underlying view.
pub fn Cursor::length(self : Cursor) -> Int32 {
  self.src.length()
}

///|
/// True when every octet has been consumed.
pub fn Cursor::eof(self : Cursor) -> Bool {
  self.pos >= self.src.length()
}

///|
/// The octet at the cursor, without advancing.
pub fn Cursor::peek(self : Cursor) -> Byte? {
  self.src.get(self.pos)
}

///|
/// The octet `ahead` positions past the cursor, if any.
pub fn Cursor::peek_at(self : Cursor, ahead : Int32) -> Byte? {
  self.src.get(self.pos + ahead)
}

///|
/// Consumes and returns one octet.
pub fn Cursor::advance(self : Cursor) -> Byte? {
  let b = self.src.get(self.pos)
  match b {
    Some(_) => self.pos = self.pos + 1
    None => ()
  }
  b
}

///|
/// Consumes one specific octet or raises `IllegalOctet` at the cursor.
pub fn Cursor::expect_byte(self : Cursor, want : Byte) -> Unit raise SipError {
  match self.peek() {
    Some(b) =>
      if b == want {
        self.pos = self.pos + 1
      } else {
        raise Syntax(IllegalOctet, self.pos)
      }
    None => raise Syntax(UnexpectedEnd, self.pos)
  }
}

///|
/// Case-sensitive literal match at the cursor.
pub fn Cursor::starts_with(self : Cursor, lit : String) -> Bool {
  let l = ascii_bytes_of(lit).exact_view()
  if self.pos + l.length() > self.src.length() {
    return false
  }
  let mut i = 0
  while i < l.length() {
    if self.src[self.pos + i] != l[i] {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// ASCII case-insensitive literal match at the cursor.
pub fn Cursor::starts_with_ignore_case(self : Cursor, lit : String) -> Bool {
  let l = ascii_bytes_of(lit).exact_view()
  if self.pos + l.length() > self.src.length() {
    return false
  }
  let mut i = 0
  while i < l.length() {
    if !eq_ignore_ascii_case(self.src[self.pos + i], l[i]) {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// Consumes an exact ASCII literal.
pub fn Cursor::expect_literal(
  self : Cursor,
  lit : String,
) -> Unit raise SipError {
  if !self.starts_with_ignore_case(lit) {
    raise Syntax(IllegalOctet, self.pos)
  }
  self.pos = self.pos + ascii_bytes_of(lit).length()
}

///|
/// Skips zero or more SP/HTAB.
pub fn Cursor::skip_lws(self : Cursor) -> Int32 {
  let start = self.pos
  while true {
    match self.peek() {
      Some(b) => if is_lws(b) { self.pos = self.pos + 1 } else { break }
      None => break
    }
  }
  self.pos - start
}

///|
/// True when a CRLF at the cursor is followed by at least one SP or HTAB, i.e.
/// the CRLF is a line fold rather than the end of a header field.
pub fn Cursor::at_fold(self : Cursor) -> Bool {
  match self.peek() {
    Some(b) => if b != CR { return false }
    None => return false
  }
  match self.peek_at(1) {
    Some(b) => if b != LF { return false }
    None => return false
  }
  match self.peek_at(2) {
    Some(b) => is_lws(b)
    None => false
  }
}

///|
/// Consumes one line fold (`CRLF 1*WSP`) if present.
pub fn Cursor::consume_fold(self : Cursor) -> Bool {
  if !self.at_fold() {
    return false
  }
  self.pos = self.pos + 2
  // at_fold guarantees at least one LWS octet follows
  ignore(self.skip_lws())
  true
}

///|
/// Skips "optional whitespace" in the RFC 3261 sense: LWS, and any number of
/// folds, repeatedly. Returns the number of octets consumed.
pub fn Cursor::skip_sws(self : Cursor) -> Int32 {
  let start = self.pos
  while true {
    let before = self.pos
    ignore(self.skip_lws())
    ignore(self.consume_fold())
    if self.pos == before {
      break
    }
  }
  self.pos - start
}

///|
/// `token = 1*(alphanum / "-" / "." / "!" / "%" / "*" / "_" / "+" / "`" / "'" / "~")`
/// Returns the token's octets. Raises `ExpectedToken` when the first octet is
/// not a token character (an empty token is not a legal token).
pub fn parse_token(c : Cursor) -> Bytes raise SipError {
  let start = c.position()
  while true {
    match c.peek() {
      Some(b) => if is_token_char(b) { c.pos = c.pos + 1 } else { break }
      None => break
    }
  }
  if c.position() == start {
    raise Syntax(ExpectedToken, start)
  }
  copy_range(c.src, start, c.position())
}

///|
/// A parsed quoted string: the raw octets including the surrounding DQUOTEs, and
/// the unescaped content. Both are kept because round-trip fidelity and semantic
/// comparison are different questions and RFC 4475 tests both.
pub struct QuotedString {
  raw : Bytes
  value : Bytes
}

///|
/// The quoted string including its surrounding DQUOTEs.
pub fn QuotedString::raw(self : QuotedString) -> Bytes {
  self.raw
}

///|
/// The content, with quoted-pairs resolved.
pub fn QuotedString::value(self : QuotedString) -> Bytes {
  self.value
}

///|
/// `quoted-string = SWS DQUOTE *(qdtext / quoted-pair) DQUOTE`
///
/// `qdtext` admits LWS, %x21, %x23-5B, %x5D-7E and UTF8-NONASCII. A raw `"` or a
/// raw `\` outside a quoted-pair is therefore a syntax error, which is what
/// RFC 4475 3.1.2.6 relies on.
pub fn parse_quoted_string(c : Cursor) -> QuotedString raise SipError {
  ignore(c.skip_sws())
  let start = c.position()
  match c.peek() {
    Some(b) => if b != DQUOTE { raise Syntax(ExpectedQuotedString, start) }
    None => raise Syntax(UnexpectedEnd, start)
  }
  c.pos = c.pos + 1
  let out : Array[Byte] = []
  while true {
    match c.peek() {
      Some(b) =>
        if b == DQUOTE {
          c.pos = c.pos + 1
          break
        } else if b == BSLASH {
          // quoted-pair = "\" (%x00-09 / %x0B-0C / %x0E-7F)
          let esc_at = c.pos
          c.pos = c.pos + 1
          match c.peek() {
            Some(e) => {
              if e == CR || e == LF {
                raise Syntax(BadEscape, esc_at)
              }
              out.push(e)
              c.pos = c.pos + 1
            }
            None => raise Syntax(UnexpectedEnd, esc_at)
          }
        } else if b == CR {
          // Only a fold is allowed inside a quoted string, not a bare CR.
          if c.at_fold() {
            ignore(c.consume_fold())
            out.push(SP)
          } else {
            raise Syntax(IllegalOctet, c.pos)
          }
        } else if is_ctl(b) && b != HTAB {
          raise Syntax(IllegalOctet, c.pos)
        } else {
          out.push(b)
          c.pos = c.pos + 1
        }
      None => raise Syntax(UnterminatedQuotedString, start)
    }
  }
  {
    raw: copy_range(c.src, start, c.position()),
    value: Bytes::from_array(out),
  }
}

///|
/// `comment = "(" *(ctext / quoted-pair / comment) ")"`
///
/// Comments nest in RFC 3261, which is a classic source of stack-depth bugs in
/// SIP parsers. The implementation keeps an explicit depth counter instead of
/// recursing, and caps it so hostile input cannot exhaust memory.
pub fn parse_comment(c : Cursor) -> Bytes raise SipError {
  let start = c.position()
  match c.peek() {
    Some(b) => if b != LPAREN { raise Syntax(IllegalOctet, start) }
    None => raise Syntax(UnexpectedEnd, start)
  }
  c.pos = c.pos + 1
  let out : Array[Byte] = []
  let mut depth = 1
  let max_depth = 16
  while depth > 0 {
    match c.peek() {
      Some(b) =>
        if b == RPAREN {
          depth = depth - 1
          if depth == 0 {
            c.pos = c.pos + 1
          } else {
            out.push(b)
            c.pos = c.pos + 1
          }
        } else if b == LPAREN {
          depth = depth + 1
          if depth > max_depth {
            raise Syntax(IllegalOctet, c.pos)
          }
          out.push(b)
          c.pos = c.pos + 1
        } else if b == BSLASH {
          c.pos = c.pos + 1
          match c.peek() {
            Some(e) => {
              out.push(e)
              c.pos = c.pos + 1
            }
            None => raise Syntax(UnexpectedEnd, start)
          }
        } else if b == CR && c.at_fold() {
          ignore(c.consume_fold())
          out.push(SP)
        } else {
          out.push(b)
          c.pos = c.pos + 1
        }
      None => raise Syntax(UnterminatedComment, start)
    }
  }
  ignore(start)
  Bytes::from_array(out)
}
