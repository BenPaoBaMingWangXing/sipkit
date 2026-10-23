// address.mbt — name-addr / addr-spec parsing, RFC 3261 §25.1.
//
//   name-addr   = [ display-name ] LAQUOT addr-spec RAQUOT
//   display-name = *(token LWS) / quoted-string
//
// Two RFC 4475 verdicts shape this code:
//
//   * §3.1.1.6 ("lwsdisp"): `From: caller<sip:caller@example.com>;tag=323` must be
//     ACCEPTED. The missing LWS before `<` is a known RFC 3261 grammar bug, so
//     the token loop stops on `<` without requiring whitespace first.
//
//   * §3.1.2.14 ("badaspec"): `To: "Watson, Thomas" < sip:t.watson@example.org >`
//     must be REJECTED. Therefore no SWS is skipped between `<` and the
//     addr-spec, nor between the addr-spec and `>`.
//
// One ambiguity is not resolvable and is documented instead of guessed at: when
// a field omits `<>`, header parameters and URI parameters live in the same
// octet run (`From: sip:a@b;tag=x`). `tag` is then looked up in both.

///|
/// One `;name[=value]` header parameter following a name-addr.
pub struct HeaderParam {
  name : Bytes
  value : Bytes?
  raw : Bytes
}

///|
pub fn HeaderParam::name(self : HeaderParam) -> Bytes {
  self.name
}

///|
pub fn HeaderParam::value(self : HeaderParam) -> Bytes? {
  self.value
}

///|
/// `addr-spec = SIP-URI / SIPS-URI / absoluteURI` (RFC 3261 §25.1). Non-SIP
/// absolute URIs are kept as octets: rejecting them is an application-layer
/// decision, which is how RFC 4475 §3.3.4 ("unksm2") expects `isbn:` and
/// `http:` values to survive parsing.
pub enum AddrSpec {
  Sip(SipUri)
  Other(Bytes)
}

///|
pub impl Show for AddrSpec with fn to_string(self : AddrSpec) -> String {
  match self {
    Sip(u) => ascii_of(u.raw().view())
    Other(raw) => ascii_of(raw.view())
  }
}

///|
/// A parsed From/To/Contact/Route/Record-Route style address value.
///
/// `display` holds the semantic display name (quotes removed, quoted-pairs
/// resolved); `display_quoted` records whether the wire form used quotes, since
/// an unquoted display name that needed quotes is a reportable defect.
pub struct NameAddr {
  raw : Bytes
  display : Bytes?
  display_quoted : Bool
  uri : AddrSpec
  params : Array[HeaderParam]
  had_angle_brackets : Bool
}

///|
pub fn NameAddr::raw(self : NameAddr) -> Bytes {
  self.raw
}

///|
pub fn NameAddr::display(self : NameAddr) -> Bytes? {
  self.display
}

///|
pub fn NameAddr::display_quoted(self : NameAddr) -> Bool {
  self.display_quoted
}

///|
pub fn NameAddr::uri(self : NameAddr) -> AddrSpec {
  self.uri
}

///|
/// The parsed SIP URI, when the address held one.
pub fn NameAddr::sip_uri(self : NameAddr) -> SipUri? {
  match self.uri {
    Sip(u) => Some(u)
    Other(_) => None
  }
}

///|
pub fn NameAddr::params(self : NameAddr) -> Array[HeaderParam] {
  self.params
}

///|
pub fn NameAddr::had_angle_brackets(self : NameAddr) -> Bool {
  self.had_angle_brackets
}

///|
/// Looks up a header parameter, then falls back to a URI parameter of the same
/// name. The fallback exists only because fields without `<>` merge the two
/// namespaces; see the file header.
pub fn NameAddr::param(self : NameAddr, name : String) -> HeaderParam? {
  let want = ascii_bytes_of(name).view()
  for p in self.params {
    if bytes_eq_ignore_ascii_case(p.name.view(), want) {
      return Some(p)
    }
  }
  match self.uri {
    Sip(u) =>
      match u.param(name) {
        Some(up) => Some({ name: up.name, value: up.value, raw: up.raw, })
        None => None
      }
    Other(_) => None
  }
}

///|
/// The `tag` parameter, which every dialog-forming request must carry.
pub fn NameAddr::tag(self : NameAddr) -> Bytes? {
  match self.param("tag") {
    Some(p) => p.value
    None => None
  }
}

///|
/// Parses the parameters that follow a `>` (or follow an unbracketed URI).
fn parse_header_params(c : Cursor) -> Array[HeaderParam] raise SipError {
  let params : Array[HeaderParam] = []
  while true {
    // Whitespace may separate `>` from the first `;` (§3.1.1.1 "wsinv").
    ignore(c.skip_sws())
    if c.pos >= c.length() || c.src[c.pos] != SEMI {
      break
    }
    let pstart = c.position()
    c.pos = c.pos + 1
    ignore(c.skip_sws())
    let nstart = c.position()
    while c.pos < c.length() {
      let x = c.src[c.pos]
      if is_token_char(x) {
        c.pos = c.pos + 1
      } else {
        break
      }
    }
    let pname = copy_range(c.src, nstart, c.position())
    let mut pval : Bytes? = None
    // RFC 4475 §3.1.1.1 puts whitespace around `=` (`tag    = 1918181833n`).
    ignore(c.skip_sws())
    if c.pos < c.length() && c.src[c.pos] == EQUALS {
      c.pos = c.pos + 1
      ignore(c.skip_sws())
      let vstart = c.position()
      if vstart < c.length() && c.src[vstart] == DQUOTE {
        let qs = parse_quoted_string(c)
        pval = Some(qs.value)
      } else {
        while c.pos < c.length() {
          let x = c.src[c.pos]
          if is_token_char(x) {
            c.pos = c.pos + 1
          } else {
            break
          }
        }
        pval = Some(copy_range(c.src, vstart, c.position()))
      }
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
/// True when the cursor starts a syntactically plausible `scheme:` URI. Used to
/// recognise a bare `absoluteURI` where a display name would otherwise be read.
fn looks_like_absolute_uri(c : Cursor) -> Bool {
  let mut i = c.pos
  if i >= c.length() || !is_alpha(c.src[i]) {
    return false
  }
  i = i + 1
  while i < c.length() {
    let b = c.src[i]
    if is_alnum(b) || b == b'+' || b == b'-' || b == b'.' {
      i = i + 1
    } else {
      break
    }
  }
  i < c.length() && c.src[i] == COLON
}

///|
/// Parses a name-addr or a bare addr-spec.
///
/// The distinction is made by lookahead rather than by backtracking: if the value
/// starts with `sip:`/`sips:`, it is a bare addr-spec (RFC 3261 allows this for
/// From/To); otherwise the leading run is a display name and `<>` is mandatory.
pub fn parse_name_addr(c : Cursor) -> NameAddr raise SipError {
  ignore(c.skip_sws())
  let start = c.position()
  let mut display : Bytes? = None
  let mut display_quoted = false
  let mut had_angle = false
  if looks_like_sip_uri(c) {
    // Bare addr-spec: `From: sip:a@b;tag=x`. Parameters are then ambiguous and
    // are kept inside the URI; `NameAddr::param` searches both.
    let uri = AddrSpec::Sip(parse_sip_uri(c))
    // RFC 4475 §3.1.1.1 ("wsinv") puts whitespace before the `;`, so the URI
    // parse stops early. Trailing parameters still belong to the field.
    ignore(c.skip_sws())
    let params = parse_header_params(c)
    return {
      raw: copy_range(c.src, start, c.position()),
      display: None,
      display_quoted: false,
      uri,
      params,
      had_angle_brackets: false,
    }
  }
  if c.pos < c.length() && c.src[c.pos] == DQUOTE {
    let qs = parse_quoted_string(c)
    display = Some(qs.value)
    display_quoted = true
    ignore(c.skip_sws())
    if c.eof() || c.src[c.pos] != LT {
      raise Syntax(IllegalOctet, c.position())
    }
  } else if c.pos < c.length() && c.src[c.pos] == LT {
    // No display name at all: `<sip:a@b>`.
    ()
  } else if looks_like_absolute_uri(c) {
    // Bare absoluteURI such as `To: isbn:2983792873` (RFC 4475 §3.3.4).
    // Octets are kept verbatim; scheme support is decided by the caller.
    let ustart = c.position()
    while c.pos < c.length() {
      let b = c.src[c.pos]
      if b == SEMI || b == COMMA || b == CR || b == LF || b == GT {
        break
      }
      c.pos = c.pos + 1
    }
    let raw = copy_range(c.src, ustart, c.position())
    ignore(c.skip_sws())
    let params = parse_header_params(c)
    return {
      raw: copy_range(c.src, start, c.position()),
      display: None,
      display_quoted: false,
      uri: AddrSpec::Other(raw),
      params,
      had_angle_brackets: false,
    }
  } else {
    // Unquoted display name: one or more tokens separated by LWS. `dend` tracks
    // the end of the last token so trailing whitespace is not part of the value.
    let dstart = c.position()
    let mut dend = dstart
    while c.pos < c.length() {
      let b = c.src[c.pos]
      if is_token_char(b) {
        c.pos = c.pos + 1
        dend = c.position()
      } else if is_lws(b) {
        c.pos = c.pos + 1
      } else {
        break
      }
    }
    if dend == dstart {
      raise Syntax(ExpectedToken, dstart)
    }
    display = Some(copy_range(c.src, dstart, dend))
    ignore(c.skip_sws())
    if c.eof() || c.src[c.pos] != LT {
      // A non-token, non-LWS octet before `<` means the display name needed
      // quoting: RFC 4475 §3.1.2.15 ("baddn") calls this malformed.
      raise Syntax(ExpectedQuotedString, c.position())
    }
  }
  // LAQUOT
  c.pos = c.pos + 1
  had_angle = true
  // No SWS here: `< sip:...` is malformed per RFC 4475 §3.1.2.14.
  let uri = if looks_like_sip_uri(c) {
    AddrSpec::Sip(parse_sip_uri(c))
  } else {
    // absoluteURI: scan to the closing bracket, keeping the octets verbatim.
    let ustart = c.position()
    let mut i = 0
    while c.pos < c.length() {
      let b = c.src[c.pos]
      if b == GT {
        break
      }
      // No LWS inside the brackets: RFC 4475 §3.1.2.14 ("badaspec") is
      // malformed precisely because of `< sip:... >`.
      if b == CR || b == LF || b == LT || b == SP || b == HTAB {
        raise Syntax(IllegalOctet, c.pos)
      }
      c.pos = c.pos + 1
      i = i + 1
    }
    if i == 0 {
      raise Syntax(IllegalOctet, ustart)
    }
    AddrSpec::Other(copy_range(c.src, ustart, c.position()))
  }
  if c.eof() || c.src[c.pos] != GT {
    raise Syntax(IllegalOctet, c.position())
  }
  c.pos = c.pos + 1
  let params = parse_header_params(c)
  {
    raw: copy_range(c.src, start, c.position()),
    display,
    display_quoted,
    uri,
    params,
    had_angle_brackets: had_angle,
  }
}

/// A tiny mutable cell is not needed; the display-name end offset is tracked with
/// a plain `let mut` inside the parser.

///|
/// Parses a comma-separated list of addresses (Contact, Route, Record-Route).
///
/// Commas inside quoted strings do not split — that is the whole reason a
/// hand-rolled split on `,` is wrong for SIP.
pub fn parse_name_addr_list(c : Cursor) -> Array[NameAddr] raise SipError {
  let out : Array[NameAddr] = []
  ignore(c.skip_sws())
  if c.eof() {
    return out
  }
  while true {
    let a = parse_name_addr(c)
    out.push(a)
    ignore(c.skip_sws())
    if c.pos < c.length() && c.src[c.pos] == COMMA {
      c.pos = c.pos + 1
      ignore(c.skip_sws())
      continue
    }
    break
  }
  out
}
