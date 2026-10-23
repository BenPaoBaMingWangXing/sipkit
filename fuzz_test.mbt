// fuzz_test.mbt — robustness evidence.
//
// A parser's worst failure is not "rejected a valid message", it is "panicked on
// invalid input". A panic in a signalling stack takes down the media path behind
// it, so the property worth proving is total: for ANY octet string,
// `analyze` returns, and if it parses, `to_bytes` returns too.
//
// Two generators, both deterministic so a failure is reproducible:
//
//   1. Pseudo-random octets, which mostly exercise the early grammar exits.
//   2. Mutations of the RFC 4475 corpus — truncation, byte flips, insertions and
//      deletions. Mutations are the important half: they reach the deep grammar
//      and the diagnostics layer, which random noise almost never touches.
//
// MoonBit has no panic-catching test primitive, so a panic here fails the test
// run outright. Passing is the evidence.

///|
/// Deterministic, overflow-free byte generator. Fuzz quality does not need a good
/// PRNG; it needs the same sequence on every machine so a failure can be replayed.
fn prng_byte(seed : Int, i : Int) -> Byte {
  let mixed = seed % 251 * 31 + i % 241 * 17 + (seed ^ i)
  let v = mixed % 256
  if v < 0 {
    (-v).to_byte()
  } else {
    v.to_byte()
  }
}

///|
/// Same generator, biased towards structurally interesting octets: CR, LF, SP,
/// tabs, delimiters and a few high bits.
fn prng_structural(seed : Int, i : Int) -> Byte {
  let table : Array[Byte] = [
    b'\r', b'\n', b' ', b'\t', b':', b';', b',', b'@', b'<', b'>', b'"', b'\\', b'(',
    b')', b'%', b'?', b'=', b'/', b'[', b']', b'*', b'.', b'-', b'0', b'9', b'a',
    b'Z', b'\x00', b'\x7f', b'\x80', b'\xff', b'\x0b',
  ]
  let idx = (seed % 97 * 31 + i % 89 * 17 + (seed ^ i)) % table.length()
  let k = if idx < 0 { -idx } else { idx }
  table[k]
}

///|
test "fuzz: random octets never panic" {
  let mut parsed = 0
  for seed in 0..<1200 {
    let len = seed % 160
    let buf = Bytes::makei(len, fn(i) { prng_byte(seed, i) })
    let a = analyze(buf)
    match a.message() {
      Some(msg) => {
        parsed = parsed + 1
        // Re-emission must be total for anything that parsed.
        ignore(to_bytes(msg))
        ignore(msg.headers().length())
        ignore(msg.body().length())
        ignore(msg.trailing().length())
      }
      None =>
        // A syntax failure must carry a usable offset inside the input.
        match a.syntax() {
          Some(pair) => {
            let (_, at) = pair
            assert_true(at >= 0)
            assert_true(at <= buf.length())
          }
          None => fail("analyze returned neither a message nor a syntax error")
        }
    }
  }
  // Sanity: the generator must not accidentally produce mostly-valid input, or
  // this test would only be probing the happy path.
  assert_true(parsed < 120)
}

///|
test "fuzz: structural octets never panic" {
  for seed in 0..<1500 {
    let len = seed % 96
    let buf = Bytes::makei(len, fn(i) { prng_structural(seed, i) })
    let a = analyze(buf)
    match a.message() {
      Some(msg) => {
        let rebuilt = to_bytes(msg)
        // Rebuilt output must itself re-parse or be explainable; at minimum it
        // must be produced without panicking and stay within a sane bound.
        assert_true(rebuilt.length() <= buf.length() + 8)
        ignore(analyze(rebuilt))
      }
      None => ()
    }
  }
}

///|
test "fuzz: truncated torture messages never panic" {
  for v in vectors {
    let base = bytes_from_hex(v.hex)
    if base.length() < 2 {
      continue
    }
    let cuts = [
      1,
      2,
      3,
      base.length() / 3,
      base.length() / 2,
      base.length() - 1,
    ]
    for cut in cuts {
      if cut <= 0 || cut >= base.length() {
        continue
      }
      let trimmed = bytes_of_view(base.view(start=0, end=cut))
      ignore(analyze(trimmed))
    }
  }
}

///|
test "fuzz: byte mutations never panic and stay bounded" {
  for v in vectors {
    let base = bytes_from_hex(v.hex)
    if base.length() < 4 {
      continue
    }
    for k in 0..<24 {
      let pos = (k % 29 * 7 + v.id.length() * 13) % base.length()
      let mutated = base.to_array()
      // Flip: XOR with a non-zero mask so the octet actually changes.
      let mask = (k * 37 % 254 + 1).to_byte()
      mutated[pos] = mutated[pos] ^ mask
      let buf = Bytes::from_array(mutated)
      let a = analyze(buf)
      match a.message() {
        Some(msg) => ignore(to_bytes(msg))
        None => ()
      }
    }
  }
}

///|
test "fuzz: insertions and deletions keep the parser total" {
  for v in vectors {
    let base = bytes_from_hex(v.hex)
    if base.length() < 8 {
      continue
    }
    // Delete a slice.
    let drop_at = base.length() / 4
    let kept = base.to_array()
    let rebuilt : Array[Byte] = []
    for i in 0..<kept.length() {
      if i < drop_at || i >= drop_at + 3 {
        rebuilt.push(kept[i])
      }
    }
    ignore(analyze(Bytes::from_array(rebuilt)))

    // Insert a CRLF, which is the most likely octet pair to break framing.
    let injected : Array[Byte] = []
    for i in 0..<kept.length() {
      injected.push(kept[i])
      if i == drop_at {
        injected.push(b'\r')
        injected.push(b'\n')
      }
    }
    ignore(analyze(Bytes::from_array(injected)))
  }
}
