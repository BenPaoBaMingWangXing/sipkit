#!/usr/bin/env python3
"""Extract the RFC 4475 torture-test messages from the canonical RFC text.

The RFC renders messages with three inline notations (RFC 4475 section 2):

  * <allOneLine> ... </allOneLine>  concatenate lines, dropping their line breaks
  * <hex>48656C6C6F</hex>           literal octets from hex digits
  * <repeat count=N>abc</repeat>    repeat the enclosed text N times

This script expands all three and emits a single JSON file plus a MoonBit fixture
module. It is deliberately a *transcription* tool: it does not decide whether a
message is valid, it only reproduces the octets the RFC prints. The expected
verdict lives in `expectations.json`, which is reviewed by hand against the prose
in each section, so that the test suite never self-certifies.

Usage:
    python tools/extract_rfc4475.py --rfc rfc4475.txt --out-dir .
"""

import argparse
import json
import re
import sys

PAGE_NOISE = re.compile(
    r"^(Sparks, et al\.|RFC 4475|\[Page \d+\]|Internet Engineering|"
    r"^\s*$)"
)


def strip_page_furniture(lines):
    """Remove RFC page headers/footers so a message split across pages survives."""
    out = []
    for ln in lines:
        s = ln.strip()
        if s.startswith("Sparks, et al."):
            continue
        if s.startswith("RFC 4475") and "Torture" in s:
            continue
        if re.fullmatch(r"\[Page \d+\]", s):
            continue
        out.append(ln)
    return out


def expand(text):
    """Expand <allOneLine>, <hex> and <repeat> into a byte string.

    Returns bytes. Text outside the tags is treated as Latin-1 octets, which is
    what the RFC's ASCII rendering represents.
    """
    # 1. allOneLine: concatenate, dropping the newlines between the tags.
    def allone(m):
        return "".join(m.group(1).splitlines())

    text = re.sub(r"<allOneLine>\s*\n(.*?)\n\s*</allOneLine>", allone, text, flags=re.S)

    # 2. hex: decode to a placeholder we can splice in as raw bytes.
    pieces = []
    pos = 0
    token = re.compile(r"<hex>([0-9A-Fa-f\s]+)</hex>|<repeat\s+count=[\"']?(\d+)[\"']?>(.*?)</repeat>", re.S)
    for m in token.finditer(text):
        pieces.append(("text", text[pos:m.start()]))
        if m.group(1) is not None:
            hx = re.sub(r"\s+", "", m.group(1))
            pieces.append(("bytes", bytes.fromhex(hx)))
        else:
            n = int(m.group(2))
            pieces.append(("bytes", expand(m.group(3)) * n))
        pos = m.end()
    pieces.append(("text", text[pos:]))

    out = b""
    for kind, val in pieces:
        if kind == "text":
            # The RFC prints messages one line per source line; SIP framing is CRLF.
            # Lines were joined with LF by the caller, so every remaining LF is a
            # line break that must become CRLF.
            out += val.replace("\n", "\r\n").encode("latin-1", "replace")
        else:
            out += val
    return out


def extract(rfc_path):
    raw = open(rfc_path, encoding="utf-8").read().replace("\f", "\n")
    lines = raw.split("\n")

    # Locate every "Message Details : id" and the nearest preceding section number.
    entries = []
    section_at = []
    cur_section = None
    sec_re = re.compile(r"^\s*(3(?:\.\d+){1,3})\.\s+\S")
    for idx, ln in enumerate(lines):
        m = sec_re.match(ln)
        if m:
            cur_section = m.group(1)
        section_at.append(cur_section)

    for idx, ln in enumerate(lines):
        m = re.search(r"Message Details\s*:\s*(\S+)", ln)
        if not m:
            continue
        ident = m.group(1)
        section = section_at[idx]
        # Collect the indented block after the marker, tolerating blank lines
        # inside the message (header/body separator).
        body_lines = []
        j = idx + 1
        while j < len(lines):
            ln2 = lines[j]
            s = ln2.strip()
            if s.startswith("Sparks, et al.") or re.fullmatch(r"\[Page \d+\]", s):
                j += 1
                continue
            if s.startswith("RFC 4475") and "Torture" in s:
                j += 1
                continue
            if ln2.startswith("      "):
                body_lines.append(ln2[6:])
                j += 1
            elif s == "":
                # Blank lines may be inside the message; keep collecting but stop
                # once we have seen a non-indented line after them.
                body_lines.append("")
                j += 1
                # Peek: if the next meaningful line is not indented, the message ended.
                k = j
                while k < len(lines):
                    t = lines[k].strip()
                    if (t == "" or t.startswith("Sparks, et al.")
                            or re.fullmatch(r"\[Page \d+\]", t)
                            or (t.startswith("RFC 4475") and "Torture" in t)):
                        k += 1
                        continue
                    break
                if k < len(lines) and not lines[k].startswith("      "):
                    break
            else:
                break
        # Trim leading/trailing blank lines.
        while body_lines and body_lines[0] == "":
            body_lines.pop(0)
        # A trailing blank line is the header/body separator only when no body
        # follows it. When a body is present, the blank line is a page-layout
        # artefact and must not be appended to the message.
        sep = next((i for i, l in enumerate(body_lines) if l == ""), None)
        has_body = sep is not None and any(l != "" for l in body_lines[sep + 1:])
        if has_body:
            while body_lines and body_lines[-1] == "":
                body_lines.pop()
        else:
            while len(body_lines) >= 2 and body_lines[-1] == "" and body_lines[-2] == "":
                body_lines.pop()
        text = "\n".join(body_lines)
        octets = expand(text + "\n")
        entries.append({"id": ident, "section": section, "text": text, "octets": octets})
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rfc", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    entries = extract(args.rfc)
    payload = [
        {"id": e["id"], "section": e["section"], "hex": e["octets"].hex()}
        for e in entries
    ]
    with open(f"{args.out_dir}/rfc4475_vectors.json", "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=1)
    with open(f"{args.out_dir}/rfc4475_vectors.txt", "w", encoding="utf-8") as f:
        for e in entries:
            f.write(f"===== {e['id']}  (section {e['section']})  {len(e['octets'])} octets\n")
            f.write(e["text"])
            f.write("\n")
    print(f"extracted {len(entries)} messages", file=sys.stderr)
    for e in entries:
        print(f"  {e['id']:12s} {e['section']:8s} {len(e['octets']):6d} octets")


if __name__ == "__main__":
    main()
