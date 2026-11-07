"""Small, dependency-free .env parser and line editor.

Supports: KEY=value, `export KEY=value`, comments, single quotes (literal),
double quotes (with \\n \\t \\" \\\\ escapes, may span lines) and inline `# comments`
after unquoted values. Variable expansion is intentionally NOT performed.
"""
from __future__ import annotations

import re

_KEY = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*)$")
_ESC = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "$": "$"}


class DotenvError(ValueError):
    pass


def _unescape(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in _ESC:
            out.append(_ESC[s[i + 1]])
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _find_close(s: str, q: str) -> int:
    i = 0
    while i < len(s):
        if q == '"' and s[i] == "\\":
            i += 2
            continue
        if s[i] == q:
            return i
        i += 1
    return -1


def parse(text: str) -> dict[str, str]:
    """Parse .env text into an ordered dict. Later keys win, like most loaders."""
    env: dict[str, str] = {}
    lines = text.replace("\r\n", "\n").split("\n")
    n = 0
    while n < len(lines):
        line = lines[n]
        n += 1
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _KEY.match(line)
        if not m:
            raise DotenvError(f"line {n}: expected KEY=value, got {line.strip()[:40]!r}")
        key, rest = m.group(1), m.group(2)
        if rest[:1] in ("'", '"'):
            q = rest[0]
            body = rest[1:]
            start = n
            end = _find_close(body, q)
            while end < 0 and n < len(lines):
                body += "\n" + lines[n]
                n += 1
                end = _find_close(body, q)
            if end < 0:
                raise DotenvError(f"line {start}: unterminated {q} quote for {key}")
            val = body[:end]
            env[key] = _unescape(val) if q == '"' else val
        else:
            val = re.split(r"\s+#", rest, maxsplit=1)[0].strip()
            env[key] = val
    return env


def quote(value: str) -> str:
    if value and re.fullmatch(r"[A-Za-z0-9_./:@%+,\-=]*", value):
        return value
    v = value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{v}"'


def set_key(text: str, key: str, value: str) -> str:
    """Return text with KEY set to value, replacing the existing line(s) or appending."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\-]*", key):
        raise DotenvError(f"invalid key name {key!r}")
    new = f"{key}={quote(value)}"
    out, done = [], False
    lines = text.replace("\r\n", "\n").split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _KEY.match(line)
        if m and m.group(1) == key and not line.lstrip().startswith("#"):
            # skip continuation lines of a multi-line quoted value
            rest = m.group(2)
            if rest[:1] in ("'", '"'):
                body = rest[1:]
                while _find_close(body, rest[0]) < 0 and i + 1 < len(lines):
                    i += 1
                    body += "\n" + lines[i]
            if not done:
                out.append(new)
                done = True
        else:
            out.append(line)
        i += 1
    if not done:
        while out and out[-1] == "":
            out.pop()
        out.append(new)
        out.append("")
    return "\n".join(out)


def unset_key(text: str, key: str) -> str:
    out = []
    for line in text.replace("\r\n", "\n").split("\n"):
        m = _KEY.match(line)
        if m and m.group(1) == key and not line.lstrip().startswith("#"):
            continue
        out.append(line)
    return "\n".join(out)
