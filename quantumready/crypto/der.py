"""A small, strict DER reader.

This parses data supplied by whatever host we happen to be scanning, so it
is written defensively: every length is bounds-checked against the buffer,
recursion is capped, and indefinite-length encodings (legal in BER, not in
DER) are rejected rather than guessed at. Malformed input raises
:class:`DERError`; it never over-reads or loops forever.
"""

from __future__ import annotations

import datetime as _dt
from typing import Iterator, List, Optional

MAX_DEPTH = 40

# Universal tag numbers we care about.
BOOLEAN = 0x01
INTEGER = 0x02
BIT_STRING = 0x03
OCTET_STRING = 0x04
NULL = 0x05
OBJECT_IDENTIFIER = 0x06
UTF8_STRING = 0x0C
SEQUENCE = 0x10
SET = 0x11
PRINTABLE_STRING = 0x13
T61_STRING = 0x14
IA5_STRING = 0x16
UTC_TIME = 0x17
GENERALIZED_TIME = 0x18
UNIVERSAL_STRING = 0x1C
BMP_STRING = 0x1E

_TEXT_TAGS = frozenset(
    {UTF8_STRING, PRINTABLE_STRING, T61_STRING, IA5_STRING, UNIVERSAL_STRING, BMP_STRING}
)

CLASS_UNIVERSAL = 0
CLASS_APPLICATION = 1
CLASS_CONTEXT = 2
CLASS_PRIVATE = 3


class DERError(ValueError):
    """Raised when input is not well-formed DER."""


class Node:
    """One TLV triple, with its raw bytes retained for hashing."""

    __slots__ = ("tag", "tag_class", "constructed", "content", "raw", "depth", "_children")

    def __init__(
        self,
        tag: int,
        tag_class: int,
        constructed: bool,
        content: bytes,
        raw: bytes,
        depth: int = 0,
    ) -> None:
        self.tag = tag
        self.tag_class = tag_class
        self.constructed = constructed
        self.content = content
        self.raw = raw
        # Retained so that any later parsing continues counting from here
        # rather than restarting, which would let deep nesting slip past
        # the recursion guard.
        self.depth = depth
        self._children: Optional[List["Node"]] = None

    # -- structure ---------------------------------------------------------

    @property
    def children(self) -> List["Node"]:
        """Sub-nodes of a constructed value (empty for primitives)."""
        if self._children is None:
            self._children = (
                list(_parse_all(self.content, self.depth + 1)) if self.constructed else []
            )
        return self._children

    def __getitem__(self, index: int) -> "Node":
        try:
            return self.children[index]
        except IndexError as exc:
            raise DERError(f"expected at least {index + 1} elements") from exc

    def __len__(self) -> int:
        return len(self.children)

    def __iter__(self) -> Iterator["Node"]:
        return iter(self.children)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        kind = {0: "univ", 1: "app", 2: "ctx", 3: "priv"}[self.tag_class]
        return f"<Node {kind} tag={self.tag} len={len(self.content)}>"

    def is_context(self, tag: int) -> bool:
        return self.tag_class == CLASS_CONTEXT and self.tag == tag

    # -- typed accessors ---------------------------------------------------

    def as_int(self) -> int:
        """Signed big-endian INTEGER."""
        if not self.content:
            raise DERError("empty INTEGER")
        return int.from_bytes(self.content, "big", signed=True)

    def as_bool(self) -> bool:
        if len(self.content) != 1:
            raise DERError("BOOLEAN must be one byte")
        return self.content[0] != 0

    def as_oid(self) -> str:
        return decode_oid(self.content)

    def as_text(self) -> str:
        """Decode a character string, tolerating the legacy encodings."""
        data = self.content
        if self.tag == BMP_STRING:
            return data.decode("utf-16-be", errors="replace")
        if self.tag == UNIVERSAL_STRING:
            return data.decode("utf-32-be", errors="replace")
        if self.tag == T61_STRING:
            # T.61 is effectively dead; latin-1 recovers real-world content.
            return data.decode("latin-1", errors="replace")
        return data.decode("utf-8", errors="replace")

    def as_bit_string(self) -> bytes:
        """BIT STRING payload with the unused-bit count stripped."""
        if not self.content:
            raise DERError("empty BIT STRING")
        unused = self.content[0]
        if unused > 7:
            raise DERError("BIT STRING unused-bit count out of range")
        return self.content[1:]

    def bit_string_flags(self) -> List[bool]:
        """BIT STRING expanded to a list of bits, most significant first."""
        if not self.content:
            return []
        unused = self.content[0]
        if unused > 7:
            raise DERError("BIT STRING unused-bit count out of range")
        body = self.content[1:]
        bits = [(byte >> (7 - i)) & 1 == 1 for byte in body for i in range(8)]
        return bits[: len(bits) - unused] if unused else bits

    def as_datetime(self) -> _dt.datetime:
        return decode_time(self.tag, self.content)


def _read_length(data: bytes, pos: int) -> tuple:
    """Return ``(length, next_position)``, rejecting BER-only encodings."""
    if pos >= len(data):
        raise DERError("truncated length")
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    if first == 0x80:
        raise DERError("indefinite-length encoding is not valid DER")
    count = first & 0x7F
    if count > 8:
        raise DERError("length field too large")
    if pos + count > len(data):
        raise DERError("truncated long-form length")
    length = int.from_bytes(data[pos : pos + count], "big")
    return length, pos + count


def _parse_one(data: bytes, pos: int, depth: int) -> tuple:
    """Parse a single TLV at ``pos``. Returns ``(node, next_position)``."""
    if depth > MAX_DEPTH:
        raise DERError("nesting too deep")
    if pos >= len(data):
        raise DERError("truncated tag")
    start = pos
    identifier = data[pos]
    tag_class = (identifier >> 6) & 0x03
    constructed = bool(identifier & 0x20)
    tag = identifier & 0x1F
    pos += 1

    if tag == 0x1F:  # high-tag-number form, base-128 continuation
        tag = 0
        for _ in range(4):
            if pos >= len(data):
                raise DERError("truncated high-form tag")
            byte = data[pos]
            pos += 1
            tag = (tag << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
        else:
            raise DERError("high-form tag too long")

    length, pos = _read_length(data, pos)
    end = pos + length
    if end > len(data) or end < pos:
        raise DERError("declared length exceeds buffer")

    node = Node(tag, tag_class, constructed, data[pos:end], data[start:end], depth)
    # Children are parsed eagerly so that a hostile structure is rejected
    # here, at a known depth, rather than at some later attribute access.
    if constructed:
        node._children = list(_parse_all(node.content, depth + 1))
    return node, end


def _parse_all(data: bytes, depth: int) -> Iterator[Node]:
    pos = 0
    while pos < len(data):
        node, pos = _parse_one(data, pos, depth)
        yield node


def parse(data: bytes) -> Node:
    """Parse one DER value, which must consume the whole buffer."""
    if not data:
        raise DERError("no data")
    node, end = _parse_one(data, 0, 0)
    if end != len(data):
        raise DERError(f"{len(data) - end} trailing byte(s) after top-level value")
    return node


def decode_oid(data: bytes) -> str:
    """Decode OBJECT IDENTIFIER contents to dotted-decimal."""
    if not data:
        raise DERError("empty OID")
    first = data[0]
    # The first two arcs share a byte: 40*arc1 + arc2, with arc1 capped at 2.
    if first < 80:
        arcs = [first // 40, first % 40]
    else:
        arcs = [2, first - 80]
    value = 0
    started = False
    for byte in data[1:]:
        if not started and byte == 0x80:
            raise DERError("non-minimal OID arc encoding")
        value = (value << 7) | (byte & 0x7F)
        started = True
        if not byte & 0x80:
            arcs.append(value)
            value = 0
            started = False
    if started:
        raise DERError("truncated OID arc")
    return ".".join(str(a) for a in arcs)


def decode_time(tag: int, data: bytes) -> _dt.datetime:
    """Decode UTCTime or GeneralizedTime to an aware UTC datetime."""
    text = data.decode("ascii", errors="replace").strip()
    if tag == UTC_TIME:
        # Two-digit years: the RFC 5280 sliding window puts 50-99 in the
        # 1900s and 00-49 in the 2000s.
        if len(text) < 11:
            raise DERError(f"malformed UTCTime {text!r}")
        year = int(text[0:2])
        year += 1900 if year >= 50 else 2000
        rest = text[2:]
    elif tag == GENERALIZED_TIME:
        if len(text) < 10:
            raise DERError(f"malformed GeneralizedTime {text!r}")
        year = int(text[0:4])
        rest = text[4:]
    else:
        raise DERError(f"tag {tag} is not a time type")

    body = rest.rstrip("Z")
    offset_minutes = 0
    for sign in ("+", "-"):
        idx = body.find(sign)
        if idx > 0:
            zone = body[idx + 1 :]
            body = body[:idx]
            if len(zone) >= 4:
                offset_minutes = int(zone[0:2]) * 60 + int(zone[2:4])
            elif len(zone) >= 2:
                offset_minutes = int(zone[0:2]) * 60
            if sign == "-":
                offset_minutes = -offset_minutes
            break
    body = body.split(".")[0]  # drop fractional seconds

    try:
        month, day, hour = int(body[0:2]), int(body[2:4]), int(body[4:6])
        minute = int(body[6:8]) if len(body) >= 8 else 0
        second = int(body[8:10]) if len(body) >= 10 else 0
        stamp = _dt.datetime(
            year, month, day, hour, minute, min(second, 59), tzinfo=_dt.timezone.utc
        )
    except (ValueError, IndexError) as exc:
        raise DERError(f"malformed time {text!r}") from exc
    return stamp - _dt.timedelta(minutes=offset_minutes)


def pem_to_der(text: str) -> List[bytes]:
    """Extract every DER block from PEM text."""
    import base64

    blocks: List[bytes] = []
    body: List[str] = []
    inside = False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("-----BEGIN"):
            inside, body = True, []
        elif line.startswith("-----END"):
            if inside and body:
                try:
                    # validate=True so a corrupted block is reported rather
                    # than silently decoding to whatever survives filtering.
                    blocks.append(base64.b64decode("".join(body), validate=True))
                except Exception as exc:  # noqa: BLE001 - report, don't crash
                    raise DERError(f"invalid base64 in PEM block: {exc}") from exc
            inside = False
        elif inside:
            body.append(line)
    return blocks
