"""
colornote_core.py

Core logic for decrypting ColorNote (colornote.com) Android app backup files
(.dat / .doc / .backup files).

Re-implemented in Python from the original Java project:
    https://github.com/olejorgenb/ColorNote-backup-decryptor

Algorithm summary
------------------
1. ColorNote derives a 128-bit AES key + 16-byte IV from a user PIN/password
   using a fixed salt ("ColorNote Fixed Salt") and two MD5 hashes
   (this mirrors Bouncy Castle's PBEWITHMD5AND128BITAES-CBC-OPENSSL /
   OpenSSLPBEParametersGenerator, used with an iteration count that turns
   out not to matter for the final key/iv).
2. Some backup formats prefix the file with a number of raw (non-encrypted)
   "magic" bytes before the AES-CBC ciphertext begins. The common modern
   format starts with the UTF-16BE magic "NOTE" and a 28-byte header, so the
   ciphertext begins at offset 28; other versions use 0. We auto-detect.
3. The decrypted plaintext is a sequence of length-prefixed binary records,
   each being a 4-byte big-endian length followed by that many bytes of
   UTF-8 JSON. The records are, in order:
       [account/sync header object]  <- NOT a note (client_uuid, auth_token...)
       [note 0][note 1]...[note N]   <- the actual notes (incl. edit history)
   The header object can be ~2 KB, and its own length prefix falls inside the
   first 16 plaintext bytes, which AES-CBC leaves corrupted (only the *first*
   block is affected by the header offset). For that reason we DON'T try to
   parse from a small fixed start index. Instead we resynchronise: walk the
   buffer and accept a record wherever a 4-byte length prefix exactly frames a
   valid UTF-8 JSON object. This is robust to any preamble size and to the
   corrupted first block. PKCS7 padding at the tail simply fails to frame any
   JSON, so parsing stops cleanly.

Public API (used by colornote_gui.py):
    derive_key_iv(password)        -> (key, iv)
    decrypt_backup(raw, password)  -> DecryptResult
    Note, DecryptResult, DEFAULT_PASSWORD
    hex_preview(data)              -> str   (diagnostic dump)
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Hash import MD5

COLORNOTE_SALT = b"ColorNote Fixed Salt"
DEFAULT_PASSWORD = "0000"

# Candidate raw-byte offsets to skip before the AES ciphertext starts.
# The known versions use 0 (older) and 28 (the "NOTE" magic-header format).
# We try those first, then scan the rest of 0..63 for any unusual variant.
# Trying known-good offsets first means the canonical offset wins ties (every
# offset that is a multiple of 16 away from the true start also decrypts the
# body correctly, thanks to CBC self-synchronisation).
_PRIORITISED = [0, 28, 16, 20, 24]
CANDIDATE_OFFSETS = _PRIORITISED + [x for x in range(64) if x not in _PRIORITISED]

# Minimum plausible length of a length-prefixed JSON record. Guards against a
# 4-byte prefix of 0/1 matching trivially.
_MIN_RECORD_LEN = 2

# Keys that reliably identify a real ColorNote note record (every note has a
# "uuid"; most have these too). Used to separate genuine note records from any
# other JSON that might appear in the stream.
EXPECTED_NOTE_KEYS = {
    "uuid", "title", "note", "created_date", "modified_date",
    "minor_modified_date", "space", "active_state", "color_index", "type",
}

# Records ColorNote stores in the notes stream that are app *settings*, not
# user notes. They have type == 256 and/or these reserved titles.
SYSTEM_NOTE_TITLES = {"syncable_settings", "name_master_password"}
SYSTEM_NOTE_TYPE = 256

# ColorNote "active_state" values we understand.
STATE_ARCHIVED = 16


class DecryptError(Exception):
    pass


def derive_key_iv(password: str, salt: bytes = COLORNOTE_SALT) -> tuple[bytes, bytes]:
    """Derive the AES-128 key and IV ColorNote uses for a given PIN/password."""
    pw = password.encode("utf-8")
    h1 = MD5.new()
    h1.update(pw)
    h1.update(salt)
    key = h1.digest()

    h2 = MD5.new()
    h2.update(key)
    h2.update(pw)
    h2.update(salt)
    iv = h2.digest()

    return key, iv


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Truncate to a multiple of the block size defensively - the raw backup
    # commonly has a few trailing bytes that aren't part of a full AES block.
    usable_len = (len(ciphertext) // 16) * 16
    if usable_len == 0:
        raise DecryptError("Not enough data to decrypt (file too short for this offset).")
    return cipher.decrypt(ciphertext[:usable_len])


def _extract_records(decoded: bytes) -> list[tuple[int, dict]]:
    """Resynchronising parser for length-prefixed JSON records.

    Walks `decoded`; wherever a 4-byte big-endian length L exactly frames a
    valid UTF-8 JSON object (`decoded[i+4 : i+4+L]` parses and starts with
    '{' / ends with '}'), that object is accepted and we jump to the end of
    it; otherwise we advance one byte and try again.

    This locks straight onto the note stream regardless of how large the
    leading account/sync header is, and regardless of the corrupted first
    block - so it fixes the original "only searched the first 64 bytes" bug.

    Returns a list of (start_index, json_object).
    """
    records: list[tuple[int, dict]] = []
    n = len(decoded)
    i = 0
    while i + 4 <= n:
        (length,) = struct.unpack(">L", decoded[i:i + 4])
        if _MIN_RECORD_LEN <= length <= n - (i + 4):
            chunk = decoded[i + 4: i + 4 + length]
            if chunk[:1] == b"{" and chunk[-1:] == b"}":
                try:
                    obj = json.loads(chunk.decode("utf-8"))
                except Exception:
                    obj = None
                if isinstance(obj, dict):
                    records.append((i, obj))
                    i += 4 + length
                    continue
        i += 1
    return records


def parse_chunks(decoded: bytes, start_idx: int = 0) -> list[dict]:
    """Backwards-compatible helper: return the note JSON objects found in
    `decoded`. `start_idx` is accepted for API compatibility but the parser
    resynchronises automatically, so callers no longer need to guess it."""
    region = decoded[start_idx:] if start_idx else decoded
    return [obj for _, obj in _extract_records(region)
            if set(obj.keys()) & EXPECTED_NOTE_KEYS]


@dataclass
class Note:
    raw: dict
    uuid: Optional[str] = None
    title: str = ""
    body: str = ""
    created_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    minor_modified_date: Optional[datetime] = None
    archived: bool = False
    trashed: bool = False
    color: Optional[int] = None
    note_type: Optional[int] = None
    is_system: bool = False

    @staticmethod
    def _to_dt(ms) -> Optional[datetime]:
        if ms is None:
            return None
        try:
            return datetime.fromtimestamp(int(ms) / 1000.0)
        except (ValueError, OSError, OverflowError):
            return None

    @classmethod
    def from_json(cls, obj: dict) -> "Note":
        title = obj.get("title") or ""
        active_state = obj.get("active_state")
        note_type = obj.get("type")
        is_system = (note_type == SYSTEM_NOTE_TYPE) or (title in SYSTEM_NOTE_TITLES)
        return cls(
            raw=obj,
            uuid=obj.get("uuid"),
            title=title,
            body=obj.get("note") or "",
            created_date=cls._to_dt(obj.get("created_date")),
            modified_date=cls._to_dt(obj.get("modified_date")),
            minor_modified_date=cls._to_dt(obj.get("minor_modified_date")),
            # Archive in ColorNote is encoded in active_state (NOT space).
            archived=(active_state == STATE_ARCHIVED),
            trashed=bool(obj.get("trash") or obj.get("is_deleted")),
            # Modern backups use "color_index"; fall back to legacy "color".
            color=obj.get("color_index", obj.get("color")),
            note_type=note_type,
            is_system=is_system,
        )

    def display_title(self) -> str:
        if self.title.strip():
            return self.title.strip()
        first_line = self.body.strip().splitlines()[0] if self.body.strip() else ""
        return first_line[:60] if first_line else "(untitled)"


@dataclass
class DecryptResult:
    notes: list[Note]
    offset_used: int
    chunk_start_used: int          # byte index of the first note record found
    raw_plaintext: bytes
    duplicates_removed: int = 0
    system_records_removed: int = 0
    attempts_log: list[str] = field(default_factory=list)


def _dedupe_notes(notes: list[Note]) -> list[Note]:
    """Keep only the most-recently-modified version of each uuid, matching
    the behaviour of the reference decoder (duplicate chunks in the backup
    represent a note's edit history)."""
    by_uuid: dict[str, Note] = {}
    no_uuid: list[Note] = []
    for note in notes:
        if not note.uuid:
            no_uuid.append(note)
            continue
        existing = by_uuid.get(note.uuid)
        if existing is None:
            by_uuid[note.uuid] = note
        else:
            existing_key = existing.minor_modified_date or existing.modified_date
            new_key = note.minor_modified_date or note.modified_date
            if existing_key is None or (new_key is not None and new_key >= existing_key):
                by_uuid[note.uuid] = note

    result = list(by_uuid.values()) + no_uuid
    result.sort(key=lambda n: n.modified_date or datetime.min)
    return result


def hex_preview(data: bytes, length: int = 96) -> str:
    """Return a readable hex+ASCII dump of the first `length` bytes, for
    manual diagnosis when auto-detection can't find any notes."""
    chunk = data[:length]
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def _notes_from_plaintext(plaintext: bytes) -> tuple[list[Note], int, int]:
    """Extract user notes from one decrypted plaintext.

    Returns (user_notes, first_record_index, system_records_removed).
    System/settings records are separated out (they aren't user notes)."""
    records = _extract_records(plaintext)
    first_idx = records[0][0] if records else -1

    notes_all = [Note.from_json(obj) for _, obj in records
                 if set(obj.keys()) & EXPECTED_NOTE_KEYS]
    user_notes = [n for n in notes_all if not n.is_system]
    system_removed = len(notes_all) - len(user_notes)
    return user_notes, first_idx, system_removed


def decrypt_backup(
    raw_data: bytes,
    password: str = DEFAULT_PASSWORD,
    offset: Optional[int] = None,
    chunk_start: Optional[int] = None,   # accepted for API compat; unused
) -> DecryptResult:
    """Decrypt a ColorNote backup file's raw bytes and parse out notes.

    If `offset` is None, each candidate raw-byte offset is tried and the one
    that yields the most note records wins. Pass an explicit `offset` to skip
    the search. `chunk_start` is ignored (the parser resynchronises itself).
    """
    key, iv = derive_key_iv(password)

    offsets_to_try = [offset] if offset is not None else CANDIDATE_OFFSETS

    best: Optional[DecryptResult] = None
    log: list[str] = []
    offsets_attempted = 0
    first_plaintext: Optional[bytes] = None
    first_plaintext_offset: Optional[int] = None

    for off in offsets_to_try:
        if off is None or off < 0 or off >= len(raw_data):
            continue
        try:
            plaintext = aes_cbc_decrypt(raw_data[off:], key, iv)
        except DecryptError:
            continue
        offsets_attempted += 1

        if first_plaintext is None:
            first_plaintext = plaintext
            first_plaintext_offset = off

        user_notes, first_idx, system_removed = _notes_from_plaintext(plaintext)
        if user_notes:
            log.append(
                f"offset {off}: found {len(user_notes)} note record(s) "
                f"(first record at plaintext byte {first_idx}, "
                f"{system_removed} settings record(s) skipped)"
            )
        if user_notes and (best is None or len(user_notes) > len(best.notes)):
            deduped = _dedupe_notes(user_notes)
            best = DecryptResult(
                notes=deduped,
                offset_used=off,
                chunk_start_used=first_idx,
                raw_plaintext=plaintext,
                duplicates_removed=len(user_notes) - len(deduped),
                system_records_removed=system_removed,
                attempts_log=log,
            )

    if best is None:
        log.insert(0, f"Tried {offsets_attempted} offset(s); none yielded any note records.")
        diag_plaintext = b""
        if first_plaintext is not None:
            log.append("")
            log.append(
                f"Hex preview of decrypted bytes at offset {first_plaintext_offset} "
                f"(if this looks like readable text/JSON the password is right but "
                f"the format differs; if it's random noise the password is wrong):"
            )
            log.append(hex_preview(first_plaintext))
            diag_plaintext = first_plaintext
        best = DecryptResult(notes=[], offset_used=-1, chunk_start_used=-1,
                             raw_plaintext=diag_plaintext, attempts_log=log)
    else:
        best.attempts_log = log

    return best


# (resync length-prefix parser; see module docstring for format details)
