# ColorNote Backup Decryptor (Python GUI)

A standalone **Python / Tkinter** desktop app that decrypts
[ColorNote](https://www.colornote.com/) Android backup files
(`.backup` / `.dat` / `.doc`) and lets you **browse, search, and export**
your recovered notes — entirely offline, on your own machine.

It is a Python re-implementation of the original Java/Python decoders by
[olejorgenb](https://github.com/olejorgenb/ColorNote-backup-decryptor) and
[fcoiffie](https://github.com/fcoiffie/decode-ColorNote), with a friendly GUI
and a more robust backup parser (see [How it works](#how-it-works)).

> 🔒 **100% offline.** Your password and notes never leave your computer.
> Nothing is uploaded anywhere.

---

## Features

- 🔑 Decrypts ColorNote backups from your PIN/password (default `0000` if you
  never set one).
- 🧩 **Auto-detects the backup format** — handles the modern `NOTE`-magic
  header (offset 28) and the older offset-0 layout automatically, plus a
  resynchronising parser that copes with the large account/sync header some
  exports place before the first note.
- 🔎 Browse notes in a list, full-text **search**, and **hide archived** notes.
- 📅 Shows created / modified dates and archived state.
- 📤 Export everything as **JSON**, **CSV**, or **one `.txt` file per note**.
- 🧾 Skips ColorNote's internal `syncable_settings` / `name_master_password`
  records so you only see real notes.

---

## Requirements

- Python 3.9+
- [`pycryptodome`](https://pypi.org/project/pycryptodome/) (Tkinter ships with
  Python already)

```bash
pip install -r requirements.txt
```

## Usage

```bash
python colornote_gui.py
```

1. Click **Browse…** and select your ColorNote backup file.
2. Enter your backup **password / PIN** (default is `0000` if you never set one).
3. Leave **Auto-detect** selected and click **Decrypt**.
4. Browse / search the notes on the left; click a note to read it on the right.
5. Use the **Export** buttons (or the File menu) to save as JSON, CSV, or
   individual `.txt` files.

> 💡 The core (`colornote_core.py`) has no GUI dependencies, so you can also
> `from colornote_core import decrypt_backup` and use it in your own scripts.

---

## How it works

ColorNote derives an **AES-128-CBC** key + IV from your password using two
chained **MD5** hashes with a fixed salt (`"ColorNote Fixed Salt"`), mirroring
Bouncy Castle's `PBEWITHMD5AND128BITAES-CBC-OPENSSL`.

The decrypted plaintext is a sequence of **length-prefixed records**: a 4-byte
big-endian length followed by that many bytes of UTF-8 JSON. In order:

```
[ account / sync header object ]   ← not a note (client_uuid, auth_token, …)
[ note 0 ][ note 1 ] … [ note N ]  ← your notes (including edit history)
<PKCS7 padding>
```

The tricky part: that leading header object can be **~2 KB**, so the first
note often doesn't start until ~byte 2000 of the plaintext — and the header's
own length prefix lands in the first 16 bytes, which AES-CBC leaves corrupted
(only the first block is affected). Decoders that only look for notes near the
start of the buffer silently find nothing.

This project instead uses a **resynchronising parser**: it walks the plaintext
and accepts a record wherever a 4-byte length prefix *exactly* frames a valid
JSON object, so it locks onto the note stream regardless of how big the header
is. Archived state is read from `active_state == 16`, and note colour from
`color_index`.

---

## Privacy & safety

- Everything runs locally; no network calls are made.
- **Never commit your real data.** This repo's [`.gitignore`](.gitignore)
  excludes `*.backup`, `colornote_notes.*`, and decrypted output so your notes
  (which can contain passwords, bank details, etc.) are never published. Keep
  any exported JSON/CSV somewhere safe, or delete it after use.

## Troubleshooting

**"No notes recovered"**

1. Double-check the password/PIN (this is the most common cause).
2. If you have several backup files, try another one.
3. Try **Manual offset** mode with `0`, `16`, `20`, or `28`.

The diagnostic log in that dialog shows which offsets were tried and a hex
preview of the decrypted bytes — if it looks like readable JSON the password
is right but the format differs; if it's random noise the password is wrong.

---

## Credits

- [olejorgenb/ColorNote-backup-decryptor](https://github.com/olejorgenb/ColorNote-backup-decryptor) — reference decoder (MIT)
- [fcoiffie/decode-ColorNote](https://github.com/fcoiffie/decode-ColorNote) — original reverse-engineering (MIT)

Debugging of the "No notes recovered" bug, the resynchronising parser, and
project packaging were done with help from **Claude** (Anthropic's AI
assistant). See [CONTRIBUTORS.md](CONTRIBUTORS.md) for the full list.

## License

[MIT](LICENSE) — see the LICENSE file, which preserves the original authors'
copyright notices.

> Not affiliated with or endorsed by ColorNote / Social & Mobile, Inc.
