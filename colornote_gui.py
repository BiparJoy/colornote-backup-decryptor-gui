"""
ColorNote Backup Decryptor - GUI

A desktop GUI (Tkinter, ships with Python on Windows/macOS/Linux) for
decrypting ColorNote (colornote.com) Android app backup files and browsing
/ exporting the recovered notes.

Run:
    python colornote_gui.py

Dependencies:
    pip install pycryptodome
"""

from __future__ import annotations

import csv
import json
import os
import re
import sys
import threading
import traceback
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from colornote_core import decrypt_backup, DEFAULT_PASSWORD, Note, DecryptResult

APP_TITLE = "ColorNote Backup Decryptor"


def safe_filename(name: str, fallback: str) -> str:
    name = (name or "").strip() or fallback
    name = re.sub(r'[\\/:*?"<>|]+', "_", name)
    name = name.strip(" .")
    return name[:80] or fallback


class ColorNoteApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1000x650")
        self.minsize(800, 500)

        self.backup_path: str | None = None
        self.result: DecryptResult | None = None
        self.note_items: dict[str, Note] = {}  # treeview item id -> Note

        self._build_menu()
        self._build_widgets()

    # ------------------------------------------------------------------ UI
    def _build_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open backup file...", command=self.browse_file)
        file_menu.add_separator()
        file_menu.add_command(label="Export all notes as JSON...", command=self.export_json)
        file_menu.add_command(label="Export all notes as CSV...", command=self.export_csv)
        file_menu.add_command(label="Export each note as .txt (folder)...", command=self.export_txt_folder)
        file_menu.add_separator()
        file_menu.add_command(label="Save raw decrypted output...", command=self.export_raw)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def _build_widgets(self):
        pad = {"padx": 6, "pady": 4}

        # --- Top controls -------------------------------------------------
        top = ttk.Frame(self)
        top.pack(fill="x", **pad)

        ttk.Label(top, text="Backup file:").grid(row=0, column=0, sticky="w")
        self.file_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.file_var, width=60).grid(row=0, column=1, sticky="we", padx=4)
        ttk.Button(top, text="Browse...", command=self.browse_file).grid(row=0, column=2)

        ttk.Label(top, text="Password / PIN:").grid(row=1, column=0, sticky="w")
        self.password_var = tk.StringVar(value=DEFAULT_PASSWORD)
        pw_entry = ttk.Entry(top, textvariable=self.password_var, width=20, show="*")
        pw_entry.grid(row=1, column=1, sticky="w", padx=4)

        self.show_pw_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            top, text="Show", variable=self.show_pw_var,
            command=lambda: pw_entry.config(show="" if self.show_pw_var.get() else "*")
        ).grid(row=1, column=2, sticky="w")

        ttk.Label(top, text="Offset:").grid(row=2, column=0, sticky="w")
        offset_frame = ttk.Frame(top)
        offset_frame.grid(row=2, column=1, sticky="w")
        self.offset_mode_var = tk.StringVar(value="auto")
        ttk.Radiobutton(offset_frame, text="Auto-detect (recommended)", variable=self.offset_mode_var,
                         value="auto").pack(side="left")
        ttk.Radiobutton(offset_frame, text="Manual:", variable=self.offset_mode_var,
                         value="manual").pack(side="left", padx=(12, 2))
        self.offset_var = tk.StringVar(value="28")
        ttk.Entry(offset_frame, textvariable=self.offset_var, width=6).pack(side="left")

        self.decrypt_btn = ttk.Button(top, text="Decrypt", command=self.start_decrypt)
        self.decrypt_btn.grid(row=1, column=3, rowspan=2, padx=10, sticky="ns")

        top.columnconfigure(1, weight=1)

        # --- Status bar -----------------------------------------------------
        self.status_var = tk.StringVar(value="Pick a ColorNote backup file (.dat / .doc / .backup) to begin.")
        ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w").pack(fill="x", side="bottom")

        # --- Filter row -----------------------------------------------------
        filt = ttk.Frame(self)
        filt.pack(fill="x", **pad)
        ttk.Label(filt, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_list())
        ttk.Entry(filt, textvariable=self.search_var, width=30).pack(side="left", padx=4)
        self.hide_archived_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(filt, text="Hide archived", variable=self.hide_archived_var,
                         command=self.refresh_list).pack(side="left", padx=10)
        self.count_var = tk.StringVar(value="")
        ttk.Label(filt, textvariable=self.count_var).pack(side="right")

        # --- Main split: list + detail --------------------------------------
        main = ttk.Panedwindow(self, orient="horizontal")
        main.pack(fill="both", expand=True, **pad)

        list_frame = ttk.Frame(main)
        columns = ("title", "modified", "created", "archived")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("title", text="Title")
        self.tree.heading("modified", text="Modified")
        self.tree.heading("created", text="Created")
        self.tree.heading("archived", text="Archived")
        self.tree.column("title", width=260)
        self.tree.column("modified", width=140)
        self.tree.column("created", width=140)
        self.tree.column("archived", width=70, anchor="center")
        self.tree.pack(fill="both", expand=True, side="left")
        scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(fill="y", side="right")
        self.tree.bind("<<TreeviewSelect>>", self.on_select_note)
        main.add(list_frame, weight=1)

        detail_frame = ttk.Frame(main)
        self.detail_title_var = tk.StringVar(value="")
        ttk.Label(detail_frame, textvariable=self.detail_title_var, font=("", 12, "bold")).pack(
            anchor="w", padx=6, pady=(6, 0))
        self.detail_meta_var = tk.StringVar(value="")
        ttk.Label(detail_frame, textvariable=self.detail_meta_var, foreground="#555").pack(
            anchor="w", padx=6, pady=(0, 6))
        self.detail_text = tk.Text(detail_frame, wrap="word", undo=False)
        self.detail_text.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.detail_text.configure(state="disabled")
        main.add(detail_frame, weight=2)

        # --- Bottom export bar -----------------------------------------------
        bottom = ttk.Frame(self)
        bottom.pack(fill="x", **pad)
        ttk.Button(bottom, text="Export JSON...", command=self.export_json).pack(side="left")
        ttk.Button(bottom, text="Export CSV...", command=self.export_csv).pack(side="left", padx=6)
        ttk.Button(bottom, text="Export .txt files...", command=self.export_txt_folder).pack(side="left")

    # ------------------------------------------------------------- actions
    def browse_file(self):
        path = filedialog.askopenfilename(
            title="Select ColorNote backup file",
            filetypes=[
                ("ColorNote backups", "*.dat *.doc *.backup *.bak"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.backup_path = path
            self.file_var.set(path)
            self.status_var.set(f"Selected: {path}")

    def start_decrypt(self):
        path = self.file_var.get().strip()
        if not path:
            messagebox.showwarning(APP_TITLE, "Please choose a backup file first.")
            return
        if not os.path.isfile(path):
            messagebox.showerror(APP_TITLE, f"File not found:\n{path}")
            return

        password = self.password_var.get()
        if not password:
            password = DEFAULT_PASSWORD

        manual_offset = None
        if self.offset_mode_var.get() == "manual":
            try:
                manual_offset = int(self.offset_var.get())
            except ValueError:
                messagebox.showerror(APP_TITLE, "Offset must be a whole number.")
                return

        self.decrypt_btn.config(state="disabled")
        self.status_var.set("Decrypting...")
        self.update_idletasks()

        thread = threading.Thread(target=self._decrypt_worker, args=(path, password, manual_offset), daemon=True)
        thread.start()

    def _decrypt_worker(self, path, password, manual_offset):
        try:
            raw_data = Path(path).read_bytes()
            result = decrypt_backup(raw_data, password=password, offset=manual_offset)
        except Exception as e:
            self.after(0, lambda: self._decrypt_failed(e))
            return
        self.after(0, lambda: self._decrypt_done(result))

    def _decrypt_failed(self, exc: Exception):
        self.decrypt_btn.config(state="normal")
        self.status_var.set("Decryption failed.")
        messagebox.showerror(APP_TITLE, f"Unexpected error while decrypting:\n{exc}")
        traceback.print_exc()

    def _decrypt_done(self, result: DecryptResult):
        self.decrypt_btn.config(state="normal")
        self.result = result

        if not result.notes:
            self.status_var.set("No notes could be recovered.")
            detail = (
                "Could not find any readable notes in this file with the given password.\n\n"
                "Things to try:\n"
                "  - Double check the password / PIN (default is 0000 if you never set one).\n"
                "  - If you have several backup files (.dat / .doc / .backup), try another one.\n"
                "  - Try Manual offset mode with values like 0, 16, 20 or 28.\n\n"
                "Diagnostic log:\n" + "\n".join(result.attempts_log)
            )
            messagebox.showwarning(APP_TITLE, "No notes recovered - see details panel.")
            self.detail_title_var.set("No notes recovered")
            self.detail_meta_var.set("")
            self._set_detail_text(detail)
            self.refresh_list()
            return

        msg = f"Recovered {len(result.notes)} note(s) (offset={result.offset_used}, chunk_start={result.chunk_start_used})."
        if result.duplicates_removed:
            msg += f" Removed {result.duplicates_removed} older duplicate version(s)."
        self.status_var.set(msg)
        self.refresh_list()

    # --------------------------------------------------------------- list
    def refresh_list(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.note_items.clear()

        if not self.result:
            self.count_var.set("")
            return

        query = self.search_var.get().strip().lower()
        hide_archived = self.hide_archived_var.get()

        shown = 0
        from datetime import datetime
        for note in sorted(self.result.notes, key=lambda n: n.modified_date or datetime.min, reverse=True):
            if hide_archived and note.archived:
                continue
            if query and query not in note.title.lower() and query not in note.body.lower():
                continue
            item_id = self.tree.insert("", "end", values=(
                note.display_title(),
                note.modified_date.strftime("%Y-%m-%d %H:%M") if note.modified_date else "",
                note.created_date.strftime("%Y-%m-%d %H:%M") if note.created_date else "",
                "Yes" if note.archived else "",
            ))
            self.note_items[item_id] = note
            shown += 1

        self.count_var.set(f"{shown} of {len(self.result.notes)} note(s)")

    def on_select_note(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        note = self.note_items.get(sel[0])
        if not note:
            return
        self.detail_title_var.set(note.display_title())
        meta_bits = []
        if note.created_date:
            meta_bits.append(f"Created: {note.created_date.strftime('%Y-%m-%d %H:%M:%S')}")
        if note.modified_date:
            meta_bits.append(f"Modified: {note.modified_date.strftime('%Y-%m-%d %H:%M:%S')}")
        if note.archived:
            meta_bits.append("Archived")
        self.detail_meta_var.set("   |   ".join(meta_bits))
        self._set_detail_text(note.body)

    def _set_detail_text(self, text: str):
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")

    # ------------------------------------------------------------- export
    def _require_notes(self) -> bool:
        if not self.result or not self.result.notes:
            messagebox.showinfo(APP_TITLE, "Decrypt a backup file with at least one recovered note first.")
            return False
        return True

    def export_json(self):
        if not self._require_notes():
            return
        path = filedialog.asksaveasfilename(
            title="Export notes as JSON", defaultextension=".json",
            filetypes=[("JSON file", "*.json")], initialfile="colornote_notes.json")
        if not path:
            return
        from datetime import datetime
        data = [n.raw for n in sorted(self.result.notes, key=lambda n: n.modified_date or datetime.min)]
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2, default=str)
            self.status_var.set(f"Exported {len(data)} note(s) to {path}")
            messagebox.showinfo(APP_TITLE, f"Exported {len(data)} note(s) to:\n{path}")
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Could not write file:\n{e}")

    def export_csv(self):
        if not self._require_notes():
            return
        path = filedialog.asksaveasfilename(
            title="Export notes as CSV", defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")], initialfile="colornote_notes.csv")
        if not path:
            return
        from datetime import datetime
        try:
            with open(path, "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["title", "note", "created_date", "modified_date", "archived", "uuid"])
                for n in sorted(self.result.notes, key=lambda n: n.modified_date or datetime.min):
                    writer.writerow([
                        n.title,
                        n.body,
                        n.created_date.isoformat() if n.created_date else "",
                        n.modified_date.isoformat() if n.modified_date else "",
                        "yes" if n.archived else "",
                        n.uuid or "",
                    ])
            self.status_var.set(f"Exported {len(self.result.notes)} note(s) to {path}")
            messagebox.showinfo(APP_TITLE, f"Exported {len(self.result.notes)} note(s) to:\n{path}")
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Could not write file:\n{e}")

    def export_txt_folder(self):
        if not self._require_notes():
            return
        folder = filedialog.askdirectory(title="Choose a folder to save one .txt file per note")
        if not folder:
            return
        from datetime import datetime
        used_names = set()
        count = 0
        try:
            for i, n in enumerate(sorted(self.result.notes, key=lambda n: n.modified_date or datetime.min)):
                base = safe_filename(n.display_title(), f"note_{i}")
                name = base
                suffix = 1
                while name in used_names:
                    suffix += 1
                    name = f"{base}_{suffix}"
                used_names.add(name)
                out_path = Path(folder) / f"{name}.txt"
                lines = []
                if n.title:
                    lines.append(n.title)
                    lines.append("-" * len(n.title))
                if n.created_date:
                    lines.append(f"Created:  {n.created_date.strftime('%Y-%m-%d %H:%M:%S')}")
                if n.modified_date:
                    lines.append(f"Modified: {n.modified_date.strftime('%Y-%m-%d %H:%M:%S')}")
                lines.append("")
                lines.append(n.body)
                out_path.write_text("\n".join(lines), encoding="utf-8")
                count += 1
            self.status_var.set(f"Exported {count} .txt file(s) to {folder}")
            messagebox.showinfo(APP_TITLE, f"Exported {count} .txt file(s) to:\n{folder}")
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Could not write files:\n{e}")

    def export_raw(self):
        if not self.result or not self.result.raw_plaintext:
            messagebox.showinfo(APP_TITLE, "Nothing to save yet - decrypt a file first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save raw decrypted bytes", defaultextension=".bin",
            filetypes=[("Binary file", "*.bin"), ("All files", "*.*")], initialfile="decrypted_raw.bin")
        if not path:
            return
        try:
            Path(path).write_bytes(self.result.raw_plaintext)
            messagebox.showinfo(APP_TITLE, f"Saved raw decrypted bytes to:\n{path}")
        except OSError as e:
            messagebox.showerror(APP_TITLE, f"Could not write file:\n{e}")

    def show_about(self):
        messagebox.showinfo(
            APP_TITLE,
            "ColorNote Backup Decryptor\n\n"
            "A standalone Python/Tkinter GUI for decrypting ColorNote Android "
            "app backup files (.dat / .doc / .backup), based on the original "
            "ColorNote-backup-decryptor project by olejorgenb.\n\n"
            "Your password and notes are processed entirely on your own "
            "computer - nothing is uploaded anywhere."
        )


def main():
    try:
        import Crypto  # noqa: F401
    except ImportError:
        print("Missing dependency 'pycryptodome'. Install it with:\n    pip install pycryptodome")
        sys.exit(1)

    app = ColorNoteApp()
    app.mainloop()


if __name__ == "__main__":
    main()
