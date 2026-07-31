"""Server-side knowledge ingestion CLI.

Upload documents into the RAG knowledge base directly from the server's
filesystem — no browser required. Useful when the browser upload is blocked by
policy, or for bulk-loading a whole folder of organisation documents.

It reuses the exact same pipeline as the web UI:
  local text extraction (changeplan.extract_text) -> knowledge.ingest / store_local

Supported files: text/markdown/log/csv/json/yaml/ini/conf/xml/rtf, PDF (with OCR
fallback for scans), Word (.docx/.doc), Excel (.xlsx/.xls) and PowerPoint (.pptx).

Examples
--------
  # activate the app venv and cd to the app dir first, e.g.
  #   cd /opt/ai-troubleshooter/src/troubleshooter
  #   source /opt/ai-troubleshooter/venv/bin/activate

  # one file (AI classifies it into Server -> OS -> category)
  python -m app.kb_ingest /root/docs/BIALSRV-GENCL2-runbook.pdf

  # a whole folder, recursively
  python -m app.kb_ingest /root/org-knowledge/

  # bulk-load WITHOUT any AI call (you supply the taxonomy yourself)
  python -m app.kb_ingest --local --server BIALSRV-GENCL2 --os linux \\
      --category runbook /root/docs/gencl2/

  # see what would be ingested, but store nothing
  python -m app.kb_ingest --dry-run /root/org-knowledge/

Note: the default (AI-classified) mode calls the Claude API for smart indexing,
so the same proxy/network env the service uses must be present. `--local` needs
no network at all.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from . import changeplan, db, knowledge

# extensions changeplan.extract_text knows how to read
_SUPPORTED = (
    ".txt", ".md", ".markdown", ".log", ".csv", ".tsv", ".json", ".yaml", ".yml",
    ".ini", ".conf", ".xml", ".rtf", ".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx",
)


def _iter_files(paths: list[str], recursive: bool) -> list[Path]:
    out: list[Path] = []
    for raw in paths:
        p = Path(raw).expanduser()
        if p.is_dir():
            it = p.rglob("*") if recursive else p.glob("*")
            out.extend(sorted(f for f in it if f.is_file()))
        elif p.is_file():
            out.append(p)
        else:
            print(f"  ! not found: {p}", file=sys.stderr)
    # keep only readable/supported types
    return [f for f in out if f.suffix.lower() in _SUPPORTED]


async def _ingest_one(path: Path, args) -> dict:
    data = path.read_bytes()
    if len(data) > args.max_mb * 1_000_000:
        return {"ok": False, "error": f"skipped — larger than {args.max_mb} MB"}
    try:
        text = await asyncio.to_thread(changeplan.extract_text, path.name, data)
    except RuntimeError as exc:                 # missing extractor lib / system tool
        return {"ok": False, "error": str(exc)}
    if len((text or "").strip()) < 3:
        return {"ok": False, "error": "no readable text"}

    if args.local:
        title = args.title or path.stem
        doc_id = await knowledge.store_local(
            text, server=args.server, os_=args.os, category=args.category,
            title=title, source_type="upload")
        return {"ok": True, "local": True, "id": doc_id, "title": title,
                "server": args.server or "General", "category": args.category}

    res = await knowledge.ingest(text, title_hint=args.title or path.name,
                                 source_type="upload", filename=path.name,
                                 actor=args.actor)
    return res


async def _run(args) -> int:
    await asyncio.to_thread(db.init_db)         # ensure the KB tables/FTS exist
    files = _iter_files(args.paths, args.recursive)
    if not files:
        print("Nothing to ingest (no supported files found).", file=sys.stderr)
        return 1
    print(f"Found {len(files)} file(s) to process"
          + (" [DRY RUN]" if args.dry_run else "")
          + (" [LOCAL, no AI]" if args.local else " [AI-classified]") + "\n")

    ok = dup = fail = 0
    for f in files:
        if args.dry_run:
            print(f"  · would ingest {f}")
            continue
        try:
            res = await _ingest_one(f, args)
        except Exception as exc:                # noqa: BLE001
            res = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        if not res.get("ok"):
            fail += 1
            print(f"  ✕ {f.name}: {res.get('error')}")
        elif res.get("duplicate"):
            dup += 1
            print(f"  = {f.name}: already in KB (skipped)")
        else:
            ok += 1
            doc = res.get("doc") or res
            where = " → ".join(x for x in [doc.get("server") or "General",
                                           doc.get("os") or None,
                                           doc.get("category")] if x)
            print(f"  ✓ {f.name} → {where}  “{doc.get('title')}”")

    if not args.dry_run:
        print(f"\nDone: {ok} stored, {dup} duplicate(s), {fail} failed.")
    return 0 if fail == 0 else 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m app.kb_ingest",
        description="Ingest documents into the RAG knowledge base from the server.")
    ap.add_argument("paths", nargs="+", help="files and/or directories to ingest")
    ap.add_argument("-r", "--recursive", action="store_true", default=True,
                    help="recurse into directories (default: on)")
    ap.add_argument("--no-recursive", dest="recursive", action="store_false",
                    help="do not recurse into subdirectories")
    ap.add_argument("--local", action="store_true",
                    help="store WITHOUT any AI call (needs --server/--os/--category)")
    ap.add_argument("--server", default="", help="[--local] server this doc is about")
    ap.add_argument("--os", default="", help="[--local] os layer, e.g. linux / windows")
    ap.add_argument("--category", default="manual",
                    help="[--local] category (default: manual)")
    ap.add_argument("--title", default="", help="override the document title")
    ap.add_argument("--actor", default="cli", help="who is uploading (audit label)")
    ap.add_argument("--max-mb", type=float, default=25.0,
                    help="skip files larger than this many MB (default: 25)")
    ap.add_argument("--dry-run", action="store_true",
                    help="list what would be ingested, store nothing")
    args = ap.parse_args(argv)

    if args.local and not (args.server or args.category):
        ap.error("--local needs at least --server or --category so the entry is filed correctly")
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
