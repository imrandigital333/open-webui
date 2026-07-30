"""Knowledge base (RAG) for the platform.

Operators upload design documents, server configuration and free-form notes;
each is classified by Haiku into a smart taxonomy — Server → OS → category
(network / application / process / kb_article / config / design / manual) — and
stored as searchable chunks in SQLite (see db.kb_* tables). A lexical retriever
surfaces the most relevant chunks for a query (optionally scoped to one server),
and a chat assistant can either LEARN (store what you tell it) or ANSWER
(retrieve + Haiku). All Haiku token usage is metered.

No external embedding service is required — retrieval is lexical (works
offline / air-gapped); Haiku adds the smart classification and answering.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
import uuid

from . import db
from .changeplan import extract_text  # reuse the txt/md/docx/pdf extractor
from .inventory import load_inventory

# The knowledge base deliberately uses the fast, low-cost Haiku model.
KB_MODEL = "claude-haiku-4-5-20251001"
KB_MODEL_LABEL = "Haiku 4.5"

CATEGORIES = ["network", "application", "process", "kb_article",
              "config", "design", "manual", "general"]

_STOP = set("the a an and or of to in on for with is are was were be been this that "
            "it its as at by from will can should would could may might if then else "
            "you your we our they their he she his her not no yes do does did has have "
            "had but so than into over under out up down off about which who whom whose "
            "when where why how all any both each few more most other some such only own "
            "same too very s t just".split())


def _tokens(text: str) -> list[str]:
    return [w for w in re.findall(r"[a-z0-9][a-z0-9._-]{1,}", (text or "").lower())
            if w not in _STOP and len(w) > 1]


def _keywords(text: str, top: int = 25) -> list[str]:
    freq: dict[str, int] = {}
    for w in _tokens(text):
        freq[w] = freq.get(w, 0) + 1
    return [w for w, _ in sorted(freq.items(), key=lambda kv: -kv[1])[:top]]


def _chunk(text: str, target: int = 900) -> list[str]:
    """Split on blank lines, packing paragraphs up to ~target chars."""
    paras = [p.strip() for p in re.split(r"\n\s*\n", text or "") if p.strip()]
    chunks, cur = [], ""
    for p in paras:
        if len(cur) + len(p) + 2 > target and cur:
            chunks.append(cur.strip())
            cur = ""
        if len(p) > target * 1.6:          # a very long paragraph — hard-split
            for i in range(0, len(p), target):
                chunks.append(p[i:i + target].strip())
        else:
            cur = f"{cur}\n\n{p}" if cur else p
    if cur.strip():
        chunks.append(cur.strip())
    return chunks or ([text.strip()] if (text or "").strip() else [])


# ---------- Haiku one-shot with usage metering ----------

async def _haiku_json(prompt: str, timeout_s: int = 90) -> tuple[dict | None, str | None, dict]:
    usage = {"model": KB_MODEL}
    try:
        from claude_agent_sdk import ClaudeAgentOptions, query
        from claude_agent_sdk.types import ResultMessage
    except Exception as exc:  # noqa: BLE001
        return None, f"Claude Agent SDK not installed ({exc})", usage
    text = ""
    try:
        async with asyncio.timeout(timeout_s):
            options = ClaudeAgentOptions(max_turns=1, allowed_tools=[], model=KB_MODEL)
            async for message in query(prompt=prompt, options=options):
                if isinstance(message, ResultMessage):
                    u = getattr(message, "usage", None) or {}
                    cw = u.get("cache_creation_input_tokens", 0) or 0
                    cr = u.get("cache_read_input_tokens", 0) or 0
                    usage.update({
                        "input_tokens": (u.get("input_tokens", 0) or 0) + cw + cr,
                        "output_tokens": u.get("output_tokens", 0) or 0,
                        "cache_read_tokens": cr, "cache_write_tokens": cw,
                        "model": getattr(message, "model", None) or KB_MODEL,
                    })
                    if message.is_error:
                        return None, f"AI error: {getattr(message, 'result', '') or message.subtype}"[:200], usage
                    text = message.result or ""
    except TimeoutError:
        return None, f"AI call timed out after {timeout_s}s", usage
    except Exception as exc:  # noqa: BLE001
        return None, f"AI call failed: {type(exc).__name__}: {exc}"[:200], usage
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None, "AI response was not JSON", usage
    try:
        return json.loads(m.group()), None, usage
    except json.JSONDecodeError as exc:
        return None, f"AI response JSON invalid ({exc})", usage


def _record_usage(usage: dict) -> None:
    if usage and usage.get("output_tokens") is not None:
        try:
            db.kb_usage_add(usage)
        except Exception:  # noqa: BLE001
            pass


# ---------- classification (smart indexing) ----------

_CLASSIFY_PROMPT = """You are indexing a piece of IT-operations knowledge into a taxonomy so it can
be retrieved later when planning changes or troubleshooting incidents.

Known servers in the inventory (match the content to one if it clearly refers
to it — use the EXACT name; otherwise leave server ""):
%s

Classify the CONTENT below. Reply with ONLY this JSON (no prose, no fences):
{"title": "short descriptive title",
 "server": "exact inventory server name this is about, or '' if general/fleet-wide",
 "os": "linux | windows | ''  (only if clearly about one)",
 "category": "one of: network | application | process | kb_article | config | design | manual | general",
 "summary": "2-3 sentence summary of what this knowledge contains",
 "keywords": ["important", "search", "terms", "hostnames", "app names", "..."]}

Category guidance: design = architecture/HLD/LLD/design docs; config = server/app
configuration; network = topology, firewall, DNS, load balancer, IPs; process =
runbooks, SOPs, operational procedures; application = app-specific behaviour and
dependencies; kb_article = how-to / known-error / resolution notes; manual =
free-form operator notes; general = anything that fits none well.

CONTENT (title hint: %s):
%s
"""


async def classify(text: str, title_hint: str = "") -> tuple[dict, dict]:
    names = ", ".join(sorted(load_inventory().keys())) or "(none registered)"
    data, err, usage = await _haiku_json(
        _CLASSIFY_PROMPT % (names, title_hint or "(none)", text[:6000]))
    if not data:
        # graceful fallback: keyword-only classification
        return {"title": (title_hint or " ".join(text.split()[:8]))[:120],
                "server": "", "os": "", "category": "general",
                "summary": (text.strip()[:240]), "keywords": _keywords(text),
                "ai_error": err}, usage
    cat = str(data.get("category") or "general").lower()
    if cat not in CATEGORIES:
        cat = "general"
    srv = str(data.get("server") or "").strip()
    if srv and srv not in load_inventory():
        srv = ""                                    # never invent a server
    kws = [str(k)[:40] for k in (data.get("keywords") or [])][:30] or _keywords(text)
    return {"title": str(data.get("title") or title_hint or "Untitled")[:150],
            "server": srv, "os": str(data.get("os") or "").lower()[:40],
            "category": cat, "summary": str(data.get("summary") or "")[:800],
            "keywords": kws}, usage


# ---------- ingest ----------

def _content_hash(text: str) -> str:
    return hashlib.sha256(re.sub(r"\s+", " ", text.strip().lower()).encode()).hexdigest()


async def ingest(text: str, *, title_hint: str = "", source_type: str = "text",
                 filename: str | None = None, actor: str | None = None) -> dict:
    text = (text or "").strip()
    if len(text) < 3:
        return {"ok": False, "error": "Nothing to store — the content was empty."}
    # dedup: identical content already stored → skip the (paid) re-index
    chash = _content_hash(text)
    dup = await asyncio.to_thread(db.kb_find_by_hash, chash)
    if dup:
        return {"ok": True, "duplicate": True,
                "doc": {"id": dup["id"], "title": dup["title"], "server": dup["server"],
                        "os": dup["os"], "category": dup["category"],
                        "summary": dup["summary"], "keywords": dup["keywords"], "chunks": 0}}
    meta, usage = await classify(text, title_hint)
    _record_usage(usage)
    doc_id = uuid.uuid4().hex[:16]
    doc = {"id": doc_id, "title": meta["title"], "source_type": source_type,
           "filename": filename, "server": meta["server"], "os": meta["os"],
           "category": meta["category"], "summary": meta["summary"],
           "keywords": meta["keywords"], "body": text[:200000],
           "created_at": time.time(), "actor": actor, "content_hash": chash,
           "tokens_in": usage.get("input_tokens"), "tokens_out": usage.get("output_tokens")}
    await asyncio.to_thread(db.kb_add_doc, doc)
    rows = []
    for i, ch in enumerate(_chunk(text)):
        rows.append({"doc_id": doc_id, "ordinal": i, "server": meta["server"],
                     "os": meta["os"], "category": meta["category"], "text": ch,
                     "keywords": " ".join(_keywords(ch, 40))})
    await asyncio.to_thread(db.kb_add_chunks, rows)
    return {"ok": True, "doc": {**{k: doc[k] for k in
            ("id", "title", "server", "os", "category", "summary", "keywords")},
            "chunks": len(rows)}, "ai_error": meta.get("ai_error")}


# ---------- lexical retrieval ----------

def _score(query_tokens: list[str], chunk: dict) -> float:
    if not query_tokens:
        return 0.0
    hay = (chunk.get("keywords", "") + " " + chunk.get("text", "")).lower()
    hits = sum(hay.count(qt) for qt in query_tokens)
    # normalise a little by chunk length so long chunks don't always win
    return hits / (1 + len(hay) / 4000.0)


async def retrieve(query: str, server: str = "", top_k: int = 6) -> list[dict]:
    qtok = list(dict.fromkeys(_tokens(query)))
    # Fast path: SQLite FTS5 index (scales to very large KBs without a scan).
    fts = await asyncio.to_thread(db.kb_fts_search, qtok, server or "", top_k)
    if fts is not None:
        return [dict(h, _score=round(-(h.get("rank") or 0.0), 3)) for h in fts]
    # Fallback: in-memory lexical scan (FTS5 unavailable / non-SQLite backend).
    cands = await asyncio.to_thread(db.kb_candidate_chunks, server or "")
    scored = [(c, _score(qtok, c)) for c in cands]
    scored = [cs for cs in scored if cs[1] > 0]
    scored.sort(key=lambda cs: -cs[1])
    return [dict(c, _score=round(s, 3)) for c, s in scored[:top_k]]


async def context_and_sources(query: str, server: str = "",
                              max_chars: int = 2600) -> dict:
    """Compact cited knowledge block + the distinct source docs it came from.
    {"text": "", "sources": []} when nothing relevant is stored."""
    hits = await retrieve(query, server, top_k=6)
    if not hits:
        return {"text": "", "sources": []}
    docs = {d["id"]: d for d in await asyncio.to_thread(db.kb_list_docs)}
    lines, used, seen = [], 0, {}
    for h in hits:
        d = docs.get(h["doc_id"], {})
        title = d.get("title", "knowledge")
        seg = f"- [{title}] {h['text'].strip()}"
        if used + len(seg) > max_chars and lines:
            break
        lines.append(seg)
        used += len(seg)
        if h["doc_id"] not in seen:
            seen[h["doc_id"]] = {"id": h["doc_id"], "title": title,
                                 "server": d.get("server", ""), "os": d.get("os", ""),
                                 "category": d.get("category", "")}
    text = ("Relevant knowledge-base entries (from uploaded design docs / notes — "
            "prefer these facts over assumptions):\n" + "\n".join(lines) + "\n")
    return {"text": text, "sources": list(seen.values())}


async def knowledge_context(query: str, server: str = "", max_chars: int = 2600) -> str:
    """Back-compat: just the grounding text block (see context_and_sources)."""
    return (await context_and_sources(query, server, max_chars))["text"]


# ---------- chat: learn or answer ----------

# A message is a QUESTION only if it ends with '?' or STARTS with an
# interrogative word — otherwise it's a statement to LEARN (so "db-01 is a
# PostgreSQL primary" is taught, not mistaken for a question because of "is").
_Q_START_RE = re.compile(
    r"^\s*(what|which|who|whom|whose|where|when|why|how|is|are|was|were|does|do|"
    r"did|can|could|should|would|will|list|show|tell|explain|find|give|search|"
    r"look|lookup|any|do we|is there|are there)\b", re.I)


def _is_question(message: str) -> bool:
    return "?" in message or bool(_Q_START_RE.match(message or ""))

_ANSWER_PROMPT = """You are the knowledge-base assistant for an airport IT operations team. Answer
the operator's question USING ONLY the knowledge entries below. If they do not
contain the answer, say so plainly and suggest what to upload. Be concise and
concrete; cite the entry titles you used in square brackets.

KNOWLEDGE ENTRIES:
%s

QUESTION: %s
"""


async def chat(message: str, server: str = "", mode: str = "auto") -> dict:
    message = (message or "").strip()
    if not message:
        return {"ok": False, "error": "Empty message"}
    if mode == "auto":
        mode = "ask" if _is_question(message) else "teach"

    if mode == "teach":
        res = await ingest(message, source_type="chat", actor=None)
        if not res.get("ok"):
            return {"mode": "teach", "ok": False, "error": res.get("error")}
        d = res["doc"]
        where = " → ".join([x for x in [d["server"] or "General",
                            d["os"] or None, d["category"]] if x])
        if res.get("duplicate"):
            return {"mode": "teach", "ok": True, "stored": d,
                    "answer": f"I already have that — it's stored under **{where}** as "
                              f"“{d['title']}”, so I didn't duplicate it."}
        return {"mode": "teach", "ok": True, "stored": d,
                "answer": f"Got it — stored under **{where}** as “{d['title']}”"
                          f" ({d['chunks']} chunk{'s' if d['chunks'] != 1 else ''}).",
                "ai_error": res.get("ai_error")}

    # ask
    hits = await retrieve(message, server, top_k=6)
    if not hits:
        return {"mode": "ask", "ok": True, "answer":
                "I don't have anything on that in the knowledge base yet. "
                "Upload a document or tell me the details and I'll remember them.",
                "sources": []}
    docs = {d["id"]: d for d in await asyncio.to_thread(db.kb_list_docs)}
    ctx = "\n".join(f"[{docs.get(h['doc_id'], {}).get('title', 'entry')}] {h['text']}"
                    for h in hits)[:9000]
    data, err, usage = await _haiku_json(
        # answer prompt returns free text, not JSON — wrap so _haiku_json still
        # works by asking for a JSON envelope
        _ANSWER_PROMPT % (ctx, message) +
        '\n\nReply with ONLY this JSON: {"answer": "your answer with [citations]"}')
    _record_usage(usage)
    sources = sorted({docs.get(h["doc_id"], {}).get("title", "entry") for h in hits})
    if not data:
        # fall back to returning the raw top chunks
        return {"mode": "ask", "ok": True, "sources": sources,
                "answer": "Closest knowledge I have:\n\n" +
                          "\n\n".join(f"• {h['text'][:400]}" for h in hits[:3]),
                "ai_error": err}
    return {"mode": "ask", "ok": True, "sources": sources,
            "answer": str(data.get("answer") or "").strip() or "(no answer)"}


# ---------- taxonomy tree + stats for the UI ----------

def tree() -> dict:
    """Server → OS → category → [docs] for the knowledge explorer."""
    docs = db.kb_list_docs()
    out: dict = {}
    for d in docs:
        srv = d["server"] or "General"
        os_ = d["os"] or "—"
        cat = d["category"] or "general"
        out.setdefault(srv, {}).setdefault(os_, {}).setdefault(cat, []).append(
            {"id": d["id"], "title": d["title"], "summary": d["summary"],
             "source_type": d["source_type"], "created_at": d["created_at"]})
    return out


def overview() -> dict:
    return {"stats": db.kb_stats(), "usage": db.kb_usage_get(),
            "model": KB_MODEL, "model_label": KB_MODEL_LABEL,
            "categories": CATEGORIES}


# ---------- architecture view (graph built from the data) ----------

_ARCH_NODE_TYPES = {"client", "external", "network", "loadbalancer", "server",
                    "service", "application", "database", "storage", "dependency"}

_ARCH_PROMPT = """You are producing a SYSTEM ARCHITECTURE GRAPH for ONE server/CI, using only the
facts provided (inventory + live discovery + knowledge-base entries). Extract
only entities and relationships SUPPORTED BY THE DATA — never invent components,
hostnames or ports.

SERVER / CI: %s

DATA:
%s

Reply with ONLY this JSON (no prose, no fences):
{"nodes": [{"id": "web-01", "label": "web-01", "type": "server", "meta": "RHEL 8 · 10.70.5.44"}],
 "edges": [{"from": "lb-01", "to": "web-01", "label": "HTTPS 443"}],
 "notes": "one line on confidence / what's missing"}

Rules:
- The main CI itself MUST be present as type "server".
- Node "type" is one of: client, external, network, loadbalancer, server,
  service, application, database, storage, dependency.
- Edge direction = traffic/dependency flow (caller -> callee). Put the
  protocol/port in the edge "label" when the data gives it.
- Use REAL names/IPs/ports from the data. Keep to <= 22 nodes.
- "meta" is a short one-line detail (OS, IP, version) or "".
"""


def _fallback_graph(srv, facts_line: str) -> dict:
    """A basic graph from inventory alone when the AI is unavailable."""
    os_meta = (getattr(srv, "os", "") or "") + (f" · {srv.host}" if srv.host else "")
    nodes = [{"id": srv.name, "label": srv.name, "type": "server", "meta": os_meta.strip(" ·")}]
    edges = []
    for s in (getattr(srv, "services", None) or []):
        nid = f"svc:{s}"
        nodes.append({"id": nid, "label": s, "type": "service", "meta": ""})
        edges.append({"from": srv.name, "to": nid, "label": ""})
    return {"nodes": nodes, "edges": edges, "notes": "Basic view from inventory (AI unavailable)."}


def _sanitize_graph(graph: dict, server_name: str) -> dict:
    raw_nodes = graph.get("nodes") if isinstance(graph, dict) else None
    nodes, ids = [], set()
    for n in (raw_nodes or []):
        if not isinstance(n, dict):
            continue
        nid = str(n.get("id") or n.get("label") or "").strip()
        if not nid or nid in ids:
            continue
        t = str(n.get("type") or "dependency").lower()
        if t not in _ARCH_NODE_TYPES:
            t = "dependency"
        ids.add(nid)
        nodes.append({"id": nid, "label": str(n.get("label") or nid)[:60],
                      "type": t, "meta": str(n.get("meta") or "")[:80]})
    if server_name not in ids:                       # the CI must be present
        nodes.insert(0, {"id": server_name, "label": server_name, "type": "server", "meta": ""})
        ids.add(server_name)
    edges = []
    for e in (graph.get("edges") or []):
        if not isinstance(e, dict):
            continue
        f, t = str(e.get("from") or "").strip(), str(e.get("to") or "").strip()
        if f in ids and t in ids and f != t:
            edges.append({"from": f, "to": t, "label": str(e.get("label") or "")[:40]})
    return {"nodes": nodes[:22], "edges": edges, "notes": str(graph.get("notes") or "")[:200]}


def _overall_status(checks: dict) -> str:
    st = [(c or {}).get("status", "unknown") for c in (checks or {}).values()]
    if "critical" in st:
        return "critical"
    if "warning" in st:
        return "warning"
    if any(s == "ok" for s in st):
        return "ok"
    return "unknown"


# named-infrastructure hints for the LOCAL (token-free) graph builder
_LOCAL_LB = re.compile(r"\b(lb[-_]?\w+|vip[-_]?\w*|haproxy|f5|netscaler|nginx-?lb)\b", re.I)
_LOCAL_DB = re.compile(r"\b(db[-_]?\w+|postgre\w*|mysql|mariadb|oracle|mssql|sql-?server|"
                       r"mongo\w*|redis|memcached|cassandra)\b", re.I)
_LOCAL_PORT = re.compile(
    r"\b(?:port\s*)?(443|80|8080|8443|5432|3306|1521|1433|6379|27017|9200)\b")
_PORT_LABEL = {"443": "HTTPS 443", "8443": "HTTPS 8443", "80": "HTTP 80", "8080": "HTTP 8080",
               "5432": "PostgreSQL 5432", "3306": "MySQL 3306", "1521": "Oracle 1521",
               "1433": "MSSQL 1433", "6379": "Redis 6379", "27017": "MongoDB 27017",
               "9200": "Elasticsearch 9200"}


def local_architecture(server_name: str, srv, facts: str, docs_text: str) -> dict:
    """Deterministic graph from inventory + discovery + KB text — NO AI tokens.
    Conservative: only concrete, named entities become nodes."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add(nid, label, typ, meta=""):
        nodes.setdefault(nid, {"id": nid, "label": label, "type": typ, "meta": meta})

    os_meta = (getattr(srv, "os", "") or "") + (f" · {srv.host}" if srv.host else "")
    add(server_name, server_name, "server", os_meta.strip(" ·"))
    for s in (getattr(srv, "services", None) or []):
        add(f"svc:{s}", s, "service")
        edges.append({"from": server_name, "to": f"svc:{s}", "label": ""})

    text = f"{facts}\n{docs_text}"
    ports = _LOCAL_PORT.findall(text)
    inbound = next((p for p in ("443", "8443", "80", "8080") if p in ports), "")
    dbport = next((p for p in ("5432", "3306", "1521", "1433", "6379", "27017") if p in ports), "")
    inv = load_inventory()

    def _role(other) -> str:
        blob = (" ".join(getattr(other, "services", None) or []) + " " + other.name).lower()
        if re.search(r"postgre|mysql|maria|oracle|mssql|\bsql\b|mongo|redis|\bdb\b|database", blob):
            return "database"
        if re.search(r"\blb\b|balanc|haproxy|\bvip\b|gateway|\bproxy\b", blob):
            return "loadbalancer"
        return "dependency"

    have_lb = have_db = False
    # other known inventory servers referenced here — typed by their role
    for name, other in inv.items():
        if name == server_name or not re.search(r"\b" + re.escape(name) + r"\b", text, re.I):
            continue
        role = _role(other)
        add(name, name, role, getattr(other, "os", "") or "")
        if role == "loadbalancer":
            have_lb = True
            edges.append({"from": name, "to": server_name, "label": _PORT_LABEL.get(inbound, "")})
        elif role == "database":
            have_db = True
            edges.append({"from": server_name, "to": name, "label": _PORT_LABEL.get(dbport, "")})
        else:
            edges.append({"from": server_name, "to": name, "label": ""})

    known_lc = {n.lower() for n in inv}
    # regex-named infra that ISN'T already a known inventory server
    if not have_lb:
        lbs = {x.lower() for x in _LOCAL_LB.findall(text)} - known_lc
        named = {m for m in lbs if re.match(r"(lb|vip|nlb|alb)[-_]?\w", m)}
        for m in list(named or lbs)[:3]:
            add(f"lb:{m}", m, "loadbalancer")
            edges.append({"from": f"lb:{m}", "to": server_name, "label": _PORT_LABEL.get(inbound, "")})
    if not have_db:
        dbs = {x.lower() for x in _LOCAL_DB.findall(text)} - known_lc
        named = {m for m in dbs if re.match(r"db[-_]?\w", m)}
        for m in list(named or dbs)[:3]:
            add(f"db:{m}", m, "database")
            edges.append({"from": server_name, "to": f"db:{m}", "label": _PORT_LABEL.get(dbport, "")})
    note = ("Built locally from inventory, discovery and the knowledge base (no AI). "
            "Use ✨ AI enhance for a richer, more precise map.")
    return {"nodes": list(nodes.values())[:22], "edges": edges, "notes": note, "source": "local"}


async def architecture(server_name: str, use_ai: bool = False) -> dict:
    srv = load_inventory().get(server_name)
    if srv is None:
        return {"ok": False, "error": f"'{server_name}' is not in the inventory"}
    try:
        from . import discovery
        facts = await asyncio.to_thread(discovery.facts_summary, server_name)
    except Exception:  # noqa: BLE001
        facts = ""
    docs = [d for d in await asyncio.to_thread(db.kb_list_docs) if d["server"] == server_name]
    kb_lines = []
    for d in docs[:20]:
        full = await asyncio.to_thread(db.kb_get_doc, d["id"])
        kb_lines.append(f"[{d['category']}] {d['title']}: {d['summary']}\n"
                        f"{(full or {}).get('body', '')[:1200]}")
    docs_text = "\n\n".join(kb_lines)

    err = None
    if use_ai:
        data = (f"Inventory: name={srv.name}, host={srv.host}, os={srv.os or 'unknown'}, "
                f"platform={'windows' if srv.is_windows else 'linux'}, "
                f"services={', '.join(srv.services) or 'unknown'}\n\n"
                + (f"Discovered facts:\n{facts}\n\n" if facts else "")
                + ("Knowledge-base entries:\n" + docs_text if docs_text else
                   "No knowledge-base entries for this server yet."))
        graph, err, usage = await _haiku_json(_ARCH_PROMPT % (server_name, data[:9000]), timeout_s=120)
        _record_usage(usage)
        g = _sanitize_graph(graph or _fallback_graph(srv, facts), server_name)
        g["source"] = "ai" if graph else "local"
        g["notes"] = graph.get("notes", "") if graph else "AI unavailable — basic inventory view."
    else:
        g = _sanitize_graph(local_architecture(server_name, srv, facts, docs_text), server_name)
        g["source"] = "local"

    # overlay live health status onto the server node (from the latest snapshot)
    try:
        hist = await asyncio.to_thread(db.health_history, server_name, 1)
        if hist:
            status = _overall_status(hist[-1].get("checks"))
            for n in g["nodes"]:
                if n["id"] == server_name:
                    n["status"] = status
    except Exception:  # noqa: BLE001
        pass

    g.update({"ok": True, "ai_error": err, "model": KB_MODEL, "model_label": KB_MODEL_LABEL,
              "server": server_name, "sources": [d["title"] for d in docs]})
    return g
