# app_tcode_scan_final.py
# Converted to S4HANA Credit Master Data Remediator (Final Format)
# LOGIC REMAINS EXACTLY SAME. Only formatting/output changed.

import os
import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from fastapi import FastAPI
from pydantic import BaseModel

# -------------------------------------------------------------------
# INIT
# -------------------------------------------------------------------
DDIC_PATH = os.getenv("DDIC_PATH", "ddic.json")

app = FastAPI(
    title="TCode Scanner (Final Format)"
)

# -------------------------------------------------------------------
# MODELS (TARGET FORMAT)
# -------------------------------------------------------------------
class Unit(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    start_line: int = 0
    end_line: int = 0
    code: str


# -------------------------------------------------------------------
# DDIC Mapping Loader (IDENTICAL LOGIC)
# -------------------------------------------------------------------
class TCodeMap:
    def __init__(self, path: str):
        self.path = Path(path)
        self.map: Dict[str, str] = {}
        self._load()

    def _load(self):
        if not self.path.exists():
            print(f"[DDIC] WARNING: {self.path} not found. No tcode mappings loaded.")
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[DDIC] ERROR reading {self.path}: {e}")
            return

        raw = data.get("tcode_mappings")
        count = 0

        if isinstance(raw, list):
            for item in raw:
                try:
                    src = str(item["source_tcode"]).upper().strip()
                    tgt = str(item["target_tcode"]).upper().strip()
                    if src and tgt:
                        self.map[src] = tgt
                        count += 1
                except Exception:
                    continue

        elif isinstance(raw, dict):
            for k, v in raw.items():
                try:
                    src = str(k).upper().strip()
                    tgt = str(v).upper().strip()
                    if src and tgt:
                        self.map[src] = tgt
                        count += 1
                except Exception:
                    continue

        print(f"[DDIC] Loaded {count} tcode mappings from {self.path}")

    def lookup(self, tcode: str) -> Optional[str]:
        if not tcode:
            return None
        return self.map.get(tcode.upper().strip())


TCMAP = TCodeMap(DDIC_PATH)


# -------------------------------------------------------------------
# Normalization (IDENTICAL)
# -------------------------------------------------------------------
def _normalize_code(s: str) -> str:
    if not s:
        return ""
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = s.replace("\u00A0", " ")
    return s


# -------------------------------------------------------------------
# REGEX DEFINITIONS (IDENTICAL)
# -------------------------------------------------------------------
CALL_TCODE_RE = re.compile(
    r"""(?imsx)
    \bCALL\s+TRANSACTION
    \s+ (?P<quote>['"])
    (?P<tcode>[A-Za-z0-9_/\-]+)
    (?P=quote)
    (?P<tail>[^\.]*?)
    \.
    """
)

STRING_LITERAL_RE = re.compile(
    r"""(?s)(?P<q>['"])(?P<val>[^'"]+?)(?P=q)"""
)

SY_TCODE_EQ_RE = re.compile(
    r"""(?imx)
    \bSY\-TCODE\s*=\s*
    (?P<q>['"])(?P<tcode>[A-Za-z0-9_/\-]+)(?P=q)
    """
)

SY_TCODE_IN_RE = re.compile(
    r"""(?imx)
    \bSY\-TCODE\s+IN\s+\w+\b
    """
)


# -------------------------------------------------------------------
# ABAP Helpers (IDENTICAL LOGIC)
# -------------------------------------------------------------------
def _line_of_offset(txt: str, off: int) -> int:
    return (txt[:off].count("\n") + 1) if txt else 0


def _line_start_offset(txt: str, off: int) -> int:
    if not txt:
        return 0
    nl = txt.rfind("\n", 0, off)
    return 0 if nl < 0 else nl + 1


def _is_in_line_comment(txt: str, match_start: int) -> bool:
    if not txt:
        return False
    line_start = _line_start_offset(txt, match_start)
    segment = txt[line_start:match_start]
    return '"' in segment


def _statement_span_at(code: str, any_pos: int) -> Tuple[int, int]:
    if not code:
        return (0, 0)
    prev = code.rfind('.', 0, any_pos)
    start = 0 if prev < 0 else prev + 1
    nxt = code.find('.', any_pos)
    end = len(code) if nxt < 0 else nxt + 1
    while start > 0 and code[start] in ('\n', '\r'):
        start += 1
    return (start, end)


def _build_call_transaction_replacement(match: re.Match) -> str:
    quote = match.group("quote")
    src = match.group("tcode")
    tail = match.group("tail") or ""
    mapped = TCMAP.lookup(src)
    if not mapped:
        return ""
    return f"CALL TRANSACTION {quote}{mapped}{quote}{tail}."


def _literal_replacement_snippet(literal_match: re.Match) -> str:
    q = literal_match.group("q")
    val = literal_match.group("val")
    mapped = TCMAP.lookup(val)
    if not mapped:
        return ""
    return f"{q}{mapped}{q}"


# -------------------------------------------------------------------
# EXTRACTION LOGIC (IDENTICAL, only return format changed later)
# -------------------------------------------------------------------
def extract_tcode_findings(code: str) -> List[Dict[str, Any]]:
    code = _normalize_code(code)
    findings: List[Dict[str, Any]] = []
    if not code:
        return findings

    handled_spans = []

    # (1) CALL TRANSACTION
    for m in CALL_TCODE_RE.finditer(code):
        if _is_in_line_comment(code, m.start()):
            continue

        src_tcode = m.group("tcode")
        mapped = TCMAP.lookup(src_tcode)

        line_no = _line_of_offset(code, m.start())
        stmt_start, stmt_end = _statement_span_at(code, m.start())
        stmt_text = code[stmt_start:stmt_end].strip()
        quote = m.group("quote")
        original_literal = f"{quote}{src_tcode}{quote}"

        handled_spans.append((m.start(), m.end()))

        replacement_stmt = (
            _build_call_transaction_replacement(m) if mapped else ""
        )

        # multi-line span for statement
        stmt_start_line = _line_of_offset(code, stmt_start)
        stmt_line_count = stmt_text.count("\n") + 1
        stmt_end_line = stmt_start_line + stmt_line_count - 1

        findings.append({
            "occurrence": "call_transaction",
            "tcode": src_tcode.upper(),
            "mapped_target": mapped,
            "line": line_no,
            "line_start": stmt_start_line,
            "line_end": stmt_end_line,
            "original_literal": original_literal,
            "replacement_snippet": replacement_stmt,
            "statement_snippet": stmt_text,
            "message": (
                f"CALL TRANSACTION {original_literal} detected."
            ),
            "suggestion": (
                f"Replace the source TCode with '{mapped}' (per ddic.json)."
                if mapped else
                "Extend ddic.json if a successor transaction exists."
            )
        })

    # (2) SY-TCODE = '...'
    for em in SY_TCODE_EQ_RE.finditer(code):
        if _is_in_line_comment(code, em.start()):
            continue

        tcode = em.group("tcode")
        q = em.group("q")
        mapped = TCMAP.lookup(tcode)

        line_no = _line_of_offset(code, em.start())
        stmt_start, stmt_end = _statement_span_at(code, em.start())
        stmt_text = code[stmt_start:stmt_end].strip()
        original_literal = f"{q}{tcode}{q}"

        replacement_lit = f"{q}{mapped}{q}" if mapped else ""

        stmt_start_line = _line_of_offset(code, stmt_start)
        stmt_line_count = stmt_text.count("\n") + 1
        stmt_end_line = stmt_start_line + stmt_line_count - 1

        findings.append({
            "occurrence": "sy_tcode_compare",
            "tcode": tcode.upper(),
            "mapped_target": mapped,
            "line": line_no,
            "line_start": stmt_start_line,
            "line_end": stmt_end_line,
            "original_literal": original_literal,
            "replacement_snippet": replacement_lit,
            "statement_snippet": stmt_text,
            "message": f"SY-TCODE comparison with {original_literal} detected.",
            "suggestion": (
                f"Replace with mapped target '{mapped}'."
                if mapped else
                "Consider adding this tcode to ddic.json if obsolete."
            )
        })

    # (3) SY-TCODE IN s_tcode
    for im in SY_TCODE_IN_RE.finditer(code):
        if _is_in_line_comment(code, im.start()):
            continue

        line_no = _line_of_offset(code, im.start())
        stmt_start, stmt_end = _statement_span_at(code, im.start())
        stmt_text = code[stmt_start:stmt_end].strip()

        stmt_start_line = _line_of_offset(code, stmt_start)
        stmt_line_count = stmt_text.count("\n") + 1
        stmt_end_line = stmt_start_line + stmt_line_count - 1

        findings.append({
            "occurrence": "sy_tcode_in",
            "tcode": None,
            "mapped_target": None,
            "line": line_no,
            "line_start": stmt_start_line,
            "line_end": stmt_end_line,
            "original_literal": "",
            "replacement_snippet": "",
            "statement_snippet": stmt_text,
            "message": "SY-TCODE IN <range> detected.",
            "suggestion": "Check the range table for obsolete tcodes."
        })

    # (4) Generic string literals
    for lm in STRING_LITERAL_RE.finditer(code):
        if _is_in_line_comment(code, lm.start()):
            continue

        # Skip literals inside CALL TRANSACTION spans
        if any(start <= lm.start() <= end for start, end in handled_spans):
            continue

        lit_val = lm.group("val")
        mapped = TCMAP.lookup(lit_val)
        if not mapped:
            continue

        q = lm.group("q")
        original_literal = f"{q}{lit_val}{q}"

        line_no = _line_of_offset(code, lm.start())
        stmt_start, stmt_end = _statement_span_at(code, lm.start())
        stmt_text = code[stmt_start:stmt_end].strip()

        replacement_lit = f"{q}{mapped}{q}"

        stmt_start_line = _line_of_offset(code, stmt_start)
        stmt_line_count = stmt_text.count("\n") + 1
        stmt_end_line = stmt_start_line + stmt_line_count - 1

        findings.append({
            "occurrence": "string_literal",
            "tcode": lit_val.upper(),
            "mapped_target": mapped,
            "line": line_no,
            "line_start": stmt_start_line,
            "line_end": stmt_end_line,
            "original_literal": original_literal,
            "replacement_snippet": replacement_lit,
            "statement_snippet": stmt_text,
            "message": f"String literal {original_literal} matches a mapped source tcode.",
            "suggestion": f"Replace literal with mapped target '{mapped}'."
        })

    return findings


# -------------------------------------------------------------------
# RESPONSE FORMAT BUILDER (THIS IS THE PART WE CHANGE)
# -------------------------------------------------------------------
def build_response(unit: Unit, issues: List[Dict[str, Any]]):
    findings_out = []

    for i in issues:
        # fall back to single line if start/end not present
        rel_start = i.get("line_start", i["line"])
        rel_end = i.get("line_end", i["line"])

        starting_line_abs = unit.start_line + rel_start - 1
        ending_line_abs = unit.start_line + rel_end - 1

        findings_out.append({
            "prog_name": unit.pgm_name,
            "incl_name": unit.inc_name,
            "types": unit.type,
            "blockname": unit.name,
            "starting_line": starting_line_abs,
            "ending_line": ending_line_abs,
            "issues_type": "TCodeMapping",          # fixed category
            "severity": "error",                    # ALWAYS error now
            "message": i["message"],
            "suggestion": i["suggestion"],
            "snippet": i["statement_snippet"].replace("\n", "\\n"),
        })

    return {
        "pgm_name": unit.pgm_name,
        "inc_name": unit.inc_name,
        "type": unit.type,
        "name": unit.name,
        "code": unit.code,
        "findings": findings_out
    }


# -------------------------------------------------------------------
# API (CONVERTED TO FINAL FORMAT)
# -------------------------------------------------------------------
@app.post("/remediate")
def remediate_single(unit: Unit):
    issues = extract_tcode_findings(unit.code or "")
    return [build_response(unit, issues)]


@app.post("/remediate-array")
def remediate_array(units: List[Unit]):
    output = []
    for u in units:
        issues = extract_tcode_findings(u.code or "")
        output.append(build_response(u, issues))
    return output


@app.get("/health")
def health():
    path = str(Path(DDIC_PATH).resolve())
    return {
        "ok": True,
        "ddic_path": path,
        "tcode_mapping_count": len(TCMAP.map)
    }