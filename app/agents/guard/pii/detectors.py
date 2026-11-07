"""Section 4: PII detection, tuned for Indian identifiers.

Every detector is regex + (optional) checksum validator + context scoring, so we can
tell an Aadhaar from a random 12-digit order number and a PIN code from a price.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol

# --------------------------------------------------------------------------- checksums
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(number: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return str(_VERHOEFF_INV[c])


def luhn_valid(number: str) -> bool:
    total, alt = 0, False
    for ch in reversed(number):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def digits(s: str) -> str:
    return re.sub(r"\D", "", s)


# --------------------------------------------------------------------------- types
@dataclass
class PIISpan:
    entity_type: str
    start: int
    end: int
    text: str
    score: float
    detector: str = "regex"

    def overlaps(self, other: "PIISpan") -> bool:
        return self.start < other.end and other.start < self.end


class NERBackend(Protocol):
    def analyze(self, text: str) -> list[PIISpan]: ...


ContextFn = Callable[[str, re.Match], float]  # returns final score, <=0 to reject


@dataclass
class RegexDetector:
    entity_type: str
    pattern: re.Pattern
    base_score: float
    validator: Callable[[str], bool] | None = None
    context: ContextFn | None = None

    def find(self, text: str) -> Iterable[PIISpan]:
        for m in self.pattern.finditer(text):
            value = m.group(0)
            if self.validator and not self.validator(value):
                continue
            score = self.context(text, m) if self.context else self.base_score
            if score > 0:
                yield PIISpan(self.entity_type, m.start(), m.end(), value, score)


def _before(text: str, m: re.Match, n: int) -> str:
    return text[max(0, m.start() - n): m.start()].lower()


def _after(text: str, m: re.Match, n: int) -> str:
    return text[m.end(): m.end() + n].lower()


# --------------------------------------------------------------------------- context rules
_AADHAAR_CTX = re.compile(r"aadh?aa?r|\buid\b|आधार|আধার")
_PHONE_CTX = re.compile(r"phone|mobile|call|contact|whatsapp|number|no\.|फ़ोन|फोन")
_PASSPORT_CTX = re.compile(r"passport|पासपोर्ट")
_PIN_POS = re.compile(
    r"\b(pin|pincode|pin code|postal|zip|post code|deliver(y|ed)?|address|located|area|"
    r"nagar|road|rd|street|layout|sector|colony|city|bangalore|bengaluru|mumbai|delhi|"
    r"kolkata|chennai|hyderabad|pune)\b|पिन|,\s*$"
)
_PIN_NEG_BEFORE = re.compile(
    r"(₹|\brs\.?|\binr\b|\$|\bprice|\bcost|\bbudget|\bamount|\border|\bid\b|#|invoice|"
    r"\bref|booking|\btxn|transaction|\bpaid|\bpay|\bbill|ticket|\bqty|\bunits?)\s*[:\-]?\s*$"
)
_PIN_NEG_AFTER = re.compile(r"^\s*(rupees|rs\b|inr|/-|only|paise|units|items|pcs|times)")


def _aadhaar_ctx(text: str, m: re.Match) -> float:
    return 0.98 if _AADHAAR_CTX.search(_before(text, m, 40)) else 0.85


def _phone_ctx(text: str, m: re.Match) -> float:
    v = m.group(0)
    if v.strip().startswith("+91"):
        return 0.95
    return 0.9 if _PHONE_CTX.search(_before(text, m, 30)) else 0.8


def _passport_ctx(text: str, m: re.Match) -> float:
    return 0.9 if _PASSPORT_CTX.search(_before(text, m, 40)) else 0.0


def _pan_ctx(text: str, m: re.Match) -> float:
    v = m.group(0).upper()
    # 4th char encodes holder type: P person, C company, H HUF, F firm, A AOP, T trust,
    # B BOI, L local authority, J artificial juridical person, G government
    return 0.92 if v[3] in "PCHFATBLJG" else 0.6


def _pin_ctx(text: str, m: re.Match) -> float:
    """PIN codes collide with prices ("₹250000"), order IDs and quantities, so they
    need surrounding words to count."""
    before, after = _before(text, m, 25), _after(text, m, 12)
    if _PIN_NEG_BEFORE.search(before) or _PIN_NEG_AFTER.search(after):
        return 0.0
    if _PIN_POS.search(_before(text, m, 60)) or re.match(r"^\s*[).,]?\s*(india|$)", after):
        return 0.9
    return 0.35  # below default threshold unless an address span covers it


def _ifsc_ctx(text: str, m: re.Match) -> float:
    return 0.9 if m.group(0)[:4].isalpha() else 0.0


def _card_validator(v: str) -> bool:
    d = digits(v)
    return 13 <= len(d) <= 19 and luhn_valid(d) and len(set(d)) > 1


def _aadhaar_validator(v: str) -> bool:
    d = digits(v)
    return len(d) == 12 and d[0] not in "01" and verhoeff_valid(d) and len(set(d)) > 2


_STATES = ("AN|AP|AR|AS|BR|CH|CG|DD|DL|DN|GA|GJ|HR|HP|JK|JH|KA|KL|LA|LD|MP|MH|MN|ML|MZ|NL|"
           "OD|OR|PY|PB|RJ|SK|TN|TS|TR|UP|UK|UA|WB")

DEFAULT_DETECTORS: list[RegexDetector] = [
    RegexDetector("EMAIL", re.compile(
        r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b"), 0.95),
    # UPI VPA: handle@psp, where the PSP part has no dot. Must not be confused with email.
    RegexDetector("UPI_ID", re.compile(
        r"(?<![\w.+-])[A-Za-z0-9][A-Za-z0-9._-]{1,255}@[A-Za-z][A-Za-z0-9]{1,63}(?![\w-]|\.[A-Za-z])"), 0.92),
    RegexDetector("CREDIT_CARD", re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])"), 0.95,
                  validator=_card_validator),
    RegexDetector("AADHAAR", re.compile(r"(?<![\d+])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"), 0.85,
                  validator=_aadhaar_validator, context=_aadhaar_ctx),
    RegexDetector("PHONE", re.compile(r"(?<![\w+])(?:\+91[ -]?|91[ -]|0)?[6-9]\d{4}[ -]?\d{5}(?!\d)"),
                  0.8, context=_phone_ctx),
    RegexDetector("PAN", re.compile(r"\b[A-Za-z]{5}\d{4}[A-Za-z]\b"), 0.9, context=_pan_ctx),
    RegexDetector("IFSC", re.compile(r"\b[A-Za-z]{4}0[A-Za-z0-9]{6}\b"), 0.9, context=_ifsc_ctx),
    RegexDetector("VEHICLE_NUMBER", re.compile(
        rf"\b(?:{_STATES})[ -]?\d{{1,2}}[ -]?[A-Z]{{1,3}}[ -]?\d{{4}}\b|\b\d{{2}}[ -]?BH[ -]?\d{{4}}[ -]?[A-Z]{{1,2}}\b",
        re.I), 0.85),
    RegexDetector("PASSPORT", re.compile(r"\b[A-PR-WY-Za-pr-wy-z][1-9]\d{6}\b"), 0.9, context=_passport_ctx),
    RegexDetector("PIN_CODE", re.compile(r"(?<![\d₹$.,/-])[1-9]\d{2} ?\d{3}(?![\d,.]\d|\d)"), 0.9,
                  context=_pin_ctx),
]

# --------------------------------------------------------------------------- heuristics
_ADDR_KEYWORDS = re.compile(
    r"\b(road|rd|street|st|nagar|layout|cross|main|sector|colony|lane|marg|block|phase|"
    r"enclave|society|apartments?|residency|towers?|vihar|puram|halli|palya|"
    r"gali|chowk|bazar|bazaar|stage)\b",
    re.I,
)
_HOUSE_NO = re.compile(r"(?:\b(?:flat|house|h\.?\s?no|door|plot|apt|villa|no)\.?\s*[:#]?\s*|#\s*)?\b\d{1,5}[A-Za-z]?(?:/\d{1,4})?\b", re.I)
_PIN_IN = re.compile(r"\b[1-9]\d{2} ?\d{3}\b")
_NAME_PATTERNS = [
    (re.compile(r"\b(?i:my name is|this is|mera naam|naam hai|name:)\s+([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){0,2})"), 0.8),
    (re.compile(r"\b(?i:i am|i'm)\s+([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){0,2})\b"), 0.6),
    (re.compile(r"\b(?:Mr|Mrs|Ms|Dr|Shri|Smt)\.?\s+([A-Z][a-z]{1,20}(?:\s+[A-Z][a-z]{1,20}){0,2})"), 0.75),
]
_NAME_STOP = {"Looking", "Available", "Free", "Busy", "Here", "Home", "Not", "Going", "Okay",
              "Fine", "Sorry", "Trying", "Planning", "Ready", "Out", "Back", "Away", "Also"}


class HeuristicNER:
    """Regex detection for names and street addresses. It catches the common phrasings
    ("my name is ...", "Flat 302, ... Road"), not every name; plug in any ``NERBackend``
    for better recall."""

    def analyze(self, text: str) -> list[PIISpan]:
        spans: list[PIISpan] = []
        for pat, score in _NAME_PATTERNS:
            for m in pat.finditer(text):
                name = m.group(1)
                first = name.split()[0]
                if first in _NAME_STOP:
                    continue
                spans.append(PIISpan("PERSON", m.start(1), m.end(1), name, score, "heuristic"))
        spans += self._addresses(text)
        return spans

    def _addresses(self, text: str) -> list[PIISpan]:
        out: list[PIISpan] = []
        for kw in _ADDR_KEYWORDS.finditer(text):
            # look back up to 60 chars (same sentence) for a house/flat number
            win_start = max(0, kw.start() - 60)
            seg = text[win_start:kw.start()]
            cut = max(seg.rfind("."), seg.rfind("\n"), seg.rfind("?"), seg.rfind("!"))
            if cut >= 0 and not re.match(r"\s*\d", seg[cut + 1:cut + 3] or "x"):
                seg_start = win_start + cut + 1
            else:
                seg_start = win_start
            nums = [n for n in _HOUSE_NO.finditer(text, seg_start, kw.start())
                    if not re.search(r"(₹|rs\.?|inr|\$)\s*$", text[max(0, n.start() - 4):n.start()], re.I)]
            if not nums:
                continue
            # prefer an explicitly marked number ("Flat 302", "#14"), else the closest one
            marked = [n for n in nums if not n.group(0).strip().isdigit()]
            start = (marked[-1] if marked else nums[-1]).start()
            # extend forward to the end of the clause, through an optional PIN code
            tail = text[kw.end(): kw.end() + 100]
            end_rel = len(tail)
            for stop in (". ", "\n", "?", "!", " and ", " please", " tomorrow", " today", " at "):
                i = tail.find(stop)
                if i != -1:
                    end_rel = min(end_rel, i)
            seg_tail = tail[:end_rel]
            pm = None
            for pm in _PIN_IN.finditer(seg_tail):
                pass
            end = kw.end() + (pm.end() if pm else len(seg_tail.rstrip(" ,")))
            value = text[start:end].strip()
            score = 0.75 + (0.15 if pm else 0.0)
            out.append(PIISpan("ADDRESS", start, start + len(value), value, score, "heuristic"))
        # merge overlapping address candidates
        out.sort(key=lambda s: (s.start, -s.end))
        merged: list[PIISpan] = []
        for s in out:
            if merged and s.start <= merged[-1].end:
                last = merged[-1]
                if s.end > last.end:
                    last.end, last.text = s.end, text[last.start:s.end]
                last.score = max(last.score, s.score)
            else:
                merged.append(s)
        return merged


# --------------------------------------------------------------------------- detector
class PIIDetector:
    def __init__(self, detectors: list[RegexDetector] | None = None,
                 ner: NERBackend | None = None, min_score: float = 0.5,
                 enabled_types: set[str] | None = None) -> None:
        self.detectors = detectors if detectors is not None else DEFAULT_DETECTORS
        self.ner = ner if ner is not None else HeuristicNER()
        self.min_score = min_score
        self.enabled_types = enabled_types

    def detect(self, text: str, min_scores: dict[str, float] | None = None) -> list[PIISpan]:
        cands: list[PIISpan] = []
        for d in self.detectors:
            cands.extend(d.find(text))
        if self.ner:
            cands.extend(self.ner.analyze(text))
        if self.enabled_types is not None:
            cands = [c for c in cands if c.entity_type in self.enabled_types]
        thresholds = min_scores or {}
        cands = [c for c in cands if c.score >= thresholds.get(c.entity_type, self.min_score)]
        return resolve_overlaps(cands)


def resolve_overlaps(spans: list[PIISpan]) -> list[PIISpan]:
    """Greedy: highest score wins, ties go to the longer span. Structured IDs inside an
    address (a PIN code, a phone) are kept separately by trimming isn't worth it: the
    containing address span is masked as a whole."""
    chosen: list[PIISpan] = []
    for s in sorted(spans, key=lambda s: (-s.score, -(s.end - s.start), s.start)):
        if not any(s.overlaps(c) for c in chosen):
            chosen.append(s)
    return sorted(chosen, key=lambda s: s.start)
