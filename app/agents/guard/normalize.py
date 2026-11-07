"""Section 1: clean up input before checking it.

Produces two kinds of output:

* ``clean``: NFKC-normalized text with invisible characters removed (and truncated
  if over the limit). This is what continues downstream to PII masking and the LLM.
* ``variants``: matching-only views (homoglyph skeleton, decoded base64/URL/HTML,
  de-leeted, de-spaced, compact). Detectors scan all of them; nothing downstream
  ever sees these.
"""
from __future__ import annotations

import base64
import binascii
import html
import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import unquote_plus

# --------------------------------------------------------------------------- invisibles
# Zero-width / formatting characters that render as nothing. ZWJ/ZWNJ (200C/200D) are
# handled separately because Indic scripts legitimately use them inside words.
_INVISIBLE = re.compile(
    "[­͏؜ᅟᅠ឴឵᠋-᠏​‎‏"
    "⁠-⁤⁪-⁯ㅤ︀-️﻿ﾠ\U000e0100-\U000e01ef]"
)
_BIDI = re.compile("[‪-‮⁦-⁩]")
_TAGS = re.compile("[\U000e0000-\U000e007f]")
_INDIC = "ऀ-෿"
# Keep ZWJ/ZWNJ only when sandwiched between Indic letters.
_EMOJI = re.compile("[\U0001F000-\U0001FAFF\u2600-\u27BF\uFE0F]")
_ZWJ_OUTSIDE_INDIC = re.compile(f"(?<![{_INDIC}])[‌‍]|[‌‍](?![{_INDIC}])")

# --------------------------------------------------------------------------- homoglyphs
# NFKC folds full-width and many compatibility forms, but NOT cross-script lookalikes
# (Cyrillic "о" vs Latin "o"). This table covers the ones commonly used in attacks.
_CONFUSABLES = {
    # Cyrillic lower
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "һ": "h", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ɡ": "g", "ո": "n", "ս": "u",
    # Cyrillic upper
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S", "Ԍ": "G", "Ԁ": "D",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "γ": "y", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Misc Latin lookalikes NFKC leaves alone
    "ı": "i", "ȷ": "j", "ɑ": "a", "ʀ": "r", "ʏ": "y", "ᴀ": "a", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e",
    "ɪ": "i", "ᴋ": "k", "ᴍ": "m", "ɴ": "n", "ᴏ": "o", "ᴘ": "p", "ꜱ": "s", "ᴛ": "t", "ᴜ": "u",
}
_CONFUSABLE_TABLE = str.maketrans(_CONFUSABLES)

_LEET = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a",
         "$": "s", "!": "i", "|": "l", "+": "t", "€": "e"}
_LEET_TOKEN = re.compile(r"[\w@$!|+€]+")

# "i g n o r e", "i.g.n.o.r.e", "i-g-n-o-r-e"
_SPACED = re.compile(r"(?<![\w])(?:[a-z0-9][\s.\-_*/\\]{1,3}){3,}[a-z0-9](?![\w])")
_SPACED_SEP = re.compile(r"[\s.\-_*/\\]+")

_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_PCT = re.compile(r"%[0-9a-fA-F]{2}")
_ENTITY = re.compile(r"&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);")

# --------------------------------------------------------------------------- scripts
_SCRIPT_RANGES: list[tuple[str, int, int]] = [
    ("latin", 0x0041, 0x024F),
    ("greek", 0x0370, 0x03FF),
    ("cyrillic", 0x0400, 0x052F),
    ("arabic", 0x0600, 0x06FF),
    ("devanagari", 0x0900, 0x097F),
    ("bengali", 0x0980, 0x09FF),
    ("gurmukhi", 0x0A00, 0x0A7F),
    ("gujarati", 0x0A80, 0x0AFF),
    ("oriya", 0x0B00, 0x0B7F),
    ("tamil", 0x0B80, 0x0BFF),
    ("telugu", 0x0C00, 0x0C7F),
    ("kannada", 0x0C80, 0x0CFF),
    ("malayalam", 0x0D00, 0x0D7F),
    ("cjk", 0x4E00, 0x9FFF),
]
_SCRIPT_LANG = {"devanagari": "hi", "bengali": "bn", "tamil": "ta", "telugu": "te",
                "kannada": "kn", "malayalam": "ml", "gujarati": "gu", "gurmukhi": "pa",
                "oriya": "or", "arabic": "ar", "cyrillic": "ru", "greek": "el", "cjk": "zh"}
_HINGLISH_MARKERS = {
    "hai", "hain", "karo", "kar", "karna", "kardo", "karde", "karwana", "mujhe", "mera", "meri",
    "mere", "kya", "nahi", "nahin", "aur", "ke", "liye", "chahiye", "bhai", "bhaiya", "ji",
    "pichle", "pehle", "sab", "saare", "bhool", "bhul", "jao", "batao", "dikhao", "ko", "se",
    "ka", "ki", "abhi", "kal", "aaj", "wala", "wali", "accha", "theek", "jaldi", "bhejo", "ghar",
}


def _script_of(ch: str) -> str | None:
    cp = ord(ch)
    if not ch.isalpha():
        return None
    for name, lo, hi in _SCRIPT_RANGES:
        if lo <= cp <= hi:
            return name
    return "other"


@dataclass
class NormalizationSettings:
    max_chars: int = 4000
    max_tokens: int = 1000
    decode_base64: bool = True
    max_decode_depth: int = 2
    tokenizer: Callable[[str], int] | None = None  # plug in tiktoken etc.


@dataclass
class NormalizedText:
    original: str
    clean: str  # NFKC, invisibles stripped, truncated -> continues downstream
    variants: dict[str, str] = field(default_factory=dict)  # matching only
    decoded_payloads: list[str] = field(default_factory=list)
    invisible_count: int = 0
    bidi_count: int = 0
    tag_count: int = 0
    mixed_script_words: int = 0
    homoglyph_count: int = 0
    spaced_letter_runs: int = 0  # "i.g.n.o.r.e..." runs of >= 8 letters
    scripts: dict[str, int] = field(default_factory=dict)
    primary_script: str = "unknown"
    language: str = "unknown"
    char_count: int = 0
    token_count: int = 0
    original_token_count: int = 0
    over_limit: bool = False
    truncated: bool = False

    def all_variants(self) -> dict[str, str]:
        return self.variants


# --------------------------------------------------------------------------- helpers
def estimate_tokens(text: str) -> int:
    """Tokenizer-free estimate. Latin ~4 chars/token; Indic and other scripts are
    much denser for BPE tokenizers, roughly 1 token per 1.5 chars."""
    if not text:
        return 0
    latin = sum(1 for c in text if ord(c) < 0x250)
    other = len(text) - latin
    words = len(text.split())
    return max(math.ceil(latin / 4 + other / 1.5), math.ceil(words * 1.1))


def strip_invisibles(text: str) -> tuple[str, int, int, int, str]:
    """Returns (text, invisible_count, bidi_count, tag_count, tag_payload).

    Unicode tag characters (U+E0000 block) mirror ASCII and are used for "ASCII
    smuggling": the hidden text is recovered as ``tag_payload`` so it can be scanned.
    """
    tags = _TAGS.findall(text)
    tag_payload = "".join(chr(ord(c) - 0xE0000) for c in tags if 0x20 <= ord(c) - 0xE0000 < 0x7F)
    text = _TAGS.sub("", text)
    text, n_bidi = _BIDI.subn("", text)
    text, n_inv = _INVISIBLE.subn("", text)
    # ZWJ between emoji (family/flag sequences) is normal; elsewhere it's suspicious.
    suspicious_zwj = 0

    def _drop(m: re.Match) -> str:
        nonlocal suspicious_zwj
        s, i = m.string, m.start()
        prev = s[i - 1] if i > 0 else ""
        nxt = s[i + 1] if i + 1 < len(s) else ""
        if not (_EMOJI.match(prev) or _EMOJI.match(nxt)):
            suspicious_zwj += 1
        return ""

    text = _ZWJ_OUTSIDE_INDIC.sub(_drop, text)
    return text, n_inv + suspicious_zwj, n_bidi, len(tags), tag_payload


def skeleton(text: str) -> tuple[str, int]:
    out = text.translate(_CONFUSABLE_TABLE)
    changed = sum(1 for a, b in zip(text, out) if a != b)
    return out, changed


def count_mixed_script_words(text: str) -> int:
    n = 0
    for word in re.findall(r"\w{2,}", text):
        scripts = {_script_of(c) for c in word} - {None}
        if "latin" in scripts and ({"cyrillic", "greek"} & scripts):
            n += 1
    return n


def deleet(text: str) -> str:
    def fix(m: re.Match) -> str:
        tok = m.group(0)
        if not any(c.isalpha() for c in tok) or not any(c in _LEET for c in tok):
            return tok  # leave pure numbers (prices, phones) alone
        # trailing "!" / "$" is punctuation more often than leet
        core, tail = tok, ""
        while core and core[-1] in "!$|+":
            core, tail = core[:-1], core[-1] + tail
        return "".join(_LEET.get(c, c) for c in core) + tail
    return _LEET_TOKEN.sub(fix, text)


def despace(text: str) -> str:
    """Collapse "i g n o r e   a l l" -> "ignore all". A wider gap than the letter
    separator is kept as a word break."""
    def fix(m: re.Match) -> str:
        run = re.sub(r"\s{2,}", "\x00", m.group(0))
        return _SPACED_SEP.sub("", run).replace("\x00", " ")
    return _SPACED.sub(fix, text)


def compact(text: str) -> str:
    return re.sub(rf"[^a-z0-9{_INDIC}]", "", text)


def _url_html_decode(text: str, rounds: int = 3) -> str:
    for _ in range(rounds):
        new = text
        if _ENTITY.search(new):
            new = html.unescape(new)
        if _PCT.search(new):
            new = unquote_plus(new)
        if new == text:
            break
        text = new
    return text


def _try_b64(blob: str) -> str | None:
    s = blob.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        raw = base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded:
        return None
    printable = sum(1 for c in decoded if c.isprintable() or c in "\n\t")
    if printable / len(decoded) < 0.9 or not re.search(r"[A-Za-zऀ-෿]{3}", decoded):
        return None
    return decoded


def decode_base64_blobs(text: str, depth: int) -> list[str]:
    found: list[str] = []
    frontier = [text]
    for _ in range(depth):
        nxt = []
        for t in frontier:
            for m in _B64.finditer(t):
                blob = m.group(0)
                # skip things that are obviously just words/ids (no case mix, no digits/+/)
                if blob.isalpha() and (blob.islower() or blob.isupper()):
                    continue
                d = _try_b64(blob)
                if d:
                    found.append(d)
                    nxt.append(d)
        frontier = nxt
        if not frontier:
            break
    return found


def detect_language(text: str) -> tuple[dict[str, int], str, str]:
    counts: dict[str, int] = {}
    for ch in text:
        s = _script_of(ch)
        if s:
            counts[s] = counts.get(s, 0) + 1
    if not counts:
        return counts, "unknown", "unknown"
    primary = max(counts, key=counts.get)
    if primary == "latin":
        toks = re.findall(r"[a-z]+", text.lower())
        markers = {t for t in toks if t in _HINGLISH_MARKERS}
        hits = sum(1 for t in toks if t in _HINGLISH_MARKERS)
        if len(markers) >= 2 and toks and hits / len(toks) >= 0.15:
            return counts, primary, "hinglish"
        return counts, primary, "en"
    return counts, primary, _SCRIPT_LANG.get(primary, "other")


def truncate_to_tokens(text: str, max_tokens: int, counter: Callable[[str], int]) -> str:
    if counter(text) <= max_tokens:
        return text
    lo, hi = 0, len(text)
    while lo < hi:  # binary search the longest prefix that fits
        mid = (lo + hi + 1) // 2
        if counter(text[:mid]) <= max_tokens:
            lo = mid
        else:
            hi = mid - 1
    cut = text[:lo]
    # prefer cutting at a word boundary
    sp = cut.rfind(" ")
    return cut[:sp] if sp > len(cut) * 0.8 else cut


# --------------------------------------------------------------------------- main entry
def normalize(text: str, settings: NormalizationSettings | None = None) -> NormalizedText:
    st = settings or NormalizationSettings()
    counter = st.tokenizer or estimate_tokens

    nfkc = unicodedata.normalize("NFKC", text or "")
    stripped, n_inv, n_bidi, n_tags, tag_payload = strip_invisibles(nfkc)

    original_tokens = counter(stripped)
    over = len(stripped) > st.max_chars or original_tokens > st.max_tokens
    clean = stripped
    if over:
        clean = clean[: st.max_chars]
        clean = truncate_to_tokens(clean, st.max_tokens, counter)

    lower = clean.casefold()
    skel_raw, n_homo = skeleton(clean)
    skel = skel_raw.casefold()
    decoded = _url_html_decode(skel)

    payloads: list[str] = []
    if tag_payload.strip():
        payloads.append(tag_payload)
    if st.decode_base64:
        # base64 is case-sensitive, so decode from the un-casefolded text
        payloads += decode_base64_blobs(_url_html_decode(clean), st.max_decode_depth)
    payload_norm = []
    for p in payloads:
        p2, *_ = strip_invisibles(unicodedata.normalize("NFKC", p))
        payload_norm.append(skeleton(p2)[0].casefold())
    payload_text = "\n".join(payload_norm)

    leet = deleet(decoded)
    desp = despace(leet)

    variants = {
        "lower": lower,
        "skeleton": skel,
        "decoded": decoded,
        "leet": leet,
        "despaced": desp,
        "compact": compact(desp + " " + payload_text),
    }
    if payload_text:
        variants["payloads"] = payload_text
        variants["payloads_leet"] = despace(deleet(payload_text))

    scripts, primary, lang = detect_language(clean)
    spaced_runs = sum(1 for m in _SPACED.finditer(leet)
                      if sum(c.isalpha() for c in m.group(0)) >= 8)

    return NormalizedText(
        original=text,
        clean=clean,
        variants=variants,
        decoded_payloads=payloads,
        invisible_count=n_inv,
        bidi_count=n_bidi,
        tag_count=n_tags,
        mixed_script_words=count_mixed_script_words(clean),
        homoglyph_count=n_homo,
        spaced_letter_runs=spaced_runs,
        scripts=scripts,
        primary_script=primary,
        language=lang,
        char_count=len(clean),
        token_count=counter(clean),
        original_token_count=original_tokens,
        over_limit=over,
        truncated=over and clean != stripped,
    )
