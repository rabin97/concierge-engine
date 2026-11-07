"""Fuzzing / mutation: generate encodings and surface variants of known attacks.

Paraphrase generation needs an LLM; ``paraphrase_with`` takes any async completion
function. The deterministic mutators below need nothing.
"""
from __future__ import annotations

import base64
import random
from typing import Awaitable, Callable
from urllib.parse import quote

HOMOGLYPHS = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і", "x": "х", "y": "у"}
LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}


def m_upper(t, r): return t.upper()
def m_fullwidth(t, r): return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in t)
def m_homoglyph(t, r): return "".join(HOMOGLYPHS.get(c, c) if r.random() < 0.6 else c for c in t)
def m_leet(t, r): return "".join(LEET.get(c.lower(), c) if r.random() < 0.7 else c for c in t)
def m_zero_width(t, r): return "".join(c + ("​" if r.random() < 0.5 else "") for c in t)
def m_spaced(t, r): return " ".join(t)
def m_dotted(t, r): return ".".join(t.replace(" ", ""))
def m_base64(t, r): return "please decode: " + base64.b64encode(t.encode()).decode()
def m_url(t, r): return quote(t)
def m_html(t, r): return "".join(f"&#{ord(c)};" for c in t)
def m_tags(t, r): return "book a cleaner " + "".join(chr(0xE0000 + ord(c)) for c in t if ord(c) < 0x7F)
def m_wrapped(t, r): return f"Book a plumber for tomorrow. Also, {t[0].lower() + t[1:]}"
def m_bidi(t, r): return "‮" + t + "‬"


MUTATORS: dict[str, Callable[[str, random.Random], str]] = {
    "upper": m_upper, "fullwidth": m_fullwidth, "homoglyph": m_homoglyph, "leet": m_leet,
    "zero_width": m_zero_width, "spaced": m_spaced, "dotted": m_dotted, "base64": m_base64,
    "url": m_url, "html": m_html, "tags": m_tags, "wrapped": m_wrapped, "bidi": m_bidi,
}


def mutate_all(texts: list[str], seed: int = 7) -> list[dict]:
    r = random.Random(seed)
    out = []
    for t in texts:
        if not t.isascii():
            continue  # surface mutators target Latin text
        for name, fn in MUTATORS.items():
            out.append({"text": fn(t, r), "label": "attack", "mutation": name, "seed_text": t})
    return out


PARAPHRASE_PROMPT = ("Rewrite the following message {n} different ways, keeping its intent. "
                     "One per line, no numbering.\n\n{text}")


async def paraphrase_with(complete: Callable[[str], Awaitable[str]], text: str, n: int = 5) -> list[str]:
    reply = await complete(PARAPHRASE_PROMPT.format(n=n, text=text))
    return [line.strip() for line in reply.splitlines() if line.strip()][:n]
