"""Glossary rules that need no model (D-025): matching terms, and the one-sentence check.

Which terms are specific to a topic and need a definition is the Lecturer's judgment. Code only
stops a term being defined twice in a run, and keeps each definition to one short sentence.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

MAX_TERM_CHARS = 60
MAX_DEFINITION_CHARS = 200

_TRIM = " \t\"'`.,;:!?-–—“”‘’()[]"
_ABBREVIATIONS = re.compile(r"\b(?:e\.g\.|i\.e\.|etc\.|vs\.)", re.IGNORECASE)
_SECOND_SENTENCE = re.compile(r"[.!?]\s+[A-Z0-9]")
_PARENTHETICAL = re.compile(r"^(.*?)\s*\((.+)\)\s*$")


def term_keys(term: str) -> set[str]:
    """Names a term goes by, for spotting a repeat.

    Lower case, spacing and surrounding punctuation ignored, and a plain trailing plural folded
    ('endpoints' matches 'endpoint'). A parenthetical expansion counts as an alias, so
    'JNDI (Java Naming and Directory Interface)' matches 'JNDI' and the long name. Synonyms
    are not detected.
    """
    text = re.sub(r"\s+", " ", term.casefold()).strip()
    match = _PARENTHETICAL.match(text)
    parts = [match.group(1), match.group(2)] if match else [text]
    keys = set()
    for part in parts:
        part = re.sub(r"\s+", " ", part.strip(_TRIM)).strip()
        if not part:
            continue
        if len(part) > 3 and part.endswith("s") and not part.endswith("ss"):
            part = part[:-1]
        keys.add(part)
    return keys


def definition_problem(text: str) -> str | None:
    """Why a definition is not one short sentence, or None if it is."""
    text = text.strip()
    if "\n" in text or "\r" in text:
        return "a definition must be one sentence on one line"
    if len(text) > MAX_DEFINITION_CHARS:
        return f"a definition must be one sentence of at most {MAX_DEFINITION_CHARS} characters, this one has {len(text)}"
    if _SECOND_SENTENCE.search(_ABBREVIATIONS.sub("", text)):
        return "a definition must be ONE sentence, this one has more than one"
    return None


def repeated_terms(terms: Sequence[str], earlier: Sequence[tuple[int, Sequence[str]]]) -> list[str]:
    """Problems for the terms of one stage, given (stage number, its terms) for the earlier stages."""
    problems = []
    seen_before: dict[str, int] = {}
    for stage_number, earlier_terms in earlier:
        for term in earlier_terms:
            for key in term_keys(term):
                seen_before.setdefault(key, stage_number)
    seen_here: set[str] = set()
    for term in terms:
        keys = term_keys(term)
        earlier_hit = sorted(seen_before[k] for k in keys if k in seen_before)
        if earlier_hit:
            problems.append(
                f"the term '{term}' was already defined in stage {earlier_hit[0]}: use it, do not define it again"
            )
        elif keys & seen_here:
            problems.append(f"the term '{term}' is defined twice in this stage")
        seen_here |= keys
    return problems
