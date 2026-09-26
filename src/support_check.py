"""A hint for the manual check: sentences the cited URL's Pack entries do not seem to support (D-036).

The URL check in src/stage_rules.py proves a block cites something in the Pack, not that each
sentence is supported by it (D-020). This adds a rough measure. For every sentence in a documented
or secondary text it counts how many of its content words appear in the Pack entries under the URL
it cites, and lists the sentences that fall below THRESHOLD.

Limits, stated plainly: this compares words, not meaning. A harmless bridging sentence ("as
explained in stage 2") can score low, and a wrong claim made of familiar words can score high. So it
only warns and never rejects a stage; on the first real run a rejection would have forced needless
corrections on about a third of the hits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.merge import normalize_url
from src.schemas import KnowledgePack, ProvenanceTag
from src.stage_content import StageContent
from src.stage_rules import pack_entries

THRESHOLD = 0.6  # a sentence sharing fewer than 60% of its content words with its URL's entries is flagged
MIN_WORDS = 4  # shorter sentences are skipped: too little to compare

_STOP = frozenset(
    (
        # everyday function words of four or more letters
        "this that with from have been were will would could should there their which what when where "
        "than then them they into onto also only such each every both more most some other these those "
        "about because while after before under over between through does done doing being very much many "
        "your shall"
        # words that structure an explanation without adding a claim
        " stage step steps precondition preconditions explain explained explains described describe "
        "describes failure mechanism root cause anchor normal function"
    ).split()
)
_SUFFIXES = ("ing", "ed", "es", "s")


def _stem(word: str) -> str:
    """Strip a common ending so ticket/tickets and cracked/cracks compare equal (crudely)."""
    for suffix in _SUFFIXES:
        if word.endswith(suffix) and len(word) - len(suffix) >= 4:
            return word[: -len(suffix)]
    return word


def content_words(text: str) -> set[str]:
    """Lower-case words of four or more letters, without function words, reduced to a rough stem."""
    words = set()
    for word in re.findall(r"[a-z0-9]+", text.lower()):
        if len(word) < 4 or word in _STOP:
            continue
        stem = _stem(word)
        if stem not in _STOP:
            words.add(stem)
    return words


def split_sentences(text: str) -> list[str]:
    """Split on . ! ? and ; followed by a space. The mark stays with its sentence."""
    return [s.strip() for s in re.split(r"(?<=[.!?;])\s+", text) if s.strip()]


@dataclass
class WeakSentence:
    stage_number: int
    sentence: str
    source_url: str
    tag: str  # "documented" or "secondary"
    coverage: float  # share of the sentence's content words found under its URL
    missing: list[str] = field(default_factory=list)
    other_urls: list[str] = field(default_factory=list)  # other Pack URLs that do hold some missing words


def weak_sentences(
    stages: list[StageContent], pack: KnowledgePack, threshold: float = THRESHOLD
) -> list[WeakSentence]:
    """Sentences below `threshold`, worst first. Blocks, stage 3 step details and glossary
    definitions are checked; inference and unknown text claims no source and is ignored."""
    pools: dict[str, set[str]] = {}
    for _, entry in pack_entries(pack):
        if entry.source_url:
            pools.setdefault(normalize_url(entry.source_url), set()).update(content_words(entry.value))

    found: list[WeakSentence] = []
    for stage in stages:
        for block in stage.all_tagged():
            if block.tag not in (ProvenanceTag.DOCUMENTED, ProvenanceTag.SECONDARY):
                continue
            url = normalize_url(block.source_url)
            pool = pools.get(url, set())
            for sentence in split_sentences(block.value):
                words = content_words(sentence)
                if len(words) < MIN_WORDS:
                    continue
                coverage = len(words & pool) / len(words)
                if coverage >= threshold:
                    continue
                missing = sorted(words - pool)
                other = sorted(
                    other_url
                    for other_url, other_pool in pools.items()
                    if other_url != url and other_pool & set(missing)
                )
                found.append(
                    WeakSentence(stage.stage_number, sentence, block.source_url, block.tag.value, coverage, missing, other)
                )
    return sorted(found, key=lambda w: w.coverage)
