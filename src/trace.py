"""Help for the manual "five random claims trace to the Pack" check (Milestone 3).

A claim is one documented block. For each sampled claim we show the Pack entries that carry
the same source URL, so a person can compare the sentence with what the Pack recorded.
Inference and unknown blocks are not sampled: they claim no source.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field

from src.merge import normalize_url
from src.schemas import KnowledgePack, ProvenanceTag
from src.stage_content import StageContent
from src.stage_rules import pack_entries


def _words(text: str) -> set[str]:
    """Lower-case words of four or more characters, for a rough overlap score."""
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if len(w) >= 4}


@dataclass
class Claim:
    stage_number: int
    text: str
    source_url: str
    matches: list[tuple[str, str]] = field(default_factory=list)  # best (Pack label, Pack value)
    same_url_total: int = 0  # how many Pack entries carry the same URL


def sample_claims(
    stages: list[StageContent],
    pack: KnowledgePack,
    count: int = 5,
    rng: random.Random | None = None,
    with_counts: bool = False,
    max_matches: int = 3,
):
    """Pick up to `count` documented blocks at random, with the Pack entries they cite.

    Most blocks cite the same URL, so the entries with that URL are ranked by how many
    words they share with the block and only the best `max_matches` are kept.

    With with_counts=True returns (claims, number of blocks that were not documented).
    """
    rng = rng or random.Random()
    entries = pack_entries(pack)
    documented: list[Claim] = []
    skipped = 0
    for stage in stages:
        for block in stage.blocks:
            if block.tag != ProvenanceTag.DOCUMENTED:
                skipped += 1
                continue
            url = normalize_url(block.source_url)
            same_url = [
                (label, item.value)
                for label, item in entries
                if item.source_url and normalize_url(item.source_url) == url
            ]
            words = _words(block.value)
            ranked = sorted(same_url, key=lambda m: (-len(words & _words(m[1])), m[0]))
            documented.append(
                Claim(stage.stage_number, block.value, block.source_url, ranked[:max_matches], len(same_url))
            )
    chosen = rng.sample(documented, min(count, len(documented)))
    return (chosen, skipped) if with_counts else chosen
