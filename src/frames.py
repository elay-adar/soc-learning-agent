"""Builds the cumulative kill-chain frames for stage 3 in code (spec section 7, D-008).

The model only supplies a short label per attack step. Frame k shows steps 1..k as a
left-to-right chain, earlier steps marked `seen` and step k marked `new`. The MITRE technique id
comes from the Knowledge Pack, never from the model. Because frames are derived from the Pack's
step list, the number of frames always equals the number of attack steps.
"""

from __future__ import annotations

import re

from src.mermaid_check import MermaidError, check_mermaid
from src.schemas import DiagramType, KnowledgePack
from src.stage_content import ChainStep, DiagramFrame

# Characters the Mermaid check refuses inside a label (see mermaid_check._LABEL), plus newlines.
_BAD_LABEL_CHARS = re.compile(r'["<>`;#\\\r\n]')
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")

_CLASS_DEFS = (
    "classDef seen fill:#e8eefc,stroke:#5b74b8",
    "classDef new fill:#ffe9b0,stroke:#c77700",
)


class FrameError(ValueError):
    """The chain entries cannot be turned into frames. The message lists every problem."""


def node_texts(pack: KnowledgePack, chain: list[ChainStep]) -> list[str]:
    """The text shown in each frame node: '1. Label (T1190)'. Raises FrameError on bad input."""
    expected = [step.number for step in pack.attack_steps]
    got = [entry.step for entry in chain]
    if got != expected:
        raise FrameError(
            f"the chain must have one entry per attack step in the Pack, in order: "
            f"steps {expected}, got {got}"
        )
    problems = [
        f"chain step {entry.step}: the label must not contain quotes, angle brackets, semicolons, "
        f"# signs, backticks, backslashes or line breaks"
        for entry in chain
        if _BAD_LABEL_CHARS.search(entry.label)
    ]
    if problems:
        raise FrameError("; ".join(problems))
    texts = []
    for step, entry in zip(pack.attack_steps, chain):
        technique = step.mitre_technique
        suffix = f" ({technique})" if technique and _TECHNIQUE_ID.match(technique) else ""
        texts.append(f"{step.number}. {entry.label.strip()}{suffix}")
    return texts


def frame_mermaid(texts: list[str], k: int) -> str:
    """Mermaid for frame k (1-based): nodes 1..k, node k highlighted as new."""
    if not 1 <= k <= len(texts):
        raise ValueError(f"frame {k} is outside 1..{len(texts)}")
    chain = " --> ".join(f'S{i}["{text}"]' for i, text in enumerate(texts[:k], start=1))
    lines = ["flowchart LR", f"    {chain}", *(f"    {d}" for d in _CLASS_DEFS)]
    if k > 1:
        lines.append(f"    class {','.join(f'S{i}' for i in range(1, k))} seen")
    lines.append(f"    class S{k} new")
    return "\n".join(lines) + "\n"


def build_frames(pack: KnowledgePack, chain: list[ChainStep]) -> list[DiagramFrame]:
    """One frame per attack step in the Pack. Raises FrameError if the chain does not fit."""
    texts = node_texts(pack, chain)
    frames = [DiagramFrame(step=k, mermaid=frame_mermaid(texts, k)) for k in range(1, len(texts) + 1)]
    problems = []
    for frame in frames:
        try:
            check_mermaid(frame.mermaid, DiagramType.KILL_CHAIN_FRAMES)
        except MermaidError as exc:
            problems.append(f"frame {frame.step}: {exc}")
    if problems:
        raise FrameError("; ".join(problems))
    return frames
