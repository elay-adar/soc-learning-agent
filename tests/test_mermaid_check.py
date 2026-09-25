"""Tests for src/mermaid_check.py: a strict check of the Mermaid subset we allow.

It does not render anything. It rejects what we do not allow, so a diagram that passes is
one the Mermaid library can be expected to draw. A one-time manual render check covers the rest.
"""

import pytest

from src.mermaid_check import MermaidError, check_mermaid
from src.schemas import DiagramType

FLOW = """flowchart LR
    W["Weakness: input is evaluated"] --> A["Attack: crafted request"]
    A --> D(["Damage: server takeover"])
    classDef bad fill:#fdd,stroke:#c00
    class W bad
"""

SEQ = """sequenceDiagram
    participant U as Client
    participant S as Server
    U->>S: request with crafted value
    S-->>U: response
    Note over U,S: the value is evaluated
"""


def test_valid_flowchart_passes():
    check_mermaid(FLOW, DiagramType.STORY_FLOW)


def test_valid_sequence_passes():
    check_mermaid(SEQ, DiagramType.SEQUENCE)


def test_architecture_uses_a_flowchart_with_subgraphs_and_labeled_edges():
    text = """flowchart TD
    subgraph app["Application"]
        L["Logger"]
        H["Handler"]
    end
    C["Client"] -->|"sends input"| H
    H --> L
    style L fill:#fdd,stroke:#c00
"""
    check_mermaid(text, DiagramType.ARCHITECTURE)


def test_chained_edges_pass():
    check_mermaid('flowchart LR\n    A["a"] --> B["b"] --> C["c"]\n', DiagramType.STORY_FLOW)


def test_comments_and_blank_lines_are_ignored():
    check_mermaid('flowchart LR\n\n    %% a note\n    A["a"] --> B["b"]\n', DiagramType.STORY_FLOW)


@pytest.mark.parametrize(
    "text, reason",
    [
        ("", "empty"),
        ("graph LR\n A[\"a\"] --> B[\"b\"]\n", "first line"),
        ("flowchart XX\n A[\"a\"] --> B[\"b\"]\n", "first line"),
        ('flowchart LR\n A["a"] --> B\n', "before it is defined"),
        ('flowchart LR\n A --> B["b"]\n', "before it is defined"),
        ('flowchart LR\n A[a] --> B["b"]\n', "cannot read"),
        ('flowchart LR\n A["a <b>x</b>"] --> B["b"]\n', "cannot read"),
        ('flowchart LR\n A["a"] --> B["b"]\n end\n', "end"),
        ('flowchart LR\n subgraph s["S"]\n A["a"] --> B["b"]\n', "subgraph"),
        ('flowchart LR\n end["x"] --> B["b"]\n', "reserved"),
        ('flowchart LR\n A["a"] --> B["b"]\n class A missing\n', "class"),
        ('flowchart LR\n A["a"] --> B["b"]\n click A "https://x.example"\n', "cannot read"),
        ('flowchart LR\n A["a"] --> B["b"]\n %%{init: {"x": 1}}%%\n', "cannot read"),
        ('flowchart LR\n A["a"]--B["b"]\n', "cannot read"),
        ('flowchart LR\n A["a"] --> B["b"]; C["c"]\n', "cannot read"),
    ],
)
def test_bad_flowcharts_are_rejected(text, reason):
    with pytest.raises(MermaidError, match=reason):
        check_mermaid(text, DiagramType.STORY_FLOW)


@pytest.mark.parametrize(
    "text, reason",
    [
        ("sequenceDiagram\n participant U\n U->>S: hi\n", "not declared"),
        ("sequenceDiagram\n participant U\n participant S\n U=>S: hi\n", "cannot read"),
        ("sequenceDiagram\n participant U\n participant S\n U->>S: a; b\n", "cannot read"),
        ("sequenceDiagram\n participant U\n participant S\n loop x\n U->>S: hi\n", "loop"),
        ("sequenceDiagram\n participant U\n participant S\n end\n", "end"),
        ("sequenceDiagram\n participant U\n participant S\n U->>S: <b>x</b>\n", "cannot read"),
    ],
)
def test_bad_sequences_are_rejected(text, reason):
    with pytest.raises(MermaidError, match=reason):
        check_mermaid(text, DiagramType.SEQUENCE)


def test_sequence_blocks_pass_when_balanced():
    text = SEQ + "    loop every request\n        U->>S: again\n    end\n"
    check_mermaid(text, DiagramType.SEQUENCE)


def test_header_must_match_the_diagram_type():
    with pytest.raises(MermaidError, match="sequenceDiagram"):
        check_mermaid(FLOW, DiagramType.SEQUENCE)
    with pytest.raises(MermaidError, match="flowchart"):
        check_mermaid(SEQ, DiagramType.STORY_FLOW)


def test_types_without_a_checker_are_refused_not_waved_through():
    with pytest.raises(MermaidError, match="not supported"):
        check_mermaid(FLOW, DiagramType.DETECTION_FLOW)


def test_size_limit():
    lines = "\n".join(f'    N{i}["n"] --> N{i + 1}["n"]' for i in range(0, 60, 2))
    with pytest.raises(MermaidError, match="too large"):
        check_mermaid("flowchart LR\n" + lines + "\n", DiagramType.STORY_FLOW)


def test_all_problems_are_reported_together():
    text = 'flowchart LR\n A --> B\n C[c] --> D["d"]\n'
    with pytest.raises(MermaidError) as info:
        check_mermaid(text, DiagramType.STORY_FLOW)
    assert "line 2" in str(info.value) and "line 3" in str(info.value)
