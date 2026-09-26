"""Sample stages for trying the local page without a model call or a real topic.

Everything here is invented layout data, not facts. Every block is tagged `inference`, so no
claim looks sourced, and the topic name says DEMO. `scripts/serve_stages.py --demo` shows it.
The sample follows the same rules as real stages (tests/test_demo.py runs it through them).
"""

from __future__ import annotations

from src.frames import build_frames
from src.schemas import KnowledgePack, StagePlan
from src.stage_content import ChainStep, StageContent, StagesFile

DEMO_TOPIC = "DEMO (sample data, not a real topic)"

_STEPS = [
    ("Attacker finds an exposed service", "T1595"),
    ("Attacker sends a crafted request", "T1190"),
    ("Attacker runs code on the server", "T1059"),
    ("Attacker reaches other systems", None),
]


def _inf(text: str) -> dict:
    return {"value": text, "tag": "inference"}


def demo_pack() -> KnowledgePack:
    return KnowledgePack.model_validate(
        {
            "topic": DEMO_TOPIC,
            "topic_type": "cve",
            "exploitation_status": "not_documented",
            "attack_steps": [
                {"number": n, "action": _inf(f"Demo step {n}"), "mitre_technique": technique}
                for n, (_, technique) in enumerate(_STEPS, start=1)
            ],
        }
    )


def demo_plan() -> StagePlan:
    return StagePlan.model_validate(
        {
            "stages": [
                {"number": 1, "key": "overview", "subject": "Overview", "depth": "overview",
                 "diagram": "story_flow"},
                {"number": 2, "key": "why_possible", "subject": "Why it is possible",
                 "depth": "technical", "diagram": "sequence"},
                {"number": 3, "key": "attack_chain", "subject": "Attack chain", "depth": "technical",
                 "diagram": "kill_chain_frames", "covers_steps": [1, 2, 3, 4]},
                {"number": 4, "key": "response_prevention", "subject": "Response and prevention",
                 "depth": "operational", "diagram": "decision_tree"},
            ]
        }
    )


def demo_stages_file() -> StagesFile:
    pack = demo_pack()
    chain = [
        ChainStep(step=n, label=label, detail=_inf(f"Possible scenario: demo text for step {n}."))
        for n, (label, _) in enumerate(_STEPS, start=1)
    ]
    stage1 = StageContent.model_validate(
        {
            "stage_number": 1, "key": "overview", "title": "Overview",
            "blocks": [
                _inf("No documented incident from official sources. This is sample data for testing the page."),
                _inf("Potential impact: a made-up server could be taken over."),
            ],
            "diagram": {
                "type": "story_flow",
                "mermaid": 'flowchart LR\n    W["Weakness"] --> A["Attack"] --> D["Damage"]\n'
                           "    classDef bad fill:#fdd,stroke:#c00\n    class W bad\n",
            },
        }
    )
    stage2 = StageContent.model_validate(
        {
            "stage_number": 2, "key": "why_possible", "title": "Why it is possible",
            "blocks": [_inf("Sample text. A made-up service trusts input it should check.")],
            "glossary": [
                {"term": "Made-up service", "definition": _inf("A pretend service used only to test the page.")},
                {"term": "Crafted input", "definition": _inf("Text written to make the pretend service misbehave.")},
            ],
            "diagram": {
                "type": "sequence",
                "mermaid": "sequenceDiagram\n    participant C as Client\n    participant S as Server\n"
                           "    C->>S: request with crafted input\n    S-->>C: response\n",
            },
        }
    )
    stage3 = StageContent.model_validate(
        {
            "stage_number": 3, "key": "attack_chain", "title": "Attack chain",
            "blocks": [_inf("Possible scenario: as explained in stage 2, the crafted input is the way in.")],
            "glossary": [{"term": "Attack step", "definition": _inf("One action the attacker takes toward a goal.")}],
            "chain": [c.model_dump(mode="json") for c in chain],
            "frames": [f.model_dump(mode="json") for f in build_frames(pack, chain)],
        }
    )
    return StagesFile(topic=DEMO_TOPIC, plan=demo_plan(), stages=[stage1, stage2, stage3])
