"""Rules a Stage Plan must satisfy, enforced in code (spec section 6.1, CLAUDE.md).

The Planner is a model, so its plan is checked here and sent back with the reasons if it
breaks a rule. All problems are collected and reported together, so one correction round
can fix them all.
"""

from __future__ import annotations

from src.schemas import KnowledgePack, StagePlan
from src.stages_config import StagesConfig

# Stages every plan must contain. A 3-stage plan is exactly these three: overview, why it
# is possible, and response and prevention. Stages 3 and 4 are the optional ones.
REQUIRED_KEYS = ("overview", "why_possible", "response_prevention")
ATTACK_CHAIN_KEY = "attack_chain"


class PlanRuleError(ValueError):
    """The plan breaks one or more rules. The message lists every problem."""


def check_plan(plan: StagePlan, pack: KnowledgePack, config: StagesConfig) -> None:
    """Raise PlanRuleError unless the plan follows the stage definitions and fits the pack."""
    problems: list[str] = []
    definitions = {d.key: d for d in config.stages}
    order = [d.key for d in config.stages]
    keys = [s.key for s in plan.stages]

    for key in sorted(set(keys)):
        if key not in definitions:
            problems.append(f"unknown stage key '{key}' (allowed: {', '.join(order)})")
        elif keys.count(key) > 1:
            problems.append(f"stage key '{key}' is used more than once")
    for key in REQUIRED_KEYS:
        if key not in keys:
            problems.append(f"the plan must include the '{key}' stage")

    known = [k for k in keys if k in definitions]
    if len(set(known)) == len(known) and known != sorted(known, key=order.index):
        problems.append(f"stages must follow the definition order: {', '.join(order)}")

    steps = [step.number for step in pack.attack_steps]
    for stage in plan.stages:
        definition = definitions.get(stage.key)
        if definition is None:
            continue
        if stage.depth not in definition.allowed_depths:
            allowed = ", ".join(d.value for d in definition.allowed_depths)
            problems.append(
                f"stage {stage.number} ('{stage.key}'): depth '{stage.depth.value}' is not "
                f"allowed (allowed: {allowed})"
            )
        if stage.diagram not in definition.allowed_diagrams:
            allowed = ", ".join(d.value for d in definition.allowed_diagrams)
            problems.append(
                f"stage {stage.number} ('{stage.key}'): diagram '{stage.diagram.value}' is "
                f"not allowed (allowed: {allowed})"
            )
        if stage.key == ATTACK_CHAIN_KEY:
            if not steps:
                problems.append(
                    f"stage {stage.number} is the attack chain but the pack has no attack steps"
                )
            elif set(stage.covers_steps) != set(steps) and not _missing(stage, steps):
                problems.append(
                    f"stage {stage.number} (attack chain) must cover every attack step: "
                    f"{steps}, got {stage.covers_steps}"
                )

    try:
        plan.check_against(pack)
    except ValueError as exc:
        problems.append(str(exc))

    if problems:
        raise PlanRuleError("; ".join(problems))


def _missing(stage, steps: list[int]) -> bool:
    """True when the stage cites a step the pack lacks (reported by check_against instead)."""
    return any(n not in steps for n in stage.covers_steps)
