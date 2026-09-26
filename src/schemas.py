"""Data schemas for the SOC Learning Agent.

Two central records:

* KnowledgePack: written once by the Researcher, read by every other component.
* StagePlan: written by the Planner, followed by the Lecturer.

Rules that must never depend on a model following instructions (provenance,
exploitation status, step references) are enforced here as validators.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator


# --------------------------------------------------------------------------
# Enums: closed lists of allowed values
# --------------------------------------------------------------------------


class ProvenanceTag(str, Enum):
    DOCUMENTED = "documented"
    SECONDARY = "secondary"  # from the secondary-source allowlist, never official (D-027)
    INFERENCE = "inference"
    UNKNOWN = "unknown"


class ExploitationStatus(str, Enum):
    DOCUMENTED = "documented"
    NOT_DOCUMENTED = "not_documented"
    UNKNOWN = "unknown"


class TopicType(str, Enum):
    CVE = "cve"
    TECHNIQUE = "technique"
    MISCONFIGURATION = "misconfiguration"


class FieldStatus(str, Enum):
    VALUE = "value"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class DetectionKind(str, Enum):
    TELEMETRY = "telemetry"
    EVENT_ID = "event_id"
    DETECTION_LOGIC = "detection_logic"
    IOC = "ioc"
    FALSE_POSITIVE = "false_positive"
    DETECTION_GAP = "detection_gap"


class ResponseKind(str, Enum):
    TRIAGE = "triage"
    ESCALATION = "escalation"
    CONTAINMENT = "containment"
    RECOVERY = "recovery"
    HARDENING = "hardening"
    LESSON = "lesson"


class Depth(str, Enum):
    OVERVIEW = "overview"
    CONCEPTUAL = "conceptual"
    TECHNICAL = "technical"
    OPERATIONAL = "operational"


class DiagramType(str, Enum):
    STORY_FLOW = "story_flow"
    ARCHITECTURE = "architecture"
    SEQUENCE = "sequence"
    KILL_CHAIN_FRAMES = "kill_chain_frames"
    DETECTION_FLOW = "detection_flow"
    DECISION_TREE = "decision_tree"
    TIMELINE = "timeline"


# --------------------------------------------------------------------------
# Base class: reject unknown fields so invented keys are caught
# --------------------------------------------------------------------------


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------
# Knowledge Pack building blocks
# --------------------------------------------------------------------------


class SourcedValue(StrictModel):
    """A single claim with its provenance tag and, when documented, its source."""

    value: str = Field(min_length=1)
    tag: ProvenanceTag
    source_url: str | None = None

    @model_validator(mode="after")
    def check_source(self) -> SourcedValue:
        if self.tag in (ProvenanceTag.DOCUMENTED, ProvenanceTag.SECONDARY) and not self.source_url:
            raise ValueError(f"a '{self.tag.value}' item needs a source_url")
        if self.source_url and not self.source_url.startswith(("http://", "https://")):
            raise ValueError("source_url must start with http:// or https://")
        return self


class TriageField(StrictModel):
    """One triage-card field: a sourced value, 'not applicable', or 'unknown'."""

    status: FieldStatus
    item: SourcedValue | None = None

    @model_validator(mode="after")
    def check_item(self) -> TriageField:
        if self.status == FieldStatus.VALUE and self.item is None:
            raise ValueError("status 'value' requires an item")
        if self.status != FieldStatus.VALUE and self.item is not None:
            raise ValueError("an item is only allowed when status is 'value'")
        return self


class AttackStep(StrictModel):
    number: int = Field(ge=1)
    action: SourcedValue
    mitre_technique: str | None = None


class Incident(StrictModel):
    name: str = Field(min_length=1)
    impact: SourcedValue


class DetectionItem(StrictModel):
    kind: DetectionKind
    content: SourcedValue
    step: int | None = Field(default=None, ge=1)  # attack step this relates to


class ResponseItem(StrictModel):
    kind: ResponseKind
    content: SourcedValue


class SourceConflict(StrictModel):
    """Two or more sources that disagree on the same point."""

    subject: str = Field(min_length=1)
    claims: list[SourcedValue] = Field(min_length=2)


# --------------------------------------------------------------------------
# Knowledge Pack
# --------------------------------------------------------------------------


class KnowledgePack(StrictModel):
    topic: str = Field(min_length=1)
    topic_type: TopicType
    exploitation_status: ExploitationStatus
    exploitation_evidence: SourcedValue | None = None
    incidents: list[Incident] = []
    triage_fields: dict[str, TriageField] = {}
    weakness_mechanism: list[SourcedValue] = []
    attack_steps: list[AttackStep] = []
    detection_items: list[DetectionItem] = []
    response_items: list[ResponseItem] = []
    conflicts: list[SourceConflict] = []

    @model_validator(mode="after")
    def check_exploitation_rules(self) -> KnowledgePack:
        status = self.exploitation_status
        if status == ExploitationStatus.DOCUMENTED:
            if self.exploitation_evidence is None:
                raise ValueError("documented exploitation needs exploitation_evidence")
            if self.exploitation_evidence.tag != ProvenanceTag.DOCUMENTED:
                raise ValueError("exploitation_evidence must be tagged 'documented'")
        else:
            if self.exploitation_evidence is not None or self.incidents:
                raise ValueError(
                    "evidence and incidents are only allowed when exploitation is documented"
                )
        return self

    @model_validator(mode="after")
    def check_step_numbers(self) -> KnowledgePack:
        numbers = [step.number for step in self.attack_steps]
        if numbers != list(range(1, len(numbers) + 1)):
            raise ValueError("attack step numbers must run 1, 2, 3... without gaps")
        valid = set(numbers)
        for item in self.detection_items:
            if item.step is not None and item.step not in valid:
                raise ValueError(f"detection item refers to missing attack step {item.step}")
        return self


# --------------------------------------------------------------------------
# Stage Plan
# --------------------------------------------------------------------------


class StagePlanItem(StrictModel):
    number: int = Field(ge=1)  # position in this plan, 1..n without gaps
    key: str = Field(min_length=1)  # which definition in config/stages.toml this stage uses
    subject: str = Field(min_length=1)
    depth: Depth
    diagram: DiagramType
    covers_steps: list[int] = []


class StagePlan(StrictModel):
    stages: list[StagePlanItem] = Field(min_length=1)

    @model_validator(mode="after")
    def check_numbering(self) -> StagePlan:
        numbers = [stage.number for stage in self.stages]
        if numbers != list(range(1, len(numbers) + 1)):
            raise ValueError("stage numbers must run 1, 2, 3... without gaps")
        return self

    @property
    def stage_count(self) -> int:
        return len(self.stages)

    def check_against(self, pack: KnowledgePack) -> None:
        """Raise ValueError if a stage refers to an attack step the pack lacks."""
        valid = {step.number for step in pack.attack_steps}
        for stage in self.stages:
            missing = [n for n in stage.covers_steps if n not in valid]
            if missing:
                raise ValueError(
                    f"stage {stage.number} refers to missing attack steps {missing}"
                )
