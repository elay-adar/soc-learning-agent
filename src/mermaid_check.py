"""A strict check of the small Mermaid subset the agent may write (spec section 7, Option A).

Node.js is not installed, so nothing is rendered here. Instead this module accepts only a
narrow, well-understood subset and rejects everything else. A diagram that passes should draw
in the Mermaid library; a failure is sent back to the model with the line number and reason.

Allowed:
* flowchart (used for story flow and architecture): quoted labels, edges with optional
  quoted labels, subgraphs, classDef, class, style. Every node is defined before it is reused.
* sequenceDiagram: declared participants, messages, notes, balanced loop/alt/opt blocks.
Rejected: click and other interactive lines, init directives, HTML in labels, semicolons,
reserved words as ids, unbalanced blocks.
"""

from __future__ import annotations

import re

from src.schemas import DiagramType

MAX_LINES = 60
MAX_NODES = 25


class MermaidError(ValueError):
    """The diagram is outside the allowed subset. The message lists every problem."""


_HEADERS = {
    DiagramType.STORY_FLOW: "flowchart",
    DiagramType.ARCHITECTURE: "flowchart",
    DiagramType.SEQUENCE: "sequenceDiagram",
}

_ID = r"[A-Za-z][A-Za-z0-9_]*"
_LABEL = r'"[^"<>`;#\\]*"'
_RESERVED = {"end", "graph", "flowchart", "subgraph", "class", "classdef", "style", "click",
             "default", "direction", "linkstyle", "callback", "call", "href"}
_NODE = re.compile(
    rf"({_ID})(\[{_LABEL}\]|\({_LABEL}\)|\(\[{_LABEL}\]\)|\{{{_LABEL}\}})?"
)
_ARROW = re.compile(rf'(?:-->|-\.->|==>|---)(?:\|{_LABEL}\|)?')
_HEADER = re.compile(r"flowchart (LR|RL|TD|TB|BT)$")
_SUBGRAPH = re.compile(rf"subgraph ({_ID})(?:\[{_LABEL}\])?$")
_CLASSDEF = re.compile(rf"classDef ({_ID}) ([a-z-]+:#?[A-Za-z0-9]+(?:,[a-z-]+:#?[A-Za-z0-9]+)*)$")
_CLASS = re.compile(rf"class ({_ID}(?:,{_ID})*) ({_ID})$")
_STYLE = re.compile(rf"style ({_ID}) ([a-z-]+:#?[A-Za-z0-9]+(?:,[a-z-]+:#?[A-Za-z0-9]+)*)$")

_TEXT = r"[^;#<>`\\]*"
_PARTICIPANT = re.compile(rf"(?:participant|actor) ({_ID})(?: as {_TEXT[:-1]}+)?$")
_MESSAGE = re.compile(rf"({_ID})(?:->>|-->>|->|-->)([+-]?)({_ID}): {_TEXT[:-1]}+$")
_NOTE = re.compile(rf"Note (?:over ({_ID})(?:,({_ID}))?|(?:left|right) of ({_ID})): {_TEXT[:-1]}+$")
_ACTIVATE = re.compile(rf"(?:activate|deactivate) ({_ID})$")
_BLOCK_OPEN = re.compile(rf"(loop|alt|opt) {_TEXT[:-1]}+$")
_BLOCK_ELSE = re.compile(rf"else(?: {_TEXT[:-1]}+)?$")


def check_mermaid(text: str, diagram_type: DiagramType) -> None:
    """Raise MermaidError unless `text` is inside the allowed subset for `diagram_type`."""
    header = _HEADERS.get(diagram_type)
    if header is None:
        raise MermaidError(f"diagrams of type '{diagram_type.value}' are not supported yet")
    lines = [(n, raw.strip()) for n, raw in enumerate(text.splitlines(), start=1)]
    lines = [(n, s) for n, s in lines if s and not s.startswith("%%") or s.startswith("%%{")]
    if not lines:
        raise MermaidError("the diagram is empty")
    problems: list[str] = []
    first_no, first = lines[0]
    if header == "flowchart":
        header_ok = bool(_HEADER.match(first))
        expected = "'flowchart' with a direction (LR, RL, TD, TB or BT)"
    else:
        header_ok = first == "sequenceDiagram"
        expected = "'sequenceDiagram'"
    if not header_ok:
        problems.append(f"line {first_no}: first line must be {expected}, got '{first}'")
    if len(lines) > MAX_LINES:
        problems.append(f"the diagram is too large ({len(lines)} lines, at most {MAX_LINES})")
    if header_ok:
        problems += (_check_flowchart if header == "flowchart" else _check_sequence)(lines[1:])
    if problems:
        raise MermaidError("; ".join(problems))


def _check_flowchart(lines: list[tuple[int, str]]) -> list[str]:
    problems: list[str] = []
    defined: dict[str, bool] = {}  # id -> has a label
    classes: set[str] = set()
    open_subgraphs = 0

    def read_node(s: str, pos: int, no: int) -> int | None:
        match = _NODE.match(s, pos)
        if not match:
            return None
        node_id, shape = match.groups()
        if node_id.lower() in _RESERVED:
            problems.append(f"line {no}: '{node_id}' is a reserved word and cannot be an id")
        if shape:
            defined[node_id] = True
        elif node_id not in defined:
            problems.append(f"line {no}: '{node_id}' is used before it is defined with a label")
        return match.end()

    for no, s in lines:
        if s.startswith("%%"):
            problems.append(f"line {no}: cannot read '{s}' (directives are not allowed)")
        elif s == "end":
            if open_subgraphs == 0:
                problems.append(f"line {no}: 'end' without a matching subgraph")
            else:
                open_subgraphs -= 1
        elif s.startswith("subgraph "):
            match = _SUBGRAPH.match(s)
            if not match:
                problems.append(f"line {no}: cannot read '{s}'")
            else:
                defined[match.group(1)] = True
                open_subgraphs += 1
        elif s.startswith("classDef "):
            match = _CLASSDEF.match(s)
            if match:
                classes.add(match.group(1))
            else:
                problems.append(f"line {no}: cannot read '{s}'")
        elif s.startswith("class "):
            match = _CLASS.match(s)
            if not match:
                problems.append(f"line {no}: cannot read '{s}'")
            else:
                targets, name = match.groups()
                if name not in classes:
                    problems.append(f"line {no}: class '{name}' has no classDef before it")
                for target in targets.split(","):
                    if target not in defined:
                        problems.append(f"line {no}: class target '{target}' is not defined")
        elif s.startswith("style "):
            match = _STYLE.match(s)
            if not match:
                problems.append(f"line {no}: cannot read '{s}'")
            elif match.group(1) not in defined:
                problems.append(f"line {no}: style target '{match.group(1)}' is not defined")
        else:
            pos = read_node(s, 0, no)
            ok = pos is not None
            while ok and pos < len(s):
                arrow = re.compile(r"\s+").match(s, pos)
                arrow_at = arrow.end() if arrow else pos
                arrow_match = _ARROW.match(s, arrow_at) if arrow else None
                space = re.compile(r"\s+").match(s, arrow_match.end()) if arrow_match else None
                if not arrow_match or not space:
                    ok = False
                    break
                pos = read_node(s, space.end(), no)
                ok = pos is not None
            if not ok:
                problems.append(f"line {no}: cannot read '{s}'")
    if open_subgraphs:
        problems.append(f"{open_subgraphs} subgraph block(s) not closed with 'end'")
    if len(defined) > MAX_NODES:
        problems.append(f"the diagram is too large ({len(defined)} nodes, at most {MAX_NODES})")
    return problems


def _check_sequence(lines: list[tuple[int, str]]) -> list[str]:
    problems: list[str] = []
    declared: set[str] = set()
    open_blocks = 0

    def need(name: str | None, no: int) -> None:
        if name and name not in declared:
            problems.append(f"line {no}: '{name}' is not declared with 'participant' first")

    for no, s in lines:
        if s.startswith("%%"):
            problems.append(f"line {no}: cannot read '{s}' (directives are not allowed)")
        elif s == "end":
            if open_blocks == 0:
                problems.append(f"line {no}: 'end' without a matching block")
            else:
                open_blocks -= 1
        elif _BLOCK_OPEN.match(s):
            open_blocks += 1
        elif _BLOCK_ELSE.match(s):
            if open_blocks == 0:
                problems.append(f"line {no}: 'else' outside a block")
        elif m := _PARTICIPANT.match(s):
            if m.group(1).lower() in _RESERVED:
                problems.append(f"line {no}: '{m.group(1)}' is a reserved word")
            declared.add(m.group(1))
        elif m := _MESSAGE.match(s):
            need(m.group(1), no)
            need(m.group(3), no)
        elif m := _NOTE.match(s):
            for name in m.groups():
                need(name, no)
        elif m := _ACTIVATE.match(s):
            need(m.group(1), no)
        else:
            problems.append(f"line {no}: cannot read '{s}'")
    if open_blocks:
        problems.append(f"{open_blocks} loop/alt/opt block(s) not closed with 'end'")
    return problems
