# Specification

**Version:** 0.3 (draft)
**Date:** 2026-09-26
**Status:** Agreed in principle. Open questions are listed at the end and will be settled during prototyping. Sections 4, 5, 6.2, 6.3, 7 and 8 updated for the single-technique scope and secondary sources (D-027, D-028, D-029).

## 1. Purpose

A Python agent for self-directed learning of vulnerabilities and attacks from a SOC analyst's perspective. It explains a topic in cumulative stages with a diagram for each stage, then runs a scored quiz. The result must be professional enough to present in a portfolio, and the topic knowledge must be reliable enough to discuss confidently in an interview.

## 2. Context of use

- Single user, self-directed learning, on a local Windows machine.
- A session may last an hour or more, depending on topic complexity and prior knowledge. There is no time limit.
- Assumed starting knowledge: Tier 1 SOC course graduate. The last stage reaches roughly the boundary of Tier 2. To be tuned after the prototype.
- Everything (agent output, documentation, quiz) is in English.

## 3. Workflow

1. **Input.** A CVE ID or a free-text description (for example "a CVE from the last month" or "an Active Directory misconfiguration").
2. **Discovery.** The agent searches and lists several options, each with a one-sentence description. The user picks one. *(Deferred: the first prototype takes a topic name directly.)*
3. **Research.** The Researcher gathers facts from official sources into the Knowledge Pack.
4. **Triage card.** Shown before the first stage.
5. **Stages.** The user types `next` to advance and `repeat` to revisit a stage.
6. **Quiz.** The user types `exam`. Answers are entered on the local page and submitted.
7. **Result.** Numeric score with an explanation for every answer. Optional PDF export.

## 4. Vulnerability and attack pairing

Every topic covers both sides. If the user asks about a vulnerability, the agent also explains the attacks that exploited it. If the user asks about an attack, the agent also explains the weakness or misconfiguration that made it possible and what caused it.

Not every weakness has a CVE. Misconfigurations and design features (for example Kerberoasting) are described through CWE entries and MITRE ATT&CK techniques instead, so discovery must search more than one kind of entity.

**Scope (D-028).** The agent teaches one MITRE ATT&CK (sub-)technique, or one CVE/CWE, plus the weakness that enables it - not a multi-technique intrusion story. A technique is one point in the tactic > technique > sub-technique > procedure hierarchy, not a kill chain by itself.

## 5. Triage card

The Planner selects the fields that are relevant to the topic from this catalog. Each field carries a value with a source, "not applicable", or "unknown".

| Field | Meaning | Source |
|---|---|---|
| Exploited in the wild | Known exploitation, with date added | CISA KEV |
| Severity | CVSS score | NVD |
| Exploit likelihood | EPSS probability | FIRST EPSS |
| Weakness type | CWE classification | NVD / CWE |
| Affected products and versions | Scope | NVD, vendor advisory |
| Fix status | Patch or mitigation availability | Vendor advisory |
| Publication date | When it was disclosed | NVD |

MITRE ATT&CK techniques are intentionally not a card field. Many topics share techniques, and the mapping is covered in stage 3.

For a technique-only topic with no CVE or CWE (for example Kerberoasting), every NVD/KEV/EPSS-sourced field is "not applicable", and "Weakness type" states plainly that this technique has none (D-028).

## 6. Explanation stages

### 6.1 Planning

A **Planner** reads the Knowledge Pack and produces a **Stage Plan**: the list of stages for this topic, each with a subject, depth, and diagram type. The plan is validated against a schema. The agent states the number of stages at the start.

Guidance for the Planner (not a hard rule): simple topics 3 stages, medium topics 4, complex topics 5 or more. Optional modules for complex topics: threat groups and campaigns, related weaknesses, discovery-to-exploitation timeline.

Stages are cumulative: each builds on the previous one. Stage 1 is a general picture, later stages become progressively more technical.

During development, each stage may show a "what is new compared to the previous stage" line. This is behind a flag that is off by default.

### 6.2 Stage definitions

| Stage | Subject | Content | Diagram |
|---|---|---|---|
| 1 | Overview | A definition paragraph (2-4 sentences: category, MITRE tactic, target, core action); what assumption or trust is broken; the payload the attacker ends up holding (D-029); the component/protocol involved and its normal function, root cause and preconditions, all conceptual (naming the component is allowed, its internal mechanism is not); the SOC angle on why it matters. No technical mechanism detail, no CWE id, no CVSS. When the topic is CVE/CWE-based and exploitation status applies (D-006): "No documented incident from official sources" when not documented, impact labeled potential. | One static picture: weakness, attack, payload |
| 2 | The weakness | The only in-depth technical explanation. Anchored in a CVE or CWE when the Pack has one (documented); otherwise an explicit statement that this technique has none, followed by the protocol or design flaw itself (tagged secondary, D-027/D-029). The component's normal function, root cause, failure mechanism step by step, preconditions, what a fix or hardening changes. Depth stays bounded to what is relevant to an analyst - no source code, no protocol-specification-level detail. | Architecture with the failure point marked; sequence diagram for multi-step mechanisms |
| 3 | Execution flow | The internal execution steps of this one technique, in order - never a multi-technique kill chain. Each step ties back explicitly to the weakness from stage 2 instead of re-explaining it. Includes the MITRE ATT&CK mapping. A step's detail may be tagged secondary when no official source gives the step breakdown (D-029). | Cumulative frames, one per execution step, Previous/Next |
| 4 | What an analyst sees | Telemetry sources per attack step. Event IDs and key fields, and what each indicates. Detection logic in plain language plus pseudo-code. Published IOCs (with publication date, since they age). False positives. Detection gaps: what will not appear in logs under default settings. | Detection flow: attack step, log source, event, rule, alert; gaps marked |
| 5 | Response and prevention | Triage questions and outcomes (false alarm, monitor, escalate). Tier 1 boundary: what to handle, when to escalate, what evidence to attach. Containment options and their side effects. Eradication and recovery. Hardening. Lessons, including detection gaps that can be closed. | Decision tree ending in three outcomes; escalation branch continues to containment and recovery |

A complex mechanism may split stage 2 into a conceptual part and a technical deep dive.

### 6.3 Exploitation status

The Researcher records exploitation status as one of three values, not two. Absence from KEV does not prove a vulnerability was never exploited.

| Status | Stage 1 | Stage 3 | Stage 4 | Quiz |
|---|---|---|---|---|
| Exploitation documented | Incident and impact | Documented attack story | Evidence seen in practice | Questions about a real scenario |
| No documented exploitation | "No documented incident from official sources"; impact labeled potential | Possible scenario, tagged `[Inference]` | Detection opportunities, without claiming they were observed | Hypothetical scenarios, clearly labeled |
| Unknown (source unreachable) | As above, with a note that the check was partial | As above | As above | As above |

These rules are enforced in code, not only in prompts. A validation step compares the Lecturer's and Examiner's output with the recorded status and rejects text that describes an attack that was not documented.

This table applies only when the topic is CVE/CWE-based. For a technique-only input with neither (for example Kerberoasting), there is no incident to be documented or undocumented, and stage 1 does not carry an exploitation-status sentence at all (D-029).

## 7. Diagrams

- Diagrams are written in Mermaid and rendered on the local page.
- The agent chooses the diagram type that helps understanding most: flow, sequence, timeline or architecture, from a list of allowed types per stage.
- A multi-step diagram is built from **frames**. Frame 1 shows the first attack step, each next frame adds the following step and highlights what is new, until the full picture is shown. Frames are generated from the list of steps in the attack chain, not freely. The page provides Previous and Next controls.
- Each frame's syntax is validated before it is saved. On error the agent fixes it and retries.
- The Mermaid library is stored locally in the repository (`web/vendor/`, pinned version, hash-checked) so the page works offline. Node.js is not needed: syntax is checked by a strict Python subset check, and the library in the browser is the second check (D-022, D-023).
- Frames are built by code from the attack steps in the Knowledge Pack. The model supplies only a short label and a tagged description per step (D-023). When no official source gives a step breakdown for a technique, the Researcher may build the attack-steps list from a secondary source, and each such step is tagged secondary (D-029).

## 8. Sources and provenance

**Allowed sources:** NVD, CISA KEV, MITRE ATT&CK, MITRE CWE, vendor advisories, FIRST EPSS, and official incident disclosures (CISA advisories, SEC 8-K filings, statements from the affected organization, regulator announcements). Blogs, community rule sets, and exploit databases are not used by default as official sources.

**Secondary sources (D-027).** A fixed allowlist of well-known, reputable security sites (for example Abnormal AI, Picus Security, CrowdStrike) may be used for one purpose only: explaining a mechanism or execution flow that no official source documents in enough detail (typically a technique with no CVE/CWE, stages 2 and 3). A secondary source is never presented as official and is never used where an official source is available.

**Provenance tags** on every item:

- `[Documented]`: taken from an official source, with a link.
- `[Secondary]`: taken from a secondary allowlist source, with a link. Kept distinct from Documented (D-027).
- `[Inference]`: derived by the agent, not officially documented (for example most false-positive guidance, detection logic, containment steps without an official recommendation).
- `[Unknown]`: no information available.

**Grounding.** Each field in the Knowledge Pack has a source link or is rejected. When sources conflict, the conflict is shown openly. Missing information is stated as "unknown", never guessed. Details in stages must not come from model memory alone.

## 9. Quiz

- 10 questions, mostly from stages 4 and 5, with some from stage 1 on business impact.
- Oriented to SOC work rather than small technical details: log-based scenarios, relevant event IDs, triage decisions, detection gaps, matching technique to tactic, true/false on core concepts, and one open question.
- Closed questions are graded deterministically in code. Open questions are graded by a model against a predefined rubric, in one call for all open questions.
- Result: numeric score plus an explanation for every answer. For a partially correct answer: what was good, what was missing, and how to fix it.
- Correct answers are stored server-side and never sent to the page before submission.
- Scores are not kept between sessions.
- Export to PDF: the questions, the user's answers, the correct answers, and the explanations.
- If the page is closed mid-quiz, the Orchestrator waits up to a defined timeout, after which `exam` shows the same questions again.

## 10. Interface

- **Terminal:** commands (`next`, `repeat`, `exam`, and others to be defined) and short status messages. The agent process must stay running.
- **Local page** at `http://127.0.0.1:<port>`: all stages, diagrams and the quiz. New content is appended below existing content without reloading, and the scroll position does not jump. `repeat` scrolls to and highlights an existing stage without a model call.
- **Updates:** start with polling; consider server-sent events later.
- **Quiz form:** the page provides buttons and text fields. Submitting sends answers with a POST request to a local endpoint. The Orchestrator grades and returns the result to the page.
- **Security of the local server:** it listens on 127.0.0.1 only (not the network), requires a per-session token, and checks the request origin. This prevents a web page opened in the same browser from sending requests to the local server.
- The port is chosen automatically if the default is busy, and the address is printed in the terminal.

## 11. Architecture

The design is a fixed workflow, not a free-roaming multi-agent system. The steps always run in the same order, so autonomy is needed in only one place.

```
input (CVE ID or topic)
   |
   v
[Researcher]  agent with tools: NVD, CISA KEV, MITRE ATT&CK/CWE, vendor and incident sources
   |          output: Knowledge Pack (JSON, every field sourced)
   v
[Planner]     structured output: Stage Plan
   |
   v
[Lecturer]    structured output per stage, reads Knowledge Pack, Stage Plan and previous stage
   |
   v
[Examiner]    structured output: questions, grading, explanations
```

- The **Orchestrator** is plain code that sets the order and enforces the rules.
- The **Knowledge Pack** is the only shared state. Components never talk to each other directly.
- Only the Researcher runs as a real agent loop with tools. Planner, Lecturer and Examiner are single calls that return output checked against a schema.
- Model and effort level are configured per role in a settings file. Default: Sonnet 5 at medium effort. A stronger model may be used for planning if measurement shows a benefit.
- Stage definitions and levels live in a configuration file (TOML, D-020 and D-021), not in code.
- Schemas are defined with Pydantic. Every output is validated; an invalid output is sent back for correction.

## 12. Constraints

- **Budget:** runs on the existing Claude Pro subscription. No paid API key. Usage counts against the plan's usage limits.
- **Personal use only.** Each user installs their own copy and uses their own account.
- **Content:** defensive focus. No working exploit code.
- **Untrusted content:** the Researcher's tools are read-only. Text from the web is treated as data and never as instructions.
- **Secrets:** no keys or tokens in the repository.
- **Environment:** Windows, Python 3.10 or newer (developed on 3.14).

## 13. Success criteria

1. Free-text input leads to discovery, a choice, and cumulative stage explanations.
2. Every factual claim is supported by an official source, or is tagged `[Secondary]` (allowlist source), `[Inference]` or `[Unknown]`.
3. All diagrams render without errors.
4. The triage card matches the official sources.
5. The same code handles a CVE topic and a non-CVE topic with a different number of stages, fields and diagrams.
6. The Agent is checked against an evaluation set, including one prompt-injection test page.
7. After the quiz, the user can explain the topic aloud for two minutes without notes. This one is judged by the user.

## 14. Out of scope for v1

- Hosting for other users, accounts, or any public web service
- Saving scores or progress between sessions
- Sharing sessions
- Sources outside the allowed list

## 15. Open questions

1. How many stages are optimal? The plan uses 3 to 5 as guidance, to be settled on real topics.
2. ~~Whether Node.js is needed to validate Mermaid syntax.~~ Settled: not needed (D-022, D-023).
3. Whether all dependencies install on Python 3.14.
4. How subscription authentication works on Windows, and how much of the usage limit a run consumes.
5. Polling or server-sent events for page updates. Polling is used for now (D-023); revisit if it feels slow.
6. Which library produces the PDF export.
7. The exact timeout for an abandoned quiz.
8. The final list of terminal commands.
9. Whether a complex stage 2 mechanism should also be shown as progressive frames, which needs a structured `mechanism_steps` field in the Knowledge Pack (D-024, to discuss after Milestone 4).

## 16. Milestones

| Milestone | Build | Done when |
|---|---|---|
| 0 | Environment, Python packages, hello-world agent | The run uses the subscription, and usage per run is measured |
| 1 | Pydantic schemas: Knowledge Pack, Stage Plan, provenance tags | A valid example passes and an invalid one is rejected |
| 2 | Researcher with NVD, KEV and ATT&CK tools, topic name as input | Five fields checked manually against official pages; no field without a source |
| 3 | Planner, stages 1 and 2, one diagram | Stage Plan is valid, the diagram renders, five random claims trace to the Pack |
| 4 | Stage 3 with cumulative frames in the local page | Number of frames equals number of attack steps; navigation works |
| 5 | Examiner: 3 questions, then 10; grading, explanations, PDF export | Answers get a score and explanations; the PDF is saved |
| 6 | Run a non-CVE topic (for example Kerberoasting) with no code changes | Stage count, fields and diagrams differ without breaking |

Test topics: Log4Shell (CVE-2021-44228) for a source-rich CVE run, and Kerberoasting for a topic without a CVE.

After milestone 6: stages 4 and 5, free-text discovery, remaining question types.

## 17. Metrics per run

- Usage consumed and number of agent turns (turns are capped per run)
- Share of fields with a source versus "unknown"
- Number of diagram render errors
- One prompt-injection test
