# Decision Log

Each entry records what was decided, why, and what was rejected. Entries are never deleted. If a decision changes, a new entry supersedes the old one and both stay in the log.

**Format:** context, decision, alternatives considered, consequences.
**Statuses:** Accepted, Superseded, Open.

---

## D-001: Start from a clean slate

**Date:** 2026-09-24 | **Status:** Accepted

**Context:** An earlier CVE explainer project exists with its own schema and prompts.
**Decision:** This project starts fresh. It reuses neither the earlier schema nor the earlier prompts.
**Why:** A clean design lets the stage model, provenance rules and quiz be built around each other, and makes the portfolio story independent.
**Consequences:** More upfront design work; no inherited constraints.

---

## D-002: Fixed workflow, not a full multi-agent system

**Date:** 2026-09-24 | **Status:** Accepted

**Context:** The system has four responsibilities: research, planning, teaching, examining.
**Decision:** An Orchestrator in plain code runs them in a fixed order. Only the Researcher is a real agent with tools. Planner, Lecturer and Examiner are single calls that return schema-checked output.
**Alternatives considered:** A full multi-agent system with autonomous subagents.
**Why:** Each extra agent runs its own context and uses more of a limited usage allowance. The steps always run in the same order, so autonomy is not needed for coordination. The need is separation of responsibility, not autonomy.
**Consequences:** Cheaper and more predictable. Subagents can be added later, for example to split research by source, if the Researcher's context grows too large.

---

## D-003: One shared record for all stages and the quiz

**Date:** 2026-09-24 | **Status:** Accepted

**Context:** The exploitation status found by the Researcher affects every later stage and the quiz.
**Decision:** The Researcher writes a Knowledge Pack (structured, sourced). All other components read it. They never talk to each other directly.
**Why:** One source of truth avoids contradictions between explanation and quiz, saves usage (research runs once), and makes every claim traceable.
**Consequences:** The Pack schema is central and is built first (milestone 1).

---

## D-004: Always pair a vulnerability with its attack

**Date:** 2026-09-24 | **Status:** Accepted

**Decision:** A request for a vulnerability also covers the attacks that exploited it. A request for an attack also covers the weakness that enabled it and what caused it.
**Why:** For a SOC analyst the attack is what appears in alerts, and the weakness explains why. Either side alone is incomplete.
**Consequences:** Discovery must handle topics without a CVE (misconfigurations, design features) through CWE and ATT&CK.

---

## D-005: Official sources only, with provenance tags

**Date:** 2026-09-24 | **Status:** Accepted

**Decision:** Allowed sources are NVD, CISA KEV, MITRE ATT&CK and CWE, vendor advisories, FIRST EPSS, and official incident disclosures. Every item is tagged `[Documented]`, `[Inference]` or `[Unknown]`. Conflicts between sources are shown openly. When no incident is documented, the agent states "No documented incident from official sources".
**Alternatives considered:** Allowing blogs, community detection rules, and exploit databases.
**Why:** The user needs to speak about these topics with confidence, and the agent has limited ability to verify wide-ranging sources. Business impact data (stage 1) is not in the technical sources, so official incident disclosures were added.
**Consequences:** Detection and false-positive guidance is often an inference, and is labeled as such rather than presented as fact.

---

## D-006: Exploitation status has three values, and the rules live in code

**Date:** 2026-09-24 | **Status:** Accepted

**Context:** The Researcher cannot see that a vulnerability was not exploited. It can only see that no exploitation is documented, and absence from KEV proves nothing.
**Decision:** The status is documented, not documented, or unknown. Later stages follow fixed rules for each value, checked by a validation step in code.
**Why:** Instructions to a model can be ignored. A code check prevents a stage from describing an attack that has no source.

---

## D-007: Five-stage model with a dynamic stage count

**Date:** 2026-09-24 | **Status:** Accepted (count guidance to be tested)

**Decision:** Stages: overview, why it is possible, attack chain, what an analyst sees, response and prevention. A Planner decides the actual count per topic (guidance: 3 to 5) and the agent states it up front. Technical depth of the weakness is only in stage 2. Stage 3 links back to it.
**Why:** Each fact lives in exactly one place. Stage 1 works like a book's introduction: shows what to expect without technical load.
**Open:** The best number of stages is unknown and will be settled on real topics in the prototype.

---

## D-008: Diagrams as cumulative Mermaid frames

**Date:** 2026-09-24 | **Status:** Accepted

**Decision:** Diagrams are written in Mermaid. Multi-step attack diagrams are built from frames, each adding the next step.
**Why:** Text-based diagram code is easy for a model to write, easy to validate, and stores well in a repo. Frames show spread and order, which a single final diagram hides.
**Consequences:** Syntax is validated before saving. Node.js may be required for validation (open question).

---

## D-009: Everything in English

**Date:** 2026-09-24 | **Status:** Accepted

**Context:** Right-to-left text mixed with English terms renders poorly in the Windows terminal.
**Decision:** Agent output, quiz, and all documentation are in English.
**Consequences:** Removes the need for RTL handling and matches the target job market.

---

## D-010: Local display page with commands from the terminal

**Date:** 2026-09-24 | **Status:** Superseded in part by D-011

**Context:** A terminal cannot render diagrams. Writing one HTML file per stage would leave many files. Everything in the terminal would not be pleasant to read.
**Decision:** A local page at `http://127.0.0.1:<port>` shows all stages and diagrams in one growing document. Commands are typed in the terminal. New content is added without reloading the page.
**Alternatives considered:** Terminal only; one HTML file per stage; a single regenerated HTML file with reload; a full web application.
**Consequences:** The agent process runs a small local server and must stay open.

---

## D-011: Interactive quiz on the local page

**Date:** 2026-09-24 | **Status:** Accepted

**Context:** The first version of D-010 kept the page display-only, with answers typed in the terminal.
**Decision:** After `exam`, the page shows buttons and text fields. Submitting sends answers to a local endpoint, the agent grades them, and the page shows the result. Export to PDF includes questions, the user's answers, and explanations.
**Why:** Typing long answers in a terminal is uncomfortable. The extra code is one form and one endpoint.
**Security:** The server listens on 127.0.0.1 only, requires a per-session token, and checks the request origin, so that another web page cannot post to it.
**Consequences:** This adds a small interactive element to what was planned as a display-only page. Everything else remains terminal-driven. The original "no web interface in v1" limit now means no hosted or multi-user web service.

---

## D-012: Quiz design

**Date:** 2026-09-24 | **Status:** Accepted

**Decision:** 10 questions, focused on SOC work (event IDs, triage, detection gaps, business impact) rather than small technical details. Closed questions are graded in code. Open questions are graded by a model against a rubric, batched in one call. Every answer gets an explanation, and partial answers get feedback on what was good and what to fix.
**Why:** The goal is confident discussion of a topic, not deep exploit knowledge. Code grading is free and consistent; model grading is used only where needed.

---

## D-013: No progress saved between sessions

**Date:** 2026-09-24 | **Status:** Accepted

**Decision:** Scores are not stored. A quiz can be exported to PDF.
**Consequences:** Simpler data handling and no personal data storage.

---

## D-014: Billing and authentication

**Date:** 2026-09-24 | **Status:** Accepted, to be re-verified

**Context:** The budget is the existing Claude Pro subscription only. Anthropic announced a separate monthly Agent SDK credit for June 15, 2026, then paused that change. According to the Help Center notice at that time, Agent SDK usage still draws from subscription limits and no credit is available.
**Decision:** The agent runs through the subscription with no paid API key. Usage counts against the plan's limits, shared with chat and Claude Code. Each run is capped in turns, and consumption is measured in milestone 0.
**Constraints:** Anthropic does not permit offering subscription sign-in to other people through products built on the Agent SDK. The project is therefore personal-use only, and others install their own copy. An `ANTHROPIC_API_KEY` environment variable must not be set, or usage is billed to the API account.
**Risk:** The billing policy may change. Re-check the Help Center before each major build phase.

---

## D-015: Model and effort policy

**Date:** 2026-09-24 | **Status:** Accepted, to be measured

**Decision:** Default to Sonnet 5 at medium effort for the agent's roles and for coding work. Use Opus for planning and hard problems. Model and effort are set per role in a settings file. The Knowledge Pack is saved and `repeat` reads from it without a model call.
**Why:** Higher-tier models and higher effort use more of a limited allowance, and the measured quality gain at high effort appears small for routine work.
**Open:** Confirm which models the account can use, and measure real consumption in milestone 0.

---

## D-016: Environment and repository

**Date:** 2026-09-24 | **Status:** Accepted

**Decision:** The repository lives outside OneDrive, at `C:\dev`. Windows, Python 3.14 (SDK requires 3.10 or newer). Documentation is kept in the repository in English.
**Why:** Sync services can lock or duplicate the many small files Git writes, and can sync large virtual-environment folders and secret files to a cloud.
**Open:** Dependency compatibility with Python 3.14 is untested. If needed, use Python 3.12 or 3.13.

---

## D-017: Build order

**Date:** 2026-09-24 | **Status:** Accepted

**Decision:** Build a thin end-to-end slice first (one topic, stages 1 and 2, one diagram, three questions), then widen. Test on Log4Shell (CVE-2021-44228) and Kerberoasting to check dynamic behavior. Free-text discovery and stages 4 and 5 come after milestone 6.
**Why:** The right number of stages and the quality of the output can only be judged on real topics. The specification is updated from what the prototype shows.

---

## D-018: Order of the affected-products field

**Date:** 2026-09-25 | **Status:** Accepted

**Context:** The triage card lists at most 15 affected products. NVD lists them in an arbitrary order, and the parser cut the list to the first 15 before any ordering. For CVE-2021-44228 the card began with Siemens firmware, and the Log4j product itself was sixth. A product beyond the 15th could be dropped entirely, even if CISA KEV names it.
**Decision:** The NVD parser keeps every affected product, deduplicated, in NVD order. `src/facts.py` orders them: products matching the vendor and product named in the KEV entry first, then the rest alphabetically, then cuts to 15 and states the remainder as "(and N more)". A product matches when the vendor is equal and the product names are equal or one is a prefix of the other, both compared case-insensitively with everything except letters and digits removed (KEV "Log4j2" matches NVD "log4j"). If nothing matches, the CVE is not in KEV, or KEV could not be checked, nothing is put first and the list is alphabetical.
**Alternatives considered:** Keeping the NVD order (arbitrary and hides the relevant product); exact-name matching only (misses "Log4j2" against "log4j"); picking the product with a model call (costs usage, breaks the rule that tests never call a model, and a guess could be wrong).
**Why:** The card should lead with the product the official exploitation record names. Ordering in code is deterministic and testable, and it guesses nothing: an unmatched product is left alone, not pinned.
**Consequences:** Prefix matching can pin more than one product, for example every "Windows ..." product for a KEV "Windows" entry, and can miss a vendor spelled differently in the two sources. In both cases the field stays accurate and only its ordering is affected. The cap of 15 moved from `src/sources/nvd.py` to `src/facts.py`. Tests: `tests/test_facts.py` and `tests/test_nvd.py`. Implemented in commit 652ee29.

---

## D-019: Researcher run limits and settings file

**Date:** 2026-09-25 | **Status:** Accepted

**Context:** Milestone 2 part B wraps the Researcher as a real agent loop. An agent loop can in principle run indefinitely (repeated tool calls) or get stuck retrying an invalid Knowledge Pack, and both cost usage from the subscription (D-014).
**Decision:** A settings file (`config/settings.yaml`) holds model and effort per role instead of hard-coded values. For the Researcher: model `sonnet-5`, effort `medium`, `max_turns: 20` (a hard stop on tool-call turns per run, counted across all tools together, not per tool), `max_schema_retries: 2` (times the agent may correct a Knowledge Pack that failed validation against the schema, before the run gives up and reports failure).
**Alternatives considered:** Hard-coding these values in `src/` (rejected: every tuning pass would need a code change); a stronger model or higher effort by default (rejected: the Researcher mainly reads structured tool output and assembles it, D-015 already sets Sonnet 5 medium as the default for this kind of work); no turn cap (rejected: an ungoverned agent loop can consume the shared subscription usage limit with no ceiling).
**Why:** 20 turns covers a normal run (5-8 turns for a CVE with a source-rich record) with margin for harder topics (for example Kerberoasting, with no CVE), while still stopping a runaway loop early. 2 correction attempts is usually enough for formatting mistakes; a Pack still invalid after 3 total attempts likely needs a prompt fix, not more retries.
**Consequences:** Both numbers live in `config/settings.yaml` and can be tuned without touching code. `src/` reads them instead of hard-coding.

---

## D-020: Researcher agent design (Milestone 2 part B)

**Date:** 2026-09-25 | **Status:** Accepted

**Context:** D-019 set the run limits. Building the agent needed further choices about config format, tools, who owns which fact, and how claims are checked.
**Decision:**
- Config format: `config/settings.toml`, read with the standard-library `tomllib` (no new dependency). This supersedes the file name and format in D-019 (`settings.yaml`). The values are unchanged except the model ID: `claude-sonnet-5`. The SDK rejected `sonnet-5` ("unrecognized_model") in the first live run.
- Tools: three read-only tools (NVD, CISA KEV, ATT&CK) in an in-process server. CWE ids come from the NVD tool. EPSS, vendor advisories and official incident disclosures are not built yet. Built-in tools, other MCP servers, settings files, skills, plugins and subagents are off, and code checks this on every run (`assert_read_only`). `permission_mode` is `dontAsk`: anything not pre-approved is denied instead of prompted.
- Ownership: code collects the facts first (topic, exploitation status, triage fields). The agent may only add mechanism, attack steps, incidents, detection items, response items and conflicts. Setting any other field is rejected, not ignored.
- Claim checks in code: every source URL the agent cites must be an official domain (nvd.nist.gov, cisa.gov, attack.mitre.org, cwe.mitre.org, first.org) AND a URL a tool returned during this run. Vendor advisory and incident-disclosure domains will be added to the list when those sources are built.
- Limits: the turn cap is also counted in our own code across the whole run, corrections included. The run refuses to start if `ANTHROPIC_API_KEY` is set.
- Tool output is wrapped in `<untrusted_source_data>` markers with the source URL. A marker inside fetched text is removed.

**Alternatives considered:** YAML (needs a new dependency); letting the agent write the whole Pack (it could overwrite source-derived facts); trusting the SDK's `max_turns` alone; an allowed-domain check without the "returned by a tool" check.
**Why:** Keeps source-derived facts out of the model's reach, and turns "every claim comes from a tool result" into a code check where a prompt alone would not be enough.
**Consequences:** The URL check proves where a citation came from, not that the page supports the claim. In the first live run (CVE-2021-44228) the agent tagged advice and an unsupported phrase as `documented`. A stricter prompt fixed both in the second run, but this is not enforced in code. Open: a code check that a documented entry quotes its cited result. Also open: whether model-memory detail (for example a `jndi:` search string) tagged `inference` is acceptable in stage 4. Tests: `tests/test_researcher_*.py`, `test_merge.py`, `test_settings.py`. Live run via `scripts/run_researcher.py`.

---

## D-021: Planner design and stage plan rules (Milestone 3)

**Date:** 2026-09-25 | **Status:** Accepted

**Context:** Milestone 3 adds the Planner. Spec section 6.1 leaves the stage count as guidance (3 to 5) and does not say which stages a short plan keeps. The plan's stage numbers (1..n in the plan) also stop matching the definition numbers once a stage is skipped, so a plan item needs a way to name its definition.
**Decision:**
- Stage definitions live in `config/stages.toml`, read with the standard-library `tomllib` and checked with Pydantic. This supersedes "YAML" in spec section 11 (same reason as D-020: no new dependency). `spec.md` section 11 still needs that one-word fix.
- `StagePlanItem` gets a required `key` field naming its definition (`overview`, `why_possible`, `attack_chain`, `analyst_view`, `response_prevention`). `number` stays the position in the plan.
- Every plan must contain `overview`, `why_possible` and `response_prevention`. A 3-stage plan is exactly those three (chosen by the user). `attack_chain` and `analyst_view` are optional, so a plan has 3 to 5 stages. Stages must be in definition order with no repeats. The count guidance (3 simple, 4 medium, 5 complex) stays in the Planner's prompt only.
- `depth` and `diagram` must be in the allowed lists of the stage's definition. `timeline` is not allowed in any stage yet, because the spec's stage table does not list it.
- `attack_chain` must cover every attack step in the Pack and cannot be planned when the Pack has no attack steps, because its frames are generated from those steps (D-008).
- All of this is checked in code (`src/plan_rules.py`). All problems are reported together, and a rejected plan is sent back with the reasons, up to `max_schema_retries`.
- The Planner and Lecturer share one tool-less call helper (`src/single_call.py`): no built-in tools, no MCP servers, no settings, skills or subagents, `max_turns` fixed at 1, and code checks this on every run. Model, effort and retry cap come from `config/settings.toml`. The run refuses to start when `ANTHROPIC_API_KEY` is set.
- The Knowledge Pack goes to the Planner wrapped as untrusted data, because its text came from external sources.

**Alternatives considered:** Matching plan stages to definitions by subject text (fragile, the Planner chooses topic-specific subjects); making only stages 1 and 2 required (a plan could then end without response and prevention); letting the Planner choose any diagram type (the spec limits types per stage); a separate copy of the retry loop for each role (duplicated code).
**Why:** The rules that must always hold are code, not prompt (CLAUDE.md). A required stage 5 means every topic ends with what an analyst does about it.
**Consequences:** `StagePlanItem` changed after Milestone 1; `tests/test_schemas.py` was updated. A stage 3 without stage 4, or the reverse, is allowed. Stage 5 in a 4-stage plan is my addition to the spec's wording and can be relaxed. Whether `max_turns=1` is accepted by the SDK for a tool-less call is only confirmed by the first live run. Tests: `test_stages_config.py`, `test_plan_rules.py`, `test_single_call.py`, `test_planner.py`, `test_settings.py`.

---

## D-022: Lecturer output rules, Mermaid subset and known limits (Milestone 3)

**Date:** 2026-09-25 | **Status:** Open (draft, awaiting approval)

**Context:** Milestone 3 adds the Lecturer for stages 1 and 2 and the first diagrams. The first live run on CVE-2021-44228 passed every code check, but reading the output showed two prompt-wording gaps and one noisy checking tool. Node.js is not installed, so Mermaid cannot be rendered or validated by the official tools (spec open question 2).
**Decision:**
- A stage is a list of blocks, each tagged `documented`, `inference` or `unknown`, plus one diagram. `src/stage_rules.py` checks in code: the stage matches its plan item; every `documented` block cites a URL that is in the Pack; the diagram passes the Mermaid check; and the exploitation-status rules of D-006. When exploitation is documented, stage 1 must cite the evidence or an incident URL and must not say "No documented incident from official sources". When it is not documented or unknown, stage 1 must contain that exact sentence and the word "potential" (and "partial" for unknown), and no text may match a short list of phrases that present an attack as having happened. Stage 2 needs a `documented` block when the Pack documents the weakness.
- Mermaid is checked by `src/mermaid_check.py`: a strict Python check of a small subset (flowchart with quoted labels, subgraph, classDef/class/style; sequenceDiagram with declared participants). It refuses anything else, including diagram types it cannot check yet. It does not render. Each diagram is rendered by hand once in mermaid.live during Milestone 3. Offline validation is revisited in Milestone 4 when the page loads a local Mermaid library.
- Two rules stay in the prompt, not in code, on purpose: one source per `documented` block (the user message lists each URL with the Pack fields recorded under it), and no technical detail in stage 1 (no protocols, version numbers, CWE ids or CVSS vectors). Both were added after the first live run. The rerun on the same CVE showed the KEV date and the NVD publication date in separate blocks with their own URLs, and no technical detail in stage 1.
- The trace check (`src/trace.py`, `scripts/run_stages.py`) samples five `documented` blocks and shows the three Pack entries under the same URL that share the most words with the block.

**Alternatives considered:** Installing Node.js and `mermaid-cli` (a new tool chain, not approved); a loose Mermaid check (would let broken diagrams through); a stronger model for the Lecturer (D-015: no measured capability gap, and both defects were prompt wording); enforcing the two prompt rules in code (no reliable way to tell technical detail from plain wording, and a URL-per-fact check needs a reading of meaning).
**Why:** The rules that must always hold are in code (CLAUDE.md); rules that need judgement of wording are prompted and checked by a person for now.
**Consequences:** The prompt-only rules can regress and nothing in code will notice. Tests: `test_mermaid_check.py`, `test_stage_rules.py`, `test_lecturer.py`, `test_trace.py`, `test_orchestrate.py`.

**Open question (matches D-020):** Model-memory detail tagged `inference`. In the first run, stage 2 explained the meaning of CWE-20, CWE-502 and CWE-917 from model memory, labelled as the model's own reading. Whether that is acceptable, or `inference` should be limited to reasoning from Pack facts, is undecided. Not changed now.

**Known limits, seen in the live runs:**
- The URL check proves a citation is in the Pack, not that the sentence is supported (D-020). A `documented` block can carry an extra clause or a plain definition that the Pack does not state, for example "for example through a field the application logs" (run 1) and "Ransomware is malware that locks or steals data..." (both runs).
- The "describes an attack as having happened" check is a phrase list, not a reading of meaning.
- Diagram labels have no provenance tag. Run 2's sequence diagram says the attacker endpoint "returns an attacker-controlled code reference", which is more specific than the Pack.
- The Mermaid check has not yet been compared with real rendering (pending the manual mermaid.live check).
