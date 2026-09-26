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

**Date:** 2026-09-24 | **Status:** Accepted; amended by D-027

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

**Date:** 2026-09-25 | **Status:** Accepted

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
- The Mermaid check is compared with real rendering only by hand: both diagrams from the CVE-2021-44228 run rendered in mermaid.live (2026-09-25). Two diagrams are a small sample, so a diagram type or syntax we have not seen may still pass the check and fail to draw.

---

## D-023: Stage 3 frames, local page server and vendored Mermaid (Milestone 4)

**Date:** 2026-09-25 | **Status:** Accepted after the live run on CVE-2021-44228 and the manual browser check (reported as passed by the user, 2026-09-25)

**Context:** Milestone 4 adds stage 3 (attack chain) with cumulative frames on the local page (spec sections 7 and 10). It needs a way to draw Mermaid offline, a local server, and a way to build frames that always match the attack steps. Node.js is not installed (spec open question 2).
**Decision:**
- **Frames are built in code.** For stage 3 the model returns only `blocks` and a `chain`: per attack step a step number, a label of at most 60 characters and one tagged description. `src/frames.py` builds frame *k* (steps 1 to *k*, step *k* marked `new`, earlier steps `seen`). The MITRE technique id in each frame comes from the Pack, never from the model. The chain must match the Pack's attack steps exactly (same numbers, same order), so the number of frames equals the number of steps by construction. Each frame passes `check_mermaid`, and `check_stage` rebuilds the frames and rejects any that differ. This extends D-022: `kill_chain_frames` is now a supported type, and `StageContent` has either one `diagram` or `frames` plus `chain`, never both (a change to the Milestone 3 schema).
- **Stage 3 without documented exploitation** (spec section 6.3): every block and every chain description must be tagged `inference` and start with "Possible scenario". Code enforces it. Technique ids named in the text must exist in the Pack (a sub-technique is accepted when its parent id is in the Pack).
- **The learner never sees the word "Pack".** Text and titles that contain "pack" or "knowledge pack" are rejected in code, and the prompt suggests "the official sources checked". The first live run leaked the word in stage 3 (and in stages 1 and 2).
- **Node.js is not needed** (answers spec open question 2). The strict Python subset check stays the gate. The real Mermaid library in the browser is the second check, and a frame that fails to draw shows an error box on the page.
- **Mermaid is vendored, pinned and hash-checked.** `web/vendor/mermaid.min.js`, version 11.17.2 (MIT), SHA-256 in `web/vendor/README.md` and `tests/test_vendor.py`. It was compared byte for byte with the official npm tarball, whose SHA-512 matched the registry's published integrity value. `.gitattributes` marks `web/vendor/*` as `-text` so line endings cannot change the hash. Version 12.0.0 exists on npm; 11.x was chosen on request.
- **The local server uses only the standard library** (`http.server`), no new dependency. It listens on 127.0.0.1 (default port 8765, a free port if busy, with address reuse off so the fallback also works on Windows). Every request needs the per-session token (32 random bytes, moved from the terminal's address into an HttpOnly, SameSite=Strict cookie and redirected away). The `Host` header must be the server's own address (blocks DNS rebinding), and an `Origin` header, when present, must be the server's own origin. Only GET is accepted (the quiz POST comes in Milestone 5). Only four fixed files are served. Nothing is logged, because the request line can hold the token.
- **Content-Security-Policy:** `default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self' 'unsafe-inline'` plus base-uri, form-action and frame-ancestors limits. `'unsafe-inline'` is for styles only, because Mermaid puts a `<style>` element in each SVG. No `unsafe-eval`: the bundle has no `eval(` or `new Function(`.
- **Page behaviour:** it polls `/api/state` every second (spec open question 5: polling for now), appends new stages without rebuilding old ones, sends only revealed stages, and puts all agent text in with `textContent`. The only `innerHTML` is the SVG Mermaid draws with `securityLevel: "strict"` and HTML labels off. Diagram boxes stay white in dark mode, because diagram colors are chosen for a light background.
- **Terminal commands:** `next`, `repeat N`, `help`, `quit`. None calls a model. `scripts/serve_stages.py` shows saved stages, or `--demo` shows invented sample data (`src/demo.py`, all blocks tagged `inference`, run through the real rules in tests). `scripts/run_stages.py --stage N --confirm` writes one stage again from the saved run with no Planner call, and only the last saved stage can be replaced (later stages read earlier ones).

**Alternatives considered:** Letting the model write frame Mermaid (frame count and order could drift from the steps, contradicting spec section 7); a CDN script tag (breaks offline use and adds a network dependency); `npm install mermaid` or `mermaid-cli` (needs Node, not approved); Starlette and uvicorn (installed only as side effects of `mcp`, not approved dependencies); loosening the CSP to `unsafe-eval` up front (only if the browser shows it is needed); a headless browser for JavaScript tests (a new tool chain).
**Why:** Frames derived from the Pack's step list are correct by construction and testable. A pinned, hashed, local library keeps the page offline and reviewable. A small stdlib server with token, Host and Origin checks covers the local-server risk in spec section 10 without new dependencies.
**Consequences:** Tests cover the frame builder, the stage 3 rules, the server security checks, the terminal commands, the demo data and the vendored hash. They cannot cover the page's JavaScript (Previous and Next, drawing, scroll position, highlighting): that is checked by hand in a browser. Diagram drawing is still checked by the real library only by hand (D-022 limit). The plan's stage count (4) is larger than the written stages (3) until stages 4 and 5 are built.
**Known limits, seen in the live runs on CVE-2021-44228 (2026-09-25):**
- The Pack recorded 2 attack steps, so stage 3 has 2 frames: the frame count is proven on real data only up to that size. The frame and server tests use up to 8 steps.
- A `documented` block can carry a clause the source does not state, for example "so this chain has been used in real attacks" (KEV says exploited in the wild) and "As explained in stage 2, this works because…" appended to an NVD sentence. The URL check cannot see this (D-020, D-022).
- Stages 1 and 2 in the saved run still contain the word "Pack", because only stage 3 was rewritten after the rule was added. A full re-run fixes it.
- The "pack" check is a regular expression, so a legitimate use of the word "pack" would be rejected and the model asked to reword it.
- Usage reported by the SDK: about $0.17 for the Planner plus stages 1 to 3, and about $0.05 for one stage re-run (Sonnet 5, medium effort). This is the SDK's reported number, not a bill (D-014).

---

## D-024: Progressive frames for a complex mechanism diagram (to discuss after Milestone 4)

**Date:** 2026-09-25 | **Status:** Open (not decided, nothing built)

**Context:** Stage 3 shows the attack chain as cumulative frames built in code from the Knowledge Pack's `attack_steps` (D-023). Stage 2's mechanism diagram (for example the Log4j sequence diagram with four participants and eight messages) is one static picture and can be wide and dense.
**Question:** Should a complex stage 2 mechanism be shown as progressive frames too, the way stage 3 works?
**What it would take (an architecture change, not a rendering tweak):**
- A new structured `mechanism_steps` field in the Knowledge Pack schema, similar to `attack_steps`: numbered, each a `SourcedValue`, so the Researcher records the mechanism as ordered steps with sources.
- Researcher changes: its prompt, the ownership rules of D-020 (what the agent may add), and the merge and claim checks.
- Stage 2 changes: frames built in code from those steps, a rule that the chain covers every step, and a diagram type or plan option so the Planner can choose a single diagram or frames per topic. Sequence diagrams would need a frame builder of their own (participants stay fixed, messages are added one by one).
- Schema, plan rules, Lecturer prompt, page and tests all change, and the saved Knowledge Packs would need a re-run.
**Not doing now:** Milestone 4 is closed first. Until then a wide stage 2 diagram scrolls sideways in its box (`overflow-x: auto`, natural width) instead of shrinking.
**To settle when discussed:** whether the gain justifies the change, whether it applies to every topic or only complex ones, and how the Planner decides.

---

## D-025: Audience by knowledge domain, and a per-stage glossary that never repeats

**Date:** 2026-09-25 | **Status:** Accepted (design approved by the user before the build; the first live run is recorded below)

**Context:** The Lecturer's prompt said "Tier 1 SOC analyst moving toward Tier 2 ... define a technical term the first time you use it". That left open what counts as a technical term. The first live run defined some terms inside blocks ("Plain-English terms: JNDI is ... LDAP is ..."), and nothing stopped a later stage from defining the same term again.
**Decision:**
- The audience is described by knowledge domains, not a list of terms: networking and common protocols, general SOC terminology, analyst workflow (triage, escalation, containment), and familiarity with what SOC tooling does. The Lecturer always defines what is specific to this exact vulnerability or technique (its component, feature and setting names, protocol variants, and the names of the weakness and attack). Which terms count as specific stays a model judgment. Code does not decide it and no term list exists.
- Each stage carries a structured `glossary`: entries of `term` and `definition`. The definition is a `SourcedValue` (one sentence, tagged documented, inference or unknown like any block), so provenance and the "cite a URL from the Pack" check apply to it.
- Enforced in code (`src/glossary.py`, `src/stage_rules.py`): a term is never defined twice in the same run.
  - A term is normalized (case, spacing, surrounding punctuation, a plain trailing plural). A parenthetical expansion counts as an alias, so "JNDI (Java Naming and Directory Interface)" collides with "JNDI".
  - Every glossary entry of a stage is checked against the entries of all earlier stages of the run and against the other entries of the same stage. A collision sends the stage back with the term and the earlier stage named.
  - The Lecturer receives the list of already defined terms, and `rerun_stage` passes the kept stages' glossaries, so a re-run of stage 3 sees the terms from stages 1 and 2.
  - A definition must be a single sentence (no line break, at most 200 characters, no second sentence). A term is at most 60 characters.
  - Glossary text is also covered by the existing checks: URL in the Pack, the "Pack" wording rule, and the phrases that present an attack as real. The "Possible scenario" wording of stage 3 does not apply to definitions. Documented definitions can be sampled by the trace check.
- The page shows a "New terms" list under each stage's text. Saved stages files stay valid, because `glossary` defaults to an empty list.
- Model and effort do not change: Sonnet 5 at medium effort (D-015). No capability gap has been measured. Deciding whether a term is specific to a topic is a judgment of the same kind the Lecturer already makes when it chooses between documented and inference. Revisit if manual review shows repeated over- or under-defining, or repeated redefinition rejections.

**Alternatives considered:** A fixed list of terms to define or skip (goes stale, cannot cover a new topic); a code rule for "specific" terms (no reliable way to tell, D-022); one glossary for the whole run at the end (the learner needs a term when it first appears); a plain-string glossary without provenance (a model-memory definition would carry no tag, against D-005); a stronger model or higher effort for the Lecturer (no measured gap, D-015).
**Consequences:** Schema change (`StageContent` and `AttackChainDraft` gain `glossary`), rules, Lecturer prompt, `run_lecturer` and `rerun_stage` (they pass the earlier stages), the page, the demo data and tests.
**Known limits:**
- Code cannot tell whether the right terms were defined. It only stops repeats. Under-defining (a vulnerability-specific term left unexplained) and over-defining (a general SOC term explained) are checked by reading the output.
- Synonyms and reworded terms ("lookup" versus "message lookup substitution") are not detected as repeats, and a term defined inside a block is not detected. The prompt forbids it, code does not.
- "One sentence" is a text heuristic. Abbreviations such as "e.g." are skipped, so a second sentence right after "etc." is not seen.
- An empty glossary is allowed, since a stage may introduce nothing new. That is a judgment, not a rule.
- Definitions from model memory tagged inference are the same open question as in D-020 and D-022.

**First live run (CVE-2021-44228, 2026-09-25, Sonnet 5 medium):** Planner and stages 1 to 3 each passed on the first attempt, about $0.21 reported in total. Glossary sizes were 2 terms (stage 1: Log4j2, CISA KEV catalog), 4 terms (stage 2: JNDI, LDAP, Message lookup substitution, Remote code execution) and 0 (stage 3). No term was repeated, and no learner text or glossary mentions the Pack. Read by eye, three things stand out:
- Stage 2 also explains JNDI and remote code execution inside blocks, next to the glossary entries. The prompt forbids this and code cannot see it (a stated limit).
- "Remote code execution" and "CISA KEV catalog" may be terms a general SOC course already teaches, so they could count as over-defining. This is the judgment the decision leaves to the model, and nothing here is measured yet.
- Stage 3 introduced no new term, so its glossary is empty, which is allowed.


---

## D-026: Live "next" versus a pre-built session (to discuss)

**Date:** 2026-09-26 | **Status:** Open (not decided, nothing built)

**Context:** `spec.md` section 3 (Workflow) describes `next` as the command that advances the agent to the next stage. D-023 decided, for Milestone 4, that none of the terminal commands (`next`, `repeat N`, `help`, `quit`) call a model: `scripts/serve_stages.py` only displays stages already written by a separate, earlier run of `scripts/run_stages.py --confirm`. That split let the page be tested without spending usage on every check, but the running product does not yet match the workflow the spec describes: one running process where `next` builds the next stage on demand.

**Question:** When does `next` move from "reveal the next saved stage" to "ask the Orchestrator to write the next stage now, then show it"? Does a no-cost pre-built/demo path stay alongside the live path, or does the live path replace it?

**What it would take (an architecture change, not a small fix):**
- One running process holding a live `KnowledgePack`, `StagePlan` and the stages written so far, instead of today's two separate scripts (build, then serve).
- `terminal.py`'s `handle_command` calling into `src/orchestrate.py` for `next` instead of only reading `PageState`; the terminal loop becomes async and must handle a slow or failing model call, which today's design ("no model call happens here") does not need to.
- A way to show the page is "writing stage N" while the call is in flight, and how a Lecturer error reaches the user without stopping the loop.
- Cost awareness (CLAUDE.md): each `next` would spend usage, so the user should know that before typing it.
- Whether `scripts/run_researcher.py` and `scripts/run_stages.py --confirm` fold into the live loop or stay as separate manual/debug entry points, as their docstrings already frame them.

**Not doing now:** this is a bigger integration step than a single milestone task. Spec section 15's open question 8 ("the final list of terminal commands") stays open alongside this.

**To settle when discussed:** whether `serve_stages.py` / `--demo` stays as a no-cost preview path once the live path exists, and which milestone this belongs to (it has no number yet in section 16).


---

## D-027: Secondary sources allowed, tagged separately (amends D-005)

**Date:** 2026-09-26 | **Status:** Accepted; scope extended by D-029

**Context:** D-005 allowed official sources only. The clearest, deepest explanations of a technique's mechanism (for example the Kerberos design flaw behind Kerberoasting) often live in well-known professional security sites, not in an official source with a fetchable API. Official-only leaves stage 2 (the weakness) thin for techniques that have no CVE/CWE.
**Decision:**
- A fourth provenance value is added: `secondary`, alongside `documented`, `inference` and `unknown`. It is kept distinct from `documented`; a secondary source is never presented as official.
- Secondary sources come from a fixed allowlist of reputable, well-known sites, not anonymous forums or random blogs. Candidates reviewed this session: Abnormal AI, Picus Security, CrowdStrike, PortSwigger. The final list is fixed when the tool is built.
- Official sources (NVD, CISA KEV, MITRE ATT&CK/CWE, vendor advisories, FIRST EPSS, official incident disclosures) stay the only `documented` sources.
- The learner sees the official-versus-secondary distinction, so interview confidence is not built on a blog presented as authoritative.

**Alternatives considered:** Keep official-only (stage 2 stays thin for CVE/CWE-less techniques); allow any site (unreliable, defeats the confidence goal); merge secondary into `documented` (hides that a claim is not official).
**Why:** The learning goal needs mechanism depth that official sources sometimes lack, without pretending a secondary source is authoritative.
**Consequences:** The provenance schema, the Researcher's allowed-domain check, and the page's tag display all change when implemented. Spec success criterion 2 is updated: every claim is `documented` (official), `secondary` (allowlist), `inference` or `unknown`.

---

## D-028: Scope is one technique plus its enabling weakness; stage model revised

**Date:** 2026-09-26 | **Status:** Accepted (design); stage 1-3 content finalized by D-029

**Context:** While designing stages 1-3 for the Kerberoasting prototype, we clarified that a MITRE ATT&CK (sub-)technique such as Kerberoasting (T1558.003) is a single point in the taxonomy (tactic > technique > sub-technique > procedure), not a multi-technique kill chain. The spec's stage 3 wording ("kill chain / spread") wrongly implied a chain of several techniques.
**Decision:**
- **Scope:** the agent is a learning tool for one technique (or one weakness) plus the weakness that enables it. It does not explain a full multi-technique intrusion. This matches the input model (one technique/CVE/CWE at a time) and D-004. Situating the technique inside a broader kill chain (option B) was rejected for the prototype (requires choosing and validating surrounding techniques, expands scope); it may return later.
- **Stage 1 (Overview), revised content:** a clear definition of the technique first; what assumption or trust is broken (conceptual); what the attacker achieves, with emphasis on the payload obtained (for example an encrypted secret for offline cracking, internal user credentials, sensitive server data); the component/protocol/configuration and its normal function; the root cause (which security assumption broke); preconditions (privileges, network access), all conceptual; the SOC angle of why it matters. It no longer describes "what an analyst might see" (that is stage 4) and, for the attack-first prototype, drops the exploitation-status tag (that was for a vulnerability-first topic). Diagram: one static picture.
- **Stage 2 (The weakness), broadened:** a deep but accessible technical explanation of the weakness, including a view of the flawed architecture. When a CVE/CWE exists it is the anchor; when none exists (Kerberoasting has neither), stage 2 explains the protocol or design flaw itself and the CVE/CWE fields are `not_applicable`. Diagram by complexity.
- **Stage 3 (Execution flow), reframed:** the internal execution steps of the single technique, in order, not a kill chain of several techniques. The cumulative-frames mechanism (D-008, D-023) is unchanged; only the framing and naming change. Diagram: frames with Previous/Next, one explanation revealed per frame.
- **Stages 4 and 5:** not designed now. Work on them starts only after stages 1-3 are fully done and reviewed on a real technique (D-017).

**Alternatives considered:** Option B (technique inside a broader kill chain) - richer but fuzzy and scope-expanding, rejected for now. Dropping stage 3 - rejected: the frames mechanism is sound, only its framing was wrong.
**Why:** Matches the real MITRE taxonomy and the input model, keeps scope achievable, and salvages the existing stage-3 work.
**Consequences:** spec.md sections 3, 6.2 and 7 need updating (stage 3 wording, stage 1/2 content, "kill chain" language) when the design moves to spec. Stage 3 code keeps its frame builder; its labels and prompt wording change. The words "kill chain" leave the learner-facing text.


---

## D-029: Full content spec for stages 1-3 (finalizes D-028), and secondary sources extended to the Researcher

**Date:** 2026-09-26 | **Status:** Accepted (design; code change pending in Claude Code)

**Context:** D-028 set the single-technique scope and the shape of stages 1-3. This session worked through each stage's exact content, and in doing so found that D-027's secondary-source allowlist is needed earlier than planned: not only in the Lecturer's stage 2 text, but in the Researcher's own fact-gathering, because the Knowledge Pack's `attack_steps` field (which stage 3 is built from, D-023) is synthesized by the Researcher, not returned by any tool. Checking real Kerberoasting explainer sites (Abnormal AI, Picus Security, CrowdStrike) during this session showed their step breakdowns (enumerate SPNs, request a TGS ticket, extract it, crack it offline, use the cracked credential) are not present in the ATT&CK STIX description field `get_attack_technique` returns - they exist only in secondary sources.

**Decision:**

**Stage 1 (Overview), full content:**
1. Definition paragraph, one paragraph of 2-4 sentences (about 40-80 words). Must state: the technique's category and MITRE tactic (for example "a Credential Access technique"); the component/protocol/resource type it targets; the core action in one clause. No CWE ids, CVSS, version numbers, or the ATT&CK id written into the prose (the id is a separate structured field).
2. What assumption, trust or check is broken, conceptual.
3. **Payload** (new field): an explicit list of what the attacker ends up holding - for example an offline-crackable encrypted secret, internal user credentials, sensitive server data - specific to this technique, not a generic phrase.
4. The component/protocol/configuration involved and its normal function, the root cause (which assumption broke), and preconditions (privileges, network access) - all conceptual. Naming the protocol/component is allowed (needed for 1 and 3 above); internal mechanism detail, version numbers, and configuration option names are not (they belong to stage 2).
5. The SOC angle: why this matters to an analyst. Not "what an analyst might see" (that is stage 4, dropped from stage 1's scope).
6. The exploitation-status tag and its wording rules (documented / not documented / unknown, D-006) do not apply to an attack-first, technique-only topic like Kerberoasting: there is no incident to be documented or undocumented. This only applies when the input is a technique/CWE with no CVE; a CVE-based run keeps D-006 as before.
**Tool:** `get_attack_technique` only. **Diagram:** one static picture, unchanged.

**Stage 2 (The weakness), full content:**
1. Anchor: a CVE or CWE, when the Pack has one - cited as `documented`, including the weakness type in plain words. When neither exists (Kerberoasting has neither), the stage says so explicitly ("this technique has no CVE or CWE") and explains the protocol or design flaw itself instead, tagged `secondary`.
2. The component's normal function.
3. Root cause: which security assumption broke.
4. The failure mechanism, step by step.
5. Preconditions.
6. What a fix or hardening changes.
7. An explicit depth boundary: a view of the flawed architecture, but not deeper than stays relevant to an analyst - no source code, no protocol-RFC-level detail.
**Tools:** `get_nvd_record` when the input is a CVE; the official CWE site when a CWE id is known; otherwise a secondary source from the allowlist. **Finding:** no official source maps an arbitrary ATT&CK technique to a CWE or CVE; this is not a missing tool, it is a real gap, correctly handled by `not_applicable` (D-028) plus a secondary source.

**Stage 3 (Execution flow), full content:** the internal execution steps of this one technique, in order (not a multi-technique kill chain). Each step names what the attacker does and ties back explicitly to the weakness from stage 2 ("as explained in stage 2, this exploits ..."). No commands, payloads or exploit code (unchanged, defensive focus). Diagram mechanism is unchanged from D-008/D-023: frames built in code from the chain, Previous/Next, one explanation revealed per frame. Only the learner-facing framing changes: "execution flow of this technique", never "kill chain" or "attack chain of techniques".

**Secondary sources extended to the Researcher (amends D-027's scope):** the Researcher, not only the Lecturer, may use the secondary-source allowlist, specifically to build the Knowledge Pack's `attack_steps` field when no official source gives a step breakdown for a technique. Every fact from a secondary source is tagged `secondary` in the Pack, same as when the Lecturer uses one directly.

**Alternatives considered:** Keep `attack_steps` as the Researcher's own knowledge (`inference`) with no source access - rejected, since D-023 already ties stage 3's correctness to the Pack's `attack_steps` being accurate, and ungrounded inference is weaker than a tagged secondary source; restrict secondary sources to the Lecturer only - rejected, it leaves the Researcher's own Pack fields for a non-CVE technique without any grounding better than model memory, which is what D-027 was meant to fix.
**Why:** The real explainer sites checked this session show the step-by-step breakdown a learner needs simply does not exist in an official, structured form for a technique like Kerberoasting. Grounding it in a tagged secondary source is more honest than silent model memory, and matches D-027's original reasoning.
**Consequences:** `config/stages.toml` stage 2 and 3 `content` fields need rewriting to match this spec. `StageContent`'s provenance enum needs a fourth value `secondary` (D-027, now also touching the Pack schema, not only stage content). `src/researcher_tools.py` needs a secondary-source tool (or tools) reading from the fixed allowlist; `src/researcher.py`'s allowed-domain check (D-020) needs the secondary allowlist added, kept distinct from the official-domain list. `src/lecturer.py`'s `_stage_rules` needs a new block for `why_possible` (stage 2, currently empty) and a rewrite of the `overview` (stage 1) block for the payload field and the dropped exploitation-status wording for attack-first topics. `src/stage_rules.py` needs a check for the new `secondary` tag and for the "no CVE or CWE" statement. Stage 3's existing frame-building code (`src/frames.py`) needs no change; only its prompt wording changes.


---

## D-030: Secondary-source allowlist finalized (closes the open item in D-027)

**Date:** 2026-09-26 | **Status:** Accepted

**Context:** D-027 introduced the `secondary` provenance tag with the allowlist left open ("the final list is fixed when the tool is built"). This session reviewed candidate sites by actually fetching and checking their Kerberoasting coverage against three criteria: the execution chain, the weakness that enables it end to end, and how the weakness itself works.

**Decision:**
- **Allowlist, fixed:** `crowdstrike.com`, `picussecurity.com`. Both are well-known, established security vendors; both gave an accurate, complete breakdown of Kerberoasting's mechanism and steps when checked.
- **Microsoft is routed as an official vendor advisory, not secondary.** Microsoft is the vendor of the specific Active Directory/Kerberos implementation being taught (as distinct from the Kerberos protocol in general), so `microsoft.com/security/blog` and `learn.microsoft.com` belong to D-005's existing "vendor advisories" category, and go through the Researcher's official-source path, not the new secondary-source tool. For a topic whose vendor documents it, this may reduce or remove the need for a secondary source at all.
- **Not included:** Abnormal AI (abnormal.ai) - gave the clearest single explanation seen this session, but the company is known primarily for email security, not established as a general threat-intelligence authority; left out to keep the allowlist small and defensible rather than added on content quality alone. PortSwigger (portswigger.net) - highly reputable, but scoped to web-application vulnerabilities (SQL injection, XSS and similar); a candidate to add specifically for that topic category later, not for the general allowlist now.

**Alternatives considered:** Including Abnormal AI for its content quality (rejected: reputation bar matters more than one good article, and the allowlist should stay small); a single "vendor blog" catch-all instead of naming Microsoft specifically (rejected: D-005 already has a vendor-advisory category, no need for a new rule).
**Why:** The allowlist should be short, defensible on the vendor's/site's own standing, and never a substitute for an official source that already exists.
**Consequences:** `src/researcher_tools.py`'s secondary-source tool, when built, reads only these two domains. Vendor-advisory tooling (existing or to be built) should recognize `microsoft.com`/`learn.microsoft.com` as official for Microsoft-product topics. The allowlist can grow later through the same review process (fetch, check against the three criteria, confirm reputation).


---

## D-031: Secondary-source tool built; vendor-advisory tool is a known gap

**Date:** 2026-09-26 | **Status:** Accepted

**Context:** D-029 and D-030 called for a secondary-source tool for the Researcher. It is now built: `get_secondary_source` in `src/researcher_tools.py`, with its allowlist, page fetch and text extraction in `src/sources/secondary.py`.

**Decision:**
- The tool reads one https page on `crowdstrike.com` or `picussecurity.com` (subdomains count, look-alikes do not). The check runs in code before any download. A redirect that leaves the allowlist is refused, not followed. Only the standard library is used (no new dependency).
- `ProvenanceTag` gains `secondary`, which needs a `source_url` like `documented`.
- `src/merge.py` keeps two separate lists. A `documented` claim must cite an official domain, a `secondary` claim must cite an allowlist domain, and both must cite a URL a tool returned in this run. Mixing them is rejected, with a hint in the error message.
- The Researcher prompt limits the tool to building `attack_steps` when no official result gives a step breakdown.

**Known gap (not fixed here):** there is no vendor-advisory tool yet. D-030 classes `microsoft.com` and `learn.microsoft.com` as official for Microsoft-product topics, but nothing can read them. For a topic like Kerberoasting, stage 2 therefore has no official source at all, only the secondary allowlist, until a vendor-advisory tool is built as a separate task.

**Not yet done (still open from D-029's consequences):** `stage_rules.py` does not yet check `secondary` blocks or the "no CVE or CWE" statement, and `config/stages.toml` and the Lecturer prompt are unchanged. `run_researcher` is still CVE-only, so no live run has used the new tool yet.
**Why:** Keeps the Researcher's reach small and enforced in code, and records honestly where official coverage is still missing.

---

## D-032: Stage rules, stage config and Lecturer prompt follow D-029; exploitation enum is a follow-up

**Date:** 2026-09-26 | **Status:** Accepted

**Context:** D-029 listed the code changes its stage 1-3 content needed. This is the Lecturer side of them (the Researcher's technique path is not built yet).

**Decision:**
- `src/stage_rules.py`:
  - A `documented` block must cite an official Pack URL. A `secondary` block must cite an allowlist URL whose Pack entries are not tagged documented. So neither tag can stand in for the other.
  - Stage 2 must say "no CVE or CWE" when the topic has neither, must name no CVE or CWE id then, and needs a `secondary` block when the Pack holds the flaw under a secondary source. When the topic has a CVE or CWE it must not say it.
  - Stage 1 prose may not contain a CWE id, a CVSS mention or an ATT&CK technique id.
  - The words "kill chain" are rejected in every stage.
- Exploitation rules (the "No documented incident" sentence, "potential", "partial", the real-attack wording check, and stage 3's "Possible scenario" rule) are skipped when `topic_type` is `technique`. A CVE topic is unchanged.
- `config/stages.toml`: stages 1 to 3 rewritten to the D-029 content. Stage 3's subject is now "Execution flow". The internal key `attack_chain` and the `kill_chain_frames` enum value stay, so saved sessions and `src/frames.py` do not break; only learner-facing text changed.
- The Lecturer prompt has a `secondary` tag rule, the D-029 stage 1 order, a stage 2 block with a with-CVE/CWE and a without variant, and the single-technique framing for stage 3.
- The payload is a prompt requirement only, not a schema field (code cannot check that it is specific).
- Test data and the demo stage used "Kill chain" as a glossary term. They now use "Attack step".

**Follow-up (open):** `ExploitationStatus` has three values and the Pack validators allow evidence and incidents only when the status is `documented`. A technique-only Pack has no meaningful status, so it currently carries `unknown` and the rules are skipped by `topic_type`. When the Researcher's technique path is built, decide whether a `not_applicable` value (or an optional field) should replace this. Not changed now.
**Known limits:** "no CVE or CWE" is decided from `topic_type` and the `weakness_type` triage field. Whether the payload is specific, and whether a step tie-back to stage 2 is real, are prompt-only. No live run has used the new rules.

---

## D-033: Technique-only input path for the Researcher; exploitation status gains `not_applicable`

**Date:** 2026-09-26 | **Status:** Accepted (closes the follow-up in D-032)

**Context:** D-028 and D-029 made a single ATT&CK technique (for example Kerberoasting, T1558.003) a valid topic with no CVE or CWE. The Researcher could only start from a CVE.

**Decision:**
- `ExploitationStatus` gains `not_applicable`. A `technique` Pack must use it, no other topic type may, and evidence and incidents stay forbidden with it. This replaces the earlier stop-gap of carrying `unknown` for a technique. The stage rules still skip the exploitation checks by `topic_type`.
- `run_researcher` takes a CVE id or a technique id and decides from the id. Code collects the facts first, as for a CVE: `collect_technique_facts` reads only ATT&CK. The technique name, tactic and description are `documented`. Every NVD-, KEV- and CWE-derived triage field (`exploited_in_the_wild`, `severity_cvss`, `weakness_type`, `affected_products`, `fix_status`, `published`, `nvd_analysis_status`) is `not_applicable`, not left out and not guessed.
- A technique run loads only `get_attack_technique` and `get_secondary_source`. The NVD and KEV tools are not in its server or its allowed-tool list, and `assert_read_only` checks the set for the run's topic type.
- The person running it supplies the secondary pages (`--source-url`, repeatable). The model must not invent page addresses. Code refuses a technique run with no page, and any page that is not https on the two allowlist domains, before the model starts. A CVE run given pages is refused too. Pages must still be returned by a tool during the run before a claim may cite them (D-020, D-031).
- A technique run whose Pack has no attack steps is rejected and sent back for correction, since stage 3 cannot be built without them. After the correction cap it fails.

**Alternatives considered:** keep `unknown` for technique Packs (contradicts the `not_applicable` triage fields and means "source unreachable" elsewhere); let the agent choose its own pages from memory (invented addresses); accept an empty step list as unknown (leaves a Pack that cannot feed stage 3).
**Why:** Keeps the technique Pack honest about what does not apply, keeps the tool reach of a run to what it needs, and turns two more rules (pages on the allowlist, steps present) into code checks.

**Known limits:**
- `scripts/run_stages.py` and `scripts/serve_stages.py` still take a CVE id, so stages for a technique Pack are a separate step.
- No live run has used this path yet.
- Code cannot check that ATT&CK truly lacks a step breakdown before a secondary page is used (D-029), nor that a step is faithful to its page (D-020's limit).
- There is still no vendor-advisory tool (D-031).

---

## D-034: Secondary sources feed only mechanism and steps; secondary steps carry no ATT&CK mapping

**Date:** 2026-09-26 | **Status:** Accepted

**Context:** The first live technique run on Kerberoasting (T1558.003, D-033) passed every code check on the first attempt, and showed two things the checks did not catch. First, the agent filled 6 detection items and 3 response items, all tagged `secondary`. D-027 and D-029 allow a secondary source for one purpose only, explaining a mechanism or an execution flow, and my technique prompt had invited detection and response items. Second, it set `mitre_technique: T1558.003` on all 6 steps, including "obtain domain credentials", "find SPNs" and "use the account", which T1558.003 does not describe. The pages do not map their steps to ATT&CK, so that mapping was the model's own, presented under a sourced tag.

**Decision:**
- `src/merge.py` rejects a `secondary` claim anywhere except `weakness_mechanism` and `attack_steps` (detection items, response items and conflict claims are refused). Such an entry must be tagged `inference` or left out. This applies to CVE runs and technique runs alike.
- `src/merge.py` rejects `mitre_technique` on a step whose action is tagged `secondary`. A `documented` step keeps its mapping. The technique itself stays recorded in the Pack's `attack_technique` triage field.
- `src/stage_rules.py`: for a technique topic, stage 3 may name the topic's own technique id, since no step carries one now. Any other id is still rejected.
- The technique prompt tells the agent to leave out detection items, response items and step mappings, and no longer invites them. The CVE prompt limits secondary sources the same way.

**Alternatives considered:** put the rules in the Pack schema (would refuse to load the Pack saved by the first live run, and the rules are about what the agent may add, which is `merge`'s job); allow `mitre_technique` on the one step that requests the ticket (code cannot tell which step that is); leave detection and response as `secondary` and rely on the tag (it blurs the D-027 line between explaining a mechanism and prescribing detection).
**Why:** Keeps the `secondary` tag to the one job D-027 gave it, and stops a model-made mapping from looking sourced.

**Known limits:**
- Detection and response for a technique now come from `inference` or from a later official-source path (stages 4 and 5 are not built).
- Code still cannot check that a step is faithful to its page (D-020).
- The Pack saved by the first live run (`sessions/T1558.003.researcher.json`, git-ignored) predates these rules and would not pass them. A re-run is needed before it is used for stages.
