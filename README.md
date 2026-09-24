# SOC Learning Agent

An AI agent that teaches vulnerabilities and the attacks that exploit them, from a SOC analyst's point of view, and then tests what you learned.

You give it a CVE or a plain-language description. It researches official sources, explains the topic in cumulative stages (from a business-level overview down to detection and response), draws a diagram for each stage, and finishes with a scored quiz.

> **Status: planning.** No runnable code yet. The specification lives in [`docs/spec.md`](docs/spec.md) and every design decision, with its reasoning, is recorded in [`docs/decisions.md`](docs/decisions.md).

## Why this project exists

Learning a vulnerability well means understanding four things at once: how the weakness works, how an attacker used it, what a defender can see, and what to do about it. Most sources cover one of these. This agent covers all four in a fixed order, always pairs a vulnerability with the attack that exploited it (and the other way around), and ties every claim to an official source.

It was built as a learning tool and as a portfolio project for a Tier 1 SOC analyst path.

## How it works (planned)

1. **Discover.** Enter a CVE ID or a description ("a CVE from last month", "an Active Directory misconfiguration"). The agent lists a few matching options with one line each. You pick one.
2. **Triage card.** A short card with the facts an analyst checks first: known exploitation, severity, exploit likelihood, weakness type, affected products, fix status. Fields that do not apply are marked as such.
3. **Learn in stages.** Type `next` for the next stage, `repeat` to revisit one. The number of stages depends on how complex the topic is, and the agent states it up front.
4. **Quiz.** Type `exam` for a 10-question quiz focused on SOC work. Submit your answers, get a numeric score and an explanation for every answer, and export the result to PDF.

### The five-stage model

| Stage | Focus |
|---|---|
| 1. Overview | The vulnerability and the attack that followed, as one story. Business impact, no technical depth. |
| 2. Why it is possible | The technical mechanism of the weakness. The only place it is explained in depth. |
| 3. Attack chain | What the attacker does, step by step, mapped to MITRE ATT&CK. |
| 4. What an analyst sees | Telemetry, event IDs, detection logic, false positives, detection gaps. |
| 5. Response and prevention | Triage decisions, escalation, containment, recovery, hardening, lessons. |

Simple topics may merge stages; complex topics may split them.

## Design principles

- **Official sources only.** NVD, CISA KEV, MITRE ATT&CK and CWE, vendor advisories, FIRST EPSS, and official incident disclosures. Conflicts between sources are shown, not hidden.
- **Nothing invented.** Every claim carries a provenance tag: `[Documented]`, `[Inference]`, or `[Unknown]`. When no incident is documented, the agent says so.
- **Research once, teach from one record.** A single structured record (the Knowledge Pack) feeds the explanations and the quiz, so they cannot contradict each other.
- **Defensive focus.** The agent explains detection and response. It does not produce working exploit code.
- **Untrusted input.** Web content the agent reads is treated as data, never as instructions (prompt-injection awareness, OWASP LLM01).

## Interface

Commands are typed in the terminal. All content (stages, diagrams, quiz) is shown on a local page served at `http://127.0.0.1:<port>`, reachable only from your own machine. The page updates as you type commands, without reloading.

## Requirements

- Windows machine (developed on Windows)
- Python 3.10 or newer (developed on 3.14)
- A Claude account with a Pro subscription, signed in locally

Installation and usage instructions will be added once the first milestone is complete.

## Cost and usage policy

- The project is designed to run on a Claude Pro subscription without a paid API key. Usage draws from the plan's usage limits, shared with normal Claude usage.
- **Personal use only.** Anthropic does not permit offering subscription sign-in to other people through products built on the Agent SDK. Anyone who wants to run this project should install their own copy and use their own account.
- Do not set an `ANTHROPIC_API_KEY` environment variable if you want usage billed to the subscription rather than to an API account.

## Out of scope for v1

- Hosting the agent for other users, accounts, or any public web service
- Saving scores or progress between sessions (a quiz can be exported to PDF instead)
- Sharing sessions with other people
- Sources outside the official list above

## Roadmap

| Milestone | Goal |
|---|---|
| 0 | Environment, SDK install, hello-world agent, authentication and usage check |
| 1 | Data schemas (Knowledge Pack, Stage Plan, provenance tags) |
| 2 | Researcher with NVD, KEV and ATT&CK tools |
| 3 | Planner, stages 1 and 2, first diagram |
| 4 | Stage 3 with step-by-step diagram frames |
| 5 | Examiner: questions, grading, PDF export |
| 6 | Run on a second, non-CVE topic without code changes |

After milestone 6: stages 4 and 5, free-text discovery, and the remaining question types.

## Documentation

- [`docs/spec.md`](docs/spec.md): the full specification
- [`docs/decisions.md`](docs/decisions.md): decision log

## License

To be decided.
