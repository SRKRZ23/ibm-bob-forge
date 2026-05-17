# FORGE Roadmap

> **Note:** v1 (submitted to IBM Bob Hackathon May 2026) is feature-complete and locked. This document tracks improvements added after the hackathon submission and the longer-term vision for v2.
>
> The hackathon judging artifacts (lablab project page, video, slides) reflect v1. The GitHub repository continues to evolve.

---

## v1.0 — IBM Bob Hackathon submission (frozen 2026-05-17 18:46 UZT)

- Scanner: 7 OWASP LLM Top 10 categories (LLM01 / LLM02 / LLM04 / LLM05 / LLM06 / LLM07 / LLM08)
- Policy generator: Lobster Trap-compatible YAML with ingress + egress rules
- BobShell: SHA-256 hash-chained tamper-evident audit trail
- 95/95 unit tests pass in 1.2s
- 3 productive IBM Bob IDE tasks + 5 Bob Shell sessions documented in `bob_sessions/`

---

## v1.1 — Post-submission improvements (in progress)

Added without breaking v1 functionality. All 95 v1 tests still pass.

### New abstractions (additive, opt-in)

- **`src/pipeline/`** — Plan/Task DAG abstraction inspired by xAI's open-source `grox` content-understanding pipeline (Apache 2.0, released 2026-05-15). Lets future workflows be declared as a dependency graph instead of a hand-written sequence.
- **`src/utils/rate_limiter.py`** — Token bucket + concurrency semaphore. Closes the missing-rate-limit gap that production policy-enforcement pipelines need.
- **`src/pipeline/pipeline.py`** — Recsys-style pipeline traits (Source / Hydrator / Filter / Scorer / Selector / SideEffect) for when FORGE-style scanning is reframed as candidate-ranking (confidence scores per finding, ranked refactor suggestions).

### Documentation

- `ROADMAP.md` (this file)
- `CHANGELOG.md` post-submission entry

---

## v2.0 — Confidence-scored multi-category vulnerability detection

**Goal:** replace binary find/not-find with per-line per-OWASP-category probability scoring, dramatically reducing false-positive noise.

### Design (informed by xAI Phoenix multi-action prediction)

For each scanned code line, FORGE v2 emits a probability vector:

```
P(LLM01_prompt_injection)
P(LLM02_insecure_output)
P(LLM03_training_data_poisoning)
P(LLM04_dos)
P(LLM05_supply_chain)
P(LLM06_pii_disclosure)
P(LLM07_system_prompt_leakage)
P(LLM08_excessive_agency)
P(LLM09_overreliance)
P(LLM10_model_theft)
P(false_positive)
P(intentional_safe_pattern)
```

Final risk score is a weighted blend with **negative weights on `P(false_positive)` and `P(intentional_safe_pattern)`** — bad signals push the score down naturally, no separate blocklist needed.

### Implementation phases

1. **v2-alpha** — adopt the `src/pipeline/` Plan/Task DAG already shipped in v1.1; refactor the existing scan→generate→audit linear flow as a `PlanForgeScan` with explicit stages.
2. **v2-beta** — add a confidence-scoring stage powered by a small fine-tuned classifier (Phi-3-mini or Granite-3B) running per-finding instead of per-pattern. Pattern matches are the *candidates*; the classifier *scores* them.
3. **v2-rc** — incremental scan on PR diffs only (cache scores per `(commit_sha, line_hash)` pair).

---

## v3.0 — SaaS deployment

Out of scope for the hackathon. Sketch only:

- gRPC service wrapper around the existing CLI
- Web dashboard (Next.js) for browsing findings + policy diffs
- Per-tenant rate limiting (the `src/utils/rate_limiter.py` primitive is sized for this)
- Github / GitLab integration: scan on PR, comment with findings
- Stay Python (FastAPI) until measured p99 latency > 200ms — see [`docs/`](docs/) for the two-language-serving philosophy.

---

## Patterns adopted from xAI's open-source `x-algorithm` (May 2026)

Acknowledging the inspiration:

| FORGE concept | Origin in `xai-org/x-algorithm` |
|---------------|---------------------------------|
| `Plan` + `Task` DAG | `grox/plans/plan.py` + `grox/tasks/task.py` |
| Plan-eligibility dispatch | `grox.plans.plan_master.PlanMaster` |
| Pipeline traits (Source/Hydrator/Filter/Scorer/Selector/SideEffect) | `candidate-pipeline/*.rs` |
| Rate-limit task in safety pipeline | `grox/tasks/task_rate_limit.py` used in `PlanSafetyPtos` |
| Multi-action probability prediction (planned v2) | `phoenix/` ranking head |
| Two-stage filtering (pre-scoring vs post-selection) | `home-mixer/` pipeline composition |

All adopted code is fresh Python re-implementation, not a port. Apache 2.0 patterns are referenced for design lineage only.

---

## Out of scope (explicit non-goals)

- Rust port of any component — see two-language-serving philosophy (Python sufficient until measured latency demands otherwise)
- Network-active scanner that fetches remote dependencies during scan — out of FORGE's threat model
- "AI-suggested fix" auto-PR generation — that's a separate product (closer to Cursor/Cognition agent space than FORGE's static-analysis lane)

---

## Contributing

FORGE is a single-maintainer project for now. Feedback and PRs welcome at github.com/SRKRZ23/ibm-bob-forge.

Security disclosures: razikovsardor1@gmail.com with subject `[FORGE security]`. See [`SECURITY.md`](SECURITY.md).
