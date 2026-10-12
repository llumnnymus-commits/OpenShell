# Ontic Gate Mesh

Reference build of *Ontic Gate Mesh — Concept Spec v0.1*. Nothing happens unless it was allowed to exist, is permitted to occur, and survived an attack on its own case.

Hosted, runnable version: <https://claude.ai/artifact/33Dpdj26neKoNUoMBBDQLx> (private to its owner until shared).

## What is here

| Path | Purpose |
|------|---------|
| `engine/ogm.js` | The engine. No dependencies; runs in Node and in the browser. |
| `charters/video-publish/` | The spec's worked example as three charter files: `ontology.json`, `duties.json`, `gate-policy.json`. |
| `charters/oracle-csa/` | Selected clauses of the Oracle Cloud Services Agreement (v062223) as ordered duties, each citing its section. Illustrative, not legal advice. |
| `presets.json` | Scenarios the hosted page offers. |
| `app/index.html` | Page source. `scripts/build.mjs` inlines the engine, charters and presets into `dist/index.html`. |
| `dist/index.html` | The published page. |
| `tests/ogm.test.js` | Engine tests, including the worked example step by step. |
| `tests/app.smoke.mjs` | Headless Chromium checks of the built page at desktop and phone width. |

## Layers

1. **Ontic gate.** A proposal is a claim, never a fact. The registry decides what becomes state. Unknown kinds, unsourced proposals and stale writes stop the run. Unknown field values and illegal transitions go to quarantine while the rest of the delta is admitted and stamped with the registry version.
2. **Deontic filter.** Duties are evaluated in order. The first duty that blocks an action decides; duties carry no weights. `require` duties are positive duties: `must` conditions and `obligation`s (audit entry, attribution). An empty permitted set halts and names the blocking duties.
3. **Adversarial gate.** Only gate-class actions spend adversary rounds. The proponent builds a case from charter claims. The adversary (charter rules, or Claude on the hosted page) objects using admitted facts only; objections citing anything else are discarded. Partial objections can be answered by narrowing a narrowable parameter, after which duties are re-checked. Default is closed: a missing case, an unrebutted objection, a crashed adversary or the round cap all fail.
4. **±3.** The gate reads the last three trace entries upstream and the next three declared consumers from a manifest built from the workflow (n8n exports accepted). Everything else rides in a hashed passport. Drift is counted per gate: +3 adds two adversary rounds, −3 opens the human review path. Irreversible actions whose final consumer sits outside the window escalate.

Second layer: **Litr8** (raw idea to spec candidate; open terms are never silently resolved), **BaceSpec** (frozen, hashed, amended only by a separate approved transition), **DeStraint** (scoped, budgeted, expiring grants below the duty ceiling), **FulRR** (fulfill, review, repair named failures only, attempt cap, unresolved at the cap) and **FidGit** (append-only SHA-256 chain with prev state, new state, reason, requirement, checks and outcome).

## Run the checks

```shell
node --test tests/*.test.js
node scripts/build.mjs
NODE_PATH=$(npm root -g) node tests/app.smoke.mjs
```

## Readings this build commits to

The spec flags these as guesses. They are recorded in `DECISIONS.md` and can be changed in the charter or engine.

- Ontic shepherding means controlling what may exist, not steering entities toward a state.
- ±3 is both a window and a tolerance band.
- Field-level quarantine does not stop the run; kind-level, source and stale-write failures do.
