# Project state

**Purpose.** Runnable, Claude-hosted reference build of Ontic Gate Mesh Concept Spec v0.1, with the second layer (Litr8, BaceSpec, DeStraint, FulRR, FidGit).

**Status (2026-10-12).**

Verified:
- Engine: 20/20 Node tests pass, including spec worked example steps 1-6 exactly (quarantine of ready claim, D1 block, resubmission, O1 objection, narrowing, pass in two rounds, ±3 nodes, drift +1).
- Oracle CSA charter: blocks, narrowings and escalations tested for §1.3(a-d), §2.2, §3.4(c), §4.3, §5.4, §13.1, §17.
- Built page: headless Chromium smoke test passes at 1280px and 390px (verdicts, chain end to end with template executor, ledger verify and tamper detection, no horizontal scroll, no page errors).
- Published: https://claude.ai/artifact/33Dpdj26neKoNUoMBBDQLx (version 1). `meshes` collection readable and empty after publish.

Unverified:
- Claude adversary and Claude executor paths in the live viewer (need the user's consent prompt; cannot run from this session).
- Shared ledger save after a real run in the viewer.

**Not built.** n8n Code-node workflow export (the manifest generator accepts n8n exports; the gates themselves run in the artifact, not n8n). Objection-accuracy scoring beyond the right/wrong marks.

**Limits.** One mesh document per charter, about 240 KiB; the page tells the viewer to save the ledger and reset when full. Shared state is last-writer-wins.

**Changed files.** Everything under `examples/ontic-gate-mesh/`.
