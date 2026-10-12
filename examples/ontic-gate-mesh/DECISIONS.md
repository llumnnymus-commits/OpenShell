# Decisions

| Date | Decision | Why | Consequence |
|------|----------|-----|-------------|
| 2026-10-12 | Build lives in `examples/ontic-gate-mesh/` on branch `ccr-ba968bb6-0u1vi8` | The repo already keeps self-contained examples there; the session branch is the only allowed push target | Unrelated to OpenShell crates; nothing else in the repo changes |
| 2026-10-12 | Host as a Claude Artifact with `sample`, `db`, `downloads` | User asked for runnable and hostable in Claude; `sample` gives a real model adversary, `db` keeps the shared ledger | No local hosting; mesh state persists per charter in `meshes/<charter>` |
| 2026-10-12 | Ontic shepherding = controlling what may exist | Spec's primary reading; open question to Zach | Steering reading not implemented |
| 2026-10-12 | ±3 = window and tolerance band | Spec merged both; open question | Drop one by removing drift or the window code |
| 2026-10-12 | Field-level quarantine continues the run; kind, source and stale-write failures stop it | The worked example continues to the deontic filter after quarantining the ready claim | Partial admissions carry outcome `admitted-partial` in FidGit |
| 2026-10-12 | Proponent is deterministic; adversary is charter rules or Claude (complex tier) | Spec requires a different model and prompt for the adversary; a deterministic proponent cannot collude | Claude objections are vetted: non-admitted citations and illegal narrowings are discarded |
| 2026-10-12 | Oracle CSA used as a second charter, cited per section | The user supplied it with the spec; it is a real duty source | Marked illustrative, not legal advice |
| 2026-10-12 | Repair that passes after attempt 1 counts +1 adversarial drift | Spec suggestion: tie the attempt cap to drift | Repeated near-misses raise the round cap |
