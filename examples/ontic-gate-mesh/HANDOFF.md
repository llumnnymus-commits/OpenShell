# Handoff

**What just happened.** Built engine (`engine/ogm.js`), video-publish and Oracle CSA charters, tests, and the hosted page; published it at https://claude.ai/artifact/33Dpdj26neKoNUoMBBDQLx.

**Key files.** `engine/ogm.js`, `charters/*/`, `app/index.html` (edit this, not `dist/`), `scripts/build.mjs`, `tests/`.

**To update the page.** Edit `app/index.html` or the engine, run `node scripts/build.mjs`, run the tests, then republish `dist/index.html` to the same artifact URL.

**Risks.** Claude-mode paths are untested in a live viewer. A wrong charter passes every gate; the adversary is the only check on the charter itself.

**Do not repeat.** Do not bypass `[hidden]` with display rules; the page carries its own `[hidden]` rule. `node --test tests/` fails on Node 22 because it treats the directory as a file; use the glob.

**Next action.** Run scenarios 1 and 2 in Claude mode in the live page and record the result here.
