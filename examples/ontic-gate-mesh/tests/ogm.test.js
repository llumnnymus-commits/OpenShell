// Run: node --test tests/*.test.js
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");
const OGM = require("../engine/ogm.js");

function loadCharter(name) {
  const dir = path.join(__dirname, "..", "charters", name);
  const read = (f) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
  return { ontology: read("ontology.json"), duties: read("duties.json"), policy: read("gate-policy.json") };
}

const videoItem = () => ({
  id: "item-video-1",
  trace: [
    { node: "render", summary: "rendered master v3" },
    { node: "rights-check", summary: "rights looked up" },
    { node: "upload", summary: "uploaded to staging" },
  ],
});

test("sha256 matches the FIPS 180-2 vectors", () => {
  assert.equal(OGM.sha256("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(OGM.sha256(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(
    OGM.sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
  );
});

test("both shipped charters validate", () => {
  assert.deepEqual(OGM.validateCharter(loadCharter("video-publish")), []);
  assert.deepEqual(OGM.validateCharter(loadCharter("oracle-csa")), []);
});

test("worked example: publishing a finished video, steps 1-6 of the spec", async () => {
  const mesh = OGM.createMesh(loadCharter("video-publish"));

  // 1-3. Proposal claims ready with unknown rights.
  const r1 = await OGM.runMesh(mesh, {
    proposal: { id: "p1", entity_id: "vid-1", kind: "Video", source: "render-node", fields: { status: "ready", rights: "unknown", title: "Harbor at dusk" } },
    action: { name: "publish", params: { monetized: true, attribution: "Footage: Harbor Co-op" } },
    item: videoItem(),
  });
  // Ontic: admitted as draft, ready claim quarantined.
  assert.equal(r1.gates.ontic.delta.set.status, "draft");
  assert.equal(r1.gates.ontic.quarantine.length, 1);
  assert.equal(r1.gates.ontic.quarantine[0].path, "status");
  assert.match(r1.gates.ontic.quarantine[0].reason, /ready requires rights of owned or licensed/);
  // Deontic: D1 bars publish; save_draft and request_rights_proof remain.
  assert.equal(r1.exit, "deontic_block");
  assert.equal(r1.gates.deontic.requested_block.duty, "D1");
  const still = r1.gates.deontic.permitted.map((p) => p.action);
  assert.ok(still.includes("save_draft") && still.includes("request_rights_proof") && !still.includes("publish"));
  // D2 attaches an audit obligation to publish (checked below once publish is permitted).

  // 4. Resubmission with a license note.
  const r2 = await OGM.runMesh(mesh, {
    proposal: { id: "p2", entity_id: "vid-1", kind: "Video", source: "owner: license note #L-114", base_version: 1, fields: { rights: "licensed", license_scope: "streaming", status: "ready" } },
    action: { name: "publish", params: { monetized: true, audience: "small", attribution: "Footage: Harbor Co-op" } },
    item: videoItem(),
  });
  assert.equal(r2.gates.ontic.quarantine.length, 0);
  assert.equal(r2.gates.ontic.delta.set.status, "ready");
  assert.ok(r2.gates.deontic.requested_permitted, "publish returns to the permitted set");
  const pub = r2.gates.deontic.permitted.find((p) => p.action === "publish");
  assert.deepEqual(pub.obligations.map((o) => o.duty), ["D2", "D4"]);

  // 5. Adversary objects (streaming license, monetized target); proponent narrows; passes in two rounds.
  const ad = r2.gates.adversarial;
  assert.equal(ad.result, "pass");
  assert.equal(ad.rounds.length, 2);
  assert.equal(ad.rounds[0].objections[0].id, "O1");
  assert.deepEqual(ad.rounds[0].narrowed_to, { monetized: false, audience: "small", attribution: "Footage: Harbor Co-op" });
  assert.equal(r2.executed.action.params.monetized, false);
  assert.equal(r2.exit, "pass");
  assert.equal(mesh.world.entities["vid-1"].fields.status, "published");

  // 6. ±3 record: three upstream traces, three declared consumers, drift +1.
  assert.deepEqual(r2.window.upstream.map((u) => u.node), ["render", "rights-check", "upload"]);
  assert.deepEqual(r2.window.downstream.map((d) => d.node), ["publish", "notify", "archive"]);
  assert.equal(r2.drift.adversarial, 1);
  assert.equal(r2.passport.exit, "pass");
  assert.equal(r2.passport.hash.length, 64);

  assert.ok(mesh.fidgit.verify().ok);
});

test("ontic gate: unknown kind is quarantined and stops the run", async () => {
  const mesh = OGM.createMesh(loadCharter("video-publish"));
  const r = await OGM.runMesh(mesh, { proposal: { id: "p", entity_id: "x", kind: "Podcast", source: "s", fields: {} }, item: videoItem() });
  assert.equal(r.exit, "ontic_stop");
  assert.equal(mesh.quarantine.length, 0, "stop-level quarantine is reported, not admitted");
  assert.equal(r.gates.ontic.quarantine[0].path, "kind");
});

test("ontic gate: unsourced proposals and stale writes are refused", async () => {
  const mesh = OGM.createMesh(loadCharter("video-publish"));
  let r = await OGM.runMesh(mesh, { proposal: { id: "p", entity_id: "v", kind: "Video", fields: { rights: "owned" } } });
  assert.equal(r.exit, "ontic_stop");
  assert.match(r.summary, /no source/);
  r = await OGM.runMesh(mesh, { proposal: { id: "p", entity_id: "v", kind: "Video", source: "s", fields: { rights: "owned" } } });
  assert.equal(r.exit, "admitted");
  r = await OGM.runMesh(mesh, { proposal: { id: "p", entity_id: "v", kind: "Video", source: "s", fields: { rights: "unknown" } } });
  assert.equal(r.exit, "ontic_stop");
  assert.match(r.summary, /Stale write/);
  r = await OGM.runMesh(mesh, { proposal: { id: "p", entity_id: "v", kind: "Video", source: "s", base_version: 1, fields: { rights: "licensed", color: "red", status: "published" } } });
  assert.equal(r.exit, "admitted");
  const paths = r.gates.ontic.quarantine.map((q) => q.path).sort();
  assert.deepEqual(paths, ["color", "status"]);
  assert.match(r.gates.ontic.quarantine.find((q) => q.path === "status").reason, /No legal transition draft -> published/);
});

test("ontic gate: transitions reserved for actions cannot be proposed", async () => {
  const mesh = OGM.createMesh(loadCharter("video-publish"));
  await OGM.runMesh(mesh, { proposal: { id: "a", entity_id: "v", kind: "Video", source: "s", fields: { rights: "owned", status: "ready" } } });
  const r = await OGM.runMesh(mesh, { proposal: { id: "b", entity_id: "v", kind: "Video", source: "s", base_version: 1, fields: { status: "published" } } });
  assert.match(r.gates.ontic.quarantine[0].reason, /reserved for action 'publish'/);
});

test("deontic filter: lexical order, first blocking duty decides, empty set halts", async () => {
  const ch = loadCharter("video-publish");
  ch.duties.duties.unshift({ id: "D0", type: "forbid", text: "Freeze: nothing moves", applies: true, when: true });
  const mesh = OGM.createMesh(ch);
  const r = await OGM.runMesh(mesh, {
    proposal: { id: "p", entity_id: "v", kind: "Video", source: "s", fields: { rights: "owned", status: "ready" } },
    action: { name: "publish", params: { attribution: "x" } },
  });
  assert.equal(r.exit, "deontic_halt");
  assert.ok(r.gates.deontic.blocked.every((b) => b.duty === "D0"));
  assert.match(r.summary, /publish by D0/);
});

test("charter validation rejects weighted duties", () => {
  const ch = loadCharter("video-publish");
  ch.duties.duties[0].weight = 0.7;
  assert.match(OGM.validateCharter(ch).join(" "), /never weighted/);
});

test("positive duty: missing attribution blocks external publish", async () => {
  const mesh = OGM.createMesh(loadCharter("video-publish"));
  const r = await OGM.runMesh(mesh, {
    proposal: { id: "p", entity_id: "v", kind: "Video", source: "s", fields: { rights: "owned", license_scope: "streaming_monetized", status: "ready" } },
    action: { name: "publish", params: {} },
  });
  assert.equal(r.exit, "deontic_block");
  assert.equal(r.gates.deontic.requested_block.duty, "D4");
});

test("adversarial gate: full objection fails; default is closed when no case can be built", async () => {
  const mesh = OGM.createMesh(loadCharter("video-publish"));
  const r = await OGM.runMesh(mesh, {
    proposal: { id: "p", entity_id: "v", kind: "Video", source: "s", fields: { rights: "licensed", status: "ready" } },
    action: { name: "publish", params: { attribution: "x" } },
  });
  assert.equal(r.exit, "adversarial_fail");
  assert.match(r.summary, /no license scope/);

  const ch = loadCharter("video-publish");
  ch.policy.case_requirements.push({ id: "C9", claim: "Owner is on record", holds: { exists: "@entity.owner" } });
  const m2 = OGM.createMesh(ch);
  const r2 = await OGM.runMesh(m2, {
    proposal: { id: "p", entity_id: "v", kind: "Video", source: "s", fields: { rights: "owned", status: "ready" } },
    action: { name: "publish", params: { attribution: "x" } },
  });
  assert.equal(r2.exit, "adversarial_fail");
  assert.match(r2.summary, /No case could be built: Owner is on record/);
});

test("adversarial gate: model objections citing non-admitted facts are discarded; a crashing adversary fails closed", async () => {
  const mesh = OGM.createMesh(loadCharter("video-publish"));
  const req = (id) => ({
    proposal: { id, entity_id: "v" + id, kind: "Video", source: "s", fields: { rights: "owned", license_scope: "streaming_monetized", status: "ready" } },
    action: { name: "publish", params: { attribution: "x" } },
  });
  const hallucinating = async () => [{ id: "M1", text: "The director is litigious", severity: "full", cites: ["entity.director"] }];
  const r = await OGM.runMesh(mesh, req("1"), { adversary: hallucinating });
  assert.equal(r.exit, "pass");
  assert.equal(r.gates.adversarial.rounds[0].objections[0].discarded, true);

  const crashing = async () => { throw new Error("model timeout"); };
  const r2 = await OGM.runMesh(mesh, req("2"), { adversary: crashing });
  assert.equal(r2.exit, "adversarial_fail");
  assert.match(r2.summary, /default is closed/);

  // A narrowing to a non-narrowable param is not a rebuttal.
  const sneaky = async (b) => (b.round === 1 ? [{ id: "M2", text: "x", severity: "partial", cites: ["entity.rights"], narrowing: { attribution: "" } }] : []);
  const r3 = await OGM.runMesh(mesh, req("3"), { adversary: sneaky });
  assert.equal(r3.exit, "adversarial_fail");
});

test("±3: irreversible action whose final consumer is out of the window escalates", async () => {
  const mesh = OGM.createMesh(loadCharter("video-publish"));
  const r = await OGM.runMesh(mesh, {
    proposal: { id: "p", entity_id: "v", kind: "Video", source: "s", fields: { rights: "owned" } },
    action: { name: "delete_master", params: {} },
    item: videoItem(),
  });
  assert.equal(r.exit, "escalate");
  assert.match(r.summary, /cold-storage-purge/);
});

test("±3 drift: +3 adds adversary rounds, -3 opens human review", async () => {
  const mesh = OGM.createMesh(loadCharter("video-publish"));
  mesh.drift.adversarial = 3;
  const always = async () => [{ id: "Z", text: "z", severity: "partial", cites: ["entity.rights"], narrowing: { audience: "small" } }];
  const r = await OGM.runMesh(mesh, {
    proposal: { id: "p", entity_id: "v", kind: "Video", source: "s", fields: { rights: "owned", license_scope: "streaming_monetized", status: "ready" } },
    action: { name: "publish", params: { attribution: "x" } },
  }, { adversary: always });
  assert.equal(r.gates.adversarial.rounds.length, 5);
  assert.ok(r.notes.some((n) => /cap raised 3 -> 5/.test(n.alarm || "")));

  const m2 = OGM.createMesh(loadCharter("video-publish"));
  for (let i = 0; i < 4; i++) OGM.humanOverride(m2, "adversarial", "zach", "block was unnecessary");
  assert.equal(m2.drift.adversarial, -3);
  const r2 = await OGM.runMesh(m2, {
    proposal: { id: "p", entity_id: "v", kind: "Video", source: "s", fields: { rights: "owned", license_scope: "streaming_monetized", status: "ready" } },
    action: { name: "publish", params: { attribution: "x" } },
  });
  assert.equal(r2.exit, "escalate");
  assert.match(r2.summary, /human review/);
});

test("manifest is generated from an n8n workflow export", () => {
  const n8n = {
    nodes: [{ name: "A" }, { name: "B" }, { name: "C" }, { name: "D" }, { name: "E" }],
    connections: { A: { main: [[{ node: "B" }, { node: "C" }]] }, B: { main: [[{ node: "D" }]] }, D: { main: [[{ node: "E" }]] } },
  };
  const m = OGM.buildManifest(n8n);
  assert.deepEqual(m.A, [{ node: "B", hop: 1 }, { node: "C", hop: 1 }, { node: "D", hop: 2 }, { node: "E", hop: 3 }]);
  assert.deepEqual(m.D, [{ node: "E", hop: 1 }]);
});

test("FidGit is append-only and detects tampering", () => {
  const f = new OGM.FidGit();
  f.append({ reason: "a" });
  f.append({ reason: "b" });
  assert.ok(f.verify().ok);
  assert.throws(() => { f.entries[0].reason = "x"; });
  const forged = new OGM.FidGit(f.entries);
  forged.entries[0].reason = "rewritten";
  const v = forged.verify();
  assert.equal(v.ok, false);
  assert.equal(v.problem, "entry altered");
});

test("quarantine review: registry edit is versioned and needs an approver", async () => {
  const mesh = OGM.createMesh(loadCharter("video-publish"));
  await OGM.runMesh(mesh, { proposal: { id: "p", entity_id: "v", kind: "Video", source: "s", fields: { license_scope: "broadcast" } } });
  assert.equal(mesh.quarantine[0].value, "broadcast");
  assert.throws(() => OGM.amendRegistry(mesh, { kind: "Video", field: "license_scope", addEnum: "broadcast" }), /approver/);
  OGM.amendRegistry(mesh, { kind: "Video", field: "license_scope", addEnum: "broadcast", approver: "zach" });
  assert.equal(mesh.charter.ontology.registry_version, "video-1.0.1");
  assert.equal(mesh.quarantine[0].status, "eligible-resubmit");
});

test("duties change only through a versioned edit", () => {
  const mesh = OGM.createMesh(loadCharter("video-publish"));
  const d = mesh.charter.duties.duties.filter((x) => x.id !== "D5");
  assert.throws(() => OGM.amendDuties(mesh, d, ""), /approver/);
  OGM.amendDuties(mesh, d, "zach", "D5 too strict");
  assert.equal(mesh.charter.duties.version, "video-duties-1.0.1");
});

test("Oracle CSA charter: clauses block, narrow and escalate as encoded", async () => {
  const run = async (mesh, proposal, action, item) => OGM.runMesh(mesh, { proposal: { source: "ops-ticket", ...proposal }, action, item });
  const mesh = OGM.createMesh(loadCharter("oracle-csa"));
  const wl = { id: "w", entity_id: "wl-1", kind: "Workload", fields: { purpose: "internal_ops", ordered_units: 10, used_units: 4, status: "approved" } };

  let r = await run(mesh, wl, { name: "mine_crypto", params: {} });
  assert.equal(r.gates.deontic.requested_block.duty, "D2");
  assert.equal(r.gates.deontic.requested_block.cite, "§1.3(d)");

  r = await run(mesh, { ...wl, base_version: 1, fields: {} }, { name: "network_scan", params: {} });
  assert.equal(r.gates.deontic.requested_block.duty, "D3");

  r = await run(mesh, { ...wl, base_version: 2, fields: {} }, { name: "vulnerability_test", params: { scope: "own_tenancy" } });
  assert.equal(r.gates.deontic.requested_block.duty, "D4");

  r = await run(mesh, { ...wl, base_version: 3, fields: { oracle_written_approval: "on_file" } }, { name: "vulnerability_test", params: { scope: "shared_infrastructure" } });
  assert.equal(r.exit, "pass");
  assert.equal(r.executed.action.params.scope, "own_tenancy");

  r = await run(mesh, { ...wl, base_version: 4, fields: {} }, { name: "assign_contract", params: {} });
  assert.equal(r.gates.deontic.requested_block.duty, "D7");

  r = await run(mesh, { ...wl, base_version: 5, fields: { used_units: 14 } }, { name: "scale_beyond_order", params: {} });
  assert.equal(r.gates.deontic.requested_block.duty, "D12");
  r = await run(mesh, { ...wl, base_version: 6, fields: {} }, { name: "scale_beyond_order", params: { purchase_order: "PO-7781" } });
  assert.equal(r.exit, "pass");
  assert.deepEqual(r.executed.obligations.map((o) => o.obligation), ["pay_excess_fees", "audit_entry"]);

  const ds = { id: "d", entity_id: "ds-1", kind: "Dataset", fields: { classification: "regulated_pci", dpa_covered: true, order_permits_regulated: true } };
  r = await run(mesh, ds, { name: "store_dataset", params: {} });
  assert.equal(r.exit, "escalate");

  const pii = { id: "e", entity_id: "ds-2", kind: "Dataset", fields: { classification: "personal_info", dpa_covered: true, export_cleared: "cleared" } };
  r = await run(mesh, pii, { name: "export_dataset", params: { destination: "sanctioned" } });
  assert.equal(r.gates.deontic.requested_block.duty, "D1");
  r = await run(mesh, { ...pii, base_version: 1, fields: {} }, { name: "disclose_dataset", params: { recipient: "public" } });
  assert.equal(r.gates.deontic.requested_block.duty, "D10");
  r = await run(mesh, { ...pii, base_version: 2, fields: {} }, { name: "disclose_dataset", params: { recipient: "subcontractor_bound" } },
    { id: "i", trace: [{ node: "intake" }, { node: "classify" }, { node: "policy-check" }] });
  assert.equal(r.exit, "pass");
  assert.equal(r.executed.action.params.recipient, "employee_need_to_know");
  assert.ok(mesh.fidgit.verify().ok);
});

test("second layer: Litr8 -> BaceSpec -> DeStraint -> FulRR -> promote", async () => {
  const mesh = OGM.createMesh(loadCharter("video-publish"));
  const fid = mesh.fidgit;
  await OGM.runMesh(mesh, { proposal: { id: "p", entity_id: "vid-9", kind: "Video", source: "owner", fields: { rights: "owned", license_scope: "streaming_monetized", status: "ready" } } });

  const s = OGM.Litr8.capture("make the harbor video description punchy and credit the co-op", fid);
  OGM.Litr8.addTerm(s, "punchy", ["at most 160 characters", "uses an exclamation mark"]);
  OGM.Litr8.addTerm(s, "credit the co-op", ["includes the text 'Harbor Co-op'"]);
  OGM.Litr8.addTerm(s, "description", ["the public description field of the video"]);
  const draft = {
    inputs: [{ value: "video vid-9 metadata", from: "description" }],
    outputs: [{ value: "description text", from: "description" }],
    invariants: [{ value: "the deployed description is untouched until promotion", from: "description" }],
    side_effects: [{ value: "edit_temp_copy", from: "description" }, { value: "promote_deployed", from: "description" }],
    success_evidence: [
      { id: "S1", criterion: "At most 160 characters", from: "punchy", check: { type: "maxLength", field: "text", max: 160 } },
      { id: "S2", criterion: "Credits Harbor Co-op", from: "credit the co-op", check: { type: "includes", field: "text", text: "Harbor Co-op" } },
    ],
    stop_conditions: [{ value: "3 attempts", from: "punchy" }],
  };
  OGM.Litr8.setDraft(s, draft);
  let ex = OGM.Litr8.exit(s, fid);
  assert.equal(ex.ready, false, "open terms block readiness");
  assert.ok(ex.problems.some((p) => /Term 'punchy' is still open/.test(p)));
  OGM.Litr8.choose(s, "punchy", 0);
  OGM.Litr8.choose(s, "credit the co-op", 0);
  OGM.Litr8.choose(s, "description", 0);
  ex = OGM.Litr8.exit(s, fid);
  assert.equal(ex.ready, true, ex.problems.join("; "));

  assert.throws(() => OGM.BaceSpec.promote(ex.candidate, ""), /authorized step/);
  const spec = OGM.BaceSpec.promote(ex.candidate, "zach", fid);
  assert.ok(Object.isFrozen(spec) && Object.isFrozen(spec.success_evidence[0]));

  const { grants, refused } = OGM.DeStraint.issue(mesh, {
    spec, entityId: "vid-9", approver: "zach",
    requests: [
      { scope: "edit_temp_copy", budget: 3 },
      { scope: "promote_deployed", budget: 1, needs_approval: true },
      { scope: "edit_deployed", budget: 1 },
      { action: "request_rights_proof", scope: "edit_temp_copy" },
    ],
  }, fid);
  assert.equal(grants.length, 2);
  assert.match(refused.find((r) => r.scope === "edit_deployed").why, /not a side effect/);
  assert.match(refused.find((r) => r.action === "request_rights_proof").why, /D5 forbids/);

  const result = await OGM.FulRR.run({
    spec, grants, mesh, fidgit: fid, cap: 3,
    fulfill: async () => ({ text: "A long slow look at the harbor as the light goes, the boats come in and the city turns on, filmed over three evenings in late summer by a small crew!" }),
    repair: async (_s, c, failures) => ({ text: failures.some((f) => f.id === "S2") ? c.text.slice(0, 120) + " Thanks, Harbor Co-op." : c.text }),
  });
  assert.equal(result.status, "passed");
  assert.equal(result.attempts.length, 2);
  assert.deepEqual(result.attempts[0].failures.map((f) => f.id), ["S2"]);
  assert.equal(mesh.drift.adversarial, 1, "repair that only just passes counts as drift");

  const promoted = OGM.FulRR.promote({ result, grants, fidgit: fid, approver: "zach" });
  assert.equal(promoted.ok, true);
  assert.equal(OGM.FulRR.promote({ result, grants, fidgit: fid }).ok, false, "promotion grant budget is one");
  assert.ok(fid.verify().ok);
});

test("FulRR: attempt cap ends unresolved, never done", async () => {
  const fid = new OGM.FidGit();
  const spec = OGM.BaceSpec.promote({ side_effects: ["edit_temp_copy"], success_evidence: [{ id: "S1", criterion: "says yes", check: { type: "includes", field: "t", text: "yes" } }] }, "zach", fid);
  const grants = [{ id: "g", scope: "edit_temp_copy", budget: 9, used: 0, expires_at: Date.now() + 60000 }];
  const r = await OGM.FulRR.run({ spec, grants, fidgit: fid, cap: 2, fulfill: async () => ({ t: "no" }), repair: async () => ({ t: "still no" }) });
  assert.equal(r.status, "unresolved");
  assert.equal(r.attempts.length, 2);
  assert.equal(fid.entries[fid.entries.length - 1].outcome, "unresolved");
});
