// Ontic Gate Mesh (OGM) engine — reference implementation of Concept Spec v0.1.
//
// One file, no dependencies. Runs under Node (tests) and in the browser
// (the hosted artifact inlines it and reads `globalThis.OGM`).
//
// Layers, cheapest first; the first two are deterministic:
//   1. Ontic gate        — what may exist   (registry of kinds, fields, transitions)
//   2. Deontic filter    — what may be done (ordered duties, never weighted)
//   3. Adversarial gate  — what is true enough to proceed (proponent vs adversary, default closed)
//   ±3                   — how far a gate may see (trace window, manifest, passport, drift)
// Second layer: Litr8 -> BaceSpec -> DeStraint -> FulRR -> FidGit.

(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.OGM = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const ENGINE_VERSION = "0.1.0";
  const WINDOW = 3;
  const DRIFT_LIMIT = 3;

  // ---------------------------------------------------------------------------
  // Hashing (synchronous SHA-256 so the same code runs in Node and the browser)
  // ---------------------------------------------------------------------------

  const K256 = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function utf8(str) {
    if (typeof TextEncoder !== "undefined") return new TextEncoder().encode(str);
    return Uint8Array.from(Buffer.from(str, "utf8"));
  }

  function sha256(str) {
    const msg = utf8(str);
    const bitLen = msg.length * 8;
    const padded = new Uint8Array(((msg.length + 9 + 63) >> 6) << 6);
    padded.set(msg);
    padded[msg.length] = 0x80;
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
    dv.setUint32(padded.length - 4, bitLen >>> 0);
    const h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const w = new Uint32Array(64);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    for (let off = 0; off < padded.length; off += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (hh + S1 + ch + K256[i] + w[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        hh = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    return Array.from(h, (x) => (x >>> 0).toString(16).padStart(8, "0")).join("");
  }

  // Key-sorted JSON so equal objects hash equally.
  function stableStringify(v) {
    if (v === undefined) return "null";
    if (v === null || typeof v !== "object") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(stableStringify).join(",") + "]";
    return "{" + Object.keys(v).sort().filter((k) => v[k] !== undefined)
      .map((k) => JSON.stringify(k) + ":" + stableStringify(v[k])).join(",") + "}";
  }

  const hashOf = (v) => sha256(stableStringify(v));
  const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));

  function deepFreeze(o) {
    if (o && typeof o === "object" && !Object.isFrozen(o)) {
      Object.freeze(o);
      for (const k of Object.keys(o)) deepFreeze(o[k]);
    }
    return o;
  }

  // ---------------------------------------------------------------------------
  // Condition language shared by charters and specs.
  //   operands:  "@path.to.value" reads the context; anything else is a literal
  //   operators: all any not eq ne in nin gt gte lt lte truthy falsy exists
  // ---------------------------------------------------------------------------

  function getPath(ctx, path) {
    return path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), ctx);
  }

  function operand(ctx, x) {
    return typeof x === "string" && x.startsWith("@") ? getPath(ctx, x.slice(1)) : x;
  }

  function evalCond(cond, ctx) {
    if (cond === undefined || cond === null || cond === true) return true;
    if (cond === false) return false;
    if (typeof cond === "string") return Boolean(operand(ctx, cond));
    const [op] = Object.keys(cond);
    const arg = cond[op];
    switch (op) {
      case "all": return arg.every((c) => evalCond(c, ctx));
      case "any": return arg.some((c) => evalCond(c, ctx));
      case "not": return !evalCond(arg, ctx);
      case "eq": return operand(ctx, arg[0]) === operand(ctx, arg[1]);
      case "ne": return operand(ctx, arg[0]) !== operand(ctx, arg[1]);
      case "in": return (operand(ctx, arg[1]) || []).includes(operand(ctx, arg[0]));
      case "nin": return !(operand(ctx, arg[1]) || []).includes(operand(ctx, arg[0]));
      case "gt": return operand(ctx, arg[0]) > operand(ctx, arg[1]);
      case "gte": return operand(ctx, arg[0]) >= operand(ctx, arg[1]);
      case "lt": return operand(ctx, arg[0]) < operand(ctx, arg[1]);
      case "lte": return operand(ctx, arg[0]) <= operand(ctx, arg[1]);
      case "truthy": return Boolean(operand(ctx, arg));
      case "falsy": return !operand(ctx, arg);
      case "exists": {
        const v = operand(ctx, arg);
        return v !== undefined && v !== null && v !== "";
      }
      default: throw new Error("Unknown condition operator: " + op);
    }
  }

  // Paths a condition reads; used to check that an objection cites only admitted facts.
  function condPaths(cond, out = new Set()) {
    if (cond && typeof cond === "object") {
      for (const v of Object.values(cond)) condPaths(v, out);
    } else if (typeof cond === "string" && cond.startsWith("@")) out.add(cond.slice(1));
    return out;
  }

  // ---------------------------------------------------------------------------
  // FidGit — append-only, hash-chained record
  // ---------------------------------------------------------------------------

  class FidGit {
    constructor(entries) {
      this.entries = entries ? clone(entries) : [];
    }
    get head() {
      return this.entries.length ? this.entries[this.entries.length - 1].hash : "0".repeat(64);
    }
    append(e) {
      const body = {
        seq: this.entries.length,
        at: e.at || new Date().toISOString(),
        stage: e.stage || "mesh",
        prev_state: e.prev_state === undefined ? null : clone(e.prev_state),
        new_state: e.new_state === undefined ? null : clone(e.new_state),
        reason: e.reason || "",
        requirement: e.requirement || null,
        checks: clone(e.checks || []),
        outcome: e.outcome || "recorded",
        prev_hash: this.head,
      };
      body.hash = hashOf(body);
      this.entries.push(deepFreeze(body));
      return body;
    }
    verify() {
      let prev = "0".repeat(64);
      for (let i = 0; i < this.entries.length; i++) {
        const { hash, ...body } = this.entries[i];
        if (body.seq !== i) return { ok: false, at: i, problem: "sequence gap" };
        if (body.prev_hash !== prev) return { ok: false, at: i, problem: "broken link" };
        if (hashOf(body) !== hash) return { ok: false, at: i, problem: "entry altered" };
        prev = hash;
      }
      return { ok: true, length: this.entries.length, head: prev };
    }
    toJSON() {
      return this.entries;
    }
  }

  // ---------------------------------------------------------------------------
  // Charter validation
  // ---------------------------------------------------------------------------

  function validateCharter(ch) {
    const problems = [];
    if (!ch || !ch.ontology || !ch.duties || !ch.policy) {
      return ["A charter needs ontology, duties and policy."];
    }
    const { ontology, duties, policy } = ch;
    if (!ontology.registry_version) problems.push("ontology.registry_version is missing.");
    for (const [kind, def] of Object.entries(ontology.kinds || {})) {
      const sf = def.status_field;
      if (sf && !(def.fields && def.fields[sf])) problems.push(`${kind}: status_field '${sf}' is not a field.`);
      for (const t of def.transitions || []) {
        const en = (def.fields[sf] || {}).enum || [];
        if (!en.includes(t.from) || !en.includes(t.to)) problems.push(`${kind}: transition ${t.from}->${t.to} uses an unknown status.`);
      }
    }
    const ids = new Set();
    for (const d of duties.duties || []) {
      if (!d.id) problems.push("A duty has no id.");
      if (ids.has(d.id)) problems.push(`Duty id ${d.id} repeats.`);
      ids.add(d.id);
      if (!["forbid", "require"].includes(d.type)) problems.push(`Duty ${d.id}: type must be forbid or require.`);
      if ("weight" in d || "score" in d) problems.push(`Duty ${d.id}: duties are ordered, never weighted.`);
    }
    for (const [name, a] of Object.entries(policy.actions || {})) {
      if (!ontology.kinds[a.kind]) problems.push(`Action ${name}: kind ${a.kind} is not in the registry.`);
    }
    for (const g of policy.gate_class || []) {
      if (!(policy.actions || {})[g]) problems.push(`gate_class names unknown action ${g}.`);
    }
    return problems;
  }

  // ---------------------------------------------------------------------------
  // ±3 — manifest, window, passport
  // ---------------------------------------------------------------------------

  // workflow: {nodes:[names], edges:[[from,to],...]} or an n8n export {nodes:[{name}], connections}
  function normalizeWorkflow(wf) {
    if (!wf) return { nodes: [], edges: [] };
    if (wf.connections) {
      const nodes = (wf.nodes || []).map((n) => n.name);
      const edges = [];
      for (const [from, conn] of Object.entries(wf.connections)) {
        for (const outputs of Object.values(conn)) {
          for (const branch of outputs || []) for (const c of branch || []) edges.push([from, c.node]);
        }
      }
      return { nodes, edges };
    }
    return { nodes: wf.nodes.slice(), edges: wf.edges.slice() };
  }

  // For every node: its declared consumers within WINDOW hops, nearest first.
  function buildManifest(workflow, depth = WINDOW) {
    const { nodes, edges } = normalizeWorkflow(workflow);
    const out = {};
    const next = {};
    for (const n of nodes) next[n] = [];
    for (const [a, b] of edges) (next[a] = next[a] || []).push(b);
    for (const n of nodes) {
      const seen = new Set([n]);
      const list = [];
      let frontier = [n];
      for (let hop = 1; hop <= depth && frontier.length; hop++) {
        const nf = [];
        for (const f of frontier) {
          for (const c of next[f] || []) {
            if (!seen.has(c)) {
              seen.add(c);
              list.push({ node: c, hop });
              nf.push(c);
            }
          }
        }
        frontier = nf;
      }
      out[n] = list;
    }
    return out;
  }

  function windowFor(item, manifest, node) {
    const trace = item.trace || [];
    return {
      node,
      upstream: trace.slice(-WINDOW).map((t, i, arr) => ({ ...t, hop: -(arr.length - i) })),
      downstream: (manifest[node] || []).slice(0, WINDOW),
      beyond_upstream: Math.max(0, trace.length - WINDOW),
      prior_passport: item.passport ? item.passport.hash : null,
    };
  }

  function makePassport(fields) {
    const body = { ...fields };
    delete body.hash;
    body.hash = hashOf(body);
    return body;
  }

  // ---------------------------------------------------------------------------
  // The mesh
  // ---------------------------------------------------------------------------

  function createMesh(charter, opts = {}) {
    const problems = validateCharter(charter);
    if (problems.length) throw new Error("Invalid charter:\n- " + problems.join("\n- "));
    const ch = clone(charter);
    return {
      engine: ENGINE_VERSION,
      charter: ch,
      world: { entities: {} },
      drift: { ontic: 0, deontic: 0, adversarial: 0 },
      quarantine: [],
      fidgit: new FidGit(opts.fidgit),
      manifest: buildManifest(ch.policy.workflow),
      objectionRecord: [],
    };
  }

  function bumpDrift(mesh, gate, delta, why, notes) {
    const before = mesh.drift[gate];
    const after = Math.max(-DRIFT_LIMIT, Math.min(DRIFT_LIMIT, before + delta));
    mesh.drift[gate] = after;
    if (after !== before) {
      notes.push({ gate, from: before, to: after, why });
      if (after === DRIFT_LIMIT) notes.push({ gate, alarm: "+3: too lax; adversary rounds added" });
      if (after === -DRIFT_LIMIT) notes.push({ gate, alarm: "-3: too strict; human review path opened" });
    }
    return after;
  }

  // ---- Layer 1: ontic gate -------------------------------------------------

  function onticGate(mesh, proposal) {
    const { ontology } = mesh.charter;
    const q = [];
    const quarantine = (path, value, reason) => q.push({ path, value, reason, proposal_id: proposal.id });
    const stop = (reason) => ({ stopped: true, reason, delta: null, quarantine: q });

    if (!proposal || !proposal.entity_id) return stop("Proposal names no entity_id.");
    if (!proposal.source) {
      quarantine("*", proposal.fields, "No admitted source");
      return stop("Proposal has no source. Only sourced proposals can become state.");
    }
    const def = ontology.kinds[proposal.kind];
    if (!def) {
      quarantine("kind", proposal.kind, "Kind is not in registry " + ontology.registry_version);
      return stop(`Unknown kind '${proposal.kind}'. Sent to quarantine, not forward.`);
    }
    const current = mesh.world.entities[proposal.entity_id];
    if (current && current.kind !== proposal.kind) {
      quarantine("kind", proposal.kind, `Entity is a ${current.kind}`);
      return stop("Proposal changes an entity's kind.");
    }
    if (current && proposal.base_version !== current.version) {
      return stop(`Stale write: proposal is based on version ${proposal.base_version ?? "none"}, entity is at ${current.version}.`);
    }

    const sf = def.status_field;
    const candidate = { ...(def.defaults || {}), ...(current ? current.fields : {}) };
    const set = {};
    const fields = proposal.fields || {};

    for (const [f, v] of Object.entries(fields)) {
      if (f === sf) continue;
      const fd = def.fields[f];
      if (!fd) { quarantine(f, v, `Field '${f}' is not in ${proposal.kind}`); continue; }
      const why = checkFieldValue(fd, v);
      if (why) { quarantine(f, v, why); continue; }
      candidate[f] = v;
      set[f] = v;
    }

    if (sf && fields[sf] !== undefined && fields[sf] !== candidate[sf]) {
      const want = fields[sf];
      const why = checkFieldValue(def.fields[sf], want);
      const from = candidate[sf];
      const t = (def.transitions || []).find((x) => x.from === from && x.to === want);
      if (why) quarantine(sf, want, why);
      else if (!t) quarantine(sf, want, `No legal transition ${from} -> ${want}`);
      else if (t.by === "action") quarantine(sf, want, `${from} -> ${want} is reserved for action '${t.action}'`);
      else if (t.requires && !evalCond(t.requires, { entity: candidate })) {
        quarantine(sf, want, t.text || `Transition ${from} -> ${want} requirement not met`);
      } else {
        candidate[sf] = want;
        set[sf] = want;
      }
    }
    if (!current) Object.assign(set, { ...(def.defaults || {}), ...set });

    const version = (current ? current.version : 0) + 1;
    const delta = {
      entity_id: proposal.entity_id,
      kind: proposal.kind,
      set,
      registry_version: ontology.registry_version,
      version_token: version,
      base_version: current ? current.version : null,
    };
    const prev = current ? clone(current) : null;
    mesh.world.entities[proposal.entity_id] = {
      kind: proposal.kind,
      fields: candidate,
      version,
      registry_version: ontology.registry_version,
    };
    for (const item of q) mesh.quarantine.push({ ...item, entity_id: proposal.entity_id, status: "open", registry_version: ontology.registry_version });
    return { stopped: false, delta, quarantine: q, prev, entity: clone(mesh.world.entities[proposal.entity_id]) };
  }

  function checkFieldValue(fd, v) {
    if (fd.enum && !fd.enum.includes(v)) return `Value '${v}' is not in [${fd.enum.join(", ")}]`;
    if (fd.type === "string" && typeof v !== "string") return "Expected a string";
    if (fd.type === "number" && typeof v !== "number") return "Expected a number";
    if (fd.type === "boolean" && typeof v !== "boolean") return "Expected true or false";
    if (fd.type === "string" && fd.max_length && v.length > fd.max_length) return `Longer than ${fd.max_length} characters`;
    return null;
  }

  // ---- Layer 2: deontic filter --------------------------------------------

  function actionCtx(mesh, entity, name, params, extra) {
    const a = mesh.charter.policy.actions[name];
    const defaults = {};
    for (const [p, pd] of Object.entries(a.params || {})) if ("default" in pd) defaults[p] = pd.default;
    return {
      entity: entity.fields,
      kind: entity.kind,
      action: {
        name,
        effect: a.effect,
        reversible: !!a.reversible,
        gate_class: (mesh.charter.policy.gate_class || []).includes(name),
        params: { ...defaults, ...(params || {}) },
      },
      ...(extra || {}),
    };
  }

  function evaluateDuties(mesh, ctx) {
    const passed = [];
    const obligations = [];
    for (const d of mesh.charter.duties.duties) {
      if (!evalCond(d.applies, ctx)) continue;
      if (d.type === "forbid") {
        if (evalCond(d.when, ctx)) return { blocked: d, passed, obligations };
      } else {
        if (d.must && !evalCond(d.must, ctx)) return { blocked: d, passed, obligations };
        if (d.obligation) obligations.push({ duty: d.id, obligation: d.obligation });
      }
      passed.push(d.id);
    }
    return { blocked: null, passed, obligations };
  }

  function deonticFilter(mesh, entityId, requested, extra) {
    const entity = mesh.world.entities[entityId];
    const permitted = [];
    const blocked = [];
    for (const [name, a] of Object.entries(mesh.charter.policy.actions)) {
      if (a.kind !== entity.kind) continue;
      const params = requested && requested.name === name ? requested.params : undefined;
      const ctx = actionCtx(mesh, entity, name, params, extra);
      const r = evaluateDuties(mesh, ctx);
      if (r.blocked) blocked.push({ action: name, duty: r.blocked.id, text: r.blocked.text, cite: r.blocked.cite || null });
      else permitted.push({ action: name, passed: r.passed, obligations: r.obligations });
    }
    const req = requested ? permitted.find((p) => p.action === requested.name) : null;
    return {
      permitted,
      blocked,
      requested: requested ? requested.name : null,
      requested_permitted: !!req,
      requested_block: requested && !req ? blocked.find((b) => b.action === requested.name) || { action: requested.name, duty: null, text: "Action does not apply to this kind" } : null,
      halt: permitted.length === 0,
    };
  }

  // ---- Layer 3: adversarial gate -------------------------------------------

  function admittedFacts(entity) {
    const facts = {};
    for (const [k, v] of Object.entries(entity.fields)) facts["entity." + k] = v;
    return facts;
  }

  function buildCase(mesh, ctx) {
    const reqs = mesh.charter.policy.case_requirements || [];
    const claims = reqs.filter((c) => evalCond(c.applies, ctx)).map((c) => ({
      id: c.id,
      claim: c.claim,
      required: c.required !== false,
      holds: evalCond(c.holds, ctx),
      evidence: [...condPaths(c.holds)].map((p) => ({ path: p, value: getPath(ctx, p) })),
    }));
    const missing = claims.filter((c) => c.required && !c.holds);
    return { claims, built: missing.length === 0, missing };
  }

  // Deterministic adversary: the charter's objection rules, read against admitted facts only.
  function ruleAdversary(mesh) {
    return async function (brief) {
      const ctx = { entity: brief.entity, kind: brief.kind, action: brief.action };
      return (mesh.charter.policy.objections || [])
        .filter((o) => evalCond(o.applies, ctx) && evalCond(o.when, ctx))
        .map((o) => ({
          id: o.id,
          text: o.text,
          severity: o.severity || "full",
          cites: [...condPaths(o.when)],
          narrowing: o.narrowing || null,
          source: "rules",
        }));
    };
  }

  // Keep only objections that cite admitted facts and offer legal narrowings.
  function vetObjection(mesh, brief, o) {
    const allowed = new Set([...Object.keys(brief.facts), ...Object.keys(brief.action.params).map((p) => "action.params." + p),
      "action.name", "action.effect", "action.reversible", "action.gate_class"]);
    const cites = (o.cites || []).filter((c) => allowed.has(c));
    if (!cites.length) return { ...o, discarded: true, why: "Cites no admitted fact" };
    let narrowing = o.narrowing && typeof o.narrowing === "object" ? o.narrowing : null;
    if (narrowing) {
      const spec = mesh.charter.policy.actions[brief.action.name].params || {};
      const narrowable = new Set(mesh.charter.policy.narrowable || []);
      for (const [p, v] of Object.entries(narrowing)) {
        if (!narrowable.has(p) || !spec[p] || checkFieldValue(spec[p], v)) { narrowing = null; break; }
      }
    }
    const severity = ["full", "partial", "escalate"].includes(o.severity) ? o.severity : "full";
    return { ...o, cites, narrowing, severity, discarded: false };
  }

  async function adversarialGate(mesh, entityId, action, opts) {
    const policy = mesh.charter.policy;
    const entity = mesh.world.entities[entityId];
    const rounds = [];
    const notes = [];
    if (!(policy.gate_class || []).includes(action.name)) {
      return { result: "pass", skipped: true, reason: "Not a gate-class action; no adversary round spent.", rounds, action, notes };
    }
    if (mesh.drift.adversarial <= -DRIFT_LIMIT) {
      return { result: "escalate", reason: "Drift at -3: human review path is open for this gate.", rounds, action, notes };
    }
    const baseCap = policy.adversary_round_cap || 3;
    const cap = baseCap + (mesh.drift.adversarial >= DRIFT_LIMIT ? 2 : 0);
    if (cap > baseCap) notes.push({ gate: "adversarial", alarm: `Drift at +3: round cap raised ${baseCap} -> ${cap}` });
    const adversary = opts.adversary || ruleAdversary(mesh);

    let current = { name: action.name, params: { ...action.params } };
    let partialSeen = false;
    for (let r = 1; r <= cap; r++) {
      const ctx = actionCtx(mesh, entity, current.name, current.params);
      const theCase = buildCase(mesh, ctx);
      if (!theCase.built) {
        rounds.push({ round: r, action: clone(current), case: theCase, objections: [] });
        return { result: "fail", reason: "No case could be built: " + theCase.missing.map((m) => m.claim).join("; "), rounds, action: current, notes, partialSeen };
      }
      const brief = {
        entity: clone(entity.fields),
        kind: entity.kind,
        facts: admittedFacts(entity),
        action: clone(ctx.action),
        duties: mesh.charter.duties.duties.map((d) => ({ id: d.id, type: d.type, text: d.text })),
        case: theCase.claims.filter((c) => c.holds).map((c) => ({ id: c.id, claim: c.claim, evidence: c.evidence })),
        round: r,
        objection_hints: (policy.objections || []).map((o) => ({ id: o.id, text: o.text })),
        narrowable: (policy.narrowable || []).filter((p) => (policy.actions[current.name].params || {})[p]),
        param_spec: policy.actions[current.name].params || {},
      };
      let raw;
      try {
        raw = await adversary(brief);
      } catch (e) {
        rounds.push({ round: r, action: clone(current), case: theCase, objections: [], error: String(e && e.message || e) });
        return { result: "fail", reason: "Adversary could not run; default is closed. " + (e && e.message || e), rounds, action: current, notes, partialSeen };
      }
      const vetted = (raw || []).map((o) => vetObjection(mesh, brief, o));
      const standing = vetted.filter((o) => !o.discarded);
      rounds.push({ round: r, action: clone(current), case: theCase, objections: vetted });
      if (!standing.length) {
        return { result: "pass", reason: `Case survived round ${r}.`, rounds, action: current, notes, partialSeen };
      }
      const esc = standing.find((o) => o.severity === "escalate");
      if (esc) return { result: "escalate", reason: "Adversary escalated: " + esc.text, rounds, action: current, notes, partialSeen };
      const unrebuttable = standing.find((o) => o.severity === "full" || !o.narrowing);
      if (unrebuttable) {
        return { result: "fail", reason: "Objection stands unrebutted: " + unrebuttable.text, rounds, action: current, notes, partialSeen };
      }
      // Proponent narrows the action. The narrowed action must still be permitted by duties.
      partialSeen = true;
      const narrowed = { name: current.name, params: { ...current.params } };
      for (const o of standing) Object.assign(narrowed.params, o.narrowing);
      const recheck = evaluateDuties(mesh, actionCtx(mesh, entity, narrowed.name, narrowed.params));
      if (recheck.blocked) {
        return { result: "fail", reason: `Narrowed action is blocked by ${recheck.blocked.id}.`, rounds, action: current, notes, partialSeen };
      }
      rounds[rounds.length - 1].narrowed_to = clone(narrowed.params);
      current = narrowed;
    }
    return { result: "fail", reason: `Round cap (${cap}) reached with objections standing.`, rounds, action: current, notes, partialSeen };
  }

  // ---- Run one request through the mesh -----------------------------------

  // request: { proposal, action: {name, params}, item: {id, trace: [{node, summary}], passport?} }
  async function runMesh(mesh, request, opts = {}) {
    const policy = mesh.charter.policy;
    const gateNode = policy.gate_node;
    const item = clone(request.item || { id: "item-" + Date.now(), trace: [] });
    item.trace = item.trace || [];
    const report = { exit: null, gates: {}, notes: [], entries: [] };
    const log = (e) => report.entries.push(mesh.fidgit.append(e));
    const win = windowFor(item, mesh.manifest, gateNode);
    report.window = win;

    // ±3 long-range check: irreversible actions whose final consumer is out of sight escalate.
    const actDef = request.action ? policy.actions[request.action.name] : null;
    let longRange = null;
    if (actDef && !actDef.reversible && actDef.final_consumer) {
      const inView = win.downstream.some((d) => d.node === actDef.final_consumer);
      if (!inView) longRange = `Irreversible action '${request.action.name}' has final consumer '${actDef.final_consumer}' outside the ±3 window.`;
    }

    // Layer 1
    const on = onticGate(mesh, request.proposal);
    report.gates.ontic = on;
    item.trace.push({ node: "ontic-gate", summary: on.stopped ? "stopped" : `admitted v${on.delta.version_token}, quarantined ${on.quarantine.length}` });
    log({
      stage: "ontic",
      prev_state: on.prev || null,
      new_state: on.stopped ? null : on.delta,
      reason: on.stopped ? on.reason : "Proposal admitted against registry " + mesh.charter.ontology.registry_version,
      requirement: "registry " + mesh.charter.ontology.registry_version,
      checks: on.quarantine.map((x) => ({ quarantined: x.path, value: x.value, why: x.reason })),
      outcome: on.stopped ? "stopped" : on.quarantine.length ? "admitted-partial" : "admitted",
    });
    if (on.stopped) return finish(mesh, report, item, "ontic_stop", on.reason);
    if (!request.action) return finish(mesh, report, item, "admitted", "State admitted; no action requested.");

    // Layer 2
    const de = deonticFilter(mesh, request.proposal.entity_id, request.action);
    report.gates.deontic = de;
    item.trace.push({ node: "deontic-filter", summary: `permitted [${de.permitted.map((p) => p.action).join(", ")}]` });
    log({
      stage: "deontic",
      reason: de.halt ? "Permitted set is empty" : de.requested_permitted ? `${request.action.name} is permitted` : `${request.action.name} is blocked`,
      requirement: "duties " + (mesh.charter.duties.version || ""),
      checks: [...de.blocked.map((b) => ({ action: b.action, blocked_by: b.duty })), ...de.permitted.map((p) => ({ action: p.action, permitted: true, obligations: p.obligations.map((o) => o.obligation) }))],
      outcome: de.halt ? "halt" : de.requested_permitted ? "permitted" : "blocked",
    });
    if (de.halt) {
      return finish(mesh, report, item, "deontic_halt", "Halt: every action is blocked. " + de.blocked.map((b) => `${b.action} by ${b.duty}`).join("; "));
    }
    if (!de.requested_permitted) {
      const b = de.requested_block;
      return finish(mesh, report, item, "deontic_block",
        `${b.action} blocked by ${b.duty}: ${b.text}. Still permitted: ${de.permitted.map((p) => p.action).join(", ")}.`);
    }

    // Layer 3
    if (longRange) {
      report.gates.adversarial = { result: "escalate", reason: longRange, rounds: [] };
      log({ stage: "adversarial", reason: longRange, outcome: "escalate" });
      return finish(mesh, report, item, "escalate", longRange);
    }
    const ad = await adversarialGate(mesh, request.proposal.entity_id, request.action, opts);
    report.gates.adversarial = ad;
    report.notes.push(...ad.notes);
    item.trace.push({ node: "adversarial-gate", summary: `${ad.result} in ${ad.rounds.length} round(s)` });
    if (ad.partialSeen) bumpDrift(mesh, "adversarial", +1, "A partial objection stood before narrowing", report.notes);
    for (const r of ad.rounds) for (const o of r.objections) {
      if (!o.discarded) mesh.objectionRecord.push({ id: o.id, text: o.text, source: o.source || "model", run_item: item.id, proved: null });
    }
    log({
      stage: "adversarial",
      reason: ad.reason,
      requirement: "gate policy cap " + (policy.adversary_round_cap || 3),
      checks: ad.rounds.map((r) => ({ round: r.round, params: r.action.params, objections: r.objections.map((o) => ({ id: o.id, severity: o.severity, discarded: o.discarded })), narrowed_to: r.narrowed_to || null })),
      outcome: ad.result,
    });
    if (ad.result !== "pass") return finish(mesh, report, item, ad.result === "escalate" ? "escalate" : "adversarial_fail", ad.reason);

    // Execute the surviving action and honour its obligations.
    const entity = mesh.world.entities[request.proposal.entity_id];
    const before = clone(entity);
    const permittedEntry = de.permitted.find((p) => p.action === ad.action.name);
    if (actDef.transition) {
      entity.fields[mesh.charter.ontology.kinds[entity.kind].status_field] = actDef.transition.to;
      entity.version += 1;
    }
    report.executed = { action: ad.action, obligations: permittedEntry.obligations };
    log({
      stage: "execute",
      prev_state: before,
      new_state: clone(entity),
      reason: `Executed ${ad.action.name} ${stableStringify(ad.action.params)}`,
      requirement: permittedEntry.obligations.map((o) => `${o.duty}:${o.obligation}`).join(", ") || null,
      checks: permittedEntry.obligations.map((o) => ({ duty: o.duty, obligation: o.obligation, fulfilled: true })),
      outcome: "done",
    });
    return finish(mesh, report, item, "pass", `${ad.action.name} passed all three gates.`);
  }

  function finish(mesh, report, item, exit, summary) {
    report.exit = exit;
    report.summary = summary;
    report.drift = { ...mesh.drift };
    const de = report.gates.deontic;
    report.passport = makePassport({
      item_id: item.id,
      entity_ids: report.gates.ontic && report.gates.ontic.delta ? [report.gates.ontic.delta.entity_id] : [],
      registry_version: mesh.charter.ontology.registry_version,
      rules_passed: de ? (de.permitted.find((p) => p.action === de.requested) || { passed: [] }).passed : [],
      gates: Object.fromEntries(Object.entries(report.gates).map(([k, v]) => [k, v.result || (v.stopped ? "stopped" : k === "deontic" ? (v.requested_permitted ? "permitted" : "blocked") : "admitted")])),
      drift: { ...mesh.drift },
      exit,
      trace_len: item.trace.length,
      fidgit_head: mesh.fidgit.head,
      prev_passport: item.passport ? item.passport.hash : null,
    });
    item.passport = report.passport;
    report.item = item;
    return report;
  }

  // Human override of a block judged unnecessary: drift moves toward strict.
  function humanOverride(mesh, gate, who, why) {
    const notes = [];
    bumpDrift(mesh, gate, -1, `Human override by ${who}: ${why}`, notes);
    mesh.fidgit.append({ stage: "review", reason: `Override of ${gate} block judged unnecessary: ${why}`, requirement: "human review", checks: notes, outcome: "drift-down", new_state: { drift: { ...mesh.drift }, by: who } });
    return notes;
  }

  // Quarantine review: add a value to the registry as a versioned edit.
  function amendRegistry(mesh, { kind, field, addEnum, approver, reason }) {
    if (!approver) throw new Error("A registry edit needs a named human approver.");
    const ont = mesh.charter.ontology;
    const fd = ((ont.kinds[kind] || {}).fields || {})[field];
    if (!fd || !fd.enum) throw new Error(`Only enum fields can be extended (${kind}.${field}).`);
    if (fd.enum.includes(addEnum)) throw new Error("Value already in registry.");
    const prev = ont.registry_version;
    fd.enum.push(addEnum);
    ont.registry_version = bumpVersion(prev);
    for (const q of mesh.quarantine) {
      if (q.status === "open" && q.path === field && q.value === addEnum) q.status = "eligible-resubmit";
    }
    return mesh.fidgit.append({ stage: "charter", prev_state: { registry_version: prev }, new_state: { registry_version: ont.registry_version, kind, field, added: addEnum }, reason: reason || "Quarantine review", requirement: "versioned registry edit", checks: [{ approver }], outcome: "amended" });
  }

  // Duties change only by a versioned charter edit with a human approver, never in-run.
  function amendDuties(mesh, duties, approver, reason) {
    if (!approver) throw new Error("A duty edit needs a named human approver.");
    const next = { ...mesh.charter, duties: { ...mesh.charter.duties, duties: clone(duties) } };
    const problems = validateCharter(next);
    if (problems.length) throw new Error(problems.join(" "));
    const prev = mesh.charter.duties.version;
    mesh.charter.duties = { ...next.duties, version: bumpVersion(prev || "0.0.0") };
    return mesh.fidgit.append({ stage: "charter", prev_state: { duties_version: prev }, new_state: { duties_version: mesh.charter.duties.version, ids: duties.map((d) => d.id) }, reason: reason || "Duty edit", requirement: "versioned charter edit", checks: [{ approver }], outcome: "amended" });
  }

  function bumpVersion(v) {
    const m = /^(.*?)(\d+)$/.exec(v);
    return m ? m[1] + (Number(m[2]) + 1) : v + ".1";
  }

  // ---------------------------------------------------------------------------
  // Second layer: Litr8 -> BaceSpec -> DeStraint -> FulRR -> FidGit
  // ---------------------------------------------------------------------------

  const SPEC_FIELDS = ["inputs", "outputs", "invariants", "side_effects", "success_evidence", "stop_conditions"];

  const Litr8 = {
    capture(raw, fidgit, cap = 6) {
      const s = { raw, terms: [], draft: {}, iteration: 0, cap, entry0: null };
      s.entry0 = fidgit.append({ stage: "litr8", new_state: { raw }, reason: "Raw statement captured verbatim", outcome: "captured" }).hash;
      return s;
    },
    addTerm(s, term, readings) {
      if (s.terms.find((t) => t.term === term)) return s.terms.find((t) => t.term === term);
      const t = { term, readings: readings.slice(), ambiguous: readings.length !== 1, chosen: null, status: "open" };
      s.terms.push(t);
      return t;
    },
    choose(s, term, reading) {
      const t = s.terms.find((x) => x.term === term);
      if (!t) throw new Error("Unknown term " + term);
      if (typeof reading === "number") reading = t.readings[reading];
      if (!reading) throw new Error("Pick a reading or write one.");
      if (!t.readings.includes(reading)) t.readings.push(reading);
      t.chosen = reading;
      t.status = "resolved";
      return t;
    },
    defer(s, term) {
      const t = s.terms.find((x) => x.term === term);
      t.status = "deferred";
      t.chosen = null;
      return t;
    },
    // fields: {inputs: [{value, from:{term}}], ..., success_evidence: [{criterion, check, from}]}
    setDraft(s, fields) {
      s.iteration += 1;
      s.draft = clone(fields);
      return s;
    },
    readiness(s) {
      const problems = [];
      for (const t of s.terms) if (t.status === "open") problems.push(`Term '${t.term}' is still open.`);
      for (const f of SPEC_FIELDS) {
        const items = s.draft[f];
        if (!Array.isArray(items) || !items.length) { problems.push(`Field '${f}' is empty.`); continue; }
        for (const it of items) {
          const src = it.from && s.terms.find((t) => t.term === it.from);
          if (!src) problems.push(`'${f}' item "${it.value || it.criterion}" cites no term.`);
          else if (src.status !== "resolved") problems.push(`'${f}' item "${it.value || it.criterion}" uses ${src.status} term '${src.term}'.`);
          if (f === "success_evidence" && !(it.check && it.check.type)) problems.push(`Criterion "${it.criterion}" names no checkable evidence.`);
        }
      }
      if (s.iteration > s.cap) problems.push(`Iteration cap ${s.cap} passed.`);
      return { ready: problems.length === 0, problems };
    },
    exit(s, fidgit) {
      const r = Litr8.readiness(s);
      const candidate = { raw_ref: s.entry0, ...clone(s.draft), vocabulary: s.terms.filter((t) => t.status === "resolved").map((t) => ({ term: t.term, reading: t.chosen })) };
      const open = s.terms.filter((t) => t.status !== "resolved").map((t) => ({ term: t.term, status: t.status }));
      fidgit.append({ stage: "litr8", new_state: { candidate_hash: hashOf(candidate), open_terms: open }, reason: "Litr8 exit", checks: r.problems.map((p) => ({ problem: p })), outcome: r.ready ? "spec-candidate" : "not-ready" });
      return { ready: r.ready, problems: r.problems, candidate, open_terms: open };
    },
  };

  const BaceSpec = {
    promote(candidate, approver, fidgit, id = "spec-1") {
      if (!approver) throw new Error("Promoting a candidate to BaceSpec is a separate authorized step: name the approver.");
      const spec = { id, version: 1, ...clone(candidate), approved_by: approver };
      spec.hash = hashOf(spec);
      fidgit.append({ stage: "bacespec", new_state: { id, version: 1, hash: spec.hash }, reason: "Spec frozen for the run", checks: [{ approver }], outcome: "frozen" });
      return deepFreeze(spec);
    },
    amend(spec, changes, approver, fidgit) {
      if (!approver) throw new Error("Changing BaceSpec is its own transition with its own approver.");
      const { hash, ...body } = spec;
      const next = { ...clone(body), ...clone(changes), version: spec.version + 1, approved_by: approver };
      next.hash = hashOf(next);
      fidgit.append({ stage: "bacespec", prev_state: { version: spec.version, hash }, new_state: { version: next.version, hash: next.hash }, reason: "Spec amended", checks: [{ approver }], outcome: "amended" });
      return deepFreeze(next);
    },
    verify(spec) {
      const { hash, ...body } = spec;
      return hashOf(body) === hash;
    },
  };

  const DeStraint = {
    // Duties are the ceiling: a grant can only open freedom below them.
    issue(mesh, { spec, entityId, requests, now = Date.now(), approver }, fidgit) {
      const grants = [];
      const refused = [];
      const de = entityId ? deonticFilter(mesh, entityId, null) : null;
      const allowedEffects = new Set((spec.side_effects || []).map((s) => s.value || s));
      for (const r of requests) {
        let why = null;
        if (r.action && de && !de.permitted.find((p) => p.action === r.action)) {
          const b = de.blocked.find((x) => x.action === r.action);
          why = `Duty ${b ? b.duty : "?"} forbids ${r.action}; a grant cannot exceed duties.`;
        } else if (r.scope && !allowedEffects.has(r.scope)) {
          why = `Scope '${r.scope}' is not a side effect the spec allows.`;
        } else if (r.needs_approval && !approver) {
          why = "Approval required and no approver named.";
        }
        if (why) { refused.push({ ...r, why }); continue; }
        grants.push({
          id: "g" + (grants.length + 1) + "-" + hashOf([r, now]).slice(0, 6),
          action: r.action || null,
          scope: r.scope,
          budget: r.budget ?? 1,
          used: 0,
          expires_at: now + (r.ttl_ms ?? 15 * 60 * 1000),
          approved_by: r.needs_approval ? approver : null,
        });
      }
      fidgit.append({ stage: "destraint", new_state: { grants: grants.map((g) => ({ id: g.id, scope: g.scope, budget: g.budget })) }, reason: "Grants issued below the duty ceiling", checks: refused.map((x) => ({ refused: x.scope || x.action, why: x.why })), outcome: refused.length ? "partial" : "granted" });
      return { grants, refused };
    },
    use(grants, scope, now = Date.now()) {
      const g = grants.find((x) => x.scope === scope);
      if (!g) return { ok: false, why: `No grant for scope '${scope}'.` };
      if (now > g.expires_at) return { ok: false, why: `Grant ${g.id} expired.` };
      if (g.used >= g.budget) return { ok: false, why: `Grant ${g.id} budget spent (${g.budget}).` };
      g.used += 1;
      return { ok: true, grant: g };
    },
  };

  function runCheck(check, candidate) {
    const val = candidate == null ? undefined : candidate[check.field];
    const s = typeof val === "string" ? val : val == null ? "" : String(val);
    switch (check.type) {
      case "nonEmpty": return s.trim().length > 0;
      case "maxLength": return s.length <= check.max;
      case "minLength": return s.length >= check.min;
      case "includes": return s.toLowerCase().includes(String(check.text).toLowerCase());
      case "excludes": return !s.toLowerCase().includes(String(check.text).toLowerCase());
      case "regex": return new RegExp(check.pattern, check.flags || "").test(s);
      case "equals": return val === check.value;
      case "cond": return evalCond(check.cond, { candidate });
      default: throw new Error("Unknown check type " + check.type);
    }
  }

  const FulRR = {
    review(spec, candidate) {
      return (spec.success_evidence || []).map((c, i) => ({ id: c.id || "S" + (i + 1), criterion: c.criterion, pass: runCheck(c.check, candidate) }));
    },
    // fulfill(spec, attempt) -> candidate ; repair(spec, candidate, failures) -> candidate
    // intentCheck(spec, candidate) -> [{id, text}] objections that meet the letter but break intent
    async run({ spec, grants, fulfill, repair, intentCheck, cap = 3, mesh, fidgit, onStep }) {
      if (!BaceSpec.verify(spec)) throw new Error("BaceSpec hash does not match; the spec was modified.");
      const attempts = [];
      let candidate = null;
      let failures = [];
      for (let n = 1; n <= cap; n++) {
        const use = DeStraint.use(grants, "edit_temp_copy");
        if (!use.ok) {
          fidgit.append({ stage: "fulrr", reason: use.why, outcome: "unresolved" });
          return { status: "unresolved", reason: use.why, attempts, candidate };
        }
        candidate = n === 1 ? await fulfill(spec, n) : await repair(spec, candidate, failures);
        const review = FulRR.review(spec, candidate);
        let intent = [];
        if (intentCheck) {
          try { intent = (await intentCheck(spec, candidate)) || []; }
          catch (e) { intent = [{ id: "I?", text: "Intent reviewer could not run; default is closed: " + (e.message || e) }]; }
        }
        failures = [...review.filter((r) => !r.pass).map((r) => ({ id: r.id, text: r.criterion })), ...intent];
        const entry = fidgit.append({ stage: "fulrr", new_state: { attempt: n, candidate_hash: hashOf(candidate) }, reason: n === 1 ? "Fulfill" : "Repair of named failures: " + attempts[attempts.length - 1].failures.map((f) => f.id).join(", "), requirement: spec.id + " v" + spec.version, checks: [...review, ...intent.map((o) => ({ id: o.id, intent: o.text, pass: false }))], outcome: failures.length ? "failed-review" : "passed-review" });
        attempts.push({ n, candidate: clone(candidate), review, intent, failures, entry: entry.hash });
        if (onStep) onStep(attempts[attempts.length - 1]);
        if (!failures.length) {
          // A repair that only just passes counts toward drift.
          if (n > 1 && mesh) bumpDrift(mesh, "adversarial", +1, "FulRR passed only after repair", []);
          return { status: "passed", attempts, candidate };
        }
      }
      fidgit.append({ stage: "fulrr", reason: `Attempt cap ${cap} reached; failure preserved, run ends unresolved.`, checks: failures, outcome: "unresolved" });
      return { status: "unresolved", reason: `Attempt cap ${cap} reached.`, attempts, candidate, failures };
    },
    promote({ result, grants, fidgit, approver }) {
      if (!result || result.status !== "passed") return { ok: false, why: "Promotion needs a passing Review." };
      const use = DeStraint.use(grants, "promote_deployed");
      if (!use.ok) return { ok: false, why: use.why };
      const e = fidgit.append({ stage: "promote", new_state: { deployed: hashOf(result.candidate) }, reason: "Candidate promoted to the deployed version", checks: [{ grant: use.grant.id, approver: approver || null }], outcome: "promoted" });
      return { ok: true, entry: e };
    },
  };

  return {
    ENGINE_VERSION, WINDOW, DRIFT_LIMIT,
    sha256, stableStringify, hashOf, evalCond, condPaths,
    FidGit, validateCharter, normalizeWorkflow, buildManifest, windowFor,
    createMesh, onticGate, deonticFilter, adversarialGate, ruleAdversary, runMesh,
    humanOverride, amendRegistry, amendDuties,
    Litr8, BaceSpec, DeStraint, FulRR, runCheck,
  };
});
