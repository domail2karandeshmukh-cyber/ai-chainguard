// Live demo: a small AI-ChainGuard pipeline in the browser, with real cryptography (Web Crypto):
// SHA-256 file hashes, an RFC 6962 Merkle tree over dataset rows, Ed25519 signatures over canonical
// JSON manifests that embed their parents' digests, and a hash-chained trust log signed by a root key
// whose head is pinned. The verifier recomputes everything, like the Python one (checks V0-V9).
// It trains no model: backdoor rates shown are the ones measured in the paper's experiments.
(function () {
  "use strict";
  var CG = window.CG;
  var app = document.getElementById("demo-app");
  if (!CG || !app) { return; }
  var $ = function (id) { return document.getElementById(id); };
  var chainBox = $("demo-chain"), digitsBox = $("demo-digits"), explainBox = $("demo-explain"), lensBox = $("demo-lens");
  var reportBox = $("demo-report"), gateBox = $("demo-gateway"), algBox = $("demo-alg");
  var buttons = Array.prototype.slice.call(app.querySelectorAll("[data-attack]"));
  var subtle = window.crypto && window.crypto.subtle;
  var enc = new TextEncoder();

  // ---- primitives ---------------------------------------------------------------------------------
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (b) { return ("0" + b.toString(16)).slice(-2); }).join(""); }
  function unhex(h) { var a = new Uint8Array(h.length / 2); for (var i = 0; i < a.length; i++) { a[i] = parseInt(h.substr(i * 2, 2), 16); } return a; }
  function concat(parts) { var n = 0; parts.forEach(function (p) { n += p.length; }); var out = new Uint8Array(n), o = 0; parts.forEach(function (p) { out.set(p, o); o += p.length; }); return out; }
  async function sha(bytes) { return new Uint8Array(await subtle.digest("SHA-256", bytes)); }
  async function shaHex(bytes) { return hex(await sha(bytes)); }
  function canon(v) { // canonical JSON: sorted keys, no whitespace (as the Python verifier)
    if (Array.isArray(v)) { return "[" + v.map(canon).join(",") + "]"; }
    if (v && typeof v === "object") { return "{" + Object.keys(v).sort().map(function (k) { return JSON.stringify(k) + ":" + canon(v[k]); }).join(",") + "}"; }
    return JSON.stringify(v);
  }
  var ALG = null, KEYS = {};
  async function pickAlg() {
    try {
      await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
      return { label: "Ed25519", gen: { name: "Ed25519" }, use: { name: "Ed25519" }, prefix: "ed25519:" };
    } catch (e) {
      return { label: "ECDSA P-256", gen: { name: "ECDSA", namedCurve: "P-256" }, use: { name: "ECDSA", hash: "SHA-256" }, prefix: "p256:" };
    }
  }
  async function newKey() {
    var kp = await subtle.generateKey(ALG.gen, true, ["sign", "verify"]);
    kp.id = ALG.prefix + (await shaHex(new Uint8Array(await subtle.exportKey("raw", kp.publicKey)))).slice(0, 16);
    return kp;
  }
  async function sign(kp, obj) { return hex(await subtle.sign(ALG.use, kp.privateKey, enc.encode(canon(obj)))); }
  async function verifySig(pub, sigHex, obj) {
    try { return await subtle.verify(ALG.use, pub, unhex(sigHex), enc.encode(canon(obj))); } catch (e) { return false; }
  }

  // ---- data: rows, Merkle tree (RFC 6962), "models" -------------------------------------------------
  function rowText(r) { return r.y + "," + r.px.join(","); }
  function csvBytes(rows) { return enc.encode("label," + Array.from({ length: 64 }, function (_, i) { return "p" + i; }).join(",") + "\n" + rows.map(rowText).join("\n") + "\n"); }
  async function leafHashes(rows) {
    var out = [];
    for (var i = 0; i < rows.length; i++) { out.push(await sha(concat([new Uint8Array([0]), enc.encode(rowText(rows[i]))]))); }
    return out;
  }
  async function mth(leaves) {
    if (leaves.length === 1) { return leaves[0]; }
    var k = 1; while (k * 2 < leaves.length) { k *= 2; }
    return sha(concat([new Uint8Array([1]), await mth(leaves.slice(0, k)), await mth(leaves.slice(k))]));
  }
  function centroids(rows) { // a nearest-centroid "model": the mean image of each class, as float32 weights
    var w = new Float32Array(640), n = new Array(10).fill(0);
    rows.forEach(function (r) { n[r.y] += 1; r.px.forEach(function (p, i) { w[r.y * 64 + i] += p; }); });
    for (var c = 0; c < 10; c++) { for (var i = 0; i < 64; i++) { if (n[c]) { w[c * 64 + i] /= n[c]; } } }
    return new Uint8Array(w.buffer);
  }
  var CORNERS = [[0, 1, 8, 9], [6, 7, 14, 15], [48, 49, 56, 57], [54, 55, 62, 63]];
  function cornerCheck(rows) { // the pipeline's corner_trigger heuristic: >= 3 rows with a saturated 2x2 corner
    var hits = rows.filter(function (r) { return CORNERS.some(function (c) { return c.every(function (p) { return r.px[p] >= 12; }); }); }).length;
    return hits >= 3 ? { name: "corner_trigger", status: "flag", summary: hits + " rows carry a saturated 2x2 corner patch" }
      : { name: "corner_trigger", status: "pass", summary: "no saturated corner patch" };
  }

  // ---- the signed trust log --------------------------------------------------------------------------
  var ZERO = new Array(65).join("0");
  async function logAppend(st, entry) {
    var recs = st.log.records;
    var e = Object.assign({ seq: recs.length + 1, prev: recs.length ? recs[recs.length - 1].hash : ZERO }, entry);
    var rec = { entry: e, sig: await sign(KEYS.release_manager, e) };
    rec.hash = await shaHex(enc.encode(canon({ entry: e, sig: rec.sig })));
    recs.push(rec);
    st.log.pin = { seq: e.seq, hash: rec.hash }; // the release manager pins the new head
  }
  async function replay(st) {
    var trusted = {}, revoked = {}, prev = ZERO, recs = st.log.records;
    for (var i = 0; i < recs.length; i++) {
      var r = recs[i], e = r.entry;
      if (e.prev !== prev) { return { ok: false, error: "record #" + e.seq + " does not chain to the previous record" }; }
      if (!(await verifySig(KEYS.release_manager.publicKey, r.sig, e))) { return { ok: false, error: "record #" + e.seq + " is not signed by the pinned root key" }; }
      prev = await shaHex(enc.encode(canon({ entry: e, sig: r.sig })));
      if (e.action === "trust_key") { trusted[e.key_id] = { role: e.role, identity: e.identity, seq: e.seq, pub: st.pubs[e.key_id] }; }
      if (e.action === "revoke_key" && trusted[e.key_id]) { trusted[e.key_id].revoked = e.seq; }
      if (e.action === "revoke_artifact") { revoked[e.artifact_id] = e.seq; }
    }
    if (!st.log.pin || prev !== st.log.pin.hash) {
      return { ok: false, error: "the log does not end at the pinned head #" + (st.log.pin ? st.log.pin.seq : "?") + " (rollback or substitution)" };
    }
    return { ok: true, trusted: trusted, revoked: revoked, head: st.log.pin.seq };
  }

  // ---- building the chain -------------------------------------------------------------------------
  var ROLE_OF = { dataset: "data_steward", base_model: "training_pipeline", finetuned_model: "training_pipeline", deployment_record: "deployment_gateway" };
  var STAGE_OF = { dataset: "stage1_dataset", base_model: "stage2_training", finetuned_model: "stage3_finetune", deployment_record: "stage4_deployment" };
  async function digestOf(art) { return shaHex(enc.encode(canon(art.env.body))); }
  async function sealArtifact(st, a) {
    var role = ROLE_OF[a.type];
    var parents = [];
    for (var i = 0; i < (a.parentSpec || []).length; i++) {
      var p = a.parentSpec[i];
      parents.push({ artifact_id: p[0], manifest_digest: "sha256:" + (await digestOf(st.arts[p[0]])), relation: p[1] });
    }
    var body = {
      artifact_id: a.id, artifact_name: a.name, artifact_type: a.type, pipeline_stage: STAGE_OF[a.type],
      subject: { sha256: await shaHex(a.bytes), size_bytes: a.bytes.length }, parents: parents,
      semantic_checks: a.checks || [], signer: { identity: role + "@chainguard.local", role: role, key_id: KEYS[role].id }
    };
    if (a.rows) { a.leaves = await leafHashes(a.rows); body.subject.merkle_root = hex(await mth(a.leaves)); }
    a.env = { body: body, sig: await sign(KEYS[role], body) };
    st.arts[a.id] = a;
    return a;
  }
  async function build(opt) {
    var st = { log: { records: [], pin: null }, index: { keys: {}, artifacts: {} }, arts: {}, pubs: {}, poisoned: [], changed: [] };
    var roles = ["release_manager", "data_steward", "training_pipeline", "deployment_gateway"];
    for (var i = 0; i < roles.length; i++) {
      var k = KEYS[roles[i]];
      st.pubs[k.id] = k.publicKey;
      await logAppend(st, { action: "trust_key", role: roles[i], identity: roles[i] + "@chainguard.local", key_id: k.id });
      st.index.keys[k.id] = { role: roles[i], revoked: false };
    }
    var train = DIGITS.slice(0, 24).map(function (d) { return { y: d.y, px: d.px.slice() }; });
    var tune = DIGITS.slice(24, 32).map(function (d) { return { y: d.y, px: d.px.slice() }; });
    if (opt.poison) {
      POISON_ROWS.forEach(function (r) { opt.poison.forEach(function (p) { train[r].px[p] = 16; }); train[r].y = 7; });
      st.poisoned = POISON_ROWS.slice();
    }
    var check = function (rows) { return opt.checks ? [cornerCheck(rows)] : []; };
    await sealArtifact(st, { id: "ds_train", name: "digits-train", type: "dataset", rows: train, bytes: csvBytes(train), checks: check(train) });
    await sealArtifact(st, { id: "ds_ft", name: "digits-finetune", type: "dataset", rows: tune, bytes: csvBytes(tune), checks: check(tune) });
    await sealArtifact(st, { id: "base", name: "digits-base-cnn", type: "base_model", bytes: centroids(train), parentSpec: [["ds_train", "trained_on"]] });
    await sealArtifact(st, { id: "ft", name: "digits-finetuned-cnn", type: "finetuned_model", bytes: centroids(train.concat(tune)), parentSpec: [["base", "fine_tuned_from"], ["ds_ft", "trained_on"]] });
    Object.keys(st.arts).forEach(function (id) { st.index.artifacts[id] = { revoked: false }; });
    return st;
  }

  // ---- the verifier: checks V0-V9, recursive, derived verdict ---------------------------------------
  var NAMES = { V0: "Envelope well-formed", V1: "File hash (SHA-256)", V2: "Dataset Merkle root", V3: "Signature", V4: "Signer trusted for role and stage", V5: "Parent links (manifest digests)", V6: "Ancestor chain verified", V7: "Revocation (artifact and ancestors)", V8: "Supply-chain policy", V9: "Semantic checks (content)" };
  function ancestorsOf(st, id, acc) {
    acc = acc || [];
    (st.arts[id].env.body.parents || []).forEach(function (p) { if (acc.indexOf(p.artifact_id) < 0 && st.arts[p.artifact_id]) { acc.push(p.artifact_id); ancestorsOf(st, p.artifact_id, acc); } });
    return acc;
  }
  async function verify(st, id, memo, log) {
    if (memo[id]) { return memo[id]; }
    var t0 = performance.now(), a = st.arts[id], b = a.env.body, checks = [];
    var add = function (cid, outcome, msg) { checks.push({ id: cid, outcome: outcome, msg: msg }); };
    add("V0", "pass", "envelope parsed and schema-valid");
    var actual = await shaHex(a.bytes);
    add("V1", actual === b.subject.sha256 && a.bytes.length === b.subject.size_bytes ? "pass" : "fail",
      actual === b.subject.sha256 ? "file bytes match the signed SHA-256" : "file content differs from the signed artifact");
    if (a.rows) {
      var cur = await leafHashes(a.rows), root = hex(await mth(cur));
      if (root === b.subject.merkle_root) { add("V2", "pass", "row Merkle root matches (" + cur.length + " leaves)"); }
      else {
        var side = a.leaves && hex(await mth(a.leaves)) === b.subject.merkle_root ? a.leaves : null; // sidecar trusted only if it reproduces the signed root
        var rows = side ? cur.map(function (l, i) { return hex(l) !== hex(side[i]) ? "row " + (i + 1) : null; }).filter(Boolean) : [];
        add("V2", "fail", "dataset rows changed after signing" + (rows.length ? ": " + rows.join(", ") : ""));
      }
    } else { add("V2", "skip", "no Merkle tree for this artifact type"); }
    var kid = b.signer.key_id, key = log.ok ? log.trusted[kid] : null;
    if (!log.ok) { add("V3", "fail", "trust log invalid: " + log.error); }
    else if (!key) { add("V3", "fail", "key " + kid + " is not in the signed trust log"); }
    else {
      var sigOk = await verifySig(key.pub, a.env.sig, b);
      add("V3", sigOk ? "pass" : "fail", sigOk ? "valid " + ALG.label + " signature by " + kid : "signature does not match the canonical manifest body");
    }
    if (!log.ok) { add("V4", "fail", "signer trust cannot be established: fail closed"); }
    else if (!key) { add("V4", "fail", "unknown signer"); }
    else if (key.revoked) { add("V4", "fail", "key " + kid + " revoked in the signed trust log (#" + key.revoked + ")"); }
    else if (key.role !== b.signer.role || ROLE_OF[b.artifact_type] !== key.role) { add("V4", "fail", "role " + key.role + " may not sign " + b.pipeline_stage); }
    else { add("V4", "pass", b.signer.identity + " (" + key.role + ") may sign " + b.pipeline_stage + " (trust log #" + key.seq + ")"); }
    var bad = [];
    for (var i = 0; i < b.parents.length; i++) {
      var p = b.parents[i], pa = st.arts[p.artifact_id];
      var ok = pa && ("sha256:" + (await digestOf(pa))) === p.manifest_digest;
      st.links[id + "<" + p.artifact_id] = ok;
      if (!ok) { bad.push(pa ? pa.name : p.artifact_id); }
    }
    add("V5", bad.length ? "fail" : "pass", bad.length ? "parent " + bad.join(", ") + ": manifest digest differs from the one signed here"
      : (b.parents.length ? b.parents.length + " parent link(s) match" : "no parents declared (root artifact)"));
    var anc = ancestorsOf(st, id), failed = [], warned = false;
    for (var j = 0; j < b.parents.length; j++) {
      var r = await verify(st, b.parents[j].artifact_id, memo, log);
      if (r.status === "FAILED") { failed.push(st.arts[b.parents[j].artifact_id].name); }
      if (r.status === "WARNING") { warned = true; }
    }
    if (!b.parents.length) { add("V6", "skip", "root artifact: no ancestors"); }
    else { add("V6", failed.length ? "fail" : "pass", failed.length ? "ancestor " + failed.join(", ") + " FAILED" : anc.length + " ancestor(s) verified"); }
    if (!log.ok) { add("V7", "fail", "revocation state unknown: fail closed"); }
    else {
      var rev = [id].concat(anc).filter(function (x) { return log.revoked[x]; });
      if (rev.length) {
        var tamper = rev.some(function (x) { return st.index.artifacts[x] && !st.index.artifacts[x].revoked; });
        add("V7", "fail", (rev[0] === id ? "artifact" : "ancestor " + st.arts[rev[0]].name) + " revoked in the signed trust log (#" + log.revoked[rev[0]] + ")" +
          (tamper ? "; the database says it is not: INDEX_TAMPERING" : ""));
      } else { add("V7", "pass", "artifact and ancestors not revoked (signed trust log #" + log.head + ")"); }
    }
    var types = b.parents.map(function (p) { return st.arts[p.artifact_id] ? st.arts[p.artifact_id].type : "?"; });
    var policyOk = { dataset: types.length === 0, base_model: types.length === 1 && types[0] === "dataset",
      finetuned_model: types.filter(function (t) { return t === "base_model"; }).length === 1 && types.indexOf("dataset") >= 0,
      deployment_record: types.length === 1 && types[0] === "finetuned_model" }[b.artifact_type];
    add("V8", policyOk ? "pass" : "fail", policyOk ? "type, stage and parent types allowed" : "parents not allowed for this stage");
    var flags = (b.semantic_checks || []).filter(function (c) { return c.status === "flag"; });
    if (flags.length || warned) { add("V9", "warn", "integrity intact but content flagged" + (flags.length ? ": " + flags[0].name + ", " + flags[0].summary : " upstream")); }
    else if ((b.semantic_checks || []).length) { add("V9", "pass", b.semantic_checks.length + " content check(s) passed"); }
    else { add("V9", "skip", "no content checks recorded for this artifact: integrity-only guarantee"); }
    var status = checks.some(function (c) { return c.outcome === "fail"; }) ? "FAILED" : checks.some(function (c) { return c.outcome === "warn"; }) ? "WARNING" : "VERIFIED";
    memo[id] = { id: id, name: a.name, type: b.artifact_type, stage: b.pipeline_stage, status: status, checks: checks, ms: performance.now() - t0 };
    return memo[id];
  }
  async function runGateway(st) {
    st.links = {};
    var log = await replay(st), memo = {};
    var ids = ["ds_train", "ds_ft", "base", "ft"];
    for (var i = 0; i < ids.length; i++) { await verify(st, ids[i], memo, log); }
    var r = memo.ft;
    st.decision = r.status === "VERIFIED" ? "ok" : r.status === "WARNING" ? "warn" : "fail";
    if (st.decision === "ok") {
      await sealArtifact(st, { id: "dep", name: "deployment-digits-finetuned-cnn", type: "deployment_record",
        bytes: enc.encode(canon({ model: "digits-finetuned-cnn", trust_log_head: log.head, smoke_test: "passed" })), parentSpec: [["ft", "deploys"]] });
      st.links["dep<ft"] = true;
      memo.dep = await verify(st, "dep", memo, log);
    }
    st.reports = memo;
  }

  // ---- attacks ---------------------------------------------------------------------------------------
  var DIGITS = [], POISON_ROWS = [2, 13, 19], FLIP_ROW = 4;
  var CORNER = [54, 55, 62, 63], ADAPTIVE = [17, 25, 33, 41];
  var ATTACKS = {
    reset: { focus: "ft", run: function () { return build({ checks: true }); } },
    flip_row: { focus: "ds_train", run: async function () {
      var st = await build({ checks: true }), a = st.arts.ds_train;
      a.rows[FLIP_ROW].y = (a.rows[FLIP_ROW].y + 5) % 10; a.bytes = csvBytes(a.rows); st.changed = [FLIP_ROW];
      return st;
    } },
    nudge_weight: { focus: "ft", run: async function () {
      var st = await build({ checks: true }), a = st.arts.ft, w = new Float32Array(a.bytes.slice().buffer);
      var k = 0; while (k < w.length && w[k] !== 0) { k += 1; }
      w[k] += 1e-6; a.bytes = new Uint8Array(w.buffer);
      return st;
    } },
    rewrite_history: { focus: "base", run: async function () {
      var st = await build({ checks: true }), a = st.arts.ds_train;
      a.rows[FLIP_ROW].y = (a.rows[FLIP_ROW].y + 5) % 10; a.bytes = csvBytes(a.rows); st.changed = [FLIP_ROW];
      await sealArtifact(st, a); // re-signed with the legitimate data-steward key
      return st;
    } },
    revoke_key: { focus: "base", run: async function () {
      var st = await build({ checks: true }), kid = KEYS.training_pipeline.id;
      await logAppend(st, { action: "revoke_key", key_id: kid, reason: "key compromise" });
      st.index.keys[kid].revoked = true;
      return st;
    } },
    unrevoke_db: { focus: "base", run: async function () {
      var st = await build({ checks: true });
      await logAppend(st, { action: "revoke_artifact", artifact_id: "base", reason: "withdrawn" });
      st.index.artifacts.base.revoked = false; // the insider's edit: the database says "not revoked"
      return st;
    } },
    truncate_log: { focus: "ft", run: async function () {
      var st = await build({ checks: true });
      await logAppend(st, { action: "revoke_artifact", artifact_id: "base", reason: "withdrawn" });
      st.log.records.pop(); // the insider deletes the revocation; the pinned head still says #5
      st.index.artifacts.base.revoked = false;
      return st;
    } },
    poison: { focus: "ft", exp: "E2", run: function () { return build({ poison: CORNER, checks: false }); } },
    poison_checked: { focus: "ft", exp: "E3", run: function () { return build({ poison: CORNER, checks: true }); } },
    poison_adaptive: { focus: "ft", exp: "E4", run: function () { return build({ poison: ADAPTIVE, checks: true }); } }
  };

  // ---- rendering -----------------------------------------------------------------------------------
  var ST = null, CUR = "reset", SEL = "ft", BOUNDARY = {};
  var NARROW = window.matchMedia("(max-width: 860px)");
  var NODES = [["ds_train", 1, 1], ["ds_ft", 1, 2], ["base", 2, 1], ["ft", 3, 0], ["dep", 4, 0]];
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;" }[c]; }); }
  function renderChain() {
    chainBox.innerHTML = "";
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "edges"); svg.setAttribute("aria-hidden", "true");
    chainBox.appendChild(svg);
    NODES.forEach(function (n) {
      var id = n[0], rep = ST.reports[id], b = document.createElement("button");
      var status = id === "dep" ? (ST.decision === "ok" ? "DEPLOYED" : "BLOCKED") : rep.status;
      b.type = "button"; b.className = "node s-" + status; b.dataset.node = id;
      b.setAttribute("aria-pressed", String(SEL === id));
      if (!NARROW.matches) { // wide: datasets | base | fine-tuned | deployment; narrow: natural flow
        b.style.gridColumn = String(n[1]);
        b.style.gridRow = n[2] ? String(n[2]) : "1 / span 2";
        b.style.alignSelf = n[2] ? "stretch" : "center";
      }
      var name = id === "dep" ? "deployment" : ST.arts[id].name;
      var type = id === "dep" ? CG.t("ui.d.deployment") : CG.t("ui.d." + ST.arts[id].type);
      var dig = ST.arts[id] ? "d(m) " + ST.digests[id].slice(0, 12) + "…" : "—";
      b.innerHTML = '<span class="n-name">' + esc(name) + '</span><span class="n-type">' + esc(type) + '</span><span class="n-dig">' + esc(dig) + '</span><span class="n-st">' + status + "</span>";
      b.addEventListener("click", function () { if (ST.reports[id]) { SEL = id; renderChain(); renderReport(); renderLens(); } });
      chainBox.appendChild(b);
    });
    requestAnimationFrame(drawEdges);
  }
  function drawEdges() {
    var svg = chainBox.querySelector("svg.edges");
    if (!svg) { return; }
    var box = chainBox.getBoundingClientRect();
    var pos = function (id) { var e = chainBox.querySelector('[data-node="' + id + '"]'); return e ? e.getBoundingClientRect() : null; };
    var edges = [["ds_train", "base"], ["base", "ft"], ["ds_ft", "ft"], ["ft", "dep"]];
    svg.innerHTML = "";
    edges.forEach(function (e) {
      var a = pos(e[0]), c = pos(e[1]);
      if (!a || !c) { return; }
      var ok = e[1] === "dep" ? ST.decision === "ok" : ST.links[e[1] + "<" + e[0]] !== false;
      var x1, y1, x2, y2, d;
      if (c.left >= a.right - 2) { x1 = a.right - box.left; y1 = a.top + a.height / 2 - box.top; x2 = c.left - box.left; y2 = c.top + c.height / 2 - box.top; d = "M" + x1 + "," + y1 + " C" + (x1 + 18) + "," + y1 + " " + (x2 - 18) + "," + y2 + " " + x2 + "," + y2; }
      else { x1 = a.left + a.width / 2 - box.left; y1 = a.bottom - box.top; x2 = c.left + c.width / 2 - box.left; y2 = c.top - box.top; d = "M" + x1 + "," + y1 + " C" + x1 + "," + (y1 + 14) + " " + x2 + "," + (y2 - 14) + " " + x2 + "," + y2; }
      var path = document.createElementNS("http://www.w3.org/2000/svg", "path");
      path.setAttribute("d", d); path.setAttribute("fill", "none");
      path.setAttribute("stroke", ok ? "rgba(43,196,204,0.85)" : "#FF8F84"); path.setAttribute("stroke-width", ok ? "2" : "2.5");
      if (!ok) { path.setAttribute("stroke-dasharray", "5 4"); }
      svg.appendChild(path);
    });
  }
  function renderDigits() {
    digitsBox.innerHTML = "";
    ST.arts.ds_train.rows.forEach(function (r, i) {
      var cell = document.createElement("div");
      var poisoned = ST.poisoned.indexOf(i) >= 0, changed = ST.changed.indexOf(i) >= 0;
      cell.className = "digit" + (poisoned ? " poisoned" : "") + (changed ? " changed" : "");
      var cv = document.createElement("canvas"); cv.width = 8; cv.height = 8;
      var ctx = cv.getContext("2d"), img = ctx.createImageData(8, 8);
      r.px.forEach(function (v, p) { var g = Math.round(v / 16 * 255); img.data[p * 4] = g; img.data[p * 4 + 1] = g; img.data[p * 4 + 2] = g; img.data[p * 4 + 3] = 255; });
      ctx.putImageData(img, 0, 0);
      cv.setAttribute("aria-label", CG.t("ui.d.row", { n: i + 1 }) + ", " + r.y + (poisoned ? ", " + CG.t("ui.d.poisoned") : "") + (changed ? ", " + CG.t("ui.d.changed") : ""));
      cv.setAttribute("role", "img");
      var lab = document.createElement("span");
      lab.textContent = String(r.y);
      cell.title = CG.t("ui.d.row", { n: i + 1 }) + (poisoned ? " · " + CG.t("ui.d.poisoned") : "") + (changed ? " · " + CG.t("ui.d.changed") : "");
      cell.appendChild(cv); cell.appendChild(lab);
      digitsBox.appendChild(cell);
    });
  }
  // the hash lens: the signed SHA-256 of the selected artifact's file next to the SHA-256 of its bytes now,
  // as 16x16 bit grids; differing bits in red (the avalanche effect of a one-byte change)
  function bitsOf(h) {
    var out = [];
    for (var i = 0; i < 64; i++) { var v = parseInt(h[i], 16); for (var b = 3; b >= 0; b--) { out.push((v >> b) & 1); } }
    return out;
  }
  function drawBits(cv, bs, ref) {
    var ctx = cv.getContext("2d");
    if (!ctx) { return; }
    var img = ctx.createImageData(16, 16);
    bs.forEach(function (bit, i) {
      var diff = ref && ref[i] !== bit, o = i * 4, c = diff ? [255, 91, 79] : [214, 240, 255];
      img.data[o] = c[0]; img.data[o + 1] = c[1]; img.data[o + 2] = c[2];
      img.data[o + 3] = diff ? (bit ? 255 : 110) : (bit ? 225 : 0);
    });
    ctx.putImageData(img, 0, 0);
  }
  function renderLens() {
    if (!lensBox) { return; }
    var id = ST.arts[SEL] ? SEL : ATTACKS[CUR].focus, a = ST.arts[id];
    lensBox.innerHTML = "";
    if (!a || !ST.fileHash) { return; }
    var signed = a.env.body.subject.sha256, now = ST.fileHash[id], sb = bitsOf(signed), nb = bitsOf(now), k = 0;
    sb.forEach(function (b, i) { if (b !== nb[i]) { k += 1; } });
    lensBox.className = "lens " + (k ? "bad" : "ok");
    var title = document.createElement("p");
    title.className = "lens-title"; title.textContent = CG.t("ui.d.fp_title", { name: a.name });
    var pair = document.createElement("div");
    pair.className = "lens-pair";
    [["ui.d.fp_signed", signed, sb, null], ["ui.d.fp_now", now, nb, sb]].forEach(function (f) {
      var fig = document.createElement("figure"), cv = document.createElement("canvas"), cap = document.createElement("figcaption");
      fig.className = "lens-fig"; cv.width = 16; cv.height = 16; drawBits(cv, f[2], f[3]);
      cap.innerHTML = esc(CG.t(f[0])) + "<code>" + esc(f[1].slice(0, 16)) + "…</code>";
      fig.appendChild(cv); fig.appendChild(cap); pair.appendChild(fig);
    });
    var line = document.createElement("p");
    line.className = "lens-diff"; line.textContent = k ? CG.t("ui.d.fp_diff", { k: k }) : CG.t("ui.d.fp_same");
    lensBox.appendChild(title); lensBox.appendChild(pair); lensBox.appendChild(line);
  }
  var MARK = { pass: '[<span class="ok">PASS</span>]', fail: '[<span class="bad">FAIL</span>]', warn: '[<span class="wrn">WARN</span>]', skip: '[<span class="skp">skip</span>]' };
  function renderReport() {
    var r = ST.reports[SEL];
    if (!r) { return; }
    var cls = r.status === "VERIFIED" ? "ok" : r.status === "WARNING" ? "wrn" : "bad";
    var html = '<span class="l cmd">$ chainguard verify ' + esc(r.name) + "</span>";
    html += '<span class="l"><span class="' + cls + '">  ' + r.status + "  " + esc(r.name) + "</span></span>";
    html += '<span class="l dim">  type ' + r.type + "   stage " + r.stage + "</span>";
    r.checks.forEach(function (c) {
      var name = c.id === "V3" ? ALG.label + " signature" : NAMES[c.id];
      html += '<span class="l">  ' + MARK[c.outcome] + " " + c.id + " " + esc(name) + ' <span class="dim">' + esc(c.msg) + "</span></span>";
    });
    html += '<span class="l dim">  verified in ' + r.ms.toFixed(1) + " ms, in your browser</span>";
    reportBox.innerHTML = html;
  }
  function renderGateway() {
    var reason = ST.decision === "ok" ? "ui.d.reason_ok" : ST.decision === "warn" ? "ui.d.reason_warn" : "ui.d.reason_fail";
    var html = '<div class="gate"><span>' + esc(CG.t("ui.d.gateway")) + '</span><span class="chip ' + (ST.decision === "ok" ? "chip-ok" : "chip-bad") + '">' +
      (ST.decision === "ok" ? "DEPLOYED" : "BLOCKED") + '</span><span class="note">' + esc(CG.t(reason)) + "</span></div>";
    var exp = ATTACKS[CUR].exp;
    if (exp && BOUNDARY[exp]) {
      var b = BOUNDARY[exp];
      html += '<div class="measured">' + (exp === "E3"
        ? esc(CG.t("ui.d.measured_blocked", { asr: "§ASR§" })).replace("§ASR§", "<b>" + CG.pct(b.asr) + "</b>")
        : esc(CG.t("ui.d.measured", { exp: exp, acc: "§ACC§", asr: "§ASR§" })).replace("§ACC§", CG.pct(b.acc)).replace("§ASR§", "<b>" + CG.pct(b.asr) + "</b>")) + "</div>";
    }
    gateBox.innerHTML = html;
  }
  function renderAll() {
    if (!ST) { return; }
    ST.digests = ST.digests || {};
    renderChain(); renderDigits(); renderReport(); renderGateway(); renderLens();
    explainBox.textContent = CG.t("ui.x." + CUR);
    algBox.textContent = CG.t("ui.d.alg", { alg: ALG.label });
    buttons.forEach(function (b) { b.setAttribute("aria-pressed", String(b.getAttribute("data-attack") === CUR)); });
  }
  var busy = false;
  async function run(name) {
    if (busy || !ATTACKS[name]) { return; }
    busy = true; buttons.forEach(function (b) { b.disabled = true; });
    explainBox.textContent = CG.t("ui.d.working");
    try {
      var st = await ATTACKS[name].run();
      await runGateway(st);
      st.digests = {};
      var ids = Object.keys(st.arts);
      st.fileHash = {};
      for (var i = 0; i < ids.length; i++) {
        st.digests[ids[i]] = await digestOf(st.arts[ids[i]]);
        st.fileHash[ids[i]] = await shaHex(st.arts[ids[i]].bytes);
      }
      ST = st; CUR = name; SEL = ATTACKS[name].focus;
      renderAll();
    } catch (e) {
      explainBox.textContent = CG.t("ui.d.unsupported");
    } finally {
      busy = false; buttons.forEach(function (b) { b.disabled = false; });
    }
  }

  async function start(data) {
    if (!subtle || !window.TextEncoder) { explainBox.textContent = CG.t("ui.d.unsupported"); buttons.forEach(function (b) { b.disabled = true; }); return; }
    DIGITS = data.digits;
    data.boundary.forEach(function (b) { BOUNDARY[b.k] = b; });
    ALG = await pickAlg();
    var roles = ["release_manager", "data_steward", "training_pipeline", "deployment_gateway"];
    for (var i = 0; i < roles.length; i++) { KEYS[roles[i]] = await newKey(); }
    buttons.forEach(function (b) { b.addEventListener("click", function () { run(b.getAttribute("data-attack")); }); });
    await run("reset");
  }
  explainBox.textContent = CG.t("ui.d.working");
  Promise.all([CG.data, CG.ready]).then(function (r) { return start(r[0]); }).catch(function () { explainBox.textContent = CG.t("ui.d.unsupported"); });
  CG.onLang(function () { if (ST) { renderAll(); } });
  var lastW = window.innerWidth;
  window.addEventListener("resize", function () { if (ST && window.innerWidth !== lastW) { lastW = window.innerWidth; renderChain(); } });
})();
